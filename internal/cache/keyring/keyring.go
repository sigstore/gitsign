// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package keyring implements a credential cache backed by the operating
// system keyring (macOS Keychain, Windows Credential Manager, Linux Secret
// Service / KWallet). Unlike the gitsign-credential-cache daemon, no
// long-running process is required.
//
// Credentials are cached per identity, keyed by cache.CredentialKey (the
// gitsign configuration used to obtain them). Multiple identities can be
// stored concurrently; entries live for the lifetime of the certificate and
// are removed lazily on read once expired.
//
// On macOS the Keychain is accessed via Security.framework, which requires
// gitsign to be built with cgo.
package keyring

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
)

const (
	// serviceName is the keyring service name all gitsign entries are stored
	// under.
	serviceName = "gitsign"
	// credentialKeyPrefix mirrors the prefix used by cache.CredentialKey;
	// used to recognize gitsign entries when enumerating keys.
	credentialKeyPrefix = "credential/v1/" //nolint:gosec // key namespace, not a credential
	// dataKeyMarker distinguishes payload chunk entries from credential
	// header entries.
	dataKeyMarker = "/data/"
	// defaultMaxEntrySize bounds individual keyring entry values. Windows
	// Credential Manager limits credential blobs to 2560 bytes, so the
	// payload is split across entries and the header must fit in one.
	defaultMaxEntrySize = 2000

	// generationGrace is how long an unreferenced generation is left alone
	// before StoreCert garbage-collects it. A concurrent store writes its
	// chunks before its header, so a young unreferenced generation may still
	// be about to become current; a store never takes anywhere near this
	// long.
	generationGrace = 5 * time.Minute

	envelopeVersion = 2
)

// header is stored under the credential key. It is kept small so it fits in
// a single keyring entry; the credential itself lives in payload chunks.
type header struct {
	Version  int       `json:"version"`
	NotAfter time.Time `json:"notAfter"`
	// Generation names the payload chunks written by one StoreCert call
	// (<key>/data/<generation>/<i>), prefixed with its creation time so
	// superseded generations can be garbage-collected. Chunks are never
	// modified after being written, so concurrent stores can't corrupt each
	// other: a reader either sees a complete generation or a miss.
	Generation string `json:"generation"`
	Chunks     int    `json:"chunks"`
	// SHA256 is the hex SHA-256 of the reassembled payload.
	SHA256 string       `json:"sha256"`
	Meta   api.Metadata `json:"meta"`
}

// payload is the credential, serialized and split across chunk entries.
type payload struct {
	PrivateKey string `json:"privateKey"`
	Cert       string `json:"cert"`
	Chain      string `json:"chain"`
}

// Cache implements cache.Cache backed by the OS keyring.
type Cache struct {
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// Config is used to derive the identity key when storing credentials.
	Config *config.Config

	// Keyring overrides the backing keyring. For testing.
	Keyring keyring.Keyring
	// maxEntrySize overrides the per-entry size limit. For testing.
	maxEntrySize int

	kr keyring.Keyring
}

var _ cache.Manager = (*Cache)(nil)

// keyring lazily opens the OS keyring, so that construction never fails and
// unavailable keyrings (e.g. headless Linux) surface as soft errors on use.
func (c *Cache) keyring() (keyring.Keyring, error) {
	if c.Keyring != nil {
		return c.Keyring, nil
	}
	if c.kr == nil {
		kr, err := openSystemKeyring()
		if err != nil {
			return nil, fmt.Errorf("error opening system keyring: %w", err)
		}
		c.kr = kr
	}
	return c.kr, nil
}

func (c *Cache) entrySize() int {
	if c.maxEntrySize > 0 {
		return c.maxEntrySize
	}
	return defaultMaxEntrySize
}

// readHeader decodes a credential header. errUnsupportedEntry is returned
// for entries that can't be decoded or were written in another format.
func readHeader(item keyring.Item) (*header, error) {
	h := new(header)
	if err := json.Unmarshal(item.Data, h); err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsupportedEntry, err)
	}
	if h.Version != envelopeVersion {
		return nil, fmt.Errorf("%w: version %d", errUnsupportedEntry, h.Version)
	}
	return h, nil
}

// errUnsupportedEntry marks an entry written by an incompatible build.
var errUnsupportedEntry = errors.New("unsupported keyring entry")

var (
	// errReplaced means a header's chunks disappeared while reading, most
	// likely because a concurrent StoreCert replaced the generation.
	errReplaced = errors.New("credential replaced while reading")
	// errCorrupt means the stored payload doesn't match its header.
	errCorrupt = errors.New("stored credential is corrupt")
)

// loadPayload reassembles and decodes the payload referenced by h. It never
// modifies the keyring.
func loadPayload(kr keyring.Keyring, key string, h *header) (*payload, error) {
	var raw []byte
	for i := range h.Chunks {
		item, err := kr.Get(dataKey(key, h.Generation, i))
		if err != nil {
			if errors.Is(err, keyring.ErrKeyNotFound) {
				return nil, errReplaced
			}
			return nil, fmt.Errorf("error reading credential chunk %d: %w", i, err)
		}
		raw = append(raw, item.Data...)
	}
	// Generations are immutable, so a mismatch means the entry is corrupt.
	if digest(raw) != h.SHA256 {
		return nil, errCorrupt
	}
	p := new(payload)
	if err := json.Unmarshal(raw, p); err != nil {
		return nil, fmt.Errorf("%w: %w", errCorrupt, err)
	}
	return p, nil
}

// GetCredentials returns the cached credential for the identity described by
// cfg. Expired or invalid entries are deleted and reported as a miss/error.
func (c *Cache) GetCredentials(_ context.Context, cfg *config.Config) (crypto.PrivateKey, []byte, []byte, error) {
	if cfg == nil {
		cfg = c.Config
	}
	kr, err := c.keyring()
	if err != nil {
		return nil, nil, nil, err
	}
	key := cache.CredentialKey(cfg)
	item, err := kr.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return nil, nil, nil, fmt.Errorf("%w: no entry for identity", cache.ErrNotFound)
		}
		return nil, nil, nil, fmt.Errorf("error reading credential from keyring: %w", err)
	}

	h, err := readHeader(item)
	if err != nil {
		// e.g. an entry written by an incompatible build - treat as a miss so
		// it's replaced on the next store.
		deleteEntry(kr, key)
		return nil, nil, nil, fmt.Errorf("%w: %w (entry deleted)", cache.ErrNotFound, err)
	}

	// Cheap expiry check before doing any crypto - the credential is only
	// useful for the lifetime of the cert.
	if time.Now().Add(30 * time.Second).After(h.NotAfter) {
		deleteEntry(kr, key)
		return nil, nil, nil, fmt.Errorf("%w: stored cert expired", cache.ErrNotFound)
	}

	p, err := loadPayload(kr, key, h)
	switch {
	case errors.Is(err, errReplaced):
		// Don't delete - the entry now in place is probably valid; just miss
		// this time.
		return nil, nil, nil, fmt.Errorf("%w: %w", cache.ErrNotFound, err)
	case errors.Is(err, errCorrupt):
		deleteEntry(kr, key)
		return nil, nil, nil, fmt.Errorf("%w: %w (entry deleted)", cache.ErrNotFound, err)
	case err != nil:
		return nil, nil, nil, fmt.Errorf("error reading credential from keyring: %w", err)
	}

	certPEM := []byte(p.Cert)
	if err := cache.ValidateCert(certPEM, c.Roots, c.Intermediates); err != nil {
		deleteEntry(kr, key)
		return nil, nil, nil, fmt.Errorf("%w: %w (entry deleted)", cache.ErrNotFound, err)
	}

	var chain []byte
	if p.Chain != "" {
		chain = []byte(p.Chain)
	}
	privateKey, _, _, err := cache.DecodeCredential(&api.Credential{
		PrivateKey: []byte(p.PrivateKey),
		Cert:       certPEM,
		Chain:      chain,
	})
	if err != nil {
		deleteEntry(kr, key)
		return nil, nil, nil, fmt.Errorf("%w: error unmarshalling private key (entry deleted): %w", cache.ErrNotFound, err)
	}

	return privateKey, certPEM, chain, nil
}

// StoreCert stores the credential under the identity derived from the
// configured Config, replacing any previous entry.
func (c *Cache) StoreCert(_ context.Context, priv crypto.PrivateKey, cert, chain []byte) error {
	kr, err := c.keyring()
	if err != nil {
		return err
	}
	cfg := c.Config
	key := cache.CredentialKey(cfg)

	cred, err := cache.EncodeCredential(priv, cert, chain)
	if err != nil {
		return err
	}

	notAfter, err := cache.NotAfter(cert)
	if err != nil {
		return err
	}

	raw, err := json.Marshal(&payload{ //nolint:gosec // intentionally serialized for storage in the OS keyring
		PrivateKey: string(cred.PrivateKey),
		Cert:       string(cert),
		Chain:      string(chain),
	})
	if err != nil {
		return fmt.Errorf("error marshalling credential: %w", err)
	}

	gen, err := newGeneration()
	if err != nil {
		return err
	}
	chunks := chunk(raw, c.entrySize())
	meta := cache.MetadataFromConfig(cfg)
	h := &header{
		Version:    envelopeVersion,
		NotAfter:   notAfter,
		Generation: gen,
		Chunks:     len(chunks),
		SHA256:     digest(raw),
		Meta:       meta,
	}
	rawHeader, err := json.Marshal(h)
	if err != nil {
		return fmt.Errorf("error marshalling credential header: %w", err)
	}
	if len(rawHeader) > c.entrySize() {
		return fmt.Errorf("credential metadata too large for a keyring entry (%d > %d bytes)", len(rawHeader), c.entrySize())
	}

	// Remember the generation being replaced so its chunks can be cleaned up
	// once the new header is in place.
	var prev *header
	if item, err := kr.Get(key); err == nil {
		prev, _ = readHeader(item)
	}

	label := serviceName
	if meta.CommitterEmail != "" {
		label = fmt.Sprintf("%s (%s)", serviceName, meta.CommitterEmail)
	}

	// Store chunks first so that a reader never sees a header pointing at
	// chunks that don't exist yet.
	for i, ch := range chunks {
		if err := kr.Set(keyring.Item{
			Key:         dataKey(key, gen, i),
			Data:        ch,
			Label:       label,
			Description: "gitsign signing credential data",
		}); err != nil {
			deleteChunks(kr, key, gen, i)
			return fmt.Errorf("error storing credential in keyring: %w", err)
		}
	}
	if err := kr.Set(keyring.Item{
		Key:         key,
		Data:        rawHeader,
		Label:       label,
		Description: "gitsign signing credential",
	}); err != nil {
		deleteChunks(kr, key, gen, len(chunks))
		return fmt.Errorf("error storing credential in keyring: %w", err)
	}

	collectGenerations(kr, key, gen, prev)
	return nil
}

// collectGenerations removes, best effort, payload generations that are no
// longer referenced after a store of generation own:
//
//   - prev, the generation this store replaced;
//   - own, if a concurrent store has already published a newer header;
//   - any other unreferenced generation older than generationGrace, e.g.
//     one orphaned when two concurrent stores replaced the same header.
//
// It never removes the current header's generation, or a young generation a
// concurrent store may be about to publish.
func collectGenerations(kr keyring.Keyring, key, own string, prev *header) {
	if prev != nil && prev.Generation != own {
		deleteChunks(kr, key, prev.Generation, prev.Chunks)
	}

	item, err := kr.Get(key)
	if err != nil {
		return
	}
	cur, err := readHeader(item)
	if err != nil {
		return
	}
	keys, err := kr.Keys()
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-generationGrace)
	for _, k := range keys {
		gen, ok := generationOf(key, k)
		if !ok || gen == cur.Generation {
			continue
		}
		if gen == own || generationTime(gen).Before(cutoff) {
			_ = kr.Remove(k)
		}
	}
}

// List enumerates stored credentials.
func (c *Cache) List(_ context.Context) ([]api.CredentialInfo, error) {
	kr, err := c.keyring()
	if err != nil {
		return nil, err
	}
	keys, err := kr.Keys()
	if err != nil {
		return nil, fmt.Errorf("error listing keyring entries: %w", err)
	}
	out := []api.CredentialInfo{}
	for _, key := range keys {
		if !isCredentialKey(key) {
			continue
		}
		// Report unreadable entries rather than hiding them, so they can be
		// found and cleared.
		item, err := kr.Get(key)
		if err != nil {
			out = append(out, api.CredentialInfo{ID: key, Error: err.Error()})
			continue
		}
		h, err := readHeader(item)
		if err != nil {
			out = append(out, api.CredentialInfo{ID: key, Error: err.Error()})
			continue
		}
		// Check the payload is actually usable (without modifying anything),
		// so an entry with missing or corrupt chunks isn't reported valid.
		if _, err := loadPayload(kr, key, h); err != nil {
			out = append(out, api.CredentialInfo{ID: key, NotAfter: h.NotAfter, Meta: h.Meta, Error: err.Error()})
			continue
		}
		out = append(out, api.CredentialInfo{
			ID:       key,
			NotAfter: h.NotAfter,
			Meta:     h.Meta,
		})
	}
	return out, nil
}

// Delete removes the credential for the identity described by the configured
// Config. It returns cache.ErrNotFound if no entry exists.
func (c *Cache) Delete(_ context.Context) error {
	kr, err := c.keyring()
	if err != nil {
		return err
	}
	key := cache.CredentialKey(c.Config)
	// Check existence explicitly - Remove semantics for missing keys vary
	// between backends.
	_, err = kr.Get(key)
	if err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return fmt.Errorf("error reading credential from keyring: %w", err)
	}
	headerFound := err == nil
	// Remove everything for the identity even without a header, so data
	// orphaned by an interrupted or racing store can still be cleared.
	removed, err := deleteAllForKey(kr, key)
	if err != nil {
		return fmt.Errorf("error deleting credential from keyring: %w", err)
	}
	if !headerFound && removed == 0 {
		return fmt.Errorf("%w: no entry for identity", cache.ErrNotFound)
	}
	return nil
}

// DeleteAll removes every gitsign credential entry (including chunks).
func (c *Cache) DeleteAll(_ context.Context) error {
	kr, err := c.keyring()
	if err != nil {
		return err
	}
	keys, err := kr.Keys()
	if err != nil {
		return fmt.Errorf("error listing keyring entries: %w", err)
	}
	// Best-effort: keep deleting remaining entries even if one fails (e.g.
	// an entry another tool created that we don't have access to remove).
	var errs []error
	for _, key := range keys {
		if !strings.HasPrefix(key, credentialKeyPrefix) {
			continue
		}
		if err := kr.Remove(key); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
			errs = append(errs, fmt.Errorf("error deleting keyring entry %q: %w", key, err))
		}
	}
	return errors.Join(errs...)
}

// isCredentialKey reports whether the key names a credential header entry (as
// opposed to a payload chunk or an unrelated entry).
func isCredentialKey(key string) bool {
	rest, ok := strings.CutPrefix(key, credentialKeyPrefix)
	return ok && !strings.Contains(rest, "/")
}

// deleteEntry removes the credential header and everything stored under it.
// Best-effort.
func deleteEntry(kr keyring.Keyring, key string) {
	_, _ = deleteAllForKey(kr, key)
}

// deleteAllForKey removes the credential header and every chunk stored under
// it, of any generation (found by enumeration, best effort). Removing only
// the generation named by a header read earlier would race with StoreCert: a
// concurrent writer could publish a new header that the removal deletes,
// orphaning the new generation's chunks. Returns how many chunk entries were
// removed (header removal isn't counted - Remove semantics for missing keys
// vary between backends), and any errors enumerating or removing entries -
// failing to remove a chunk would leave private-key material behind.
func deleteAllForKey(kr keyring.Keyring, key string) (int, error) {
	removed := 0
	if err := kr.Remove(key); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return removed, err
	}
	keys, err := kr.Keys()
	if err != nil {
		return removed, fmt.Errorf("error listing keyring entries: %w", err)
	}
	var errs []error
	for _, k := range keys {
		if !strings.HasPrefix(k, key+"/") {
			continue
		}
		if err := kr.Remove(k); err == nil {
			removed++
		} else if !errors.Is(err, keyring.ErrKeyNotFound) {
			errs = append(errs, fmt.Errorf("error deleting keyring entry %q: %w", k, err))
		}
	}
	return removed, errors.Join(errs...)
}

func deleteChunks(kr keyring.Keyring, key, gen string, chunks int) {
	for i := range chunks {
		_ = kr.Remove(dataKey(key, gen, i))
	}
}

func newGeneration() (string, error) {
	return newGenerationAt(time.Now())
}

// newGenerationAt returns a unique generation ID: the creation time (hex unix
// nanoseconds) followed by random bytes.
func newGenerationAt(t time.Time) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("error generating credential generation: %w", err)
	}
	return fmt.Sprintf("%016x-%s", t.UnixNano(), hex.EncodeToString(b)), nil
}

// generationTime returns when a generation was created. Unparseable IDs
// (e.g. from an older layout) are treated as infinitely old.
func generationTime(gen string) time.Time {
	ts, _, ok := strings.Cut(gen, "-")
	if !ok {
		return time.Time{}
	}
	n, err := strconv.ParseInt(ts, 16, 64)
	if err != nil {
		return time.Time{}
	}
	return time.Unix(0, n)
}

// generationOf returns the generation of payload chunk key k for credential
// key.
func generationOf(key, k string) (string, bool) {
	rest, ok := strings.CutPrefix(k, key+dataKeyMarker)
	if !ok {
		return "", false
	}
	gen, _, ok := strings.Cut(rest, "/")
	return gen, ok
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func dataKey(key, gen string, i int) string {
	return fmt.Sprintf("%s%s%s/%d", key, dataKeyMarker, gen, i)
}

func chunk(b []byte, size int) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		n := min(size, len(b))
		out = append(out, b[:n])
		b = b[n:]
	}
	return out
}
