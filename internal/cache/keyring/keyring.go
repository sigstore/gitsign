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
// On macOS the Keychain is accessed via the /usr/bin/security CLI (the
// native Security.framework API requires cgo, which gitsign builds don't
// use); other platforms use the native credential store APIs.
package keyring

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	credentialKeyPrefix = "credential/v1/"
	// chainKeyMarker distinguishes chain chunk entries from credential
	// entries.
	chainKeyMarker = "/chain/"
	// defaultMaxEntrySize bounds individual keyring entry values. Windows
	// Credential Manager limits credential blobs to 2560 bytes, so larger
	// payloads (typically the certificate chain) are split across entries.
	defaultMaxEntrySize = 2000

	envelopeVersion = 1
)

// envelope is the JSON payload stored under the credential key.
type envelope struct {
	Version    int       `json:"version"`
	NotAfter   time.Time `json:"notAfter"`
	PrivateKey string    `json:"privateKey"`
	Cert       string    `json:"cert"`
	// ChainChunks is the number of chain chunk entries stored alongside the
	// credential (0 if there is no chain).
	ChainChunks int            `json:"chainChunks"`
	Meta        cache.Metadata `json:"meta"`
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
// The backend is selected per-platform by openSystemKeyring: the native
// credential store on most builds, or the /usr/bin/security CLI on macOS
// builds without cgo.
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

	env := new(envelope)
	if err := json.Unmarshal(item.Data, env); err != nil {
		c.deleteEntry(kr, key, 0)
		return nil, nil, nil, fmt.Errorf("error unmarshalling stored credential (entry deleted): %w", err)
	}
	if env.Version != envelopeVersion {
		c.deleteEntry(kr, key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("%w: unsupported credential version %d (entry deleted)", cache.ErrNotFound, env.Version)
	}

	// Cheap expiry check before doing any crypto - the credential is only
	// useful for the lifetime of the cert.
	if time.Now().Add(30 * time.Second).After(env.NotAfter) {
		c.deleteEntry(kr, key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("%w: stored cert expired", cache.ErrNotFound)
	}

	chain, err := readChain(kr, key, env.ChainChunks)
	if err != nil {
		c.deleteEntry(kr, key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("error reading stored chain (entry deleted): %w", err)
	}

	certPEM := []byte(env.Cert)
	if err := cache.ValidateCert(certPEM, c.Roots, c.Intermediates); err != nil {
		c.deleteEntry(kr, key, env.ChainChunks)
		return nil, nil, nil, err
	}

	privateKey, _, _, err := cache.DecodeCredential(&api.Credential{
		PrivateKey: []byte(env.PrivateKey),
		Cert:       certPEM,
		Chain:      chain,
	})
	if err != nil {
		c.deleteEntry(kr, key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("error unmarshalling private key (entry deleted): %w", err)
	}

	return privateKey, certPEM, chain, nil
}

// StoreCert stores the credential under the identity derived from the
// configured Config, overwriting any previous entry.
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

	chunks := chunk(chain, c.entrySize())
	meta := cache.MetadataFromConfig(cfg)
	env := &envelope{
		Version:     envelopeVersion,
		NotAfter:    notAfter,
		PrivateKey:  string(cred.PrivateKey),
		Cert:        string(cert),
		ChainChunks: len(chunks),
		Meta:        meta,
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("error marshalling credential: %w", err)
	}

	label := serviceName
	if meta.CommitterEmail != "" {
		label = fmt.Sprintf("%s (%s)", serviceName, meta.CommitterEmail)
	}

	// Store chain chunks first so that a reader never sees a credential
	// entry pointing at chunks that don't exist yet.
	for i, ch := range chunks {
		if err := kr.Set(keyring.Item{
			Key:         chainKey(key, i),
			Data:        ch,
			Label:       label,
			Description: "gitsign signing certificate chain",
		}); err != nil {
			return fmt.Errorf("error storing chain in keyring: %w", err)
		}
	}
	if err := kr.Set(keyring.Item{
		Key:         key,
		Data:        raw,
		Label:       label,
		Description: "gitsign signing credential",
	}); err != nil {
		return fmt.Errorf("error storing credential in keyring: %w", err)
	}

	return nil
}

// List enumerates stored credentials.
func (c *Cache) List(_ context.Context) ([]cache.CredentialInfo, error) {
	kr, err := c.keyring()
	if err != nil {
		return nil, err
	}
	keys, err := kr.Keys()
	if err != nil {
		return nil, fmt.Errorf("error listing keyring entries: %w", err)
	}
	out := []cache.CredentialInfo{}
	for _, key := range keys {
		if !isCredentialKey(key) {
			continue
		}
		item, err := kr.Get(key)
		if err != nil {
			continue
		}
		env := new(envelope)
		if err := json.Unmarshal(item.Data, env); err != nil {
			continue
		}
		out = append(out, cache.CredentialInfo{
			ID:       key,
			NotAfter: env.NotAfter,
			Meta:     env.Meta,
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
	item, err := kr.Get(key)
	if err != nil {
		if errors.Is(err, keyring.ErrKeyNotFound) {
			return fmt.Errorf("%w: no entry for identity", cache.ErrNotFound)
		}
		return fmt.Errorf("error reading credential from keyring: %w", err)
	}
	chunks := 0
	env := new(envelope)
	if err := json.Unmarshal(item.Data, env); err == nil {
		chunks = env.ChainChunks
	}
	if err := kr.Remove(key); err != nil && !errors.Is(err, keyring.ErrKeyNotFound) {
		return fmt.Errorf("error deleting credential from keyring: %w", err)
	}
	deleteChain(kr, key, chunks)
	return nil
}

// DeleteAll removes every gitsign credential entry (including chain chunks).
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

// isCredentialKey reports whether the key names a credential envelope entry
// (as opposed to a chain chunk or an unrelated entry).
func isCredentialKey(key string) bool {
	return strings.HasPrefix(key, credentialKeyPrefix) && !strings.Contains(key, chainKeyMarker)
}

// chainChunkCount reads the stored envelope to discover how many chain chunk
// entries accompany the credential. Returns 0 if the entry is missing or
// malformed.
func chainChunkCount(kr keyring.Keyring, key string) int {
	item, err := kr.Get(key)
	if err != nil {
		return 0
	}
	env := new(envelope)
	if err := json.Unmarshal(item.Data, env); err != nil {
		return 0
	}
	return env.ChainChunks
}

func readChain(kr keyring.Keyring, key string, chunks int) ([]byte, error) {
	if chunks == 0 {
		return nil, nil
	}
	var chain []byte
	for i := range chunks {
		item, err := kr.Get(chainKey(key, i))
		if err != nil {
			return nil, fmt.Errorf("error reading chain chunk %d: %w", i, err)
		}
		chain = append(chain, item.Data...)
	}
	return chain, nil
}

// deleteEntry removes the credential entry and its chain chunks. All
// deletions are best-effort.
func (c *Cache) deleteEntry(kr keyring.Keyring, key string, chunks int) {
	_ = kr.Remove(key)
	deleteChain(kr, key, chunks)
}

func deleteChain(kr keyring.Keyring, key string, chunks int) {
	for i := range chunks {
		_ = kr.Remove(chainKey(key, i))
	}
}

func chainKey(key string, i int) string {
	return fmt.Sprintf("%s%s%d", key, chainKeyMarker, i)
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
