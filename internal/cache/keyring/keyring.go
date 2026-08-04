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
// Service). Unlike the gitsign-credential-cache daemon, no long-running
// process is required.
//
// Credentials are cached per identity, keyed by cache.CredentialKey (the
// gitsign configuration used to obtain them). Multiple identities can be
// stored concurrently; entries live for the lifetime of the certificate and
// are removed lazily on read once expired.
package keyring

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/zalando/go-keyring"
)

const (
	// defaultService is the keyring service name all gitsign entries are
	// stored under.
	defaultService = "gitsign"
	// indexKey holds a JSON list of stored credentials, since the keyring
	// API has no enumeration support.
	indexKey = "index/v1"
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

	// service overrides the keyring service name. For testing.
	service string
	// maxEntrySize overrides the per-entry size limit. For testing.
	maxEntrySize int
}

var _ cache.Manager = (*Cache)(nil)

func (c *Cache) serviceName() string {
	if c.service != "" {
		return c.service
	}
	return defaultService
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
	key := cache.CredentialKey(cfg)
	raw, err := keyring.Get(c.serviceName(), key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil, nil, fmt.Errorf("%w: no entry for identity", cache.ErrNotFound)
		}
		return nil, nil, nil, fmt.Errorf("error reading credential from keyring: %w", err)
	}

	env := new(envelope)
	if err := json.Unmarshal([]byte(raw), env); err != nil {
		c.deleteEntry(key, 0)
		return nil, nil, nil, fmt.Errorf("error unmarshalling stored credential (entry deleted): %w", err)
	}
	if env.Version != envelopeVersion {
		c.deleteEntry(key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("%w: unsupported credential version %d (entry deleted)", cache.ErrNotFound, env.Version)
	}

	// Cheap expiry check before doing any crypto - the credential is only
	// useful for the lifetime of the cert.
	if time.Now().Add(30 * time.Second).After(env.NotAfter) {
		c.deleteEntry(key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("%w: stored cert expired", cache.ErrNotFound)
	}

	chain, err := c.readChain(key, env.ChainChunks)
	if err != nil {
		c.deleteEntry(key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("error reading stored chain (entry deleted): %w", err)
	}

	certPEM := []byte(env.Cert)
	if err := cache.ValidateCert(certPEM, c.Roots, c.Intermediates); err != nil {
		c.deleteEntry(key, env.ChainChunks)
		return nil, nil, nil, err
	}

	privateKey, _, _, err := cache.DecodeCredential(&api.Credential{
		PrivateKey: []byte(env.PrivateKey),
		Cert:       certPEM,
		Chain:      chain,
	})
	if err != nil {
		c.deleteEntry(key, env.ChainChunks)
		return nil, nil, nil, fmt.Errorf("error unmarshalling private key (entry deleted): %w", err)
	}

	return privateKey, certPEM, chain, nil
}

// StoreCert stores the credential under the identity derived from the
// configured Config, overwriting any previous entry.
func (c *Cache) StoreCert(_ context.Context, priv crypto.PrivateKey, cert, chain []byte) error {
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
	env := &envelope{
		Version:     envelopeVersion,
		NotAfter:    notAfter,
		PrivateKey:  string(cred.PrivateKey),
		Cert:        string(cert),
		ChainChunks: len(chunks),
		Meta:        cache.MetadataFromConfig(cfg),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return fmt.Errorf("error marshalling credential: %w", err)
	}

	// Store chain chunks first so that a reader never sees a credential
	// entry pointing at chunks that don't exist yet.
	for i, ch := range chunks {
		if err := keyring.Set(c.serviceName(), chainKey(key, i), string(ch)); err != nil {
			return fmt.Errorf("error storing chain in keyring: %w", err)
		}
	}
	if err := keyring.Set(c.serviceName(), key, string(raw)); err != nil {
		return fmt.Errorf("error storing credential in keyring: %w", err)
	}

	// Index maintenance is best-effort - it only powers enumeration
	// (e.g. `gitsign credentials list`).
	c.updateIndex(func(entries []cache.CredentialInfo) []cache.CredentialInfo {
		out := entries[:0]
		for _, e := range entries {
			if e.ID != key {
				out = append(out, e)
			}
		}
		return append(out, cache.CredentialInfo{ID: key, NotAfter: notAfter, Meta: env.Meta})
	})

	return nil
}

// List returns the index of stored credentials. The index is advisory - it is
// maintained best-effort on store/delete.
func (c *Cache) List(_ context.Context) ([]cache.CredentialInfo, error) {
	entries, err := c.readIndex()
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return entries, nil
}

// Delete removes the credential for the identity described by the configured
// Config. It returns cache.ErrNotFound if no entry exists.
func (c *Cache) Delete(_ context.Context) error {
	key := cache.CredentialKey(c.Config)
	chunks := c.chainChunkCount(key)
	if err := keyring.Delete(c.serviceName(), key); err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return fmt.Errorf("%w: no entry for identity", cache.ErrNotFound)
		}
		return fmt.Errorf("error deleting credential from keyring: %w", err)
	}
	c.deleteChain(key, chunks)
	c.updateIndex(func(entries []cache.CredentialInfo) []cache.CredentialInfo {
		out := entries[:0]
		for _, e := range entries {
			if e.ID != key {
				out = append(out, e)
			}
		}
		return out
	})
	return nil
}

// DeleteAll removes every indexed credential and the index itself.
func (c *Cache) DeleteAll(_ context.Context) error {
	entries, err := c.readIndex()
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	for _, e := range entries {
		c.deleteEntry(e.ID, c.chainChunkCount(e.ID))
	}
	if err := keyring.Delete(c.serviceName(), indexKey); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("error deleting credential index from keyring: %w", err)
	}
	return nil
}

// chainChunkCount reads the stored envelope to discover how many chain chunk
// entries accompany the credential. Returns 0 if the entry is missing or
// malformed.
func (c *Cache) chainChunkCount(key string) int {
	raw, err := keyring.Get(c.serviceName(), key)
	if err != nil {
		return 0
	}
	env := new(envelope)
	if err := json.Unmarshal([]byte(raw), env); err != nil {
		return 0
	}
	return env.ChainChunks
}

func (c *Cache) readChain(key string, chunks int) ([]byte, error) {
	if chunks == 0 {
		return nil, nil
	}
	var chain []byte
	for i := range chunks {
		part, err := keyring.Get(c.serviceName(), chainKey(key, i))
		if err != nil {
			return nil, fmt.Errorf("error reading chain chunk %d: %w", i, err)
		}
		chain = append(chain, part...)
	}
	return chain, nil
}

// deleteEntry removes the credential entry, its chain chunks, and its index
// row. All deletions are best-effort.
func (c *Cache) deleteEntry(key string, chunks int) {
	_ = keyring.Delete(c.serviceName(), key)
	c.deleteChain(key, chunks)
	c.updateIndex(func(entries []cache.CredentialInfo) []cache.CredentialInfo {
		out := entries[:0]
		for _, e := range entries {
			if e.ID != key {
				out = append(out, e)
			}
		}
		return out
	})
}

func (c *Cache) deleteChain(key string, chunks int) {
	for i := range chunks {
		_ = keyring.Delete(c.serviceName(), chainKey(key, i))
	}
}

func (c *Cache) readIndex() ([]cache.CredentialInfo, error) {
	raw, err := keyring.Get(c.serviceName(), indexKey)
	if err != nil {
		return nil, err
	}
	var entries []cache.CredentialInfo
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, fmt.Errorf("error unmarshalling credential index: %w", err)
	}
	return entries, nil
}

// updateIndex applies fn to the current index entries and writes the result
// back. Failures are ignored - the index is advisory only.
func (c *Cache) updateIndex(fn func([]cache.CredentialInfo) []cache.CredentialInfo) {
	entries, err := c.readIndex()
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return
	}
	entries = fn(entries)
	raw, err := json.Marshal(entries)
	if err != nil {
		return
	}
	_ = keyring.Set(c.serviceName(), indexKey, string(raw))
}

func chainKey(key string, i int) string {
	return fmt.Sprintf("%s/chain/%d", key, i)
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
