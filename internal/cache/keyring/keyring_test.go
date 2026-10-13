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

package keyring

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/99designs/keyring"
	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func testConfig(email string) *config.Config {
	return &config.Config{
		Fulcio:         "https://fulcio.example.com",
		Issuer:         "https://oauth2.example.com/auth",
		ClientID:       "sigstore",
		ConnectorID:    "connector",
		CommitterEmail: email,
	}
}

// newTestCredential issues a leaf cert from a fresh fake CA and returns a
// cache backed by the given in-memory keyring along with the credential
// parts.
func newTestCredential(t *testing.T, kr keyring.Keyring, caOpts ...fakeca.Option) (*Cache, *ecdsa.PrivateKey, []byte, []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := fakeca.New(append([]fakeca.Option{fakeca.IsCA}, caOpts...)...)
	leaf := ca.Issue(append([]fakeca.Option{fakeca.PrivateKey(priv)}, caOpts...)...)

	certPEM, err := cryptoutils.MarshalCertificateToPEM(leaf.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	chainPEM, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	c := &Cache{
		Roots:   ca.ChainPool(),
		Config:  testConfig("user@example.com"),
		Keyring: kr,
	}
	return c, priv, certPEM, chainPEM
}

func TestRoundtrip(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)

	// Miss before store.
	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials before store: want ErrNotFound, got %v", err)
	}

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatalf("StoreCert: %v", err)
	}

	gotPriv, gotCert, gotChain, err := c.GetCredentials(ctx, c.Config)
	if err != nil {
		t.Fatalf("GetCredentials: %v", err)
	}
	gotSigner, ok := gotPriv.(*ecdsa.PrivateKey)
	if !ok || !priv.Equal(gotSigner) {
		t.Error("private key did not match")
	}
	if diff := cmp.Diff(certPEM, gotCert); diff != "" {
		t.Errorf("cert mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(chainPEM, gotChain); diff != "" {
		t.Errorf("chain mismatch (-want +got):\n%s", diff)
	}

	// Storing again overwrites without error.
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatalf("StoreCert (second): %v", err)
	}

	// Enumeration should show exactly one credential for this identity.
	entries, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if diff := cmp.Diff([]api.CredentialInfo{wantInfo(t, c, certPEM)}, entries); diff != "" {
		t.Errorf("List (-want +got):\n%s", diff)
	}
}

// wantInfo returns the CredentialInfo List should report for a credential
// stored by c with the given cert.
func wantInfo(t *testing.T, c *Cache, certPEM []byte) api.CredentialInfo {
	t.Helper()
	notAfter, err := cache.NotAfter(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	return api.CredentialInfo{
		ID:       cache.CredentialKey(c.Config),
		NotAfter: notAfter,
		Meta:     cache.MetadataFromConfig(c.Config),
	}
}

// byID sorts List output for stable comparison.
var byID = cmpopts.SortSlices(func(a, b api.CredentialInfo) bool { return a.ID < b.ID })

func TestMultipleIdentities(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	a, privA, certA, chainA := newTestCredential(t, kr)
	b, privB, certB, chainB := newTestCredential(t, kr)
	b.Config = testConfig("other@example.com")

	if err := a.StoreCert(ctx, privA, certA, chainA); err != nil {
		t.Fatal(err)
	}
	if err := b.StoreCert(ctx, privB, certB, chainB); err != nil {
		t.Fatal(err)
	}

	_, gotA, _, err := a.GetCredentials(ctx, a.Config)
	if err != nil {
		t.Fatal(err)
	}
	_, gotB, _, err := b.GetCredentials(ctx, b.Config)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(certA, gotA); diff != "" {
		t.Errorf("identity A cert mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(certB, gotB); diff != "" {
		t.Errorf("identity B cert mismatch (-want +got):\n%s", diff)
	}

	entries, err := a.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []api.CredentialInfo{wantInfo(t, a, certA), wantInfo(t, b, certB)}
	if diff := cmp.Diff(want, entries, byID); diff != "" {
		t.Errorf("List (-want +got):\n%s", diff)
	}
}

func TestExpiredCert(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr,
		fakeca.NotBefore(time.Now().Add(-2*time.Hour)),
		fakeca.NotAfter(time.Now().Add(-time.Hour)),
	)

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Expired cert is a miss, not an error...
	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials: want ErrNotFound, got %v", err)
	}

	// ...and the entries are removed.
	if _, err := kr.Get(cache.CredentialKey(c.Config)); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Errorf("credential entry not deleted: %v", err)
	}
	entries, err := c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]api.CredentialInfo{}, entries); diff != "" {
		t.Errorf("List (-want +got):\n%s", diff)
	}
}

// storedKeys returns all keys in kr, sorted.
func storedKeys(t *testing.T, kr keyring.Keyring) []string {
	t.Helper()
	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(keys)
	return keys
}

// storedHeader returns the header stored under key.
func storedHeader(t *testing.T, kr keyring.Keyring, key string) *header {
	t.Helper()
	item, err := kr.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	h, err := readHeader(item)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// entryKeys returns the keys a credential with header h should occupy.
func entryKeys(key string, h *header) []string {
	keys := make([]string, 0, 1+h.Chunks)
	keys = append(keys, key)
	for i := range h.Chunks {
		keys = append(keys, dataKey(key, h.Generation, i))
	}
	sort.Strings(keys)
	return keys
}

func TestChunking(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	// Force the payload to split into many chunks.
	c.maxEntrySize = 512

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	key := cache.CredentialKey(c.Config)
	h := storedHeader(t, kr, key)
	if h.Chunks < 2 {
		t.Fatalf("expected multiple chunks, got %d", h.Chunks)
	}
	if diff := cmp.Diff(entryKeys(key, h), storedKeys(t, kr)); diff != "" {
		t.Errorf("stored keys (-want +got):\n%s", diff)
	}
	// Every value - including the header - must fit in one entry (Windows
	// Credential Manager limits blobs to 2560 bytes).
	for _, k := range storedKeys(t, kr) {
		item, err := kr.Get(k)
		if err != nil {
			t.Fatal(err)
		}
		if len(item.Data) > c.maxEntrySize {
			t.Errorf("entry %q is %d bytes, over the %d byte limit", k, len(item.Data), c.maxEntrySize)
		}
	}

	_, gotCert, gotChain, err := c.GetCredentials(ctx, c.Config)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(certPEM, gotCert); diff != "" {
		t.Errorf("cert mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(chainPEM, gotChain); diff != "" {
		t.Errorf("chain mismatch (-want +got):\n%s", diff)
	}

	// Deleting removes the chunk entries too.
	if err := c.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("keys after delete (-want +got):\n%s", diff)
	}
}

func TestHeaderTooLarge(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	c.maxEntrySize = 64

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err == nil {
		t.Fatal("StoreCert: expected error for header over the entry size limit")
	}
	if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("keys after failed store (-want +got):\n%s", diff)
	}
}

func TestRestoreReplacesGeneration(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	key := cache.CredentialKey(c.Config)

	// First store with many chunks, then re-store with fewer.
	c.maxEntrySize = 512
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}
	c.maxEntrySize = 0
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Only the new generation remains.
	h := storedHeader(t, kr, key)
	if diff := cmp.Diff(entryKeys(key, h), storedKeys(t, kr)); diff != "" {
		t.Errorf("keys after re-store (-want +got):\n%s", diff)
	}
	if _, _, _, err := c.GetCredentials(ctx, c.Config); err != nil {
		t.Fatal(err)
	}
}

// hookKeyring runs hook (once) when an item matching match is about to be,
// or has just been, set.
type hookKeyring struct {
	keyring.Keyring
	match  func(keyring.Item) bool
	before bool
	hook   func()
}

func (h *hookKeyring) Set(item keyring.Item) error {
	fire := h.hook != nil && h.match(item)
	if fire && h.before {
		f := h.hook
		h.hook = nil
		f()
	}
	if err := h.Keyring.Set(item); err != nil {
		return err
	}
	if fire && !h.before {
		f := h.hook
		h.hook = nil
		f()
	}
	return nil
}

func TestConcurrentStores(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		// before fires the second store just before the first store's
		// header is written (the first store wins); otherwise just after
		// (the second store wins, then the first runs its cleanup).
		before bool
	}{
		{name: "second store between first header and cleanup", before: false},
		{name: "second store between first chunks and header", before: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arr := keyring.NewArrayKeyring(nil)
			hk := &hookKeyring{Keyring: arr, before: tc.before}

			// Two stores for the same identity with different payload
			// lengths: a short credential (no chain) and a long one.
			short, privS, certS, _ := newTestCredential(t, hk)
			long, privL, certL, chainL := newTestCredential(t, arr)
			short.maxEntrySize, long.maxEntrySize = 512, 512
			key := cache.CredentialKey(short.Config)

			hk.match = func(item keyring.Item) bool { return item.Key == key }
			hk.hook = func() {
				if err := long.StoreCert(ctx, privL, certL, chainL); err != nil {
					t.Fatalf("concurrent StoreCert: %v", err)
				}
			}
			if err := short.StoreCert(ctx, privS, certS, nil); err != nil {
				t.Fatal(err)
			}

			// Whichever store won, its header must point at intact chunks.
			wantCert, roots := certL, long.Roots
			if tc.before {
				wantCert, roots = certS, short.Roots
			}
			reader := &Cache{Roots: roots, Config: short.Config, Keyring: arr}
			_, gotCert, _, err := reader.GetCredentials(ctx, reader.Config)
			if err != nil {
				t.Fatalf("GetCredentials: %v", err)
			}
			if diff := cmp.Diff(wantCert, gotCert); diff != "" {
				t.Errorf("cert mismatch (-want +got):\n%s", diff)
			}

			if !tc.before {
				// The first store saw it had been superseded and removed its
				// own generation, leaving nothing orphaned.
				h := storedHeader(t, arr, key)
				if diff := cmp.Diff(entryKeys(key, h), storedKeys(t, arr)); diff != "" {
					t.Errorf("stored keys (-want +got):\n%s", diff)
				}
			}
		})
	}
}

func TestCollectGenerations(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	key := cache.CredentialKey(c.Config)

	// Unreferenced generations, e.g. orphaned when two concurrent stores
	// replaced the same header: one old enough to collect, and one young
	// enough that a concurrent store may be about to publish it.
	oldGen, err := newGenerationAt(time.Now().Add(-2 * generationGrace))
	if err != nil {
		t.Fatal(err)
	}
	youngGen, err := newGenerationAt(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{dataKey(key, oldGen, 0), dataKey(key, youngGen, 0)} {
		if err := kr.Set(keyring.Item{Key: k, Data: []byte("chunk")}); err != nil {
			t.Fatal(err)
		}
	}

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	h := storedHeader(t, kr, key)
	want := append(entryKeys(key, h), dataKey(key, youngGen, 0))
	sort.Strings(want)
	if diff := cmp.Diff(want, storedKeys(t, kr)); diff != "" {
		t.Errorf("keys after store (-want +got):\n%s", diff)
	}
}

func TestReplacedWhileReading(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	c.maxEntrySize = 512
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}
	key := cache.CredentialKey(c.Config)

	// Simulate a concurrent store having removed this generation's chunks
	// after the header was read.
	h := storedHeader(t, kr, key)
	if err := kr.Remove(dataKey(key, h.Generation, 0)); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials: want ErrNotFound, got %v", err)
	}
	// The entry is left for the concurrent writer rather than deleted.
	if _, err := kr.Get(key); err != nil {
		t.Errorf("credential entry was deleted: %v", err)
	}
}

func TestCorruptChunk(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	c.maxEntrySize = 512
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}
	key := cache.CredentialKey(c.Config)

	h := storedHeader(t, kr, key)
	if err := kr.Set(keyring.Item{Key: dataKey(key, h.Generation, 0), Data: []byte("corrupt")}); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials: want ErrNotFound, got %v", err)
	}
	// Generations are immutable, so a mismatch is corruption - deleted.
	if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("keys after corrupt read (-want +got):\n%s", diff)
	}
}

func TestValidationFailure(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, kr)
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Reads with roots from a different CA must fail and remove the entry.
	other := fakeca.New(fakeca.IsCA)
	c.Roots = other.ChainPool()
	if _, _, _, err := c.GetCredentials(ctx, c.Config); err == nil {
		t.Fatal("GetCredentials: expected error with wrong roots")
	}
	if _, err := kr.Get(cache.CredentialKey(c.Config)); !errors.Is(err, keyring.ErrKeyNotFound) {
		t.Errorf("credential entry not deleted: %v", err)
	}
}

// errKeyring simulates an unavailable/locked keyring.
type errKeyring struct {
	err error
}

func (e errKeyring) Get(string) (keyring.Item, error)             { return keyring.Item{}, e.err }
func (e errKeyring) GetMetadata(string) (keyring.Metadata, error) { return keyring.Metadata{}, e.err }
func (e errKeyring) Set(keyring.Item) error                       { return e.err }
func (e errKeyring) Remove(string) error                          { return e.err }
func (e errKeyring) Keys() ([]string, error)                      { return nil, e.err }

func TestKeyringUnavailable(t *testing.T) {
	wantErr := errors.New("keyring unavailable")
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t, errKeyring{err: wantErr})

	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, wantErr) {
		t.Errorf("GetCredentials: want %v, got %v", wantErr, err)
	}
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); !errors.Is(err, wantErr) {
		t.Errorf("StoreCert: want %v, got %v", wantErr, err)
	}
}

func TestMalformedEntry(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		header []byte
	}{{
		name:   "not json",
		header: []byte("not json"),
	}, {
		// Valid JSON from another envelope version must not be reported as
		// a usable credential.
		name:   "unsupported version",
		header: []byte(`{"version":1,"notAfter":"2099-01-01T00:00:00Z","meta":{"committerEmail":"user@example.com"}}`),
	}} {
		t.Run(tc.name, func(t *testing.T) {
			kr := keyring.NewArrayKeyring(nil)
			c, priv, certPEM, chainPEM := newTestCredential(t, kr)
			key := cache.CredentialKey(c.Config)
			// e.g. an entry written by an incompatible build, with chunks
			// alongside it (both the current and the old v1 layout).
			for _, item := range []keyring.Item{
				{Key: key, Data: tc.header},
				{Key: dataKey(key, "old", 0), Data: []byte("chunk")},
				{Key: key + "/chain/0", Data: []byte("chunk")},
			} {
				if err := kr.Set(item); err != nil {
					t.Fatal(err)
				}
			}

			// List reports the unreadable entry instead of hiding it.
			entries, err := c.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			want := []api.CredentialInfo{{ID: key}}
			if diff := cmp.Diff(want, entries, cmpopts.IgnoreFields(api.CredentialInfo{}, "Error")); diff != "" {
				t.Errorf("List (-want +got):\n%s", diff)
			}
			if len(entries) == 1 && entries[0].Error == "" {
				t.Error("List: expected Error to be set for unreadable entry")
			}

			// Malformed entries are a miss, not an error, and are removed
			// along with everything stored under them.
			if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
				t.Fatalf("GetCredentials: want ErrNotFound, got %v", err)
			}
			if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("keys after malformed read (-want +got):\n%s", diff)
			}

			// The identity can be re-cached afterwards.
			if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
				t.Fatalf("StoreCert: %v", err)
			}
			if _, _, _, err := c.GetCredentials(ctx, c.Config); err != nil {
				t.Errorf("GetCredentials after re-store: %v", err)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	a, privA, certA, chainA := newTestCredential(t, kr)
	b, privB, certB, chainB := newTestCredential(t, kr)
	b.Config = testConfig("other@example.com")

	// Deleting a missing entry reports a miss.
	if err := a.Delete(ctx); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Delete: want ErrNotFound, got %v", err)
	}

	if err := a.StoreCert(ctx, privA, certA, chainA); err != nil {
		t.Fatal(err)
	}
	if err := b.StoreCert(ctx, privB, certB, chainB); err != nil {
		t.Fatal(err)
	}

	// Delete only removes the current identity.
	if err := a.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := a.GetCredentials(ctx, a.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("GetCredentials after delete: want ErrNotFound, got %v", err)
	}
	if _, _, _, err := b.GetCredentials(ctx, b.Config); err != nil {
		t.Errorf("GetCredentials for other identity: %v", err)
	}

	// DeleteAll removes everything, including chain chunks.
	if err := b.DeleteAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := b.GetCredentials(ctx, b.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("GetCredentials after DeleteAll: want ErrNotFound, got %v", err)
	}
	keys, err := kr.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]string{}, keys, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("Keys after DeleteAll (-want +got):\n%s", diff)
	}
	entries, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff([]api.CredentialInfo{}, entries); diff != "" {
		t.Errorf("List after DeleteAll (-want +got):\n%s", diff)
	}
}

func TestListValidatesPayload(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name    string
		corrupt func(t *testing.T, kr keyring.Keyring, key string, h *header)
	}{{
		name: "missing chunk",
		corrupt: func(t *testing.T, kr keyring.Keyring, key string, h *header) {
			if err := kr.Remove(dataKey(key, h.Generation, 0)); err != nil {
				t.Fatal(err)
			}
		},
	}, {
		name: "corrupt chunk",
		corrupt: func(t *testing.T, kr keyring.Keyring, key string, h *header) {
			if err := kr.Set(keyring.Item{Key: dataKey(key, h.Generation, 0), Data: []byte("corrupt")}); err != nil {
				t.Fatal(err)
			}
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			kr := keyring.NewArrayKeyring(nil)
			c, priv, certPEM, chainPEM := newTestCredential(t, kr)
			c.maxEntrySize = 512
			if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
				t.Fatal(err)
			}
			key := cache.CredentialKey(c.Config)
			tc.corrupt(t, kr, key, storedHeader(t, kr, key))
			before := storedKeys(t, kr)

			entries, err := c.List(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// The header's metadata is still reported, alongside the error.
			want := []api.CredentialInfo{wantInfo(t, c, certPEM)}
			if diff := cmp.Diff(want, entries, cmpopts.IgnoreFields(api.CredentialInfo{}, "Error")); diff != "" {
				t.Errorf("List (-want +got):\n%s", diff)
			}
			if len(entries) == 1 && entries[0].Error == "" {
				t.Error("List: expected Error for an entry with an unusable payload")
			}
			// List never modifies the keyring.
			if diff := cmp.Diff(before, storedKeys(t, kr)); diff != "" {
				t.Errorf("keys changed by List (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeleteRemovesAllGenerations(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name   string
		caOpts []fakeca.Option
		delete func(c *Cache) error
	}{{
		name:   "Delete",
		delete: func(c *Cache) error { return c.Delete(ctx) },
	}, {
		// Expired entries are deleted on read.
		name:   "expired on read",
		caOpts: []fakeca.Option{fakeca.NotBefore(time.Now().Add(-2 * time.Hour)), fakeca.NotAfter(time.Now().Add(-time.Hour))},
		delete: func(c *Cache) error {
			if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, cache.ErrNotFound) {
				return fmt.Errorf("GetCredentials: want ErrNotFound, got %w", err)
			}
			return nil
		},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			kr := keyring.NewArrayKeyring(nil)
			c, priv, certPEM, chainPEM := newTestCredential(t, kr, tc.caOpts...)
			if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
				t.Fatal(err)
			}
			key := cache.CredentialKey(c.Config)
			// Chunks of another generation, e.g. from a concurrent store
			// whose header hasn't been (or was just) replaced.
			if err := kr.Set(keyring.Item{Key: dataKey(key, "concurrent", 0), Data: []byte("chunk")}); err != nil {
				t.Fatal(err)
			}

			if err := tc.delete(c); err != nil {
				t.Fatal(err)
			}
			if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("keys after delete (-want +got):\n%s", diff)
			}
		})
	}
}

func TestDeleteOrphanedData(t *testing.T) {
	kr := keyring.NewArrayKeyring(nil)
	ctx := context.Background()

	c, _, _, _ := newTestCredential(t, kr)
	key := cache.CredentialKey(c.Config)

	// Chunks with no header, e.g. left by an interrupted store, can still
	// be cleared for the identity.
	if err := kr.Set(keyring.Item{Key: dataKey(key, "orphan", 0), Data: []byte("chunk")}); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(ctx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if diff := cmp.Diff([]string{}, storedKeys(t, kr), cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("keys after delete (-want +got):\n%s", diff)
	}

	// With nothing left, it's a miss.
	if err := c.Delete(ctx); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Delete: want ErrNotFound, got %v", err)
	}
}

// failRemoveKeyring fails to remove keys matching fail.
type failRemoveKeyring struct {
	keyring.Keyring
	fail func(string) bool
}

func (f failRemoveKeyring) Remove(key string) error {
	if f.fail(key) {
		return errors.New("access denied")
	}
	return f.Keyring.Remove(key)
}

func TestDeleteReportsChunkFailures(t *testing.T) {
	ctx := context.Background()

	arr := keyring.NewArrayKeyring(nil)
	c, priv, certPEM, chainPEM := newTestCredential(t, arr)
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Failing to remove a chunk (which holds private-key material) must not
	// be reported as a successful clear.
	c.Keyring = failRemoveKeyring{Keyring: arr, fail: func(k string) bool { return strings.Contains(k, dataKeyMarker) }}
	if err := c.Delete(ctx); err == nil {
		t.Fatal("Delete: expected error when a chunk can't be removed")
	}
}
