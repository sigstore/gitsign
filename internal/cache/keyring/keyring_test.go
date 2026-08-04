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
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/zalando/go-keyring"
)

// Note: keyring.MockInit and MockInitWithError mutate package-global state in
// go-keyring, so these tests must not run in parallel.

func testConfig(email string) *config.Config {
	return &config.Config{
		Fulcio:         "https://fulcio.example.com",
		Issuer:         "https://oauth2.example.com/auth",
		ClientID:       "sigstore",
		ConnectorID:    "connector",
		CommitterEmail: email,
	}
}

// newTestCredential issues a leaf cert from a fresh fake CA and returns the
// cache under test along with the credential parts.
func newTestCredential(t *testing.T, caOpts ...fakeca.Option) (*Cache, *ecdsa.PrivateKey, []byte, []byte) {
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
		Roots:  ca.ChainPool(),
		Config: testConfig("user@example.com"),
	}
	return c, priv, certPEM, chainPEM
}

func TestRoundtrip(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t)

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

	// The index should have exactly one row for this identity.
	entries, err := c.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("List: want 1 entry, got %d", len(entries))
	}
	if entries[0].Meta.CommitterEmail != "user@example.com" {
		t.Errorf("List: unexpected meta %+v", entries[0].Meta)
	}
}

func TestMultipleIdentities(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	a, privA, certA, chainA := newTestCredential(t)
	b, privB, certB, chainB := newTestCredential(t)
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
	if len(entries) != 2 {
		t.Fatalf("List: want 2 entries, got %d", len(entries))
	}
}

func TestExpiredCert(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t,
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
	if _, err := keyring.Get(defaultService, cache.CredentialKey(c.Config)); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("credential entry not deleted: %v", err)
	}
	entries, err := c.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("List: want 0 entries, got %d", len(entries))
	}
}

func TestChainChunking(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t)
	// Force the chain to split into many chunks.
	c.maxEntrySize = 64

	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Sanity check that chunking actually happened.
	key := cache.CredentialKey(c.Config)
	if got := c.chainChunkCount(key); got < 2 {
		t.Fatalf("expected multiple chain chunks, got %d", got)
	}

	_, _, gotChain, err := c.GetCredentials(ctx, c.Config)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(chainPEM, gotChain); diff != "" {
		t.Errorf("chain mismatch (-want +got):\n%s", diff)
	}

	// Deleting removes the chunk entries too.
	chunks := c.chainChunkCount(key)
	if err := c.Delete(ctx); err != nil {
		t.Fatal(err)
	}
	for i := range chunks {
		if _, err := keyring.Get(defaultService, chainKey(key, i)); !errors.Is(err, keyring.ErrNotFound) {
			t.Errorf("chain chunk %d not deleted: %v", i, err)
		}
	}
}

func TestValidationFailure(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t)
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); err != nil {
		t.Fatal(err)
	}

	// Reads with roots from a different CA must fail and remove the entry.
	other := fakeca.New(fakeca.IsCA)
	c.Roots = other.ChainPool()
	if _, _, _, err := c.GetCredentials(ctx, c.Config); err == nil {
		t.Fatal("GetCredentials: expected error with wrong roots")
	}
	if _, err := keyring.Get(defaultService, cache.CredentialKey(c.Config)); !errors.Is(err, keyring.ErrNotFound) {
		t.Errorf("credential entry not deleted: %v", err)
	}
}

func TestKeyringUnavailable(t *testing.T) {
	wantErr := errors.New("keyring unavailable")
	keyring.MockInitWithError(wantErr)
	t.Cleanup(keyring.MockInit)
	ctx := context.Background()

	c, priv, certPEM, chainPEM := newTestCredential(t)

	if _, _, _, err := c.GetCredentials(ctx, c.Config); !errors.Is(err, wantErr) {
		t.Errorf("GetCredentials: want %v, got %v", wantErr, err)
	}
	if err := c.StoreCert(ctx, priv, certPEM, chainPEM); !errors.Is(err, wantErr) {
		t.Errorf("StoreCert: want %v, got %v", wantErr, err)
	}
}

func TestDelete(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()

	a, privA, certA, chainA := newTestCredential(t)
	b, privB, certB, chainB := newTestCredential(t)
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

	// DeleteAll removes everything, including the index.
	if err := b.DeleteAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := b.GetCredentials(ctx, b.Config); !errors.Is(err, cache.ErrNotFound) {
		t.Errorf("GetCredentials after DeleteAll: want ErrNotFound, got %v", err)
	}
	entries, err := b.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("List after DeleteAll: want 0 entries, got %d", len(entries))
	}
}
