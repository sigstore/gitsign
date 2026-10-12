// Copyright 2022 The Sigstore Authors
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

package cache_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net"
	"net/rpc"
	"path/filepath"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func newTestClient(t *testing.T) *cache.Client {
	t.Helper()

	path := filepath.Join(t.TempDir(), "cache.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := rpc.NewServer()
	srv.Register(service.NewService())
	go func() {
		for {
			srv.Accept(l)
		}
	}()

	rpcClient, err := rpc.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rpcClient.Close() })
	return &cache.Client{
		Client: rpcClient,
	}
}

func TestCache(t *testing.T) {
	ctx := context.Background()

	client := newTestClient(t)
	ca := fakeca.New()
	client.Roots = ca.ChainPool()

	// Cache miss is reported as ErrNotFound. Note: the client's Config is
	// nil, so the service does not fall back to the interactive flow.
	if _, _, _, err := client.GetCredentials(ctx, nil); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials: want ErrNotFound, got %v", err)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatalf("StoreCert: %v", err)
	}

	// The credential is stored under the host-prefixed config-derived key.
	id, err := cache.DaemonKey(client.Config)
	if err != nil {
		t.Fatal(err)
	}
	cred := new(api.Credential)
	if err := client.Client.Call("Service.GetCredential", &api.GetCredentialRequest{ID: id}, cred); err != nil {
		t.Fatal(err)
	}

	privPEM, _ := cryptoutils.MarshalPrivateKeyToPEM(priv)
	want := &api.Credential{
		PrivateKey: privPEM,
		Cert:       certPEM,
	}

	if diff := cmp.Diff(want, cred); diff != "" {
		t.Error(diff)
	}

	gotPriv, gotCert, _, err := client.GetCredentials(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(gotPriv) {
		t.Fatal("private key did not match")
	}
	if ok := cmp.Equal(certPEM, gotCert); !ok {
		t.Error("stored cert does not match")
	}

	// Re-storing within the credential lifetime overwrites without error.
	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatalf("StoreCert (second): %v", err)
	}
}

func TestCacheExpiredCert(t *testing.T) {
	ctx := context.Background()

	client := newTestClient(t)
	ca := fakeca.New(fakeca.NotAfter(time.Now().Add(-time.Hour)))
	client.Roots = ca.ChainPool()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	// The service refuses to store an already-expired cert.
	if err := client.StoreCert(ctx, priv, certPEM, nil); err == nil {
		t.Fatal("StoreCert: expected error for expired cert")
	}
}

func TestCacheManagement(t *testing.T) {
	ctx := context.Background()

	client := newTestClient(t)
	ca := fakeca.New()
	client.Roots = ca.ChainPool()

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	// Deleting a missing entry reports a miss.
	if err := client.Delete(ctx); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("Delete: want ErrNotFound, got %v", err)
	}

	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatal(err)
	}

	entries, err := client.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	id, err := cache.DaemonKey(client.Config)
	if err != nil {
		t.Fatal(err)
	}
	notAfter, err := cache.NotAfter(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	want := []api.CredentialInfo{{
		ID:       id,
		NotAfter: notAfter,
		Meta:     cache.MetadataFromConfig(client.Config),
	}}
	if diff := cmp.Diff(want, entries); diff != "" {
		t.Errorf("List (-want +got):\n%s", diff)
	}

	if err := client.Delete(ctx); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, _, err := client.GetCredentials(ctx, nil); !errors.Is(err, cache.ErrNotFound) {
		t.Fatalf("GetCredentials after delete: want ErrNotFound, got %v", err)
	}

	// DeleteAll clears everything.
	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatal(err)
	}
	if err := client.DeleteAll(ctx); err != nil {
		t.Fatalf("DeleteAll: %v", err)
	}
	entries, err = client.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// gob decodes an empty slice as nil.
	if diff := cmp.Diff([]api.CredentialInfo{}, entries, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("List after DeleteAll (-want +got):\n%s", diff)
	}
}
