//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package rekor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/go-openapi/runtime"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
)

// fakeIndex is an index.ClientService returning a fixed search result.
type fakeIndex struct {
	err   error
	calls int
}

func (f *fakeIndex) SearchIndex(params *index.SearchIndexParams, opts ...index.ClientOption) (*index.SearchIndexOK, error) {
	return f.SearchIndexContext(context.Background(), params, opts...)
}

func (f *fakeIndex) SearchIndexContext(_ context.Context, _ *index.SearchIndexParams, _ ...index.ClientOption) (*index.SearchIndexOK, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return &index.SearchIndexOK{}, nil
}

func (f *fakeIndex) SetTransport(runtime.ContextualTransport) {}

func testCert(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestSearchRetry(t *testing.T) {
	orig := searchRetryDelays
	searchRetryDelays = []time.Duration{time.Millisecond, time.Millisecond}
	t.Cleanup(func() { searchRetryDelays = orig })

	cert := testCert(t)
	ctx := context.Background()

	t.Run("no match retries then fails", func(t *testing.T) {
		idx := &fakeIndex{}
		c := &Client{Rekor: &client.Rekor{Index: idx}}
		if _, err := c.Search(ctx, "abc", cert); !errors.Is(err, errNoMatchingEntry) {
			t.Fatalf("Search() error = %v, want %v", err, errNoMatchingEntry)
		}
		if want := len(searchRetryDelays) + 1; idx.calls != want {
			t.Errorf("search calls = %d, want %d", idx.calls, want)
		}
	})

	t.Run("search error is not retried", func(t *testing.T) {
		searchErr := errors.New("boom")
		idx := &fakeIndex{err: searchErr}
		c := &Client{Rekor: &client.Rekor{Index: idx}}
		if _, err := c.Search(ctx, "abc", cert); !errors.Is(err, searchErr) {
			t.Fatalf("Search() error = %v, want %v", err, searchErr)
		}
		if idx.calls != 1 {
			t.Errorf("search calls = %d, want 1", idx.calls)
		}
	})

	t.Run("canceled context stops retries", func(t *testing.T) {
		idx := &fakeIndex{}
		c := &Client{Rekor: &client.Rekor{Index: idx}}
		ctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := c.Search(ctx, "abc", cert); !errors.Is(err, context.Canceled) {
			t.Fatalf("Search() error = %v, want %v", err, context.Canceled)
		}
		if idx.calls != 1 {
			t.Errorf("search calls = %d, want 1", idx.calls)
		}
	})
}
