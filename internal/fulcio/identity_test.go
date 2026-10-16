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

package fulcio

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/gitsign/internal/cache/keyring"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestNewCacheClient(t *testing.T) {
	ctx := context.Background()

	// Point FulcioRoot at a local PEM so root loading doesn't hit TUF.
	ca := fakeca.New(fakeca.IsCA)
	rootPEM, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	rootPath := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(rootPath, rootPEM, 0600); err != nil {
		t.Fatal(err)
	}

	t.Run("disabled by default", func(t *testing.T) {
		c, err := newCacheClient(ctx, &config.Config{FulcioRoot: rootPath})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if c != nil {
			t.Fatalf("expected nil cache, got %T", c)
		}
	})

	t.Run("system keyring mode", func(t *testing.T) {
		for _, mode := range []string{"system", "System"} {
			c, err := newCacheClient(ctx, &config.Config{
				FulcioRoot:          rootPath,
				CredentialCacheMode: mode,
			})
			if err != nil {
				t.Fatalf("mode %q: unexpected error: %v", mode, err)
			}
			if _, ok := c.(*keyring.Cache); !ok {
				t.Fatalf("mode %q: expected *keyring.Cache, got %T", mode, c)
			}
		}
	})

	t.Run("socket mode requires a path", func(t *testing.T) {
		if _, err := newCacheClient(ctx, &config.Config{
			FulcioRoot:          rootPath,
			CredentialCacheMode: "socket",
		}); err == nil {
			t.Fatal("expected error for socket mode without a path")
		}
	})

	t.Run("unreachable socket is a hard error", func(t *testing.T) {
		if _, err := newCacheClient(ctx, &config.Config{
			FulcioRoot:      rootPath,
			CredentialCache: filepath.Join(t.TempDir(), "missing.sock"),
		}); err == nil {
			t.Fatal("expected error for unreachable socket")
		}
	})

	t.Run("unknown mode", func(t *testing.T) {
		if _, err := newCacheClient(ctx, &config.Config{
			FulcioRoot:          rootPath,
			CredentialCacheMode: "carrier-pigeon",
		}); err == nil {
			t.Fatal("expected error for unknown mode")
		}
	})
}

func TestCacheFromConfigSoftFails(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		cfg  *config.Config
	}{{
		name: "unknown mode",
		cfg:  &config.Config{CredentialCacheMode: "carrier-pigeon"},
	}, {
		name: "socket mode without a path",
		cfg:  &config.Config{CredentialCacheMode: "socket"},
	}, {
		// cache.NewClient returns a typed nil *Client on error, which must
		// not leak out as a non-nil cache.Cache.
		name: "unreachable socket",
		cfg:  &config.Config{CredentialCache: filepath.Join(t.TempDir(), "missing.sock")},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			out := new(bytes.Buffer)
			if c := cacheFromConfig(ctx, tc.cfg, out); c != nil {
				t.Fatalf("expected nil cache, got %T", c)
			}
			if !strings.Contains(out.String(), "continuing without it") {
				t.Errorf("expected setup error to be reported, got %q", out.String())
			}
		})
	}

	// Caching disabled is not an error and prints nothing.
	out := new(bytes.Buffer)
	if c := cacheFromConfig(ctx, &config.Config{}, out); c != nil {
		t.Fatalf("expected nil cache, got %T", c)
	}
	if out.Len() != 0 {
		t.Errorf("expected no output, got %q", out.String())
	}
}
