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

package config

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
)

func TestGet(t *testing.T) {
	// Create in-memory repo for testing.
	repo, err := git.Init(memory.NewStorage(), memfs.New())
	if err != nil {
		t.Fatal(err)
	}

	cfg := &format.Config{
		Sections: format.Sections{
			&format.Section{
				Name: "gitsign",
				Options: format.Options{
					// This will be ignored.
					&format.Option{
						Key:   "foo",
						Value: "bar",
					},
					&format.Option{
						Key:   "fulcio",
						Value: "example.com",
					},
					&format.Option{
						Key:   "rekor",
						Value: "example.com",
					},
				},
			},
		},
	}
	if err := repo.SetConfig(&config.Config{
		Raw: cfg,
	}); err != nil {
		t.Fatal(err)
	}

	// This should take precedence over config value.
	t.Setenv("GITSIGN_REKOR_URL", "rekor.example.com")
	// This just overrides default value.
	t.Setenv("GITSIGN_OIDC_ISSUER", "tacocat")

	// Recognize SIGSTORE prefixes.
	t.Setenv("SIGSTORE_OIDC_REDIRECT_URL", "example.com")

	// GITSIGN prefix takes priority over SIGSTORE.
	t.Setenv("SIGSTORE_CONNECTOR_ID", "foo")
	t.Setenv("GITSIGN_CONNECTOR_ID", "bar")

	want := &Config{
		// Default overridden by config
		Fulcio: "example.com",
		// Overridden by config, then by env var
		Rekor: "rekor.example.com",
		// Default value
		ClientID: "sigstore",
		// Overridden by env var
		Issuer:           "tacocat",
		RedirectURL:      "example.com",
		ConnectorID:      "bar",
		RekorMode:        "online",
		EnableSigstoreGo: true,
		RekorVersion:     1,
		Autoclose:        true,
		AutocloseTimeout: 6,
		// From config file.
		URLOpener: "firefox --new-tab {{.URL}}",
	}

	execFn = func() (io.Reader, error) {
		return os.Open("testdata/config.txt")
	}

	got, err := Get()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got, cmp.AllowUnexported(Config{})); diff != "" {
		t.Error(diff)
	}
}

func TestEnableSigstoreGo(t *testing.T) {
	t.Cleanup(func() { execFn = realExec })

	// enableSigstoreGo is valid regardless of Rekor mode: the offline-only
	// requirement for signing is enforced by the sign command, not Get(), so that
	// the verification commands can enable sigstore-go to verify legacy online
	// signatures. Get() must not reject either combination.
	for _, mode := range []string{"online", "offline"} {
		execFn = func() (io.Reader, error) {
			return strings.NewReader("gitsign.enableSigstoreGo true\ngitsign.rekorMode " + mode + "\n"), nil
		}
		got, err := Get()
		if err != nil {
			t.Fatalf("rekorMode %q: unexpected error: %v", mode, err)
		}
		if !got.EnableSigstoreGo {
			t.Errorf("rekorMode %q: EnableSigstoreGo = false, want true", mode)
		}
		if got.RekorMode != mode {
			t.Errorf("rekorMode %q: RekorMode = %q, want %q", mode, got.RekorMode, mode)
		}
	}
}

func TestCredentialCache(t *testing.T) {
	t.Cleanup(func() { execFn = realExec })

	t.Run("from git config", func(t *testing.T) {
		// git config lowercases key names.
		execFn = func() (io.Reader, error) {
			return strings.NewReader("gitsign.credentialcachemode system\ngitsign.credentialcache /tmp/cache.sock\n"), nil
		}
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.CredentialCacheMode != "system" {
			t.Errorf("CredentialCacheMode: got %q, want %q", got.CredentialCacheMode, "system")
		}
		if got.CredentialCache != "/tmp/cache.sock" {
			t.Errorf("CredentialCache: got %q, want %q", got.CredentialCache, "/tmp/cache.sock")
		}
	})

	t.Run("env takes precedence over git config", func(t *testing.T) {
		execFn = func() (io.Reader, error) {
			return strings.NewReader("gitsign.credentialcachemode keyring\ngitsign.credentialcache /tmp/cache.sock\n"), nil
		}
		t.Setenv("GITSIGN_CREDENTIAL_CACHE_MODE", "system")
		t.Setenv("GITSIGN_CREDENTIAL_CACHE", "/other/cache.sock")
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.CredentialCacheMode != "system" {
			t.Errorf("CredentialCacheMode: got %q, want %q", got.CredentialCacheMode, "system")
		}
		if got.CredentialCache != "/other/cache.sock" {
			t.Errorf("CredentialCache: got %q, want %q", got.CredentialCache, "/other/cache.sock")
		}
	})

	t.Run("defaults to empty", func(t *testing.T) {
		execFn = func() (io.Reader, error) {
			return strings.NewReader(""), nil
		}
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.CredentialCacheMode != "" || got.CredentialCache != "" {
			t.Errorf("expected empty credential cache config, got mode=%q path=%q", got.CredentialCacheMode, got.CredentialCache)
		}
	})
}

func TestRekorVersion(t *testing.T) {
	t.Cleanup(func() { execFn = realExec })

	for _, tc := range []struct {
		name    string
		config  string
		want    uint32
		wantErr bool
	}{
		{
			name:   "default is v1 when unset",
			config: "",
			want:   1,
		},
		{
			name:   "explicit v1 with sigstore-go + offline",
			config: "gitsign.rekorVersion 1\ngitsign.enableSigstoreGo true\ngitsign.rekorMode offline\n",
			want:   1,
		},
		{
			name:   "v2 with sigstore-go + offline",
			config: "gitsign.rekorVersion 2\ngitsign.enableSigstoreGo true\ngitsign.rekorMode offline\n",
			want:   2,
		},
		{
			// The option only applies to the sigstore-go signing path; the legacy
			// path is Rekor v1 only. enableSigstoreGo defaults to true, so it must
			// be explicitly disabled to exercise the gate.
			name:    "v2 with sigstore-go disabled errors",
			config:  "gitsign.rekorVersion 2\ngitsign.enableSigstoreGo false\n",
			wantErr: true,
		},
		{
			// Even v1 may not be set explicitly without the sigstore-go path.
			name:    "explicit v1 with sigstore-go disabled errors",
			config:  "gitsign.rekorVersion 1\ngitsign.enableSigstoreGo false\n",
			wantErr: true,
		},
		{
			name:    "unsupported version errors",
			config:  "gitsign.rekorVersion 3\ngitsign.enableSigstoreGo true\ngitsign.rekorMode offline\n",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			execFn = func() (io.Reader, error) {
				return strings.NewReader(tc.config), nil
			}
			got, err := Get()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got config: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.RekorVersion != tc.want {
				t.Errorf("RekorVersion: got %d, want %d", got.RekorVersion, tc.want)
			}
		})
	}
}

func TestRekorVersionEnv(t *testing.T) {
	t.Cleanup(func() { execFn = realExec })
	execFn = func() (io.Reader, error) {
		return strings.NewReader("gitsign.enableSigstoreGo true\ngitsign.rekorMode offline\n"), nil
	}

	t.Run("GITSIGN prefix", func(t *testing.T) {
		t.Setenv("GITSIGN_REKOR_VERSION", "2")
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.RekorVersion != 2 {
			t.Errorf("RekorVersion: got %d, want 2", got.RekorVersion)
		}
	})

	t.Run("SIGSTORE prefix", func(t *testing.T) {
		t.Setenv("SIGSTORE_REKOR_VERSION", "2")
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.RekorVersion != 2 {
			t.Errorf("RekorVersion: got %d, want 2", got.RekorVersion)
		}
	})

	t.Run("GITSIGN takes precedence over SIGSTORE", func(t *testing.T) {
		t.Setenv("SIGSTORE_REKOR_VERSION", "1")
		t.Setenv("GITSIGN_REKOR_VERSION", "2")
		got, err := Get()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.RekorVersion != 2 {
			t.Errorf("RekorVersion: got %d, want 2", got.RekorVersion)
		}
	})

	t.Run("non-numeric errors", func(t *testing.T) {
		t.Setenv("GITSIGN_REKOR_VERSION", "banana")
		if _, err := Get(); err == nil {
			t.Error("expected error for non-numeric GITSIGN_REKOR_VERSION")
		}
	})
}
