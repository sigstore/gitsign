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
		Issuer:      "tacocat",
		RedirectURL: "example.com",
		ConnectorID: "bar",
	}

	got, err := getWithRepo(repo)
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Error(diff)
	}
}
