// Copyright 2024 The Sigstore Authors
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

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/gitsign/internal/git/gittest"
	"github.com/sigstore/gitsign/pkg/fulcio"
	gsgit "github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/gitsign/pkg/gitsign"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauthflow"

	// Enable OIDC providers
	_ "github.com/sigstore/cosign/v2/pkg/providers/all"
)

func TestSign(t *testing.T) {
	ctx := context.Background()

	var flow oauthflow.TokenGetter = &oauthflow.InteractiveIDTokenGetter{
		HTMLPage: oauth.InteractiveSuccessHTML,
	}
	if providers.Enabled(ctx) {
		// If automatic token provisioning is enabled, use it.
		token, err := providers.Provide(ctx, "sigstore")
		if err != nil {
			t.Fatal(err)
		}
		flow = &oauthflow.StaticTokenGetter{
			RawToken: token,
		}
	}
	fulcio, err := fulcio.NewClient("https://fulcio.sigstore.dev", fulcio.OIDCOptions{
		ClientID:    "sigstore",
		Issuer:      "https://oauth2.sigstore.dev/auth",
		TokenGetter: flow,
	})
	if err != nil {
		t.Fatal(err)
	}
	rekor, err := rekor.NewWithOptions(ctx, "https://rekor.sigstore.dev")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gitsign.NewSigner(ctx, fulcio, rekor)
	if err != nil {
		t.Fatal(err)
	}

	// Make a commit + sign it
	storage := memory.NewStorage()
	repo, err := git.Init(storage, memfs.New())
	if err != nil {
		panic(err)
	}
	w, err := repo.Worktree()
	if err != nil {
		panic(err)
	}
	sha, err := w.Commit("example commit", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "John Doe",
			Email: "john@example.com",
			When:  time.UnixMicro(1234567890).UTC(),
		},
		Signer:            signer,
		AllowEmptyCommits: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	commit, err := repo.CommitObject(sha)
	if err != nil {
		t.Fatal(err)
	}
	body := gittest.MarshalCommitBody(t, commit)
	sig := []byte(commit.PGPSignature)

	// Verify the commit
	verifier, err := gsgit.NewDefaultVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := gsgit.Verify(ctx, verifier, rekor, body, sig, true)
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(summary.LogEntry)
}
