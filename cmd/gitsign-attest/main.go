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

package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/go-git/go-git/v5"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/gitsign/cmd/gitsign-attest/internal/attest"
)

var (
	tree    = flag.Bool("t", false, "sign tree instead of commit")
	path    = flag.String("f", "", "file to attest")
	attType = flag.String("type", "", "attestation type")
)

const (
	attCommitRef = "refs/attestations/commits"
	attTreeRef   = "refs/attestations/trees"
)

func main() {
	flag.Parse()
	ctx := context.Background()

	repo, err := git.PlainOpen(".")
	if err != nil {
		log.Fatal(err)
	}

	head, err := repo.Head()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(head)

	// If we're attaching the attestation to a tree, resolve the tree SHA.
	sha := head.Hash()
	refName := attCommitRef
	if *tree {
		commit, err := repo.CommitObject(head.Hash())
		if err != nil {
			log.Fatal(err)
		}
		sha = commit.TreeHash

		refName = attTreeRef
	}

	// TODO: read values from config.
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", options.KeyOpts{
		FulcioURL:    "https://fulcio.sigstore.dev",
		RekorURL:     "https://rekor.sigstore.dev",
		OIDCIssuer:   "https://oauth2.sigstore.dev/auth",
		OIDCClientID: "sigstore",
	})
	if err != nil {
		log.Fatalf("getting signer: %v", err)
	}
	defer sv.Close()

	attestor := attest.NewAttestor(repo, sv, cosign.TLogUploadInTotoAttestation)

	out, err := attestor.WriteFile(ctx, refName, sha, *path, *attType)
	fmt.Println(out, err)
}
