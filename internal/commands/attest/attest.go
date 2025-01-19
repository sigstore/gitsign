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

package attest

import (
	"context"
	"fmt"

	"github.com/go-git/go-git/v5"
	cosignopts "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/gitsign/internal/attest"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/spf13/cobra"
)

const (
	attCommitRef = "refs/attestations/commits"
	attTreeRef   = "refs/attestations/trees"

	FlagObjectTypeCommit = "commit"
	FlagObjectTypeTree   = "tree"
)

type options struct {
	Config *config.Config

	FlagObjectType      string
	FlagPath            string
	FlagAttestationType string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.FlagObjectType, "objtype", FlagObjectTypeCommit, "[commit | tree] - Git object type to attest")
	cmd.Flags().StringVarP(&o.FlagPath, "filepath", "f", "", "attestation filepath")
	cmd.Flags().StringVar(&o.FlagAttestationType, "type", "", `specify a predicate type URI`)
}

func (o *options) Run(ctx context.Context) error {
	repo, err := git.PlainOpen(".")
	if err != nil {
		return fmt.Errorf("error opening repo: %w", err)
	}

	head, err := repo.Head()
	if err != nil {
		return fmt.Errorf("error getting repository head: %w", err)
	}

	// If we're attaching the attestation to a tree, resolve the tree SHA.
	sha := head.Hash()
	refName := attCommitRef
	if o.FlagObjectType == FlagObjectTypeTree {
		commit, err := repo.CommitObject(head.Hash())
		if err != nil {
			return fmt.Errorf("error getting tree: %w", err)
		}
		sha = commit.TreeHash

		refName = attTreeRef
	}

	sv, err := sign.SignerFromKeyOpts(ctx, "", "", cosignopts.KeyOpts{
		FulcioURL:    o.Config.Fulcio,
		RekorURL:     o.Config.Rekor,
		OIDCIssuer:   o.Config.Issuer,
		OIDCClientID: o.Config.ClientID,
	})
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	attestor := attest.NewAttestor(repo, sv, cosign.TLogUploadInTotoAttestation, o.Config)

	out, err := attestor.WriteFile(ctx, refName, sha, o.FlagPath, o.FlagAttestationType)
	if err != nil {
		return err
	}
	fmt.Println(out)

	return nil
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{
		Config: cfg,
	}
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "add attestations to Git objects",
		Args:  cobra.ArbitraryArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx := context.Background()
			return o.Run(ctx)
		},
	}
	o.AddFlags(cmd)

	return cmd
}
