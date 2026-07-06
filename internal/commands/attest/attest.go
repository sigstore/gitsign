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
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/fulcio"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/signcommon"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/gitsign/internal/attest"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/sigstore/pkg/signature"
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
	digestType := attest.DigestTypeCommit
	if o.FlagObjectType == FlagObjectTypeTree {
		commit, err := repo.CommitObject(head.Hash())
		if err != nil {
			return fmt.Errorf("error getting tree: %w", err)
		}
		sha = commit.TreeHash

		refName = attTreeRef
		digestType = attest.DigestTypeTree
	}

	ko := cosignopts.KeyOpts{
		FulcioURL:    o.Config.Fulcio,
		RekorURL:     o.Config.Rekor,
		OIDCIssuer:   o.Config.Issuer,
		OIDCClientID: o.Config.ClientID,
	}

	// cosign v3.1 unexported its keyless SignerVerifier constructor
	// (signcommon.GetSignerVerifier). Build the equivalent here the way cosign
	// used to: generate an ephemeral key, get a Fulcio cert for it, and wrap
	// both in a signcommon.SignerVerifier, which the attestor uses to DSSE-sign
	// and for the Rekor upload.
	keyDetails, err := signcommon.ParseSignatureAlgorithmFlag("")
	if err != nil {
		return fmt.Errorf("parsing signature algorithm: %w", err)
	}
	algo, err := signature.GetAlgorithmDetails(keyDetails)
	if err != nil {
		return fmt.Errorf("getting algorithm details: %w", err)
	}
	privKey, err := cosign.GeneratePrivateKeyWithAlgorithm(&algo)
	if err != nil {
		return fmt.Errorf("generating ephemeral key: %w", err)
	}
	loadOptions := cosign.GetDefaultLoadOptions(nil)
	signer, err := signature.LoadSignerVerifierFromAlgorithmDetails(privKey, algo, *loadOptions...)
	if err != nil {
		return fmt.Errorf("loading ephemeral signer: %w", err)
	}
	fulcioSigner, err := fulcio.NewSigner(ctx, ko, signer)
	if err != nil {
		return fmt.Errorf("getting signer: %w", err)
	}
	sv := &signcommon.SignerVerifier{
		Cert:           fulcioSigner.Cert,
		Chain:          fulcioSigner.Chain,
		SignerVerifier: fulcioSigner.SignerVerifier,
	}

	attestor := attest.NewAttestor(repo, sv, cosign.TLogUploadInTotoAttestation, o.Config, digestType)

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
