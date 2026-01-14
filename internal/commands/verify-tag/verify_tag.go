// Copyright 2023 The Sigstore Authors
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

package verifytag

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/gitsign/internal/commands/verify"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/gitsign"
	"github.com/spf13/cobra"
)

type options struct {
	Config *config.Config
	cosignopts.CertVerifyOptions
}

func (o *options) AddFlags(cmd *cobra.Command) {
	o.CertVerifyOptions.AddFlags(cmd)
}

func (o *options) Run(_ io.Writer, args []string) error {
	ctx := context.Background()
	repo, err := gogit.PlainOpenWithOptions(".", &gogit.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}

	if len(args) == 0 {
		return fmt.Errorf("tag reference is required")
	}
	tagRef := args[0]

	// Resolve the tag reference
	ref, err := repo.Reference(plumbing.ReferenceName(fmt.Sprintf("refs/tags/%s", tagRef)), true)
	if err != nil {
		return fmt.Errorf("error resolving tag reference: %w", err)
	}

	// Get the tag object
	tagObj, err := repo.TagObject(ref.Hash())
	if err != nil {
		return fmt.Errorf("error reading tag object: %w", err)
	}

	// Extract the signature
	sig := []byte(tagObj.PGPSignature)
	p, _ := pem.Decode(sig)
	if p == nil || p.Type != "SIGNED MESSAGE" {
		return fmt.Errorf("unsupported signature type")
	}

	// Get the tag data without the signature
	tagData := new(plumbing.MemoryObject)
	if err := tagObj.EncodeWithoutSignature(tagData); err != nil {
		return err
	}
	r, err := tagData.Reader()
	if err != nil {
		return err
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	// Verify the signature
	v, err := gitsign.NewVerifierWithCosignOpts(ctx, o.Config, &o.CertVerifyOptions)
	if err != nil {
		return err
	}
	summary, err := v.Verify(ctx, data, sig, true)
	if err != nil {
		return err
	}

	// Import the internal package just for the PrintSummary function
	verify.PrintSummary(os.Stdout, summary)

	return nil
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{Config: cfg}

	cmd := &cobra.Command{
		Use:          "verify-tag <tag>",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		Short:        "Verify a tag",
		Long: `Verify a tag.

verify-tag verifies a tag against a set of certificate claims.
This should generally be used over git verify-tag, since verify-tag will
check the identity included in the signature's certificate.`,
		RunE: func(_ *cobra.Command, args []string) error {
			// Simulate unknown flag errors.
			if o.Cert != "" {
				return fmt.Errorf("unknown flag: --certificate")
			}
			if o.CertChain != "" {
				return fmt.Errorf("unknown flag: --certificate-chain")
			}

			return o.Run(os.Stdout, args)
		},
	}
	o.AddFlags(cmd)

	// Hide flags we don't implement.
	// --certificate: The cert should always come from the tag.
	_ = cmd.Flags().MarkHidden("certificate")
	// --certificate-chain: We only support reading from a TUF root at the moment.
	// TODO: add support for this.
	_ = cmd.Flags().MarkHidden("certificate-chain")
	// --ca-intermediates and --ca-roots
	_ = cmd.Flags().MarkHidden("ca-intermediates")
	_ = cmd.Flags().MarkHidden("ca-roots")

	return cmd
}
