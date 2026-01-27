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

package verify

import (
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/gitsign/internal"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/gitsign"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

	revision := "HEAD"
	if len(args) > 0 {
		revision = args[0]
	}

	h, err := repo.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return fmt.Errorf("error resolving commit object: %w", err)
	}
	c, err := repo.CommitObject(*h)
	if err != nil {
		return fmt.Errorf("error reading commit object: %w", err)
	}

	sig := []byte(c.PGPSignature)
	p, _ := pem.Decode(sig)
	if p == nil || p.Type != "SIGNED MESSAGE" {
		return fmt.Errorf("unsupported signature type")
	}

	c2 := new(plumbing.MemoryObject)
	if err := c.EncodeWithoutSignature(c2); err != nil {
		return err
	}
	r, err := c2.Reader()
	if err != nil {
		return err
	}
	defer r.Close() // nolint:errcheck
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}

	v, err := gitsign.NewVerifierWithCosignOpts(ctx, o.Config, &o.CertVerifyOptions)
	if err != nil {
		return err
	}
	summary, err := v.Verify(ctx, data, sig, true)
	if err != nil {
		return err
	}

	PrintSummary(os.Stdout, summary)

	return nil
}

func PrintSummary(w io.Writer, summary *git.VerificationSummary) {
	fpr := internal.CertHexFingerprint(summary.Cert)

	fmt.Fprintln(w, "tlog index:", *summary.LogEntry.LogIndex)                                           // nolint:errcheck
	fmt.Fprintf(w, "gitsign: Signature made using certificate ID 0x%s | %v\n", fpr, summary.Cert.Issuer) // nolint:errcheck

	ce := cosign.CertExtensions{Cert: summary.Cert}
	fmt.Fprintf(w, "gitsign: Good signature from %v(%s)\n", cryptoutils.GetSubjectAlternateNames(summary.Cert), ce.GetIssuer()) // nolint:errcheck

	for _, c := range summary.Claims {
		fmt.Fprintf(w, "%s: %t\n", string(c.Key), c.Value) // nolint:errcheck
	}
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{Config: cfg}

	cmd := &cobra.Command{
		Use:          "verify [commit]",
		Args:         cobra.MaximumNArgs(1),
		SilenceUsage: true,
		Short:        "Verify a commit",
		Long: `Verify a commit.

verify verifies a commit against a set of certificate claims.
This should generally be used over git verify-commit, since verify will
check the identity included in the signature's certificate.

If no revision is specified, HEAD is used.`,
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
	// --certificate: The cert should always come from the commit.
	_ = cmd.Flags().MarkHidden("certificate")
	// --certificate-chain: We only support reading from a TUF root at the moment.
	// TODO: add support for this.
	_ = cmd.Flags().MarkHidden("certificate-chain")
	// --ca-intermediates and --ca-roots
	_ = cmd.Flags().MarkHidden("ca-intermediates")
	_ = cmd.Flags().MarkHidden("ca-roots")

	return cmd
}
