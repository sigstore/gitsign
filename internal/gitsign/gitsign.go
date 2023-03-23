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

package gitsign

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"

	cosignopts "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/v2/pkg/cosign"
	"github.com/sigstore/gitsign/internal/cert"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio/fulcioroots"
	rekorinternal "github.com/sigstore/gitsign/internal/rekor"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Verifier struct {
	git   git.Verifier
	cert  cert.Verifier
	rekor rekor.Verifier
}

// NewVerifierWithCosignOpts implements a Gitsign verifier using Cosign CertVerifyOptions.
// Note: not all options are supported.
//   - cert: This is always taken from the commit.
func NewVerifierWithCosignOpts(ctx context.Context, cfg *config.Config, opts *cosignopts.CertVerifyOptions) (*Verifier, error) {
	root, intermediate, err := fulcioroots.NewFromConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("error getting certificate root: %w", err)
	}

	tsa, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error getting system root pool: %w", err)
	}
	if path := cfg.TimestampCert; path != "" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		cert, err := cryptoutils.LoadCertificatesFromPEM(f)
		if err != nil {
			return nil, fmt.Errorf("error loading certs from %s: %w", path, err)
		}
		for _, c := range cert {
			tsa.AddCert(c)
		}
	}

	gitverifier, err := git.NewCertVerifier(
		git.WithRootPool(root),
		git.WithIntermediatePool(intermediate),
		git.WithTimestampCertPool(tsa),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating Git verifier: %w", err)
	}

	rekor, err := rekorinternal.NewClient(cfg.Rekor)
	if err != nil {
		return nil, fmt.Errorf("failed to create rekor client: %w", err)
	}

	// Optionally include cert.Verifier.
	// This needs to be optional because when verifying with
	// `git verify-commit` we don't have access to issuer / identity details.
	// In these cases, clients should look for the certificate validated claim
	// and warn if missing.
	var certverifier cert.Verifier
	if opts != nil {
		ctpub, err := cosign.GetCTLogPubs(ctx)
		if err != nil {
			return nil, fmt.Errorf("error getting CT log public key: %w", err)
		}
		identities, err := opts.Identities()
		if err != nil {
			return nil, fmt.Errorf("error parsing identities: %w", err)
		}
		certverifier = cert.NewCosignVerifier(&cosign.CheckOpts{
			RekorClient:                  rekor.Rekor,
			RootCerts:                    root,
			IntermediateCerts:            intermediate,
			CTLogPubKeys:                 ctpub,
			RekorPubKeys:                 rekor.PublicKeys(),
			CertGithubWorkflowTrigger:    opts.CertGithubWorkflowTrigger,
			CertGithubWorkflowSha:        opts.CertGithubWorkflowSha,
			CertGithubWorkflowName:       opts.CertGithubWorkflowName,
			CertGithubWorkflowRepository: opts.CertGithubWorkflowRepository,
			CertGithubWorkflowRef:        opts.CertGithubWorkflowRef,
			Identities:                   identities,
			IgnoreSCT:                    opts.IgnoreSCT,
		})
	}

	return &Verifier{
		git:   gitverifier,
		cert:  certverifier,
		rekor: rekor,
	}, nil
}

func (v *Verifier) Verify(ctx context.Context, data []byte, sig []byte, detached bool) (*git.VerificationSummary, error) {
	// TODO: we probably want to deprecate git.Verify in favor of this struct.
	summary, err := git.Verify(ctx, v.git, v.rekor, data, sig, detached)
	if err != nil {
		return summary, err
	}

	if v.cert != nil {
		if err := v.cert.Verify(summary.Cert); err != nil {
			summary.Claims = append(summary.Claims, git.NewClaim(git.ClaimValidatedCerificate, false))
			return summary, err
		}
		summary.Claims = append(summary.Claims, git.NewClaim(git.ClaimValidatedCerificate, true))
	} else {
		summary.Claims = append(summary.Claims, git.NewClaim(git.ClaimValidatedCerificate, false))
	}

	return summary, nil
}
