//
// Copyright 2024 The Sigstore Authors.
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

package gitsign

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	cosignopts "github.com/sigstore/cosign/v3/cmd/cosign/cli/options"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
	sgbundle "github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// verifyBundle verifies a gitsign CMS signature by converting it to sigstore
// bundles and verifying each signer with the sigstore-go verifier. It is the
// bundle-based equivalent of git.Verify (CMS signature + cert chain + Rekor
// inclusion) plus the cert identity check, gated behind the experimental
// useBundle flag.
//
// sigstore-go verifies the signature over the CMS SignedAttrs, the certificate
// chain, the transparency log inclusion, and the certificate identity - but it
// does not check that the SignedAttrs bind to the git object being verified.
// That content binding is enforced separately by verifyContentBinding.
func (v *Verifier) verifyBundle(ctx context.Context, data, sig []byte, detached bool) (*git.VerificationSummary, error) {
	sd, err := compat.ParseSignaturePEM(sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	raw := sd.Raw()
	if len(raw.SignerInfos) == 0 {
		return nil, errors.New("no signers found in signature")
	}

	// Identity policy is the same for every signer; only the artifact differs.
	var policyOpts []verify.PolicyOption
	if len(v.identities) > 0 {
		for _, id := range v.identities {
			policyOpts = append(policyOpts, verify.WithCertificateIdentity(id))
		}
	} else {
		policyOpts = append(policyOpts, verify.WithoutIdentitiesUnsafe())
	}

	// A CMS signature may carry multiple signers. We require at least one to
	// verify (matching "at least one valid signature"); a failing signer does not
	// fail the whole verification. The first signer that verifies drives the
	// summary, mirroring the legacy CertVerifier which returns the leaf of the
	// first verified chain.
	var (
		leafCert *x509.Certificate
		logEntry *models.LogEntryAnon
		errs     []error
	)
	for i, si := range raw.SignerInfos {
		cert, le, err := v.verifySigner(ctx, sd, si, data, detached, policyOpts)
		if err != nil {
			errs = append(errs, fmt.Errorf("signer %d: %w", i, err))
			continue
		}
		leafCert, logEntry = cert, le
		break
	}
	if leafCert == nil {
		return nil, fmt.Errorf("no signer could be verified: %w", errors.Join(errs...))
	}

	claims := []git.Claim{git.NewClaim(git.ClaimValidatedSignature, true)}
	claims = append(claims, git.NewClaim(git.ClaimValidatedRekorEntry, logEntry != nil))
	claims = append(claims, git.NewClaim(git.ClaimValidatedCerificate, len(v.identities) > 0))

	return &git.VerificationSummary{
		Cert:     leafCert,
		LogEntry: logEntry,
		Claims:   claims,
	}, nil
}

// verifySigner verifies a single CMS signer against the trust material using the
// sigstore-go verifier, returning its leaf certificate and Rekor log entry. It
// enforces content binding (the signature covers this git object) and requires
// a Rekor transparency log entry, since the legacy path requires one and the
// bundle path does not fall back to an unattested current-time verification.
func (v *Verifier) verifySigner(ctx context.Context, sd *cms.SignedData, si protocol.SignerInfo, data []byte, detached bool, policyOpts []verify.PolicyOption) (*x509.Certificate, *models.LogEntryAnon, error) {
	sb, err := compat.SignerInfoToBundle(ctx, sd, si)
	if err != nil {
		return nil, nil, err
	}

	// Content binding: prove the signature covers this git object. This is the
	// one check sigstore-go cannot do from the bundle alone.
	if err := verifyContentBinding(si, sd, data, detached); err != nil {
		return nil, nil, err
	}

	if len(sb.Bundle.GetVerificationMaterial().GetTlogEntries()) == 0 {
		return nil, nil, errors.New("no Rekor transparency log entry")
	}

	pb, err := sgbundle.NewBundle(sb.Bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid bundle: %w", err)
	}

	// The verifier's time policy depends on whether this signer carries an
	// RFC3161 timestamp, so it is built per signer.
	hasTimestamp := len(sb.Bundle.GetVerificationMaterial().GetTimestampVerificationData().GetRfc3161Timestamps()) > 0
	sev, err := newSignedEntityVerifier(v.trustedMaterial, hasTimestamp, v.ignoreSCT)
	if err != nil {
		return nil, nil, err
	}

	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(sb.Artifact)), policyOpts...)
	if _, err := sev.Verify(pb, policy); err != nil {
		return nil, nil, err
	}

	leafCert, err := x509.ParseCertificate(sb.Bundle.GetVerificationMaterial().GetCertificate().GetRawBytes())
	if err != nil {
		return nil, nil, fmt.Errorf("parsing leaf certificate: %w", err)
	}
	var logEntry *models.LogEntryAnon
	if tles := sb.Bundle.GetVerificationMaterial().GetTlogEntries(); len(tles) > 0 {
		logEntry = rekoroid.ProtoToLogEntryAnon(tles[0])
	}
	return leafCert, logEntry, nil
}

// verifyContentBinding checks that the git object content hashes to the
// message-digest signed attribute, i.e. that the authenticated SignedAttrs
// actually describe this object. For attached signatures the content is the
// CMS encapsulated data; for detached signatures it is the supplied data.
func verifyContentBinding(si protocol.SignerInfo, sd *cms.SignedData, data []byte, detached bool) error {
	md, err := si.GetMessageDigestAttribute()
	if err != nil {
		return fmt.Errorf("getting message digest attribute: %w", err)
	}
	hashFn, err := si.Hash()
	if err != nil {
		return fmt.Errorf("unsupported digest algorithm: %w", err)
	}

	content := data
	if !detached {
		content, err = sd.GetData()
		if err != nil {
			return fmt.Errorf("getting encapsulated content: %w", err)
		}
	}

	h := hashFn.New()
	h.Write(content)
	if !bytes.Equal(h.Sum(nil), md) {
		return errors.New("content digest does not match signed message digest")
	}
	return nil
}

// newSignedEntityVerifier builds a verifier that requires a verified Rekor
// transparency log entry and uses its timestamp (the Rekor SET / integrated
// time) to establish signing time for certificate chain validation. This
// mirrors the legacy path, which requires a Rekor entry and defers signing time
// to it.
//
// When hasTimestamp is set, the signature also carries an RFC3161 timestamp,
// which is additionally required to verify against the configured timestamping
// authorities (see timestampAuthorities) - matching the legacy CMS verifier,
// which validates any embedded timestamp token. Signatures relying solely on an
// RFC3161 timestamp (no Rekor entry) are not supported by the bundle path.
//
// Embedded SCTs are verified by default unless ignoreSCT is set.
func newSignedEntityVerifier(tm root.TrustedMaterial, hasTimestamp, ignoreSCT bool) (*verify.Verifier, error) {
	opts := []verify.VerifierOption{
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	}
	if hasTimestamp {
		opts = append(opts, verify.WithSignedTimestamps(1))
	}
	if !ignoreSCT {
		opts = append(opts, verify.WithSignedCertificateTimestamps(1))
	}
	return verify.NewVerifier(tm, opts...)
}

// mapIdentities converts cosign certificate verification options into
// sigstore-go certificate identities. Each cosign identity (subject + issuer,
// with optional regexp variants) becomes a CertificateIdentity, and the GitHub
// workflow claim options are attached as certificate extensions.
func mapIdentities(opts *cosignopts.CertVerifyOptions) ([]verify.CertificateIdentity, error) {
	if opts == nil {
		return nil, nil
	}
	ids, err := opts.Identities()
	if err != nil {
		return nil, fmt.Errorf("parsing identities: %w", err)
	}

	ext := certificate.Extensions{
		GithubWorkflowTrigger:    opts.CertGithubWorkflowTrigger,
		GithubWorkflowSHA:        opts.CertGithubWorkflowSha,
		GithubWorkflowName:       opts.CertGithubWorkflowName,
		GithubWorkflowRepository: opts.CertGithubWorkflowRepository,
		GithubWorkflowRef:        opts.CertGithubWorkflowRef,
	}

	out := make([]verify.CertificateIdentity, 0, len(ids))
	for _, id := range ids {
		san, err := verify.NewSANMatcher(id.Subject, id.SubjectRegExp)
		if err != nil {
			return nil, err
		}
		issuer, err := verify.NewIssuerMatcher(id.Issuer, id.IssuerRegExp)
		if err != nil {
			return nil, err
		}
		ci, err := verify.NewCertificateIdentity(san, issuer, ext)
		if err != nil {
			return nil, err
		}
		out = append(out, ci)
	}
	return out, nil
}
