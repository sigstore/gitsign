//
// Copyright 2026 The Sigstore Authors.
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

package signature

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// signBundle implements the experimental "sign -> bundle -> CMS" path: it builds
// the CMS signed attributes, has sigstore-go sign them and upload the result to
// Rekor (producing a bundle), then converts that bundle back into a CMS
// signature for storage. The on-disk CMS format is unchanged.
//
// The signing key and certificate come from gitsign's existing identity, so the
// OIDC + Fulcio flow and credential cache are unchanged - sigstore-go drives the
// signing and Rekor upload, not credential acquisition.
func signBundle(ctx context.Context, body []byte, ident Identity, tlog sign.Transparency, opts SignOptions) (*SignResponse, error) {
	cert, err := ident.Certificate()
	if err != nil {
		return nil, fmt.Errorf("failed to get identity certificate: %w", err)
	}
	kp, err := ident.Keypair()
	if err != nil {
		return nil, err
	}

	// Defend against an identity whose certificate and signing key disagree:
	// otherwise we would sign + log with the key but embed a cert for a different
	// key, producing an unverifiable signature with no error at signing time.
	if err := samePublicKey(kp.GetPublicKey(), cert.PublicKey); err != nil {
		return nil, fmt.Errorf("identity certificate does not match signing key: %w", err)
	}

	attrs, sm, err := compat.BuildSignedAttributes(body)
	if err != nil {
		return nil, fmt.Errorf("failed to build signed attributes: %w", err)
	}

	pb, err := sign.Bundle(&sign.PlainData{Data: sm}, kp, sign.BundleOptions{
		CertificateProvider: compat.NewCertificateProvider(cert),
		TransparencyLogs:    []sign.Transparency{tlog},
		Context:             ctx,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign bundle: %w", err)
	}

	sd, err := compat.BundleToSignedData(body, attrs, pb, opts.Detached)
	if err != nil {
		return nil, fmt.Errorf("failed to convert bundle to CMS: %w", err)
	}

	// RFC3161 timestamping is applied to the assembled CMS via the fork, which
	// produces the correct TimeStampToken unsigned attribute. (sigstore-go's TSA
	// client returns a full TimeStampResp rather than the token the CMS stores,
	// so timestamping at the CMS layer avoids that conversion.)
	if opts.TimestampAuthority != "" {
		if err := sd.AddTimestamps(opts.TimestampAuthority); err != nil {
			return nil, fmt.Errorf("failed to add timestamp: %w", err)
		}
	}

	der, err := sd.ToDER()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize signature: %w", err)
	}

	var lea *models.LogEntryAnon
	if tles := pb.GetVerificationMaterial().GetTlogEntries(); len(tles) > 0 {
		lea = rekoroid.ProtoToLogEntryAnon(tles[0])
	}

	sig := der
	if opts.Armor {
		sig = pem.EncodeToMemory(&pem.Block{Type: "SIGNED MESSAGE", Bytes: der})
	}
	return &SignResponse{Signature: sig, Cert: cert, LogEntry: lea, Bundle: pb}, nil
}

// SignOnline performs the Rekor half of the legacy "online" signing flow using
// sigstore-go instead of the cosign helpers. It signs the reconstructed commit
// SHA with the identity's key (via a sigstore-go sign.Keypair) and uploads a
// HashedRekord over the commit SHA using sigstore-go's Rekor client, returning
// the resulting log entry.
//
// Unlike signBundle / the offline path, the entry is keyed on the commit SHA and
// is NOT embedded in the signature - it is discovered at verification time via
// Rekor's online search API (see compat.OnlineBundle). The commit body CMS
// signature is produced separately by the legacy path, so the on-disk signature
// is byte-for-byte identical to legacy online signing; only the signing of the
// commit SHA and its Rekor upload now go through sigstore-go.
func SignOnline(ctx context.Context, commitSHA string, ident Identity, cert *x509.Certificate, rekorURL string) (*models.LogEntryAnon, error) {
	tlog, err := newRekorTransparency(rekorURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create rekor client: %w", err)
	}
	return signOnline(ctx, commitSHA, ident, cert, tlog)
}

// signOnline is the transport-independent core of SignOnline, with the Rekor
// transparency log injected so it can be exercised without a live Rekor.
func signOnline(ctx context.Context, commitSHA string, ident Identity, cert *x509.Certificate, tlog sign.Transparency) (*models.LogEntryAnon, error) {
	kp, err := ident.Keypair()
	if err != nil {
		return nil, err
	}

	// Defend against an identity whose certificate and signing key disagree, as
	// the offline bundle path does: otherwise we would log an entry signed with
	// one key under a certificate for another.
	if err := samePublicKey(kp.GetPublicKey(), cert.PublicKey); err != nil {
		return nil, fmt.Errorf("identity certificate does not match signing key: %w", err)
	}

	// Sign the commit SHA. SignData returns the signature and the bytes that were
	// signed - the sha256(commitSHA) digest for gitsign's P-256 keys - which is
	// exactly the HashedRekord's artifact digest and matches what the verifier
	// reconstructs in compat.OnlineBundle.
	sig, digest, err := kp.SignData(ctx, []byte(commitSHA))
	if err != nil {
		return nil, fmt.Errorf("signing commit hash: %w", err)
	}

	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	// A minimal bundle carrying the commit-SHA MessageSignature; sigstore-go's
	// Rekor client reads it, uploads a HashedRekord, and appends the log entry.
	b := &protobundle.Bundle{
		MediaType: compat.MediaType,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: kp.GetHashAlgorithm(),
					Digest:    digest,
				},
				Signature: sig,
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw},
			},
		},
	}

	if err := tlog.GetTransparencyLogEntry(ctx, certPEM, b); err != nil {
		return nil, fmt.Errorf("uploading commit-SHA rekor entry: %w", err)
	}

	tles := b.GetVerificationMaterial().GetTlogEntries()
	if len(tles) == 0 {
		return nil, errors.New("rekor upload produced no log entry")
	}
	return rekoroid.ProtoToLogEntryAnon(tles[0]), nil
}

// newRekorTransparency builds a sign.Transparency for the given Rekor URL whose
// CreateLogEntry responses are checked to contain an inclusion proof. Without
// this, a proof-less response would panic inside sigstore-go's transparency log
// entry conversion; here it surfaces as an error instead.
func newRekorTransparency(url string) (sign.Transparency, error) {
	rc, err := rekorclient.GetRekorClient(url, rekorclient.WithUserAgent("gitsign"))
	if err != nil {
		return nil, err
	}
	return sign.NewRekor(&sign.RekorOptions{
		BaseURL: url,
		Client:  &validatingRekorClient{inner: rc.Entries},
	}), nil
}

// validatingRekorClient wraps a sign.RekorClient and rejects responses whose log
// entry lacks an inclusion proof, before sigstore-go attempts to convert it.
type validatingRekorClient struct {
	inner sign.RekorClient
}

func (c *validatingRekorClient) CreateLogEntry(params *entries.CreateLogEntryParams, opts ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	resp, err := c.inner.CreateLogEntry(params, opts...)
	if err != nil {
		return nil, err
	}
	entry, ok := resp.Payload[resp.ETag]
	if !ok {
		return nil, errors.New("rekor response missing log entry")
	}
	if entry.Verification == nil || entry.Verification.InclusionProof == nil || entry.Verification.InclusionProof.RootHash == nil {
		return nil, errors.New("rekor log entry is missing an inclusion proof")
	}
	return resp, nil
}

// samePublicKey reports whether two public keys are equal, using the key's own
// Equal method (implemented by all stdlib public key types).
func samePublicKey(a, b crypto.PublicKey) error {
	key, ok := a.(interface {
		Equal(x crypto.PublicKey) bool
	})
	if !ok {
		return fmt.Errorf("public key of type %T does not support equality comparison", a)
	}
	if !key.Equal(b) {
		return errors.New("public keys differ")
	}
	return nil
}
