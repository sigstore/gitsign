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
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	rekorclient "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
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

// samePublicKey reports whether two public keys are identical by comparing their
// PKIX encodings.
func samePublicKey(a, b any) error {
	ab, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return err
	}
	bb, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(ab, bb) {
		return errors.New("public keys differ")
	}
	return nil
}
