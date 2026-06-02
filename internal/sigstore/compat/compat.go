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

// Package compat converts between gitsign's x509 CMS/PKCS7 signature format and
// the sigstore bundle format (protobuf-specs Bundle). It exists to let gitsign
// use the sigstore-go signing and verification libraries without changing the
// on-disk CMS signature format.
//
// The key insight is that gitsign's signed *artifact* is not the git commit/tag
// body, but the marshaled CMS SignedAttrs
// (SignerInfo.SignedAttrs.MarshaledForVerification()). The CMS signature is
// computed over that, and the Rekor HashedRekord is sha256(SignedAttrs) +
// signature + signer-cert. This maps directly onto a sigstore bundle
// MessageSignature, so callers must pass the returned marshaled SignedAttrs as
// the verification artifact.
package compat

import (
	"context"
	"crypto/sha256"
	"encoding/pem"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
)

// MediaType is the sigstore bundle media type emitted by the conversion
// functions. gitsign uses v0.3, which carries a single leaf certificate (rather
// than a chain) and requires an inclusion proof for any transparency log entries.
const MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

// ParseSignaturePEM parses a gitsign CMS SignedData from a signature that is
// either PEM-armored (e.g. a "SIGNED MESSAGE" block) or raw DER/BER. Git
// signatures may be stored in either form, so callers verifying a signature
// should use this rather than deciding the encoding themselves.
func ParseSignaturePEM(sig []byte) (*cms.SignedData, error) {
	der := sig
	if blk, _ := pem.Decode(sig); blk != nil {
		der = blk.Bytes
	}
	return cms.ParseSignedData(der)
}

// SignerBundle is the result of converting one CMS SignerInfo to a sigstore
// bundle. Artifact is the marshaled CMS SignedAttrs that Bundle's signature and
// transparency log entry are computed over; callers MUST supply it as the
// verification artifact (e.g. verify.WithArtifact), since the bundle's
// MessageSignature only carries its digest.
type SignerBundle struct {
	Bundle   *protobundle.Bundle
	Artifact []byte
}

// SignedDataToBundle converts every signer in a parsed gitsign CMS SignedData
// into a sigstore bundle, returning one SignerBundle per SignerInfo.
//
// gitsign signs with a single signer, but the CMS format permits several and a
// sigstore bundle holds exactly one MessageSignature, so each signer becomes its
// own bundle. Callers verifying an arbitrary signature should verify every
// returned bundle, mirroring the CMS verifier which validates every signer
// (internal/fork/ietf-cms/verify.go).
func SignedDataToBundle(ctx context.Context, sd *cms.SignedData) ([]*SignerBundle, error) {
	raw := sd.Raw()
	out := make([]*SignerBundle, 0, len(raw.SignerInfos))
	for _, si := range raw.SignerInfos {
		sb, err := SignerInfoToBundle(ctx, sd, si)
		if err != nil {
			return nil, err
		}
		out = append(out, sb)
	}
	return out, nil
}

// SignerInfoToBundle converts a single signer (selected by signerIndex) of a
// parsed gitsign CMS SignedData into a sigstore bundle suitable for verification
// with sigstore-go.
func SignerInfoToBundle(ctx context.Context, sd *cms.SignedData, si protocol.SignerInfo) (*SignerBundle, error) {
	// The signed artifact is the marshaled SignedAttrs, not the commit body.
	message, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, fmt.Errorf("marshalling signed attributes: %w", err)
	}

	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("getting signature certificates: %w", err)
	}
	cert, err := si.FindCertificate(certs)
	if err != nil {
		return nil, fmt.Errorf("finding signer certificate: %w", err)
	}

	digest := sha256.Sum256(message)
	b := &protobundle.Bundle{
		MediaType: MediaType,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: si.Signature,
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			// v0.3 single leaf certificate. gitsign only ever embeds the leaf
			// cert in the CMS bag; intermediates/roots come from the trusted root.
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: cert.Raw,
				},
			},
		},
	}

	// Offline Rekor transparency log entry, stored in the unsigned attrs under
	// OIDRekorTransparencyLogEntry. The canonicalized body is cleared on storage,
	// so ToLogEntryProto recomputes it from the signed message + signature + cert.
	if si.UnsignedAttrs.HasAttribute(rekoroid.OIDRekorTransparencyLogEntry) {
		tlog, err := rekoroid.ToLogEntryProto(ctx, message, si.Signature, cert, si.UnsignedAttrs)
		if err != nil {
			return nil, fmt.Errorf("reconstructing rekor log entry: %w", err)
		}
		b.VerificationMaterial.TlogEntries = []*rekorpb.TransparencyLogEntry{tlog}
	}

	// RFC3161 timestamp tokens, stored in the unsigned attrs.
	tokens, err := timestampTokens(si)
	if err != nil {
		return nil, err
	}
	if len(tokens) > 0 {
		tvd := &protobundle.TimestampVerificationData{}
		for _, tok := range tokens {
			tvd.Rfc3161Timestamps = append(tvd.Rfc3161Timestamps, &protocommon.RFC3161SignedTimestamp{
				SignedTimestamp: tok,
			})
		}
		b.VerificationMaterial.TimestampVerificationData = tvd
	}

	return &SignerBundle{Bundle: b, Artifact: message}, nil
}

// BundleToAttributes converts each Rekor transparency log entry carried in a
// sigstore bundle into CMS unsigned attributes, encoded under
// OIDRekorTransparencyLogEntry exactly as the legacy signing path produced them.
// It returns one protocol.Attributes per transparency log entry (gitsign
// produces a single entry, but the bundle format permits several), or an empty
// slice if the bundle has none (e.g. a timestamp-only signature).
//
// This is the inverse of the tlog half of SignerInfoToBundle. It is not a full
// bundle->SignerInfo conversion: a bundle does not carry the SignedAttrs,
// content-type, or payload a SignerInfo needs, so the caller is expected to
// already hold a signed CMS SignedData and to append the returned attributes to
// the appropriate SignerInfo's UnsignedAttrs itself.
//
// RFC3161 timestamps are intentionally not handled here: gitsign adds those via
// cms.SignedData.AddTimestamps, keeping timestamping in the CMS layer.
func BundleToAttributes(b *protobundle.Bundle) ([]protocol.Attributes, error) {
	tles := b.GetVerificationMaterial().GetTlogEntries()
	out := make([]protocol.Attributes, 0, len(tles))
	for _, tle := range tles {
		lea := rekoroid.ProtoToLogEntryAnon(tle)
		attrs, err := rekoroid.ToAttributes(lea)
		if err != nil {
			return nil, fmt.Errorf("encoding rekor log entry: %w", err)
		}
		out = append(out, attrs)
	}
	return out, nil
}
