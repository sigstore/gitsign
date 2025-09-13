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

package oid

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	"github.com/sigstore/rekor/pkg/types/hashedrekord"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/proto"
)

var (
	// OIDRekorTransparencyLogEntry is the OID for a serialized Rekor TransparencyLogEntry proto.
	// See https://github.com/sigstore/rekor/pull/1390
	OIDRekorTransparencyLogEntry = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 3, 1}
)

// ToLogEntry reconstructs a Rekor HashedRekord from Git commit signature PKCS7 components.
func ToLogEntry(ctx context.Context, message []byte, sig []byte, cert *x509.Certificate, attrs protocol.Attributes) (*models.LogEntryAnon, error) {
	var b []byte
	if err := unmarshalAttribute(attrs, OIDRekorTransparencyLogEntry, &b); err != nil {
		return nil, fmt.Errorf("error unmarshalling attribute: %w", err)
	}
	pb := new(rekorpb.TransparencyLogEntry)
	if err := proto.Unmarshal(b, pb); err != nil {
		return nil, fmt.Errorf("error unmarshalling TransparencyLogEntry attribute: %w", err)
	}
	out := logEntryAnonFromProto(pb)

	// Recompute HashedRekord body.
	hash := sha256.Sum256(message)
	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, fmt.Errorf("error marshalling cert: %w", err)
	}
	re := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer("sha256"),
					Value:     conv.Pointer(hex.EncodeToString(hash[:])),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := types.CanonicalizeEntry(ctx, re)
	if err != nil {
		return nil, fmt.Errorf("error canonicalizing entry: %w", err)
	}
	out.Body = base64.StdEncoding.EncodeToString(body)

	return out, nil
}

func unmarshalAttribute(attrs protocol.Attributes, oid asn1.ObjectIdentifier, target any) error {
	rv, err := attrs.GetOnlyAttributeValueBytes(oid)
	if err != nil {
		return fmt.Errorf("get oid: %w", err)
	}

	if _, err := asn1.Unmarshal(rv.FullBytes, target); err != nil {
		return fmt.Errorf("asn1.unmarshal(%v): %w", oid, err)
	}
	return nil
}

// ToAttributes takes a Rekor log entry and extracts fields into Attributes suitable to be included in the signature's
// unauthenticated attributes.
func ToAttributes(tlog *models.LogEntryAnon) (protocol.Attributes, error) {
	pb, err := logEntryAnonToProto(tlog, &rekorpb.KindVersion{
		Kind:    hashedrekord.KIND,
		Version: hashedrekord_v001.APIVERSION,
	})
	if err != nil {
		return nil, err
	}
	// Clear out body - we store this data elsewhere so including is in the serialized log entry is redundant.
	pb.CanonicalizedBody = nil
	out, err := proto.Marshal(pb)
	if err != nil {
		return nil, err
	}

	attrs := protocol.Attributes{}
	attr, err := protocol.NewAttribute(OIDRekorTransparencyLogEntry, out)
	if err != nil {
		return nil, err
	}
	attrs = append(attrs, attr)
	return attrs, nil
}
