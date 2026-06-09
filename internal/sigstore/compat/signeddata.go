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

package compat

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/github/smimesign/ietf-cms/protocol"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
)

// gitsign signs with an ephemeral ECDSA P-256 key, so the CMS signed attributes
// and SignerInfo use SHA-256. The keypair (see Keypair) derives its algorithms
// from the key; the CMS assembly here mirrors that with SHA-256.
const signingHash = crypto.SHA256

// BuildSignedAttributes builds the CMS signed attributes (content-type,
// message-digest over body, and signing-time) that a gitsign signature signs
// over, returning the attributes and their marshaled-for-signing form. The
// marshaled bytes are what the signer signs; the attributes are stored verbatim
// in the resulting CMS SignerInfo (see BundleToSignedData), so the two must come
// from the same call - in particular they share a single signing-time.
func BuildSignedAttributes(body []byte) (protocol.Attributes, []byte, error) {
	attrs, err := cms.SignedAttributes(body, signingHash)
	if err != nil {
		return nil, nil, err
	}
	sm, err := attrs.MarshaledForSigning()
	if err != nil {
		return nil, nil, err
	}
	return attrs, sm, nil
}

// BundleToSignedData assembles a gitsign CMS SignedData from the original git
// object body, the signed attributes that were signed (see
// BuildSignedAttributes), and a sigstore bundle carrying the signature, signing
// certificate, and (optionally) Rekor transparency log entry. It is the inverse
// of SignerInfoToBundle: rather than reading an existing CMS, it constructs one
// from a freshly produced bundle for storage.
//
// The body is encapsulated in the result unless detached is set. Serialized with
// ToDER, the result is byte-for-byte equivalent to what the ietf-cms fork would
// produce for the same attributes, signature, and certificate. The returned
// *cms.SignedData can be further manipulated (e.g. AddTimestamps) before
// serialization.
func BundleToSignedData(body []byte, signedAttrs protocol.Attributes, b *protobundle.Bundle, detached bool) (*cms.SignedData, error) {
	ms := b.GetMessageSignature()
	if ms == nil {
		return nil, errors.New("bundle has no message signature")
	}
	certBytes := b.GetVerificationMaterial().GetCertificate().GetRawBytes()
	if certBytes == nil {
		return nil, errors.New("bundle has no leaf certificate")
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing bundle certificate: %w", err)
	}

	// Encode any Rekor transparency log entry into the unsigned attributes,
	// exactly as the legacy signing path did.
	var unsignedAttrs protocol.Attributes
	attrSets, err := BundleToAttributes(b)
	if err != nil {
		return nil, err
	}
	for _, attrs := range attrSets {
		unsignedAttrs = append(unsignedAttrs, attrs...)
	}

	sd, err := cms.NewSignedData(body)
	if err != nil {
		return nil, err
	}
	if err := sd.AddSignerInfoWithSignature(cert, signingHash, signedAttrs, ms.GetSignature(), unsignedAttrs); err != nil {
		return nil, err
	}
	if detached {
		sd.Detached()
	}

	return sd, nil
}
