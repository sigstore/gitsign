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
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/go-openapi/runtime"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/tle"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
)

// OnlineBundle builds a sigstore bundle for a legacy "online" gitsign signature,
// whose Rekor entry is not embedded in the signature but stored in Rekor keyed on
// the commit SHA (uploaded by git.LegacySHASign as a HashedRekord over the commit
// SHA, signed with the same key as the commit).
//
// Unlike SignerInfoToBundle, the signed artifact here is the commit SHA itself
// (not the CMS SignedAttrs): the MessageSignature is sha256(commitSHA) plus the
// signature over the commit SHA carried in the Rekor entry. Callers MUST supply
// the returned Artifact ([]byte(commitSHA)) as the verification artifact.
//
// le is the entry returned by an online Rekor search (rekor.Verifier.Search);
// cert is the leaf certificate from the CMS signature.
func OnlineBundle(commitSHA string, le *models.LogEntryAnon, cert *x509.Certificate) (*SignerBundle, error) {
	if le == nil {
		return nil, errors.New("nil rekor log entry")
	}

	// sigstore-go reads the signature from the bundle's MessageSignature, not from
	// the Rekor body, so pull the commit-SHA signature out of the HashedRekord.
	sig, err := hashedRekordSignature(le)
	if err != nil {
		return nil, fmt.Errorf("extracting commit-SHA signature from rekor entry: %w", err)
	}

	// tle.GenerateTransparencyLogEntry base64-decodes the (base64-encoded) Body of
	// the search result and sets the KindVersion, producing a bundle-shaped proto
	// with the raw canonicalized body.
	tlog, err := tle.GenerateTransparencyLogEntry(*le)
	if err != nil {
		return nil, fmt.Errorf("converting rekor entry to transparency log entry: %w", err)
	}

	artifact := []byte(commitSHA)
	digest := sha256.Sum256(artifact)
	b := &protobundle.Bundle{
		MediaType: MediaType,
		Content: &protobundle.Bundle_MessageSignature{
			MessageSignature: &protocommon.MessageSignature{
				MessageDigest: &protocommon.HashOutput{
					Algorithm: protocommon.HashAlgorithm_SHA2_256,
					Digest:    digest[:],
				},
				Signature: sig,
			},
		},
		VerificationMaterial: &protobundle.VerificationMaterial{
			Content: &protobundle.VerificationMaterial_Certificate{
				Certificate: &protocommon.X509Certificate{
					RawBytes: cert.Raw,
				},
			},
			TlogEntries: []*rekorpb.TransparencyLogEntry{tlog},
		},
	}

	return &SignerBundle{Bundle: b, Artifact: artifact}, nil
}

// hashedRekordSignature returns the signature content of a HashedRekord Rekor log
// entry. The entry Body is the base64-encoded canonical entry as returned by the
// Rekor API.
func hashedRekordSignature(le *models.LogEntryAnon) ([]byte, error) {
	body, ok := le.Body.(string)
	if !ok {
		return nil, fmt.Errorf("unexpected rekor body type %T", le.Body)
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("decoding rekor body: %w", err)
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(raw), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}
	hr, ok := eimpl.(*hashedrekord_v001.V001Entry)
	if !ok {
		return nil, fmt.Errorf("unexpected rekor entry type %T, want hashedrekord", eimpl)
	}
	if hr.HashedRekordObj.Signature == nil {
		return nil, errors.New("rekor entry has no signature")
	}
	return hr.HashedRekordObj.Signature.Content, nil
}
