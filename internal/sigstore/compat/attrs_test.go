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
	"encoding/asn1"
	"testing"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

// TestTimestampTokens verifies that the bytes returned for a CMS
// id-aa-timeStampToken unsigned attribute (a bare RFC 5652 SS11.4
// TimeStampToken) parse as a DER TimeStampResp, since that is the structure
// the sigstore bundle's RFC3161SignedTimestamp.SignedTimestamp field
// requires. Before the fix, timestampTokens returned the TimeStampToken bytes
// verbatim, which fail to parse as a TimeStampResp (a different ASN.1
// structure) and made every timestamped bundle unverifiable.
func TestTimestampTokens(t *testing.T) {
	// A minimal but well-formed TimeStampToken (CMS ContentInfo), matching
	// the shape gitsign's sign path stores in the attribute.
	token := protocol.ContentInfo{
		ContentType: oid.ContentTypeSignedData,
		Content: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			Tag:        0,
			IsCompound: true,
			Bytes:      []byte{0x05, 0x00}, // ASN.1 NULL
		},
	}

	attr, err := protocol.NewAttribute(oid.AttributeTimeStampToken, token)
	if err != nil {
		t.Fatalf("NewAttribute: %v", err)
	}
	si := protocol.SignerInfo{UnsignedAttrs: protocol.Attributes{attr}}

	tokens, err := timestampTokens(si)
	if err != nil {
		t.Fatalf("timestampTokens: %v", err)
	}
	if len(tokens) != 1 {
		t.Fatalf("got %d tokens, want 1", len(tokens))
	}

	var resp timestamp.Response
	if rest, err := asn1.Unmarshal(tokens[0], &resp); err != nil {
		t.Fatalf("returned bytes do not parse as a TimeStampResp: %v", err)
	} else if len(rest) > 0 {
		t.Fatalf("trailing data after TimeStampResp: %d bytes", len(rest))
	}

	if resp.Status.Status != 0 {
		t.Errorf("Status.Status = %d, want 0 (granted)", resp.Status.Status)
	}
	if !resp.TimeStampToken.ContentType.Equal(token.ContentType) {
		t.Errorf("TimeStampToken.ContentType = %v, want %v", resp.TimeStampToken.ContentType, token.ContentType)
	}

	// Sanity check: the raw ContentInfo bytes on their own do NOT parse as a
	// TimeStampResp, which is the bug this wraps around.
	rawToken, err := asn1.Marshal(token)
	if err != nil {
		t.Fatalf("asn1.Marshal(token): %v", err)
	}
	var bad timestamp.Response
	if _, err := asn1.Unmarshal(rawToken, &bad); err == nil {
		t.Fatal("expected a bare TimeStampToken to fail parsing as a TimeStampResp")
	}
}
