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
	"fmt"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

// timestampTokens extracts the RFC3161 timestamp tokens stored in the
// SignerInfo's unsigned attributes and re-encodes each as a DER TimeStampResp
// (status "granted" wrapping the token), which is what a sigstore bundle's
// RFC3161SignedTimestamp.SignedTimestamp field is specified to hold. The CMS
// attribute itself stores a bare TimeStampToken (a ContentInfo) per RFC 5652
// SS11.4, which is a different ASN.1 structure and fails downstream
// TimeStampResp parsing if passed through unwrapped. gitsign normally stores
// at most one token, but the CMS structure permits several, so all are
// returned.
func timestampTokens(si protocol.SignerInfo) ([][]byte, error) {
	if !si.UnsignedAttrs.HasAttribute(oid.AttributeTimeStampToken) {
		return nil, nil
	}
	vals, err := si.UnsignedAttrs.GetValues(oid.AttributeTimeStampToken)
	if err != nil {
		return nil, fmt.Errorf("getting timestamp tokens: %w", err)
	}

	var tokens [][]byte
	for _, v := range vals {
		for _, el := range v.Elements {
			tok, err := protocol.ParseContentInfo(el.FullBytes)
			if err != nil {
				return nil, fmt.Errorf("parsing timestamp token: %w", err)
			}
			resp, err := asn1.Marshal(timestamp.Response{
				Status:         timestamp.PKIStatusInfo{Status: 0}, // granted
				TimeStampToken: tok,
			})
			if err != nil {
				return nil, fmt.Errorf("encoding timestamp response: %w", err)
			}
			tokens = append(tokens, resp)
		}
	}
	return tokens, nil
}
