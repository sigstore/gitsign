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

package compat

import (
	"fmt"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
)

// timestampTokens extracts the raw DER RFC3161 timestamp tokens stored in the
// SignerInfo's unsigned attributes. Each token is the full DER of an RFC3161
// TimeStampToken (a CMS ContentInfo), which is exactly what a sigstore bundle's
// RFC3161SignedTimestamp.SignedTimestamp holds. gitsign normally stores at most
// one, but the CMS structure permits several, so all are returned.
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
			tokens = append(tokens, el.FullBytes)
		}
	}
	return tokens, nil
}
