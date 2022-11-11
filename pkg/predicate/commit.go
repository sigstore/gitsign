// Copyright 2022 The Sigstore Authors
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

package predicate

import (
	"time"
)

type GitCommit struct {
	Commit    *Commit `json:"source,omitempty"`
	Signature string  `json:"signature,omitempty"`
	// SignerInfo contains select fields from the PKCS7 SignerInfo.
	// This is intended as a convenience for consumers to access relevant
	// fields like certificate instead of needing to parse the signature.
	// See https://datatracker.ietf.org/doc/html/rfc5652#section-5.3 for details.
	SignerInfo []*SignerInfo `json:"signer_info,omitempty"`
}

type Commit struct {
	Tree      string   `json:"tree,omitempty"`
	Parents   []string `json:"parents,omitempty"`
	Author    *Author  `json:"author,omitempty"`
	Committer *Author  `json:"committer,omitempty"`
	Message   string   `json:"message,omitempty"`
}

type Author struct {
	Name  string    `json:"name,omitempty"`
	Email string    `json:"email,omitempty"`
	Date  time.Time `json:"date,omitempty"`
}

type SignerInfo struct {
	// Attributes contains a base64 encoded ASN.1 marshalled signed attributes.
	// See https://datatracker.ietf.org/doc/html/rfc5652#section-5.6 for more details.
	Attributes  string `json:"attributes,omitempty"`
	Certificate string `json:"certificate,omitempty"`
}
