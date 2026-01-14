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

package cert

import (
	"crypto/x509"

	"github.com/sigstore/cosign/v3/pkg/cosign"
)

// Verifier verifies a given cert for a set of claims.
type Verifier interface {
	Verify(cert *x509.Certificate) error
}

// CosignVerifier borrows its certificate verification logic from cosign.
type CosignVerifier struct {
	opts *cosign.CheckOpts
}

func NewCosignVerifier(opts *cosign.CheckOpts) *CosignVerifier {
	return &CosignVerifier{opts: opts}
}

func (v *CosignVerifier) Verify(cert *x509.Certificate) error {
	_, err := cosign.ValidateAndUnpackCert(cert, v.opts)
	return err
}
