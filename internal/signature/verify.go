//
// Copyright 2022 The Sigstore Authors.
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
	"crypto/x509"
	"encoding/pem"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// Verify verifies a signature for a given identity.
//
// WARNING: this function doesn't do any revocation checking.
func Verify(body, sig []byte, detached bool, opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(sig); blk != nil {
		der = blk.Bytes
	} else {
		der = sig
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse signature")
	}

	if detached {
		return sd.VerifyDetached(body, opts)
	} else {
		return sd.Verify(opts)
	}
}
