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

package git

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cms "github.com/github/smimesign/ietf-cms"
)

// VerifySignature verifies for a given Git data + signature pair.
//
// Data should be the Git data that was signed (i.e. everything in the commit
// besides the signature). Note: passing in the commit object itself will not
// work.
//
// Signatures should be CMS/PKCS7 formatted.
func VerifySignature(data, sig []byte, detached bool, rootCerts, intermediates *x509.CertPool) (*x509.Certificate, error) {
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
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Generate verification options.
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("error getting signature certs: %w", err)
	}
	cert := certs[0]

	opts := x509.VerifyOptions{
		Roots:         rootCerts,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: cert.NotBefore,
	}

	if detached {
		if _, err := sd.VerifyDetached(data, opts); err != nil {
			return nil, fmt.Errorf("failed to verify detached signature: %w", err)
		}
	} else {
		if _, err := sd.Verify(opts); err != nil {
			return nil, fmt.Errorf("failed to verify attached signature: %w", err)
		}
	}

	return cert, nil
}
