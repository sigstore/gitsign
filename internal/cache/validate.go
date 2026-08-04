// Copyright 2026 The Sigstore Authors
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

package cache

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// ValidateCert checks that the PEM-encoded cert(s) chain to the given roots
// and intermediates, are valid for code signing, and won't expire in the next
// 30 seconds.
func ValidateCert(certPEM []byte, roots, intermediates *x509.CertPool) error {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPEM)
	if err != nil {
		return fmt.Errorf("error unmarshalling cert: %w", err)
	}
	// There should really only be 1 cert, but check them all anyway.
	for _, cert := range certs {
		if len(cert.UnhandledCriticalExtensions) > 0 {
			var unhandledExts []asn1.ObjectIdentifier
			for _, oid := range cert.UnhandledCriticalExtensions {
				if !oid.Equal(cryptoutils.SANOID) {
					unhandledExts = append(unhandledExts, oid)
				}
			}

			cert.UnhandledCriticalExtensions = unhandledExts
		}

		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			// We're going to be using this key immediately, so we don't need a long window.
			// Just make sure it's not about to expire.
			CurrentTime: time.Now().Add(30 * time.Second),
		}); err != nil {
			return fmt.Errorf("stored cert no longer valid: %w", err)
		}
	}
	return nil
}
