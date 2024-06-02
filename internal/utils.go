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

package internal

import (
	"crypto/sha1" // #nosec G505
	"crypto/x509"
	"encoding/hex"
	"net/url"
)

// certHexFingerprint calculated the hex SHA1 fingerprint of a certificate.
func CertHexFingerprint(cert *x509.Certificate) string {
	return hex.EncodeToString(certFingerprint(cert))
}

// certFingerprint calculated the SHA1 fingerprint of a certificate.
func certFingerprint(cert *x509.Certificate) []byte {
	if len(cert.Raw) == 0 {
		return nil
	}

	fpr := sha1.Sum(cert.Raw) // nolint:gosec
	return fpr[:]
}

// StripUrl returns the baseHost with the basePath given a full endpoint
func StripUrl(endpoint string) (string, string) {
	u, _ := url.Parse(endpoint)
	return u.Host, u.Path
}
