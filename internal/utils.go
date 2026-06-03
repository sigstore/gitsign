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
	"fmt"
	"net/url"
	"strings"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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

// SigningIdentity holds the certificate-identity and certificate-oidc-issuer
// values that were used to sign, so a user knows what to pass to the matching
// `gitsign verify` flags. These are read from the same certificate extensions
// that the verify path reads back.
type SigningIdentity struct {
	// Identity is the subject the signing certificate was issued to. For the
	// GitHub OIDC issuer this is the user's (possibly private) email address.
	// It corresponds to the `--certificate-identity` verify flag.
	Identity string
	// Issuer is the OIDC issuer URI recorded in the certificate. It corresponds
	// to the `--certificate-oidc-issuer` verify flag.
	Issuer string
}

// NewSigningIdentity extracts the certificate-identity and
// certificate-oidc-issuer from a signing certificate. The identity is taken
// from the certificate's subject alternative names (the same source the verify
// command prints), and the issuer is read from the Fulcio OIDC issuer
// extension. If a cert carries more than one SAN, they are joined so nothing is
// silently dropped.
func NewSigningIdentity(cert *x509.Certificate) SigningIdentity {
	identity := strings.Join(cryptoutils.GetSubjectAlternateNames(cert), ", ")
	ce := cosign.CertExtensions{Cert: cert}
	return SigningIdentity{
		Identity: identity,
		Issuer:   ce.GetIssuer(),
	}
}

// String formats the signing identity as guidance for the verify command,
// pointing the user at the exact flag values to pass.
func (s SigningIdentity) String() string {
	return fmt.Sprintf("gitsign: signed with identity %q (issuer %q)\ngitsign: to verify, run: gitsign verify --certificate-identity %q --certificate-oidc-issuer %q",
		s.Identity, s.Issuer, s.Identity, s.Issuer)
}

// StripURL returns the baseHost with the basePath given a full endpoint
func StripURL(endpoint string) (string, string) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", ""
	}
	return u.Host, u.Path
}
