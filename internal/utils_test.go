// Copyright 2024 The Sigstore Authors
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

package internal

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"net/url"
	"strings"
	"testing"
)

func TestStripUrl(t *testing.T) {
	endpoint := "https://private.rekor.com/rekor"
	host, basePath := StripURL(endpoint)
	if host != "private.rekor.com" || basePath != "/rekor" {
		t.Fatalf("Host and/or BasePath are not correct")
	}
}

// oidcIssuerOID is the Fulcio certificate extension that records the OIDC
// issuer (1.3.6.1.4.1.57264.1.1).
var oidcIssuerOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1}

func issuerExtension(issuer string) pkix.Extension {
	return pkix.Extension{Id: oidcIssuerOID, Value: []byte(issuer)}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parsing %q: %v", raw, err)
	}
	return u
}

func TestNewSigningIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		cert         *x509.Certificate
		wantIdentity string
		wantIssuer   string
	}{
		{
			name: "email SAN with GitHub issuer",
			cert: &x509.Certificate{
				EmailAddresses: []string{"foo@example.com"},
				Extensions:     []pkix.Extension{issuerExtension("https://github.com/login/oauth")},
			},
			wantIdentity: "foo@example.com",
			wantIssuer:   "https://github.com/login/oauth",
		},
		{
			name: "uri SAN with issuer",
			cert: &x509.Certificate{
				URIs:       []*url.URL{mustParseURL(t, "https://github.com/foo/bar/.github/workflows/ci.yml@refs/heads/main")},
				Extensions: []pkix.Extension{issuerExtension("https://token.actions.githubusercontent.com")},
			},
			wantIdentity: "https://github.com/foo/bar/.github/workflows/ci.yml@refs/heads/main",
			wantIssuer:   "https://token.actions.githubusercontent.com",
		},
		{
			name: "multiple SANs are joined, not dropped",
			cert: &x509.Certificate{
				EmailAddresses: []string{"a@example.com", "b@example.com"},
				Extensions:     []pkix.Extension{issuerExtension("https://accounts.google.com")},
			},
			wantIdentity: "a@example.com, b@example.com",
			wantIssuer:   "https://accounts.google.com",
		},
		{
			name:         "no SAN, no issuer extension",
			cert:         &x509.Certificate{},
			wantIdentity: "",
			wantIssuer:   "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := NewSigningIdentity(tc.cert)
			if got.Identity != tc.wantIdentity {
				t.Errorf("Identity = %q, want %q", got.Identity, tc.wantIdentity)
			}
			if got.Issuer != tc.wantIssuer {
				t.Errorf("Issuer = %q, want %q", got.Issuer, tc.wantIssuer)
			}
		})
	}
}

func TestSigningIdentityString(t *testing.T) {
	s := SigningIdentity{
		Identity: "foo@example.com",
		Issuer:   "https://github.com/login/oauth",
	}
	out := s.String()

	// The output should surface both the identity and the issuer.
	for _, want := range []string{
		"foo@example.com",
		"https://github.com/login/oauth",
		"signed with identity",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("String() output missing %q\ngot: %s", want, out)
		}
	}
}
