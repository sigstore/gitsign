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

package fulcioroots

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestNew(t *testing.T) {
	ca := fakeca.New()
	certpath := filepath.Join(t.TempDir(), "cert.pem")
	b, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatalf("error marshalling cert: %v", err)
	}
	if err := os.WriteFile(certpath, b, 0600); err != nil {
		t.Fatalf("error writing cert: %v", err)
	}

	for _, tc := range []struct {
		name string
		opts []CertificateSource
		root []*x509.Certificate
	}{
		{
			name: "FromFile",
			opts: []CertificateSource{FromFile(certpath)},
			root: []*x509.Certificate{ca.Certificate},
		},
		{
			name: "Static",
			opts: []CertificateSource{Static(ca.Certificate)},
			root: []*x509.Certificate{ca.Certificate},
		},
		{
			name: "None",
		},
		// TODO: Figure out how to test TUF locally.
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := x509.NewCertPool()
			root, _, err := New(base, tc.opts...)
			if err != nil {
				t.Fatal(err)
			}
			if !root.Equal(certpool(tc.root...)) {
				t.Errorf("Root CertPool did not match, want: %+v", tc.root)
			}
		})
	}
}

func certpool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool
}
