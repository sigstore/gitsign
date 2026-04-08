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
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"os"

	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/sigstoreroot"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type CertificateSource func() ([]*x509.Certificate, error)

// New returns new CertPool(s) with certificates populated by provided CertificateSources.
func New(root *x509.CertPool, opts ...CertificateSource) (*x509.CertPool, *x509.CertPool, error) {
	var intermediate *x509.CertPool

	certs := []*x509.Certificate{}
	for _, fn := range opts {
		c, err := fn()
		if err != nil {
			return nil, nil, err
		}
		certs = append(certs, c...)
	}

	for _, cert := range certs {
		// root certificates are self-signed
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			root.AddCert(cert)
		} else {
			if intermediate == nil {
				intermediate = x509.NewCertPool()
			}
			intermediate.AddCert(cert)
		}
	}
	return root, intermediate, nil
}

func NewFromConfig(ctx context.Context, cfg *config.Config) (*x509.CertPool, *x509.CertPool, error) {
	src := []CertificateSource{FromTUF(ctx)}

	if cfg.FulcioRoot != "" {
		src = []CertificateSource{FromFile(cfg.FulcioRoot)}
	}

	return New(x509.NewCertPool(), src...)
}

// FromTUF loads Fulcio certificates from the sigstore-go TUF cache.
func FromTUF(_ context.Context) CertificateSource {
	return func() ([]*x509.Certificate, error) {
		trustedRoot, err := sigstoreroot.FetchTrustedRoot()
		if err != nil {
			return nil, fmt.Errorf("initializing tuf: %w", err)
		}
		certs, err := sigstoreroot.FulcioCertificates(trustedRoot)
		if err != nil {
			return nil, fmt.Errorf("initializing tuf: %w", err)
		}
		return certs, nil
	}
}

// FromTrustedRoot loads Fulcio certificates from a pre-fetched TrustedRoot.
func FromTrustedRoot(trustedRoot *root.TrustedRoot) CertificateSource {
	return func() ([]*x509.Certificate, error) {
		certs, err := sigstoreroot.FulcioCertificates(trustedRoot)
		if err != nil {
			return nil, fmt.Errorf("getting fulcio certificates from trusted root: %w", err)
		}
		return certs, nil
	}
}

// FromFile loads certs from a PEM file.
func FromFile(path string) CertificateSource {
	return func() ([]*x509.Certificate, error) {
		b, err := os.ReadFile(path) // nolint:gosec
		if err != nil {
			return nil, err
		}
		return cryptoutils.UnmarshalCertificatesFromPEM(b)
	}
}

// Static loads a static set of Certificates.
func Static(certs ...*x509.Certificate) CertificateSource {
	return func() ([]*x509.Certificate, error) {
		return certs, nil
	}
}
