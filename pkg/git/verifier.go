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
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

// Verifier verifies git commit signature data.
type Verifier interface {
	Verify(ctx context.Context, data, sig []byte, detached bool) (*x509.Certificate, error)
}

// CertVerifier is the default implementation of Verifier.
// It verifies git commits against a given CertPool. By default, the system
// CertPool + Fulcio roots are used for validation.
type CertVerifier struct {
	roots         *x509.CertPool
	intermediates *x509.CertPool
}

type CertVerifierOption func(*CertVerifier) error

func NewCertVerifier(opts ...CertVerifierOption) (*CertVerifier, error) {
	// Setup default cert pool - system pool + fulcio roots.
	pool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("error getting system cert pool: %w", err)
	}

	roots := pool.Clone()
	if err := fulcioroots.GetWithCertPool(roots); err != nil {
		return nil, fmt.Errorf("getting fulcio root certificate: %w", err)
	}

	intermediates := pool.Clone()
	if err := fulcioroots.GetIntermediatesWithCertPool(intermediates); err != nil {
		return nil, fmt.Errorf("getting fulcio intermediate certificates: %w", err)
	}

	v := &CertVerifier{
		roots:         roots,
		intermediates: intermediates,
	}

	for _, o := range opts {
		if err := o(v); err != nil {
			return nil, err
		}
	}

	return v, err
}

// WithRootPool sets the base CertPool for the verifier.
// NOTE: this option is order sensitive - setting this will
// wipe out any previous cert pool configuration.
func WithRootPool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.roots = pool
		return nil
	}
}

// WithRootPool sets the base CertPool for the verifier.
// NOTE: this option is order sensitive - setting this will
// wipe out any previous cert pool configuration.
func WithIntermediatePool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.intermediates = pool
		return nil
	}
}

// AddIntermediateCert adds the given cert to the root pool.
func AddRootCert(certs ...*x509.Certificate) CertVerifierOption {
	return func(v *CertVerifier) error {
		for _, c := range certs {
			v.roots.AddCert(c)
		}
		return nil
	}
}

// AddIntermediateCert adds the given cert to the intermediate pool.
func AddIntermediateCert(certs ...*x509.Certificate) CertVerifierOption {
	return func(v *CertVerifier) error {
		for _, c := range certs {
			v.intermediates.AddCert(c)
		}
		return nil
	}
}

// Verify verifies for a given Git data + signature pair.
//
// Data should be the Git data that was signed (i.e. everything in the commit
// besides the signature). Note: passing in the commit object itself will not
// work.
//
// Signatures should be CMS/PKCS7 formatted.
func (v *CertVerifier) Verify(ctx context.Context, data, sig []byte, detached bool) (*x509.Certificate, error) {
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
		Roots:         v.roots,
		Intermediates: v.intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: cert.NotBefore.Add(1 * time.Minute),
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
