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

	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
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
	tsa           *x509.CertPool
}

type CertVerifierOption func(*CertVerifier) error

func NewCertVerifier(opts ...CertVerifierOption) (*CertVerifier, error) {
	v := &CertVerifier{}

	for _, o := range opts {
		if err := o(v); err != nil {
			return nil, err
		}
	}

	// Use empty pool if not set - this makes it so that we don't fallback
	// to the system pool.
	if v.roots == nil {
		v.roots = x509.NewCertPool()
	}

	return v, nil
}

// WithRootPool sets the base CertPool for the verifier.
func WithRootPool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.roots = pool
		return nil
	}
}

// WithIntermediatePool sets the base intermediate CertPool for the verifier.
func WithIntermediatePool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.intermediates = pool
		return nil
	}
}

// WithIntermediatePool sets the base intermediate CertPool for the verifier.
func WithTimestampCertPool(pool *x509.CertPool) CertVerifierOption {
	return func(v *CertVerifier) error {
		v.tsa = pool
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

	tsaOpts := x509.VerifyOptions{
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if v.tsa != nil {
		tsaOpts.Roots = v.tsa
	}

	if detached {
		if _, err := sd.VerifyDetached(data, opts, tsaOpts); err != nil {
			return nil, fmt.Errorf("failed to verify detached signature: %w", err)
		}
	} else {
		if _, err := sd.Verify(opts, tsaOpts); err != nil {
			return nil, fmt.Errorf("failed to verify attached signature: %w", err)
		}
	}

	return cert, nil
}
