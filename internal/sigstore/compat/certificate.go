//
// Copyright 2026 The Sigstore Authors.
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

package compat

import (
	"context"
	"crypto/x509"

	"github.com/sigstore/sigstore-go/pkg/sign"
)

// CertificateProvider supplies sigstore-go with a gitsign identity's
// already-acquired Fulcio certificate, so sign.Bundle does not perform its own
// Fulcio exchange (preserving gitsign's identity flow and credential cache).
type CertificateProvider struct {
	cert *x509.Certificate
}

var _ sign.CertificateProvider = (*CertificateProvider)(nil)

// NewCertificateProvider returns a sign.CertificateProvider that always returns
// the given certificate.
func NewCertificateProvider(cert *x509.Certificate) *CertificateProvider {
	return &CertificateProvider{cert: cert}
}

func (p *CertificateProvider) GetCertificate(_ context.Context, _ sign.Keypair, _ *sign.CertificateProviderOptions) ([]byte, error) {
	return p.cert.Raw, nil
}
