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

package signature

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	cms "github.com/github/smimesign/ietf-cms"
)

type SignOptions struct {
	// Make a detached signature
	Detached bool
	// URL of RFC3161 timestamp authority to use for timestamping
	TimestampAuthority string
	// Create ascii armored output
	Armor bool
	// IncludeCerts specifies what certs to include in the resulting signature.
	// -3 is the same as -2, but ommits issuer when cert has Authority Information Access extension.
	// -2 includes all certs except root.
	// -1 includes all certs.
	// 0 includes no certs.
	// 1 includes leaf cert.
	// >1 includes n from the leaf.
	IncludeCerts int
}

// Identity is a copy of smimesign.Identity to allow for compatibility without
// needing a dependency on the whole package. This can be removed once
// https://github.com/github/smimesign/pull/108 is merged.
type Identity interface {
	// Certificate gets the identity's certificate.
	Certificate() (*x509.Certificate, error)
	// CertificateChain attempts to get the identity's full certificate chain.
	CertificateChain() ([]*x509.Certificate, error)
	// Signer gets a crypto.Signer that uses the identity's private key.
	Signer() (crypto.Signer, error)
	// Delete deletes this identity from the system.
	Delete() error
	// Close any manually managed memory held by the Identity.
	Close()
}

// Sign signs a given payload for the given identity.
// The resulting signature and cert used is returned.
func Sign(ident Identity, body []byte, opts SignOptions) ([]byte, *x509.Certificate, error) {
	cert, err := ident.Certificate()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get idenity certificate: %w", err)
	}
	signer, err := ident.Signer()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get idenity signer: %w", err)
	}

	sd, err := cms.NewSignedData(body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create signed data: %w", err)
	}

	if err := sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}
	if opts.Detached {
		sd.Detached()
	}

	if len(opts.TimestampAuthority) > 0 {
		if err = sd.AddTimestamps(opts.TimestampAuthority); err != nil {
			return nil, nil, fmt.Errorf("failed to add timestamp: %w", err)
		}
	}

	chain, err := ident.CertificateChain()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get identity certificate chain: %w", err)
	}
	// TODO: look into adding back support for opts.IncludeCerts here.
	// This was removed due to unstable ordering in the cert chain when
	// intermediates were included.
	if chain, err = certsForSignature(chain, 1); err != nil {
		return nil, nil, fmt.Errorf("failed to extract certificates from chain: %w", err)
	}
	if err := sd.SetCertificates(chain); err != nil {
		return nil, nil, fmt.Errorf("failed to set certificates: %w", err)
	}

	der, err := sd.ToDER()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize signature: %w", err)
	}

	if opts.Armor {
		return pem.EncodeToMemory(&pem.Block{
			Type:  "SIGNED MESSAGE",
			Bytes: der,
		}), cert, nil
	}

	return der, cert, nil
}

// certsForSignature determines which certificates to include in the signature
// based on the --include-certs option specified by the user.
func certsForSignature(chain []*x509.Certificate, include int) ([]*x509.Certificate, error) { // nolint:unparam
	if include < -3 {
		include = -2 // default
	}
	if include > len(chain) {
		include = len(chain)
	}

	switch include {
	case -3:
		for i := len(chain) - 1; i > 0; i-- {
			issuer, cert := chain[i], chain[i-1]

			// remove issuer when cert has AIA extension
			if bytes.Equal(issuer.RawSubject, cert.RawIssuer) && len(cert.IssuingCertificateURL) > 0 {
				chain = chain[0:i]
			}
		}
		return chainWithoutRoot(chain), nil
	case -2:
		return chainWithoutRoot(chain), nil
	case -1:
		return chain, nil
	default:
		return chain[0:include], nil
	}
}

// Returns the provided chain, having removed the root certificate, if present.
// This includes removing the cert itself if the chain is a single self-signed
// cert.
func chainWithoutRoot(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return chain
	}

	lastIdx := len(chain) - 1
	last := chain[lastIdx]

	if bytes.Equal(last.RawIssuer, last.RawSubject) {
		return chain[0:lastIdx]
	}

	return chain
}
