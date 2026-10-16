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
	"crypto"
	"fmt"
	"time"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// EncodeCredential marshals the private key to PEM and wraps the credential
// parts for storage.
func EncodeCredential(priv crypto.PrivateKey, cert, chain []byte) (*api.Credential, error) {
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		return nil, fmt.Errorf("error marshalling private key: %w", err)
	}
	return &api.Credential{
		PrivateKey: privPEM,
		Cert:       cert,
		Chain:      chain,
	}, nil
}

// DecodeCredential unmarshals a stored credential back into its parts.
func DecodeCredential(cred *api.Credential) (crypto.PrivateKey, []byte, []byte, error) {
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(cred.PrivateKey, cryptoutils.SkipPassword)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error unmarshalling private key: %w", err)
	}
	return privateKey, cred.Cert, cred.Chain, nil
}

// NotAfter returns the expiry of the (first) PEM-encoded certificate.
func NotAfter(certPEM []byte) (time.Time, error) {
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(certPEM)
	if err != nil {
		return time.Time{}, fmt.Errorf("error parsing certificate: %w", err)
	}
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("no certificate found")
	}
	return certs[0].NotAfter, nil
}
