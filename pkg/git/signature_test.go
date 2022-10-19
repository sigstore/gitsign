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
	"crypto"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/gitsign/internal/signature"
)

type identity struct {
	signature.Identity
	base *fakeca.Identity
}

func (i *identity) Certificate() (*x509.Certificate, error) {
	return i.base.Certificate, nil
}

func (i *identity) CertificateChain() ([]*x509.Certificate, error) {
	return i.base.Chain(), nil
}

func (i *identity) Signer() (crypto.Signer, error) {
	return i.base.PrivateKey, nil
}

// TestSignVerify is a basic test to ensure that the Sign/Verify funcs can be
// used with each other. We're assuming that the actual signature format has
// been more thoroghly vetted in other packages (i.e. ietf-cms).
func TestSignVerify(t *testing.T) {
	ca := fakeca.New()
	id := &identity{
		base: ca,
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	data := []byte("tacocat")

	for _, detached := range []bool{true, false} {
		t.Run(fmt.Sprintf("detached(%t)", detached), func(t *testing.T) {
			sig, _, err := signature.Sign(id, data, signature.SignOptions{
				Detached: detached,
				Armor:    true,
				// Fake CA outputs self-signed certs, so we need to use -1 to make sure
				// the self-signed cert itself is included in the chain, otherwise
				// Verify cannot find a cert to use for verification.
				IncludeCerts: 0,
			})
			if err != nil {
				t.Fatalf("Sign() = %v", err)
			}

			// Deprecated, included for completeness
			t.Run("VerifySignature", func(t *testing.T) {
				if _, err := VerifySignature(data, sig, detached, roots, ca.ChainPool()); err != nil {
					t.Fatalf("Verify() = %v", err)
				}
			})

			t.Run("CertVerifier.Verify", func(t *testing.T) {
				cv, err := NewCertVerifier(WithRootPool(roots))
				if err != nil {
					t.Fatal(err)
				}
				ctx := context.Background()
				if _, err := cv.Verify(ctx, data, sig, detached); err != nil {
					t.Fatalf("Verify() = %v", err)
				}
			})
		})
	}
}
