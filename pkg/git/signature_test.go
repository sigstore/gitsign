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
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
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
	initFulcioRoots(t, ca.Certificate)

	id := &identity{
		base: ca,
	}
	data := []byte("tacocat")

	for _, detached := range []bool{true, false} {
		t.Run(fmt.Sprintf("detached(%t)", detached), func(t *testing.T) {
			sig, _, err := signature.Sign(id, data, signature.SignOptions{
				Detached: detached,
				Armor:    true,
				// Fake CA outputs self-signed certs, so we need to use -1 to make sure
				// the self-signed cert itself is included in the chain, otherwise
				// Verify cannot find a cert to use for verification.
				IncludeCerts: -1,
			})
			if err != nil {
				t.Fatalf("Sign() = %v", err)
			}
			if _, err := VerifySignature(data, sig, detached); err != nil {
				t.Fatalf("Verify() = %v", err)
			}
		})
	}
}

func initFulcioRoots(t *testing.T, cert *x509.Certificate) {
	t.Helper()

	pem, _ := cryptoutils.MarshalCertificateToPEM(cert)
	tmp, err := os.CreateTemp(t.TempDir(), "fulcio_root_*.cert")
	if err != nil {
		t.Fatalf("failed to create temp cert file: %v", err)
	}
	defer tmp.Close()
	if _, err := tmp.Write(pem); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	t.Setenv("SIGSTORE_ROOT_FILE", tmp.Name())

	// Call fulcioroots to set up the root init.
	_ = fulcioroots.Get()
}
