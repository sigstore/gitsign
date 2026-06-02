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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	"github.com/sigstore/sigstore-go/pkg/sign"
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

func (i *identity) Keypair() (sign.Keypair, error) {
	return compat.NewKeypair(i.base.PrivateKey)
}

// TestSignVerify is a basic test to ensure that the Sign/Verify funcs can be
// used with each other. We're assuming that the actual signature format has
// been more thoroghly vetted in other packages (i.e. ietf-cms).
func TestSignVerify(t *testing.T) {
	ctx := context.Background()
	ca := fakeca.New()
	id := &identity{
		base: ca,
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	data := []byte("tacocat")

	certpath := filepath.Join(t.TempDir(), "cert.pem")
	b, err := cryptoutils.MarshalCertificateToPEM(ca.Certificate)
	if err != nil {
		t.Fatalf("error marshalling cert: %v", err)
	}
	if err := os.WriteFile(certpath, b, 0600); err != nil {
		t.Fatalf("error writing cert: %v", err)
	}

	for _, detached := range []bool{true, false} {
		t.Run(fmt.Sprintf("detached(%t)", detached), func(t *testing.T) {
			resp, err := signature.Sign(ctx, id, data, signature.SignOptions{
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
				if _, err := VerifySignature(data, resp.Signature, detached, roots, ca.ChainPool()); err != nil {
					t.Fatalf("Verify() = %v", err)
				}
			})

			t.Run("CertVerifier.Verify", func(t *testing.T) {
				cv, err := NewCertVerifier(WithRootPool(roots))
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cv.Verify(ctx, data, resp.Signature, detached); err != nil {
					t.Fatalf("Verify() = %v", err)
				}
			})
		})
	}
}

// TestVerifyReturnsSignerCert ensures that Verify returns the certificate that
// actually authenticated the signature (resolved via SignerInfo) rather than
// whatever certificate happens to be at position 0 in the PKCS7 cert bag. An
// attacker who controls the SignedData can put a decoy cert at position 0
// while signing with a different one; the caller must not be handed back the
// decoy. See CVE-2026-39984 for the equivalent issue in timestamp-authority.
func TestVerifyReturnsSignerCert(t *testing.T) {
	ctx := context.Background()
	ca := fakeca.New(fakeca.IsCA)
	// Issue the decoy first so it gets the lower serial — the ASN.1 SET
	// encoding of the PKCS7 cert bag sorts by canonical DER, and within this
	// fake CA the lower-serial cert lands at position 0 after a roundtrip.
	decoy := ca.Issue()
	signer := ca.Issue()
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	data := []byte("tacocat")

	for _, detached := range []bool{true, false} {
		t.Run(fmt.Sprintf("detached(%t)", detached), func(t *testing.T) {
			sd, err := cms.NewSignedData(data)
			if err != nil {
				t.Fatalf("NewSignedData() = %v", err)
			}
			if err := sd.Sign([]*x509.Certificate{signer.Certificate}, signer.PrivateKey); err != nil {
				t.Fatalf("Sign() = %v", err)
			}
			// Replace the cert bag with [decoy, signer] — the decoy is what an
			// attacker would inject as certs[0] to confuse callers.
			if err := sd.SetCertificates([]*x509.Certificate{decoy.Certificate, signer.Certificate}); err != nil {
				t.Fatalf("SetCertificates() = %v", err)
			}
			if detached {
				sd.Detached()
			}
			der, err := sd.ToDER()
			if err != nil {
				t.Fatalf("ToDER() = %v", err)
			}

			// Sanity check: confirm the attack setup landed the decoy at certs[0].
			// If this ever stops being true (e.g. ASN.1 SET sorting changes), the
			// test is no longer exercising the vulnerability and needs updating.
			parsed, err := cms.ParseSignedData(der)
			if err != nil {
				t.Fatalf("ParseSignedData() = %v", err)
			}
			certs, err := parsed.GetCertificates()
			if err != nil {
				t.Fatalf("GetCertificates() = %v", err)
			}
			if !certs[0].Equal(decoy.Certificate) {
				t.Fatalf("attack setup failed: certs[0] is not the decoy")
			}

			cv, err := NewCertVerifier(WithRootPool(roots))
			if err != nil {
				t.Fatal(err)
			}
			got, err := cv.Verify(ctx, data, der, detached)
			if err != nil {
				t.Fatalf("Verify() = %v", err)
			}
			if got.Equal(decoy.Certificate) {
				t.Errorf("Verify() returned the decoy certificate; signer cert authentication was bypassed")
			}
			if !got.Equal(signer.Certificate) {
				t.Errorf("Verify() returned cert with serial %v, want signer serial %v",
					got.SerialNumber, signer.Certificate.SerialNumber)
			}
		})
	}
}

// TestVerifyMultiSignerDifferentWindows ensures Verify succeeds for a PKCS7
// containing multiple SignerInfos whose certs have non-overlapping validity
// windows. With a single shared CurrentTime, one of the chain verifications
// would always fail; the internal verifier must derive a per-cert time so
// that each SignerInfo is checked against a time within its own window.
func TestVerifyMultiSignerDifferentWindows(t *testing.T) {
	ctx := context.Background()
	ca := fakeca.New(fakeca.IsCA)

	// Issue two signers with deliberately non-overlapping validity windows.
	now := time.Now()
	oldSigner := ca.Issue(
		fakeca.NotBefore(now.Add(-48*time.Hour)),
		fakeca.NotAfter(now.Add(-24*time.Hour)),
	)
	newSigner := ca.Issue(
		fakeca.NotBefore(now.Add(24*time.Hour)),
		fakeca.NotAfter(now.Add(48*time.Hour)),
	)
	roots := x509.NewCertPool()
	roots.AddCert(ca.Certificate)
	data := []byte("tacocat")

	sd, err := cms.NewSignedData(data)
	if err != nil {
		t.Fatalf("NewSignedData() = %v", err)
	}
	if err := sd.Sign([]*x509.Certificate{oldSigner.Certificate}, oldSigner.PrivateKey); err != nil {
		t.Fatalf("Sign() old = %v", err)
	}
	if err := sd.Sign([]*x509.Certificate{newSigner.Certificate}, newSigner.PrivateKey); err != nil {
		t.Fatalf("Sign() new = %v", err)
	}
	der, err := sd.ToDER()
	if err != nil {
		t.Fatalf("ToDER() = %v", err)
	}

	cv, err := NewCertVerifier(WithRootPool(roots))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cv.Verify(ctx, data, der, false); err != nil {
		t.Fatalf("Verify() = %v; want success despite non-overlapping cert windows", err)
	}
}

// TestVerifyNoCerts ensures that Verify returns an error (rather than panicking
// on an out-of-bounds index) when the parsed signature contains no
// certificates.
func TestVerifyNoCerts(t *testing.T) {
	ctx := context.Background()
	data := []byte("tacocat")

	ca := fakeca.New()
	sd, err := cms.NewSignedData(data)
	if err != nil {
		t.Fatalf("NewSignedData() = %v", err)
	}
	if err := sd.Sign([]*x509.Certificate{ca.Certificate}, ca.PrivateKey); err != nil {
		t.Fatalf("Sign() = %v", err)
	}
	// Strip the certificates so GetCertificates returns an empty slice.
	if err := sd.SetCertificates(nil); err != nil {
		t.Fatalf("SetCertificates() = %v", err)
	}
	der, err := sd.ToDER()
	if err != nil {
		t.Fatalf("ToDER() = %v", err)
	}

	cv, err := NewCertVerifier(WithRootPool(x509.NewCertPool()))
	if err != nil {
		t.Fatal(err)
	}

	for _, detached := range []bool{true, false} {
		t.Run(fmt.Sprintf("detached(%t)", detached), func(t *testing.T) {
			cert, err := cv.Verify(ctx, data, der, detached)
			if err == nil {
				t.Fatalf("Verify() expected error, got cert %v", cert)
			}
			if !strings.Contains(err.Error(), "no certificates") {
				t.Errorf("Verify() error = %v, want error containing %q", err, "no certificates")
			}
			if cert != nil {
				t.Errorf("Verify() cert = %v, want nil", cert)
			}
		})
	}
}
