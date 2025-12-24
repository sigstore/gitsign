// Copyright 2023 The Sigstore Authors
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

package gitsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	certverifier "github.com/sigstore/gitsign/internal/cert"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestVerify(t *testing.T) {
	ctx := context.Background()

	// Generate cert
	cert, priv := generateCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "tacocat",
		},
		EmailAddresses: []string{"tacocat@example.com"},
		ExtraExtensions: []pkix.Extension{{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 1},
			Value: []byte("example.com"),
		}},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(5 * time.Minute),
	})

	// Git verifier
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	gv, err := git.NewCertVerifier(git.WithRootPool(roots))
	if err != nil {
		t.Fatalf("error creating git verifer: %v", err)
	}

	// Cert verifier
	cv := certverifier.NewCosignVerifier(&cosign.CheckOpts{
		RootCerts: roots,
		Identities: []cosign.Identity{{
			Issuer:  "example.com",
			Subject: "tacocat@example.com",
		}},
		IgnoreSCT:  true,
		IgnoreTlog: true,
	})

	// Rekor verifier - we don't have a good way to test this right now so mock it out.
	rekor := fakeRekor{}

	v := Verifier{
		git:   gv,
		cert:  cv,
		rekor: rekor,
	}

	data, sig := generateData(t, cert, priv)
	if _, err := v.Verify(ctx, data, sig, true); err != nil {
		t.Fatal(err)
	}
}

func generateCert(t *testing.T, tmpl *x509.Certificate) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("error generating private key: %v", err)
	}
	pub := &priv.PublicKey
	raw, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("error generating certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert, priv
}

func generateData(t *testing.T, cert *x509.Certificate, priv crypto.Signer) ([]byte, []byte) {
	t.Helper()
	ctx := context.Background()

	// Generate commit data
	commit := object.Commit{
		Message: "hello world!",
	}
	obj := memory.NewStorage().NewEncodedObject()
	if err := commit.Encode(obj); err != nil {
		t.Fatal(err)
	}
	reader, err := obj.Reader()
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("error reading git data: %v", err)
	}

	id := &identity{
		cert: cert,
		priv: priv,
	}
	resp, err := signature.Sign(ctx, id, data, signature.SignOptions{
		Detached: true,
		Armor:    true,
		// Fake CA outputs self-signed certs, so we need to use -1 to make sure
		// the self-signed cert itself is included in the chain, otherwise
		// Verify cannot find a cert to use for verification.
		IncludeCerts: 0,
	})
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	return data, resp.Signature
}

type fakeRekor struct{}

func (fakeRekor) Verify(_ context.Context, _ string, _ *x509.Certificate) (*models.LogEntryAnon, error) {
	return nil, nil
}

func (fakeRekor) VerifyInclusion(_ context.Context, _ []byte, _ *x509.Certificate) (*models.LogEntryAnon, error) {
	return nil, nil
}

type identity struct {
	signature.Identity
	cert *x509.Certificate
	priv crypto.Signer
}

func (i *identity) Certificate() (*x509.Certificate, error) {
	return i.cert, nil
}

func (i *identity) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}

func (i *identity) Signer() (crypto.Signer, error) {
	return i.priv, nil
}
