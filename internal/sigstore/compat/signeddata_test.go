//
// Copyright 2024 The Sigstore Authors.
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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// TestBundleToSignedData proves that assembling a CMS from a bundle produces
// byte-for-byte the same output as the ietf-cms fork's own signer, given the
// same signed attributes, signature, and certificate. This anchors the
// "sign -> bundle -> CMS" path to the format the legacy path produces.
func TestBundleToSignedData(t *testing.T) {
	cert, signer := selfSignedCert(t)
	body := []byte("tree deadbeef\n\nhello world")

	for _, detached := range []bool{false, true} {
		// Reference: let the fork build and sign the CMS.
		sd, err := cms.NewSignedData(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
			t.Fatal(err)
		}
		if detached {
			sd.Detached()
		}
		if err := sd.SetCertificates([]*x509.Certificate{cert}); err != nil {
			t.Fatal(err)
		}
		want, err := sd.ToDER()
		if err != nil {
			t.Fatal(err)
		}

		// Reuse the reference signature + signed attributes, packaged as a bundle,
		// and assemble the CMS from scratch.
		si := sd.Raw().SignerInfos[0]
		b := &protobundle.Bundle{
			MediaType: MediaType,
			Content: &protobundle.Bundle_MessageSignature{
				MessageSignature: &protocommon.MessageSignature{
					Signature: si.Signature,
				},
			},
			VerificationMaterial: &protobundle.VerificationMaterial{
				Content: &protobundle.VerificationMaterial_Certificate{
					Certificate: &protocommon.X509Certificate{RawBytes: cert.Raw},
				},
			},
		}

		assembled, err := BundleToSignedData(body, si.SignedAttrs, b, detached)
		if err != nil {
			t.Fatalf("BundleToSignedData(detached=%t): %v", detached, err)
		}
		got, err := assembled.ToDER()
		if err != nil {
			t.Fatalf("ToDER(detached=%t): %v", detached, err)
		}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("assembled CMS differs from fork output (detached=%t) (-want +got):\n%s", detached, diff)
		}
	}
}

// TestBundleToSignedDataWithTlog proves that the tlog-embedding path of
// BundleToSignedData reproduces the exact CMS the legacy path produces - a
// fork-signed SignedData with the Rekor entry appended via oid.ToAttributes.
func TestBundleToSignedDataWithTlog(t *testing.T) {
	ctx := context.Background()
	cert, signer := selfSignedCert(t)
	body := []byte("tree deadbeef\n\nhello world")

	lea := new(models.LogEntryAnon)
	if err := json.Unmarshal(readfile(t, "testdata/tlog.json"), lea); err != nil {
		t.Fatal(err)
	}

	// Reference: fork-signed CMS with the Rekor entry appended as the legacy
	// signing path does (oid.ToAttributes).
	sd, err := cms.NewSignedData(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := sd.Sign([]*x509.Certificate{cert}, signer); err != nil {
		t.Fatal(err)
	}
	tlogAttrs, err := rekoroid.ToAttributes(lea)
	if err != nil {
		t.Fatal(err)
	}
	si := sd.Raw().SignerInfos[0]
	si.UnsignedAttrs = append(si.UnsignedAttrs, tlogAttrs...)
	sd.Raw().SignerInfos[0] = si
	want, err := sd.ToDER()
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip the signed data through a bundle and reassemble it.
	sb, err := SignerInfoToBundle(ctx, sd, sd.Raw().SignerInfos[0])
	if err != nil {
		t.Fatal(err)
	}
	assembled, err := BundleToSignedData(body, si.SignedAttrs, sb.Bundle, false)
	if err != nil {
		t.Fatalf("BundleToSignedData: %v", err)
	}
	got, err := assembled.ToDER()
	if err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("assembled CMS with tlog differs from legacy output (-want +got):\n%s", diff)
	}
}

func selfSignedCert(t *testing.T) (*x509.Certificate, crypto.Signer) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, priv
}
