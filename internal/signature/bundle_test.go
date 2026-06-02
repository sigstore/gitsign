// Copyright 2024 The Sigstore Authors
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

package signature

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	"github.com/sigstore/gitsign/internal/sigstore/compat"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/sign"
)

// fakeTransparency is a sign.Transparency that returns a fixed transparency log
// entry without contacting Rekor.
type fakeTransparency struct {
	entry *rekorpb.TransparencyLogEntry
}

func (f fakeTransparency) GetTransparencyLogEntry(_ context.Context, _ []byte, b *protobundle.Bundle) error {
	b.VerificationMaterial.TlogEntries = append(b.VerificationMaterial.TlogEntries, f.entry)
	return nil
}

// TestSignBundle exercises the sign -> bundle -> CMS path: sigstore-go produces
// the signature (over the CMS signed attributes) and bundle, which is converted
// to a CMS signature. The resulting CMS must embed the Rekor entry and carry a
// signature that verifies against the signing certificate.
func TestSignBundle(t *testing.T) {
	ctx := context.Background()
	cert, signer := selfSignedCert(t)
	body := []byte("tree deadbeef\n\nhello world")

	tle := fakeTLE()
	ident := testIdentity{cert: cert, signer: signer}
	resp, err := signBundle(ctx, body, ident, fakeTransparency{entry: tle}, SignOptions{})
	if err != nil {
		t.Fatalf("signBundle: %v", err)
	}

	if !resp.Cert.Equal(cert) {
		t.Error("response certificate does not match signing certificate")
	}
	if diff := cmp.Diff(rekoroid.ProtoToLogEntryAnon(tle), resp.LogEntry); diff != "" {
		t.Errorf("log entry mismatch (-want +got):\n%s", diff)
	}

	// The assembled CMS must parse, embed the Rekor entry, and its signature must
	// verify against the signed attributes with the signing certificate's key.
	sd, err := cms.ParseSignedData(resp.Signature)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := sd.Raw().SignerInfos[0]
	if !si.UnsignedAttrs.HasAttribute(rekoroid.OIDRekorTransparencyLogEntry) {
		t.Error("signature is missing the Rekor transparency log entry attribute")
	}

	msg, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], si.Signature) {
		t.Error("CMS signature does not verify against the signed attributes")
	}
}

// TestSignBundleThroughRekorClient exercises the full signing path through the
// real sign.Rekor transparency (getRekorV1TLE -> rekor tle.GenerateTransparencyLogEntry),
// rather than the fakeTransparency shortcut, by injecting a fake inner Rekor
// client that returns a canned, proof-bearing log entry. This covers the
// transparency-log-entry conversion code that real signing would hit, without
// OIDC or live infrastructure.
func TestSignBundleThroughRekorClient(t *testing.T) {
	ctx := context.Background()
	cert, signer := selfSignedCert(t)
	body := []byte("tree deadbeef\n\nhello world")

	raw, err := os.ReadFile("testdata/tlog.json")
	if err != nil {
		t.Fatal(err)
	}
	lea := new(models.LogEntryAnon)
	if err := json.Unmarshal(raw, lea); err != nil {
		t.Fatal(err)
	}

	tlog := sign.NewRekor(&sign.RekorOptions{
		BaseURL: "https://rekor.example.com",
		Client:  &validatingRekorClient{inner: fakeRekorClient{resp: logEntryResponse(*lea)}},
	})

	resp, err := signBundle(ctx, body, testIdentity{cert: cert, signer: signer}, tlog, SignOptions{})
	if err != nil {
		t.Fatalf("signBundle: %v", err)
	}
	if resp.LogEntry == nil {
		t.Error("expected a log entry in the response")
	}

	sd, err := cms.ParseSignedData(resp.Signature)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}
	si := sd.Raw().SignerInfos[0]
	if !si.UnsignedAttrs.HasAttribute(rekoroid.OIDRekorTransparencyLogEntry) {
		t.Error("signature is missing the Rekor transparency log entry attribute")
	}
	msg, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(msg)
	if !ecdsa.VerifyASN1(cert.PublicKey.(*ecdsa.PublicKey), digest[:], si.Signature) {
		t.Error("CMS signature does not verify against the signed attributes")
	}
}

// fakeTLE builds a structurally complete transparency log entry with dummy
// values, sufficient to round-trip through the compat conversion.
func fakeTLE() *rekorpb.TransparencyLogEntry {
	return &rekorpb.TransparencyLogEntry{
		LogIndex:       42,
		LogId:          &v1.LogId{KeyId: []byte("test-log-id")},
		KindVersion:    &rekorpb.KindVersion{Kind: "hashedrekord", Version: "0.0.1"},
		IntegratedTime: 1234567890,
		InclusionPromise: &rekorpb.InclusionPromise{
			SignedEntryTimestamp: []byte("test-signed-entry-timestamp"),
		},
		InclusionProof: &rekorpb.InclusionProof{
			LogIndex:   42,
			RootHash:   []byte("test-root-hash"),
			TreeSize:   100,
			Hashes:     [][]byte{[]byte("hash-1"), []byte("hash-2")},
			Checkpoint: &rekorpb.Checkpoint{Envelope: "test-checkpoint"},
		},
		CanonicalizedBody: []byte("test-body"),
	}
}

// fakeRekorClient is a sign.RekorClient returning a fixed response.
type fakeRekorClient struct {
	resp *entries.CreateLogEntryCreated
}

func (f fakeRekorClient) CreateLogEntry(_ *entries.CreateLogEntryParams, _ ...entries.ClientOption) (*entries.CreateLogEntryCreated, error) {
	return f.resp, nil
}

func logEntryResponse(entry models.LogEntryAnon) *entries.CreateLogEntryCreated {
	const uuid = "test-uuid"
	return &entries.CreateLogEntryCreated{ETag: uuid, Payload: models.LogEntry{uuid: entry}}
}

// TestValidatingRekorClient checks that the wrapper rejects a Rekor entry with
// no inclusion proof (which would otherwise panic in sigstore-go's conversion)
// while passing a complete one through.
func TestValidatingRekorClient(t *testing.T) {
	rootHash := "deadbeef"
	withProof := models.LogEntryAnon{Verification: &models.LogEntryAnonVerification{
		InclusionProof: &models.InclusionProof{RootHash: &rootHash},
	}}
	withoutProof := models.LogEntryAnon{}

	if _, err := (&validatingRekorClient{inner: fakeRekorClient{resp: logEntryResponse(withProof)}}).CreateLogEntry(nil); err != nil {
		t.Errorf("expected entry with inclusion proof to pass, got: %v", err)
	}
	if _, err := (&validatingRekorClient{inner: fakeRekorClient{resp: logEntryResponse(withoutProof)}}).CreateLogEntry(nil); err == nil {
		t.Error("expected entry without inclusion proof to be rejected")
	}
}

// testIdentity is a minimal signature.Identity backed by a cert + signer.
type testIdentity struct {
	cert   *x509.Certificate
	signer crypto.Signer
}

func (i testIdentity) Certificate() (*x509.Certificate, error) { return i.cert, nil }
func (i testIdentity) CertificateChain() ([]*x509.Certificate, error) {
	return []*x509.Certificate{i.cert}, nil
}
func (i testIdentity) Signer() (crypto.Signer, error) { return i.signer, nil }
func (i testIdentity) Keypair() (sign.Keypair, error) { return compat.NewKeypair(i.signer) }
func (i testIdentity) Delete() error                  { return nil }
func (i testIdentity) Close()                         {}

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
