package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/github/smimesign/ietf-cms/oid"
)

// TestAddSignerInfoWithSignature signs the SignedAttributes externally (the way
// the bundle signing path does) and confirms the resulting SignedData verifies
// with the fork's own Verify, for both attached and detached signatures.
func TestAddSignerInfoWithSignature(t *testing.T) {
	cert, signer := selfSignedCert(t)
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	opts := x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}}

	body := []byte("hello world")

	for _, detached := range []bool{false, true} {
		attrs, err := SignedAttributes(body, crypto.SHA256)
		if err != nil {
			t.Fatalf("SignedAttributes: %v", err)
		}
		sm, err := attrs.MarshaledForSigning()
		if err != nil {
			t.Fatal(err)
		}

		// Sign the marshaled attributes externally.
		digest := sha256.Sum256(sm)
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatal(err)
		}

		sd, err := NewSignedData(body)
		if err != nil {
			t.Fatal(err)
		}
		if err := sd.AddSignerInfoWithSignature(cert, crypto.SHA256, attrs, sig, nil); err != nil {
			t.Fatalf("AddSignerInfoWithSignature: %v", err)
		}

		var chains [][][]*x509.Certificate
		if detached {
			sd.Detached()
			chains, err = sd.VerifyDetached(body, opts, x509.VerifyOptions{})
		} else {
			chains, err = sd.Verify(opts, x509.VerifyOptions{})
		}
		if err != nil {
			t.Fatalf("verify (detached=%t): %v", detached, err)
		}
		if len(chains) == 0 {
			t.Errorf("verify (detached=%t): no verified chains", detached)
		}
	}
}

// TestSignedAttributes checks that SignedAttributes produces the three mandatory
// signed attributes (content-type, message-digest, signing-time) over the
// content.
func TestSignedAttributes(t *testing.T) {
	body := []byte("hello world")
	attrs, err := SignedAttributes(body, crypto.SHA256)
	if err != nil {
		t.Fatalf("SignedAttributes: %v", err)
	}

	for name, attrOID := range map[string]asn1.ObjectIdentifier{
		"content-type":   oid.AttributeContentType,
		"message-digest": oid.AttributeMessageDigest,
		"signing-time":   oid.AttributeSigningTime,
	} {
		if !attrs.HasAttribute(attrOID) {
			t.Errorf("missing %s attribute", name)
		}
	}

	// The message-digest attribute must be sha256(body).
	md, err := attrs.GetOnlyAttributeValueBytes(oid.AttributeMessageDigest)
	if err != nil {
		t.Fatalf("getting message-digest: %v", err)
	}
	var got []byte
	if _, err := asn1.Unmarshal(md.FullBytes, &got); err != nil {
		t.Fatalf("unmarshalling message-digest: %v", err)
	}
	want := sha256.Sum256(body)
	if !bytes.Equal(got, want[:]) {
		t.Error("message-digest does not match sha256(body)")
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
