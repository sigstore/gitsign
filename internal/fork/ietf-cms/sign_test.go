package cms

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"os"
	"os/exec"
	"testing"
	"time"
)

var (
	examplePrivateKey = leaf.PrivateKey
	exampleChain      = leaf.Chain()
)

func TestSign(t *testing.T) {
	data := []byte("hello, world!")

	ci, err := Sign(data, leaf.Chain(), leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd2.Verify(rootOpts, x509.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}

	// test that we're including whole chain in sd
	sdCerts, err := sd2.psd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, chainCert := range leaf.Chain() {
		var found bool
		for _, sdCert := range sdCerts {
			if sdCert.Equal(chainCert) {
				if found == true {
					t.Fatal("duplicate cert in sd")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing cert in sd")
		}
	}

	// check that we're including signing time attribute
	st, err := sd2.psd.SignerInfos[0].GetSigningTimeAttribute()
	delta := 5 * time.Second
	if st.After(time.Now().Add(delta)) || st.Before(time.Now().Add(-1 * delta)) {
		t.Fatal("expected SigningTime to be now. Difference was", st.Sub(time.Now()))
	}
}

func TestSignDetached(t *testing.T) {
	data := []byte("hello, world!")

	ci, err := SignDetached(data, leaf.Chain(), leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	sd2, err := ParseSignedData(ci)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = sd2.VerifyDetached(data, rootOpts, x509.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}

	// test that we're including whole chain in sd
	sdCerts, err := sd2.psd.X509Certificates()
	if err != nil {
		t.Fatal(err)
	}
	for _, chainCert := range leaf.Chain() {
		var found bool
		for _, sdCert := range sdCerts {
			if sdCert.Equal(chainCert) {
				if found == true {
					t.Fatal("duplicate cert in sd")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("missing cert in sd")
		}
	}

	// check that we're including signing time attribute
	st, err := sd2.psd.SignerInfos[0].GetSigningTimeAttribute()
	delta := 5 * time.Second
	if st.After(time.Now().Add(delta)) || st.Before(time.Now().Add(-1 * delta)) {
		t.Fatal("expected SigningTime to be now. Difference was", st.Sub(time.Now()))
	}
}

func TestSignDetachedWithOpenSSL(t *testing.T) {
	// Do not require this test to pass if openssl is not in the path
	opensslPath, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("could not find openssl in path")
	}

	content := []byte("hello, world!")

	signatureDER, err := SignDetached(content, leaf.Chain(), leaf.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}

	signatureFile, err := ioutil.TempFile("", "TestSignatureOpenSSL_signatureFile_*")
	if err != nil {
		t.Fatal(err)
	}

	_, err = signatureFile.Write(signatureDER)
	if err != nil {
		t.Fatal(err)
	}

	signatureFile.Close()

	// write content to a temp file
	contentFile, err := ioutil.TempFile("", "TestSignatureOpenSSL_contentFile_*")
	if err != nil {
		t.Fatal(err)
	}

	_, err = contentFile.Write(content)
	if err != nil {
		t.Fatal(err)
	}

	contentFile.Close()

	// write CA cert to a temp file
	certsFile, err := ioutil.TempFile("", "TestSignatureOpenSSL_certsFile_*")
	if err != nil {
		t.Fatal(err)
	}

	for _, cert := range leaf.Chain() {
		// write leaf as PEM
		certBlock := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}

		certPEM := pem.EncodeToMemory(certBlock)

		_, err = certsFile.Write(certPEM)
		if err != nil {
			t.Fatal(err)
		}
	}

	certsFile.Close()

	cmd := exec.Command(opensslPath, "cms", "-verify",
		"-content", contentFile.Name(), "-binary",
		"-in", signatureFile.Name(), "-inform", "DER",
		"-CAfile", certsFile.Name())

	_, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}

	//
	// Remove temporary files if test was successful.
	// Intentionally leave the temp files if test fails.
	//
	os.Remove(contentFile.Name())
	os.Remove(signatureFile.Name())
	os.Remove(certsFile.Name())
}

func TestSignRemoveHeaders(t *testing.T) {
	sd, err := NewSignedData([]byte("hello, world"))
	if err != nil {
		t.Fatal(err)
	}
	if err = sd.Sign(leaf.Chain(), leaf.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err = sd.SetCertificates([]*x509.Certificate{}); err != nil {
		t.Fatal(err)
	}
	if certs, err := sd.GetCertificates(); err != nil {
		t.Fatal(err)
	} else if len(certs) != 0 {
		t.Fatal("expected 0 certs")
	}

	der, err := sd.ToDER()
	if err != nil {
		t.Fatal(err)
	}
	if sd, err = ParseSignedData(der); err != nil {
		t.Fatal(err)
	}
	sd.SetCertificates([]*x509.Certificate{leaf.Certificate})

	opts := x509.VerifyOptions{
		Roots:         root.ChainPool(),
		Intermediates: leaf.ChainPool(),
	}

	if _, err := sd.Verify(opts, x509.VerifyOptions{}); err != nil {
		t.Fatal(err)
	}
}
