package signature

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/github/smimesign/fakeca"
)

type identity struct {
	Identity
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
	id := &identity{
		base: fakeca.New(),
	}
	data := []byte("tacocat")

	sig, _, err := Sign(id, data, SignOptions{
		Detached: true,
		Armor:    true,
		// Fake CA outputs self-signed certs, so we need to use -1 to make sure
		// the self-signed cert itself is included in the chain, otherwise
		// Verify cannot find a cert to use for verification.
		IncludeCerts: -1,
	})
	if err != nil {
		t.Fatalf("Sign() = %v", err)
	}

	fmt.Println(id.base.Chain())
	if _, err := Verify(data, sig, true, x509.VerifyOptions{
		// Trust the fake CA
		Roots: id.base.ChainPool(),
	}); err != nil {
		t.Fatalf("Verify() = %v", err)
	}
}
