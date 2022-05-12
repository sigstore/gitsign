package signature

import (
	"crypto/x509"
	"encoding/pem"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/pkg/errors"
)

// Verify verifies a signature for a given identity.
//
// WARNING: this function doesn't do any revocation checking.
func Verify(body, sig []byte, detached bool, opts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(sig); blk != nil {
		der = blk.Bytes
	} else {
		der = sig
	}

	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse signature")
	}

	if detached {
		return sd.VerifyDetached(body, opts)
	} else {
		return sd.Verify(opts)
	}
}
