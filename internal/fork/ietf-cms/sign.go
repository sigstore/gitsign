package cms

import (
	"crypto"
	"crypto/x509"
)

// Sign creates a CMS SignedData from the content and signs it with signer. At
// minimum, chain must contain the leaf certificate associated with the signer.
// Any additional intermediates will also be added to the SignedData. The DER
// encoded CMS message is returned.
func Sign(data []byte, chain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Sign(chain, signer); err != nil {
		return nil, err
	}

	return sd.ToDER()
}

// SignDetached creates a detached CMS SignedData from the content and signs it
// with signer. At minimum, chain must contain the leaf certificate associated
// with the signer. Any additional intermediates will also be added to the
// SignedData. The DER encoded CMS message is returned.
func SignDetached(data []byte, chain []*x509.Certificate, signer crypto.Signer) ([]byte, error) {
	sd, err := NewSignedData(data)
	if err != nil {
		return nil, err
	}

	if err = sd.Sign(chain, signer); err != nil {
		return nil, err
	}

	sd.Detached()

	return sd.ToDER()
}

// Sign adds a signature to the SignedData.At minimum, chain must contain the
// leaf certificate associated with the signer. Any additional intermediates
// will also be added to the SignedData.
func (sd *SignedData) Sign(chain []*x509.Certificate, signer crypto.Signer) error {
	return sd.psd.AddSignerInfo(chain, signer)
}
