package cms

import (
	"bytes"
	"crypto/x509"
	"errors"

	"github.com/github/smimesign/ietf-cms/protocol"
)

// Verify verifies the SingerInfos' signatures. Each signature's associated
// certificate is verified using the provided roots. UnsafeNoVerify may be
// specified to skip this verification. Nil may be provided to use system roots.
// The full chains for the certificates whose keys made the signatures are
// returned.
//
// WARNING: this function doesn't do any revocation checking.
func (sd *SignedData) Verify(opts x509.VerifyOptions, tsaOpts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	econtent, err := sd.psd.EncapContentInfo.EContentValue()
	if err != nil {
		return nil, err
	}
	if econtent == nil {
		return nil, errors.New("detached signature")
	}

	return sd.verify(econtent, opts, tsaOpts)
}

// VerifyDetached verifies the SingerInfos' detached signatures over the
// provided data message. Each signature's associated certificate is verified
// using the provided roots. UnsafeNoVerify may be specified to skip this
// verification. Nil may be provided to use system roots. The full chains for
// the certificates whose keys made the signatures are returned.
//
// WARNING: this function doesn't do any revocation checking.
func (sd *SignedData) VerifyDetached(message []byte, opts x509.VerifyOptions, tsaOpts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	if sd.psd.EncapContentInfo.EContent.Bytes != nil {
		return nil, errors.New("signature not detached")
	}
	return sd.verify(message, opts, tsaOpts)
}

func (sd *SignedData) verify(econtent []byte, opts x509.VerifyOptions, tsOpts x509.VerifyOptions) ([][][]*x509.Certificate, error) {
	if len(sd.psd.SignerInfos) == 0 {
		return nil, protocol.ASN1Error{Message: "no signatures found"}
	}

	certs, err := sd.psd.X509Certificates()
	if err != nil {
		return nil, err
	}

	if opts.Intermediates == nil {
		opts.Intermediates = x509.NewCertPool()
	}

	for _, cert := range certs {
		opts.Intermediates.AddCert(cert)
	}

	chains := make([][][]*x509.Certificate, 0, len(sd.psd.SignerInfos))

	for _, si := range sd.psd.SignerInfos {
		var signedMessage []byte

		// SignedAttrs is optional if EncapContentInfo eContentType isn't id-data.
		if si.SignedAttrs == nil {
			// SignedAttrs may only be absent if EncapContentInfo eContentType is
			// id-data.
			if !sd.psd.EncapContentInfo.IsTypeData() {
				return nil, protocol.ASN1Error{Message: "missing SignedAttrs"}
			}

			// If SignedAttrs is absent, the signature is over the original
			// encapsulated content itself.
			signedMessage = econtent
		} else {
			// If SignedAttrs is present, we validate the mandatory ContentType and
			// MessageDigest attributes.
			siContentType, err := si.GetContentTypeAttribute()
			if err != nil {
				return nil, err
			}
			if !siContentType.Equal(sd.psd.EncapContentInfo.EContentType) {
				return nil, protocol.ASN1Error{Message: "invalid SignerInfo ContentType attribute"}
			}

			// Calculate the digest over the actual message.
			hash, err := si.Hash()
			if err != nil {
				return nil, err
			}
			actualMessageDigest := hash.New()
			if _, err = actualMessageDigest.Write(econtent); err != nil {
				return nil, err
			}

			// Get the digest from the SignerInfo.
			messageDigestAttr, err := si.GetMessageDigestAttribute()
			if err != nil {
				return nil, err
			}

			// Make sure message digests match.
			if !bytes.Equal(messageDigestAttr, actualMessageDigest.Sum(nil)) {
				return nil, errors.New("invalid message digest")
			}

			// The signature is over the DER encoded signed attributes, minus the
			// leading class/tag/length bytes. This includes the digest of the
			// original message, so it is implicitly signed too.
			if signedMessage, err = si.SignedAttrs.MarshaledForVerification(); err != nil {
				return nil, err
			}
		}

		cert, err := si.FindCertificate(certs)
		if err != nil {
			return nil, err
		}

		algo := si.X509SignatureAlgorithm()
		if algo == x509.UnknownSignatureAlgorithm {
			return nil, protocol.ErrUnsupported
		}

		if err := cert.CheckSignature(algo, signedMessage, si.Signature); err != nil {
			return nil, err
		}

		// If the caller didn't specify the signature time, we'll use the verified
		// timestamp. If there's no timestamp we use the current time when checking
		// the cert validity window. This isn't perfect because the signature may
		// have been created before the cert's not-before date, but this is the best
		// we can do. We update a copy of opts because we are verifying multiple
		// signatures in a loop and only want the timestamp to affect this one.
		optsCopy := opts

		if hasTS, err := hasTimestamp(si); err != nil {
			return nil, err
		} else if hasTS {
			// Use provided verification options for timestamp verification also, but
			// explicitly ask for key-usage=timestamping.
			tsOpts.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping}

			tsti, err := getTimestamp(si, tsOpts)
			if err != nil {
				return nil, err
			}

			// This check is slightly redundant, given that the cert validity times
			// are checked by cert.Verify. We take the timestamp accuracy into account
			// here though, whereas cert.Verify will not.
			if !tsti.Before(cert.NotAfter) || !tsti.After(cert.NotBefore) {
				return nil, x509.CertificateInvalidError{Cert: cert, Reason: x509.Expired, Detail: "timestamp authority verification failed"}
			}

			if optsCopy.CurrentTime.IsZero() {
				optsCopy.CurrentTime = tsti.GenTime
			}
		}

		if chain, err := cert.Verify(optsCopy); err != nil {
			return nil, err
		} else {
			chains = append(chains, chain)
		}
	}

	// OK
	return chains, nil
}
