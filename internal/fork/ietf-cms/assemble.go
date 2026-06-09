package cms

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"sort"
	"time"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
)

// SignedAttributes builds the standard CMS signed attributes (content-type
// id-data, message-digest over econtent using hash, and signing-time) in the
// canonical SET OF order, matching the attributes the smimesign protocol's
// AddSignerInfo builds internally. It lets a caller obtain the to-be-signed
// bytes (via the returned Attributes' MarshaledForSigning) and delegate signing
// externally, then reassemble the SignedData with AddSignerInfoWithSignature.
func SignedAttributes(econtent []byte, hash crypto.Hash) (protocol.Attributes, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("unavailable hash function %v", hash)
	}

	eci, err := protocol.NewDataEncapsulatedContentInfo(econtent)
	if err != nil {
		return nil, err
	}

	md := hash.New()
	if _, err := md.Write(econtent); err != nil {
		return nil, err
	}

	stAttr, err := protocol.NewAttribute(oid.AttributeSigningTime, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	mdAttr, err := protocol.NewAttribute(oid.AttributeMessageDigest, md.Sum(nil))
	if err != nil {
		return nil, err
	}
	ctAttr, err := protocol.NewAttribute(oid.AttributeContentType, eci.EContentType)
	if err != nil {
		return nil, err
	}

	return sortAttributes(stAttr, mdAttr, ctAttr), nil
}

// AddSignerInfoWithSignature assembles a SignerInfo for cert over the given
// already-built signed attributes (see SignedAttributes) and an
// externally-computed signature, plus any unsigned attributes, and adds it to
// the SignedData. It is the external-signature counterpart to the smimesign
// protocol's AddSignerInfo, which signs internally; signedAttrs must be the
// attributes whose MarshaledForSigning (hashed with hash) produced signature.
func (sd *SignedData) AddSignerInfoWithSignature(cert *x509.Certificate, hash crypto.Hash, signedAttrs protocol.Attributes, signature []byte, unsignedAttrs protocol.Attributes) error {
	sid, err := protocol.NewIssuerAndSerialNumber(cert)
	if err != nil {
		return err
	}

	digestOID, ok := digestAlgorithmOID(hash)
	if !ok {
		return fmt.Errorf("unsupported digest algorithm %v", hash)
	}
	digestAlgorithm := pkix.AlgorithmIdentifier{Algorithm: digestOID}

	signatureAlgorithmOID, ok := oid.X509PublicKeyAndDigestAlgorithmToSignatureAlgorithm[cert.PublicKeyAlgorithm][digestOID.String()]
	if !ok {
		return fmt.Errorf("unsupported certificate public key algorithm %v", cert.PublicKeyAlgorithm)
	}

	si := protocol.SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlgorithm,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: signatureAlgorithmOID},
		Signature:          signature,
		UnsignedAttrs:      unsignedAttrs,
	}

	if err := sd.psd.AddCertificate(cert); err != nil {
		return err
	}
	sd.psd.DigestAlgorithms = append(sd.psd.DigestAlgorithms, digestAlgorithm)
	sd.psd.SignerInfos = append(sd.psd.SignerInfos, si)
	return nil
}

// sortAttributes orders attributes by their DER-encoded values, the canonical
// SET OF ordering. This mirrors the smimesign protocol's unexported
// sortAttributes, which is not accessible from here.
func sortAttributes(attrs ...protocol.Attribute) protocol.Attributes {
	sort.Slice(attrs, func(i, j int) bool {
		return bytes.Compare(attrs[i].RawValue.FullBytes, attrs[j].RawValue.FullBytes) < 0
	})
	return attrs
}

func digestAlgorithmOID(hash crypto.Hash) (asn1.ObjectIdentifier, bool) {
	switch hash {
	case crypto.SHA256:
		return oid.DigestAlgorithmSHA256, true
	case crypto.SHA384:
		return oid.DigestAlgorithmSHA384, true
	case crypto.SHA512:
		return oid.DigestAlgorithmSHA512, true
	default:
		return nil, false
	}
}
