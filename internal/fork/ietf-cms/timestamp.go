package cms

import (
	"bytes"
	"crypto/x509"
	"errors"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

// AddTimestamps adds a timestamp to the SignedData using the RFC3161
// timestamping service at the given URL. This timestamp proves that the signed
// message existed the time of generation, allowing verifiers to have more trust
// in old messages signed with revoked keys.
func (sd *SignedData) AddTimestamps(url string) error {
	var (
		attrs = make([]protocol.Attribute, len(sd.psd.SignerInfos))
		err   error
	)

	// Fetch all timestamp tokens before adding any to sd. This avoids a partial
	// failure.
	for i := range attrs {
		if attrs[i], err = fetchTS(url, sd.psd.SignerInfos[i]); err != nil {
			return err
		}
	}

	for i := range attrs {
		sd.psd.SignerInfos[i].UnsignedAttrs = append(sd.psd.SignerInfos[i].UnsignedAttrs, attrs[i])
	}

	return nil
}

func fetchTS(url string, si protocol.SignerInfo) (protocol.Attribute, error) {
	nilAttr := protocol.Attribute{}

	req, err := tsRequest(si)
	if err != nil {
		return nilAttr, err
	}

	resp, err := req.Do(url)
	if err != nil {
		return nilAttr, err
	}

	if tsti, err := resp.Info(); err != nil {
		return nilAttr, err
	} else if !req.Matches(tsti) {
		return nilAttr, errors.New("invalid message imprint")
	}

	return protocol.NewAttribute(oid.AttributeTimeStampToken, resp.TimeStampToken)
}

func tsRequest(si protocol.SignerInfo) (timestamp.Request, error) {
	hash, err := si.Hash()
	if err != nil {
		return timestamp.Request{}, err
	}

	mi, err := timestamp.NewMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return timestamp.Request{}, err
	}

	return timestamp.Request{
		Version:        1,
		CertReq:        true,
		Nonce:          timestamp.GenerateNonce(),
		MessageImprint: mi,
	}, nil
}

// getTimestamp verifies and returns the timestamp.Info from the SignerInfo.
func getTimestamp(si protocol.SignerInfo, opts x509.VerifyOptions) (timestamp.Info, error) {
	rawValue, err := si.UnsignedAttrs.GetOnlyAttributeValueBytes(oid.AttributeTimeStampToken)
	if err != nil {
		return timestamp.Info{}, err
	}

	tst, err := ParseSignedData(rawValue.FullBytes)
	if err != nil {
		return timestamp.Info{}, err
	}

	tsti, err := timestamp.ParseInfo(tst.psd.EncapContentInfo)
	if err != nil {
		return timestamp.Info{}, err
	}

	if tsti.Version != 1 {
		return timestamp.Info{}, protocol.ErrUnsupported
	}

	// verify timestamp signature and certificate chain..
	if _, err = tst.Verify(opts, opts); err != nil {
		return timestamp.Info{}, err
	}

	// verify timestamp token matches SignerInfo.
	hash, err := tsti.MessageImprint.Hash()
	if err != nil {
		return timestamp.Info{}, err
	}
	mi, err := timestamp.NewMessageImprint(hash, bytes.NewReader(si.Signature))
	if err != nil {
		return timestamp.Info{}, err
	}
	if !mi.Equal(tsti.MessageImprint) {
		return timestamp.Info{}, errors.New("invalid message imprint")
	}

	return tsti, nil
}

// hasTimestamp checks if si has a timestamp.
func hasTimestamp(si protocol.SignerInfo) (bool, error) {
	vals, err := si.UnsignedAttrs.GetValues(oid.AttributeTimeStampToken)
	if err != nil {
		return false, err
	}

	return len(vals) > 0, nil
}
