package timestamp

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
)

// HTTPClient is an interface for *http.Client, allowing callers to customize
// HTTP behavior.
type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// DefaultHTTPClient is the HTTP client used for fetching timestamps. This
// variable may be changed to modify HTTP behavior (eg. add timeouts).
var DefaultHTTPClient = HTTPClient(http.DefaultClient)

const (
	contentTypeTSQuery = "application/timestamp-query"
	contentTypeTSReply = "application/timestamp-reply"
	nonceBytes         = 16
)

// GenerateNonce generates a new nonce for this TSR.
func GenerateNonce() *big.Int {
	buf := make([]byte, nonceBytes)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return new(big.Int).SetBytes(buf[:])
}

// Request is a TimeStampReq
//
//	TimeStampReq ::= SEQUENCE  {
//		version                      INTEGER  { v1(1) },
//		messageImprint               MessageImprint,
//			--a hash algorithm OID and the hash value of the data to be
//			--time-stamped
//		reqPolicy             TSAPolicyId              OPTIONAL,
//		nonce                 INTEGER                  OPTIONAL,
//		certReq               BOOLEAN                  DEFAULT FALSE,
//		extensions            [0] IMPLICIT Extensions  OPTIONAL  }
type Request struct {
	Version        int
	MessageImprint MessageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional,default:false"`
	Extensions     []pkix.Extension      `asn1:"tag:1,optional"`
}

// Matches checks if the MessageImprint and Nonce from a responsee match those
// of the request.
func (req Request) Matches(tsti Info) bool {
	if !req.MessageImprint.Equal(tsti.MessageImprint) {
		return false
	}

	if req.Nonce != nil && tsti.Nonce == nil || req.Nonce.Cmp(tsti.Nonce) != 0 {
		return false
	}

	return true
}

// Do sends this timestamp request to the specified timestamp service, returning
// the parsed response. The timestamp.HTTPClient is used to make the request and
// HTTP behavior can be modified by changing that variable.
func (req Request) Do(url string) (Response, error) {
	var nilResp Response

	reqDER, err := asn1.Marshal(req)
	if err != nil {
		return nilResp, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(reqDER))
	if err != nil {
		return nilResp, err
	}
	httpReq.Header.Add("Content-Type", contentTypeTSQuery)

	httpResp, err := DefaultHTTPClient.Do(httpReq)
	if err != nil {
		return nilResp, err
	}
	if ct := httpResp.Header.Get("Content-Type"); ct != contentTypeTSReply {
		return nilResp, fmt.Errorf("Bad content-type: %s", ct)
	}

	buf := bytes.NewBuffer(make([]byte, 0, httpResp.ContentLength))
	if _, err = io.Copy(buf, httpResp.Body); err != nil {
		return nilResp, err
	}

	return ParseResponse(buf.Bytes())
}

// Response is a TimeStampResp
//
//	TimeStampResp ::= SEQUENCE  {
//		status                  PKIStatusInfo,
//		timeStampToken          TimeStampToken     OPTIONAL  }
//
//	TimeStampToken ::= ContentInfo
type Response struct {
	Status         PKIStatusInfo
	TimeStampToken protocol.ContentInfo `asn1:"optional"`
}

// ParseResponse parses a BER encoded TimeStampResp.
func ParseResponse(ber []byte) (Response, error) {
	var resp Response

	der, err := protocol.BER2DER(ber)
	if err != nil {
		return resp, err
	}

	rest, err := asn1.Unmarshal(der, &resp)
	if err != nil {
		return resp, err
	}
	if len(rest) > 0 {
		return resp, protocol.ErrTrailingData
	}

	return resp, nil
}

// Info gets an Info from the response, doing no validation of the SignedData.
func (r Response) Info() (Info, error) {
	var nilInfo Info

	if err := r.Status.GetError(); err != nil {
		return nilInfo, err
	}

	sd, err := r.TimeStampToken.SignedDataContent()
	if err != nil {
		return nilInfo, err
	}

	return ParseInfo(sd.EncapContentInfo)
}

//	PKIStatusInfo ::= SEQUENCE {
//		status        PKIStatus,
//		statusString  PKIFreeText     OPTIONAL,
//		failInfo      PKIFailureInfo  OPTIONAL  }
//
//	PKIStatus ::= INTEGER {
//		granted                (0),
//			-- when the PKIStatus contains the value zero a TimeStampToken, as
//			requested, is present.
//		grantedWithMods        (1),
//			-- when the PKIStatus contains the value one a TimeStampToken,
//			with modifications, is present.
//		rejection              (2),
//		waiting                (3),
//		revocationWarning      (4),
//			-- this message contains a warning that a revocation is
//			-- imminent
//		revocationNotification (5)
//			-- notification that a revocation has occurred   }
//
// -- When the TimeStampToken is not present
// -- failInfo indicates the reason why the
// -- time-stamp request was rejected and
// -- may be one of the following values.
//
//	PKIFailureInfo ::= BIT STRING {
//		badAlg               (0),
//			-- unrecognized or unsupported Algorithm Identifier
//		badRequest           (2),
//			-- transaction not permitted or supported
//		badDataFormat        (5),
//			-- the data submitted has the wrong format
//		timeNotAvailable    (14),
//			-- the TSA's time source is not available
//		unacceptedPolicy    (15),
//			-- the requested TSA policy is not supported by the TSA.
//		unacceptedExtension (16),
//			-- the requested extension is not supported by the TSA.
//		addInfoNotAvailable (17)
//			-- the additional information requested could not be understood
//			-- or is not available
//		systemFailure       (25)
//			-- the request cannot be handled due to system failure  }
type PKIStatusInfo struct {
	Status       int
	StatusString PKIFreeText    `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// Error represents an unsuccessful PKIStatusInfo as an error.
func (si PKIStatusInfo) GetError() error {
	if si.Status == 0 {
		return nil
	}
	return si
}

// Error implements the error interface.
func (si PKIStatusInfo) Error() string {
	fiStr := ""
	if si.FailInfo.BitLength > 0 {
		fibin := make([]byte, si.FailInfo.BitLength)
		for i := range fibin {
			if si.FailInfo.At(i) == 1 {
				fibin[i] = byte('1')
			} else {
				fibin[i] = byte('0')
			}
		}
		fiStr = fmt.Sprintf(" FailInfo(0b%s)", string(fibin))
	}

	statusStr := ""
	if len(si.StatusString) > 0 {
		if strs, err := si.StatusString.Strings(); err == nil {
			statusStr = fmt.Sprintf(" StatusString(%s)", strings.Join(strs, ","))
		}
	}

	return fmt.Sprintf("Bad TimeStampResp: Status(%d)%s%s", si.Status, statusStr, fiStr)
}

// PKIFreeText ::= SEQUENCE SIZE (1..MAX) OF UTF8String
type PKIFreeText []asn1.RawValue

// Append returns a new copy of the PKIFreeText with the provided string
// appended.
func (ft PKIFreeText) Append(t string) PKIFreeText {
	return append(ft, asn1.RawValue{
		Class: asn1.ClassUniversal,
		Tag:   asn1.TagUTF8String,
		Bytes: []byte(t),
	})
}

// Strings decodes the PKIFreeText into a []string.
func (ft PKIFreeText) Strings() ([]string, error) {
	strs := make([]string, len(ft))

	for i := range ft {
		if rest, err := asn1.Unmarshal(ft[i].FullBytes, &strs[i]); err != nil {
			return nil, err
		} else if len(rest) != 0 {
			return nil, protocol.ErrTrailingData
		}
	}

	return strs, nil
}

// Info is a TSTInfo
//
//	TSTInfo ::= SEQUENCE  {
//	  version                      INTEGER  { v1(1) },
//	  policy                       TSAPolicyId,
//	  messageImprint               MessageImprint,
//	    -- MUST have the same value as the similar field in
//	    -- TimeStampReq
//	  serialNumber                 INTEGER,
//	    -- Time-Stamping users MUST be ready to accommodate integers
//	    -- up to 160 bits.
//	  genTime                      GeneralizedTime,
//	  accuracy                     Accuracy                 OPTIONAL,
//	  ordering                     BOOLEAN             DEFAULT FALSE,
//	  nonce                        INTEGER                  OPTIONAL,
//	    -- MUST be present if the similar field was present
//	    -- in TimeStampReq.  In that case it MUST have the same value.
//	  tsa                          [0] GeneralName          OPTIONAL,
//	  extensions                   [1] IMPLICIT Extensions   OPTIONAL  }
//
//	TSAPolicyId ::= OBJECT IDENTIFIER
type Info struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint MessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       Accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional,default:false"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

// ParseInfo parses an Info out of a CMS EncapsulatedContentInfo.
func ParseInfo(eci protocol.EncapsulatedContentInfo) (Info, error) {
	i := Info{}

	if !eci.EContentType.Equal(oid.ContentTypeTSTInfo) {
		return i, protocol.ErrWrongType
	}

	ecval, err := eci.EContentValue()
	if err != nil {
		return i, err
	}
	if ecval == nil {
		return i, protocol.ASN1Error{Message: "missing EContent for non data type"}
	}

	if rest, err := asn1.Unmarshal(ecval, &i); err != nil {
		return i, err
	} else if len(rest) > 0 {
		return i, protocol.ErrTrailingData
	}

	return i, nil
}

// Before checks if the latest time the signature could have been generated at
// is before the specified time. For example, you might check that a signature
// was made *before* a certificate's not-after date.
func (i *Info) Before(t time.Time) bool {
	return i.genTimeMax().Before(t) || i.genTimeMax().Equal(t)
}

// After checks if the earlier time the signature could have been generated at
// is before the specified time. For example, you might check that a signature
// was made *after* a certificate's not-before date.
func (i *Info) After(t time.Time) bool {
	return i.genTimeMin().After(t) || i.genTimeMin().Equal(t)
}

// genTimeMax is the latest time at which the token could have been generated
// based on the included GenTime and Accuracy attributes.
func (i *Info) genTimeMax() time.Time {
	return i.GenTime.Add(i.Accuracy.Duration())
}

// genTimeMin is the earliest time at which the token could have been generated
// based on the included GenTime and Accuracy attributes.
func (i *Info) genTimeMin() time.Time {
	return i.GenTime.Add(-i.Accuracy.Duration())
}

//	MessageImprint ::= SEQUENCE  {
//	  hashAlgorithm                AlgorithmIdentifier,
//	  hashedMessage                OCTET STRING  }
type MessageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

// NewMessageImprint creates a new MessageImprint, digesting all bytes from the
// provided reader using the specified hash.
func NewMessageImprint(hash crypto.Hash, r io.Reader) (MessageImprint, error) {
	digestAlgorithm := oid.CryptoHashToDigestAlgorithm[hash]
	if len(digestAlgorithm) == 0 {
		return MessageImprint{}, protocol.ErrUnsupported
	}

	if !hash.Available() {
		return MessageImprint{}, protocol.ErrUnsupported
	}
	h := hash.New()
	if _, err := io.Copy(h, r); err != nil {
		return MessageImprint{}, err
	}

	return MessageImprint{
		HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: digestAlgorithm},
		HashedMessage: h.Sum(nil),
	}, nil
}

// Hash gets the crypto.Hash associated with this SignerInfo's DigestAlgorithm.
// 0 is returned for unrecognized algorithms.
func (mi MessageImprint) Hash() (crypto.Hash, error) {
	algo := mi.HashAlgorithm.Algorithm.String()
	hash := oid.DigestAlgorithmToCryptoHash[algo]
	if hash == 0 || !hash.Available() {
		return 0, protocol.ErrUnsupported
	}

	return hash, nil
}

// Equal checks if this MessageImprint is identical to another MessageImprint.
func (mi MessageImprint) Equal(other MessageImprint) bool {
	if !mi.HashAlgorithm.Algorithm.Equal(other.HashAlgorithm.Algorithm) {
		return false
	}
	if len(mi.HashAlgorithm.Parameters.Bytes) > 0 || len(other.HashAlgorithm.Parameters.Bytes) > 0 {
		if !bytes.Equal(mi.HashAlgorithm.Parameters.FullBytes, other.HashAlgorithm.Parameters.FullBytes) {
			return false
		}
	}
	if !bytes.Equal(mi.HashedMessage, other.HashedMessage) {
		return false
	}
	return true
}

//	Accuracy ::= SEQUENCE {
//	  seconds        INTEGER              OPTIONAL,
//	  millis     [0] INTEGER  (1..999)    OPTIONAL,
//	  micros     [1] INTEGER  (1..999)    OPTIONAL  }
type Accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

// Duration returns this Accuracy as a time.Duration.
func (a Accuracy) Duration() time.Duration {
	return 0 +
		time.Duration(a.Seconds)*time.Second +
		time.Duration(a.Millis)*time.Millisecond +
		time.Duration(a.Micros)*time.Microsecond
}
