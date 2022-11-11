package cms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/asn1"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

var (
	// fake PKI setup
	root      = fakeca.New(fakeca.IsCA)
	otherRoot = fakeca.New(fakeca.IsCA)

	intermediateKey, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	intermediate       = root.Issue(fakeca.IsCA, fakeca.PrivateKey(intermediateKey))

	leaf = intermediate.Issue(
		fakeca.NotBefore(time.Now().Add(-time.Hour)),
		fakeca.NotAfter(time.Now().Add(time.Hour)),
	)

	rootOpts         = x509.VerifyOptions{Roots: root.ChainPool()}
	otherRootOpts    = x509.VerifyOptions{Roots: otherRoot.ChainPool()}
	intermediateOpts = x509.VerifyOptions{Roots: intermediate.ChainPool()}

	// fake timestamp authority setup
	tsa = &testTSA{ident: intermediate.Issue()}
	thc = &testHTTPClient{tsa}
)

func init() {
	timestamp.DefaultHTTPClient = thc
}

type testTSA struct {
	ident        *fakeca.Identity
	sn           int64
	hookInfo     func(timestamp.Info) timestamp.Info
	hookToken    func(*protocol.SignedData) *protocol.SignedData
	hookResponse func(timestamp.Response) timestamp.Response
}

func (tt *testTSA) Clear() {
	tt.hookInfo = nil
	tt.hookToken = nil
	tt.hookResponse = nil
}

func (tt *testTSA) HookInfo(hook func(timestamp.Info) timestamp.Info) {
	tt.Clear()
	tt.hookInfo = hook
}

func (tt *testTSA) HookToken(hook func(*protocol.SignedData) *protocol.SignedData) {
	tt.Clear()
	tt.hookToken = hook
}

func (tt *testTSA) HookResponse(hook func(timestamp.Response) timestamp.Response) {
	tt.Clear()
	tt.hookResponse = hook
}

func (tt *testTSA) nextSN() *big.Int {
	defer func() { tt.sn++ }()
	return big.NewInt(tt.sn)
}

func (tt *testTSA) Do(req timestamp.Request) (timestamp.Response, error) {
	info := timestamp.Info{
		Version:        1,
		Policy:         asn1.ObjectIdentifier{1, 2, 3},
		SerialNumber:   tt.nextSN(),
		GenTime:        time.Now(),
		MessageImprint: req.MessageImprint,
		Nonce:          req.Nonce,
	}

	if tt.hookInfo != nil {
		info = tt.hookInfo(info)
	}

	eciDER, err := asn1.Marshal(info)
	if err != nil {
		panic(err)
	}

	eci, err := protocol.NewEncapsulatedContentInfo(oid.ContentTypeTSTInfo, eciDER)
	if err != nil {
		panic(err)
	}

	tst, err := protocol.NewSignedData(eci)
	if err != nil {
		panic(err)
	}

	if err = tst.AddSignerInfo(tsa.ident.Chain(), tsa.ident.PrivateKey); err != nil {
		panic(err)
	}

	if tt.hookToken != nil {
		tt.hookToken(tst)
	}

	ci, err := tst.ContentInfo()
	if err != nil {
		panic(err)
	}

	resp := timestamp.Response{
		Status:         timestamp.PKIStatusInfo{Status: 0},
		TimeStampToken: ci,
	}

	if tt.hookResponse != nil {
		resp = tt.hookResponse(resp)
	}

	return resp, nil
}

type testHTTPClient struct {
	tt *testTSA
}

func (thc *testHTTPClient) Do(httpReq *http.Request) (*http.Response, error) {
	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, httpReq.Body); err != nil {
		return nil, err
	}

	var tsReq timestamp.Request
	if _, err := asn1.Unmarshal(buf.Bytes(), &tsReq); err != nil {
		return nil, err
	}

	tsResp, err := thc.tt.Do(tsReq)
	if err != nil {
		return nil, err
	}

	respDER, err := asn1.Marshal(tsResp)
	if err != nil {
		return nil, err
	}

	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": {"application/timestamp-reply"}},
		Body:       ioutil.NopCloser(bytes.NewReader(respDER)),
	}, nil
}
