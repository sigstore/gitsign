package cms

import (
	"crypto/rsa"
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/github/smimesign/ietf-cms/oid"
	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/sigstore/gitsign/internal/fork/ietf-cms/timestamp"
)

func TestAddTimestamps(t *testing.T) {
	// Good response
	tsa.Clear()
	sd, _ := NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Error status in response
	tsa.HookResponse(func(resp timestamp.Response) timestamp.Response {
		resp.Status.Status = 1
		return resp
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err != nil {
		if _, isStatusErr := err.(timestamp.PKIStatusInfo); !isStatusErr {
			t.Fatalf("expected timestamp.PKIStatusInfo error, got %v", err)
		}
	}

	// Bad nonce
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Nonce.SetInt64(123123)
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd, _ = NewSignedData([]byte("hi"))
	sd.Sign(leaf.Chain(), leaf.PrivateKey)
	if err := sd.AddTimestamps("https://google.com"); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}
}

func TestTimestampsVerifications(t *testing.T) {
	getTimestampedSignedData := func() *SignedData {
		sd, _ := NewSignedData([]byte("hi"))
		sd.Sign(leaf.Chain(), leaf.PrivateKey)
		tsReq, _ := tsRequest(sd.psd.SignerInfos[0])
		tsResp, _ := tsa.Do(tsReq)
		tsAttr, _ := protocol.NewAttribute(oid.AttributeTimeStampToken, tsResp.TimeStampToken)
		sd.psd.SignerInfos[0].UnsignedAttrs = append(sd.psd.SignerInfos[0].UnsignedAttrs, tsAttr)
		return sd
	}

	// Good timestamp
	tsa.Clear()
	sd := getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Timestamped maybe before not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//     |--------|
	//  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err == nil || !strings.HasPrefix(err.Error(), "x509: certificate has expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	// Timestamped after not-before
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//          |--------|
	//      sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotBefore.Add(31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Timestamped maybe after not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                      |--------|
	//                                  sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err == nil || !strings.HasPrefix(err.Error(), "x509: certificate has expired") {
		t.Fatalf("expected expired error, got %v", err)
	}

	// Timestamped before not-after
	//
	//       Not-Before                       Not-After
	//          |--------------------------------|
	//                                  |--------|
	//                              sig-min   sig-max
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.Accuracy.Seconds = 30
		info.GenTime = leaf.Certificate.NotAfter.Add(-31 * time.Second)
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != nil {
		t.Fatal(err)
	}
	if _, err := sd.Verify(intermediateOpts, intermediateOpts); err != nil {
		t.Fatal(err)
	}

	// Bad message imprint
	tsa.HookInfo(func(info timestamp.Info) timestamp.Info {
		info.MessageImprint.HashedMessage[0] ^= 0xFF
		return info
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err == nil || err.Error() != "invalid message imprint" {
		t.Fatalf("expected 'invalid message imprint', got %v", err)
	}

	// Untrusted signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		badIdent := fakeca.New()
		tst.SignerInfos = nil
		tst.AddSignerInfo(badIdent.Chain(), badIdent.PrivateKey)
		return tst
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err == nil {
		t.Fatal("expected error")
	} else if _, ok := err.(x509.UnknownAuthorityError); !ok {
		t.Fatalf("expected x509.UnknownAuthorityError, got %v", err)
	}

	// Bad signature
	tsa.HookToken(func(tst *protocol.SignedData) *protocol.SignedData {
		tst.SignerInfos[0].Signature[0] ^= 0xFF
		return tst
	})
	sd = getTimestampedSignedData()
	if _, err := getTimestamp(sd.psd.SignerInfos[0], intermediateOpts); err != rsa.ErrVerification {
		t.Fatalf("expected %v, got %v", rsa.ErrVerification, err)
	}
}
