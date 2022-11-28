# CMS 

This package is forked from [github/smimesign](https://github.com/github/smimesign) with the following changes:

- Adds inclusive checking for cert timestamps in timestamp authorities (https://github.com/github/smimesign/pull/121)
- Fixes tests for MacOS due to regressions in return types in Go 1.18 crypto libraries (https://github.com/golang/go/issues/52010)
- Adds support for separate cert pools for cert validation and TSA validation.

[CMS (Cryptographic Message Syntax)](https://tools.ietf.org/html/rfc5652) is a syntax for signing, digesting, and encrypting arbitrary messages. It evolved from PKCS#7 and is the basis for higher level protocols such as S/MIME. This package implements the SignedData CMS content-type, allowing users to digitally sign data as well as verify data signed by others.

## Signing and Verifying Data

High level APIs are provided for signing a message with a certificate and key:

```go
msg := []byte("some data")
cert, _ := x509.ParseCertificate(someCertificateData)
key, _ := x509.ParseECPrivateKey(somePrivateKeyData)

der, _ := cms.Sign(msg, []*x509.Certificate{cert}, key)

////
/// At another time, in another place...
//

sd, _ := ParseSignedData(der)
if err, _ := sd.Verify(x509.VerifyOptions{}); err != nil {
  panic(err)
}
```

By default, CMS SignedData includes the original message. High level APIs are also available for creating and verifying detached signatures:

```go
msg := []byte("some data")
cert, _ := x509.ParseCertificate(someCertificateData)
key, _ := x509.ParseECPrivateKey(somePrivateKeyData)

der, _ := cms.SignDetached(msg, cert, key)

////
/// At another time, in another place...
//

sd, _ := ParseSignedData(der)
if err, _ := sd.VerifyDetached(msg, x509.VerifyOptions{}); err != nil {
  panic(err)
}
```

## Timestamping

Because certificates expire and can be revoked, it is may be helpful to attach certified timestamps to signatures, proving that they existed at a given time. RFC3161 timestamps can be added to signatures like so:

```go
signedData, _ := NewSignedData([]byte("Hello, world!"))
signedData.Sign(identity.Chain(), identity.PrivateKey)
signedData.AddTimestamps("http://timestamp.digicert.com")

derEncoded, _ := signedData.ToDER()
io.Copy(os.Stdout, bytes.NewReader(derEncoded))
```

Verification functions implicitly verify timestamps as well. Without a timestamp, verification will fail if the certificate is no longer valid.
