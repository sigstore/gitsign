# gitsign

[![CI](https://github.com/sigstore/gitsign/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigstore/gitsign/actions/workflows/ci.yaml)
[![E2E](https://github.com/sigstore/gitsign/actions/workflows/e2e.yaml/badge.svg)](https://github.com/sigstore/gitsign/actions/workflows/e2e.yaml)

Keyless Git signing with Sigstore!

This is heavily inspired by <https://github.com/github/smimesign>, but uses
keyless Sigstore to sign Git commits with your own GitHub / OIDC identity.

## Installation

```sh
go install github.com/sigstore/gitsign@latest
```

## Configuration

Single Repository:

```sh
cd /path/to/my/repository
git config --local commit.gpgsign true  # Sign all commits
git config --local gpg.x509.program gitsign  # Use gitsign for signing
git config --local gpg.format x509  # gitsign expects x509 args
```

All respositories:

```sh
git config --global commit.gpgsign true  # Sign all commits
git config --global gpg.x509.program gitsign  # Use gitsign for signing
git config --global gpg.format x509  # gitsign expects x509 args
```

### Environment Variables

| Environment Variable      | Default                               | Description                                                                                                   |
| ------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| GITSIGN_FULCIO_URL        | https://fulcio.sigstore.dev           | Address of Fulcio server                                                                                      |
| GITSIGN_LOG               |                                       | Path to log status output. Helpful for debugging, since Git will not forward stderr output to user terminals. |
| GITSIGN_OIDC_CLIENT_ID    | sigstore                              | OIDC client ID for application                                                                                |
| GITSIGN_OIDC_ISSUER       | https://oauth2.sigstore.dev/auth      | OIDC provider to be used to issue ID token                                                                    |
| GITSIGN_OIDC_REDIRECT_URL | http://localhost:5000/auth/callback   | OIDC Redirect URL                                                                                             |
| GITSIGN_REKOR_URL         | https://rekor.sigstore.dev            | Address of Rekor server                                                                                       |

## Usage

Once configured, you can sign commits as usual with `git commit -S` (or
`git config --global commit.gpgsign true` to enable signing for all commits).

```sh
$ git commit --allow-empty --message="Signed commit"
[main cb6eee1] Signed commit
```

This will redirect you through the Sigstore Keyless flow to authenticate and
sign the commit.

Commits can then be verified using `git log`:

```sh
$ git --no-pager log --show-signature -1
commit 227e796042fdd170e58b7e3b7627a1badd320224 (HEAD -> main)
searching tlog for commit: 227e796042fdd170e58b7e3b7627a1badd320224
tlog index: 2212633
smimesign: Signature made using certificate ID 0x815ada5516906a862af8f528d69d3c86e4774b4f | CN=sigstore,O=sigstore.dev
smimesign: Good signature from "" ([billy@chainguard.dev])
Author: Billy Lynch <billy@chainguard.dev>
Date:   Mon May 2 16:51:44 2022 -0400

    Signed commit
```

## Limitations

- When Git invokes signing tools, both stdout and stderr are captured which
  means `gitsign` cannot push back messages to shells interactively. Because of
  this, device mode does not work with `gitsign` - a browser capable session is
  required to sign commits.
- [GitHub Verified Badge](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)

  <img src="./images/unverified.png" width="400" />

  GitHub doesn't recognize gitsign signatures as verfied at the moment:

  1. The sigstore CA root is not a part of
     [GitHub's trust root](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#smime-commit-signature-verification).
  2. Because gitsign's ephemeral keys are only valid for a short time, using
     standard x509 verification would consider the certificate invalid after
     expiration. Verification needs to include validation via Rekor to verify
     the cert was valid at the time it was used.

  We hope to work with GitHub to get these types of signatures recognized as
  verified in the future!

## Debugging

If there is an error during signing, you may see an error like:

```
error: gpg failed to sign the data
fatal: failed to write commit object
```

Because of [`Limitations`](#limitations) with Git signing tools, `gitsign`
cannot write back to stderr. Instead, you can use the `GITSIGN_LOG` environment
variable to tee logs into a readable location for debugging.

## Security

Should you discover any security issues, please refer to sigstores
[security process](https://github.com/sigstore/community/blob/main/SECURITY.md)

## Advanced

### Inspecting the Git commit signature

Git commit signatures use
[CMS/PKCS7 signatures](https://datatracker.ietf.org/doc/html/rfc5652). We can
inspect the underlying data / certificate used by running:

```sh
$ git cat-file commit HEAD | sed -n '/BEGIN/, /END/p' | sed 's/^ //g' | sed 's/gpgsig //g' | sed 's/SIGNED MESSAGE/PKCS7/g' | openssl pkcs7 -print -print_certs -text
PKCS7:
  type: pkcs7-signedData (1.2.840.113549.1.7.2)
  d.sign:
    version: 1
    md_algs:
        algorithm: sha256 (2.16.840.1.101.3.4.2.1)
        parameter: <ABSENT>
    contents:
      type: pkcs7-data (1.2.840.113549.1.7.1)
      d.data: <ABSENT>
    cert:
        cert_info:
          version: 2
          serialNumber: 4061203728062639434060493046878247211328523247
          signature:
            algorithm: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
            parameter: <ABSENT>
          issuer: O=sigstore.dev, CN=sigstore
          validity:
            notBefore: May  2 20:51:47 2022 GMT
            notAfter: May  2 21:01:46 2022 GMT
          subject:
          key:
            algor:
              algorithm: id-ecPublicKey (1.2.840.10045.2.1)
              parameter: OBJECT:prime256v1 (1.2.840.10045.3.1.7)
            public_key:  (0 unused bits)
              0000 - 04 ec 60 4b 67 aa 28 d9-34 f3 83 9c 17 a5   ..`Kg.(.4.....
              000e - c8 a5 87 5e de db c2 65-c8 8b e6 dc c4 6f   ...^...e.....o
              001c - 9c 87 60 05 42 18 f7 b7-0d 8f 06 f1 62 ce   ..`.B.......b.
              002a - 9a 59 9d 71 12 55 1b c3-d4 c7 90 a5 f6 0a   .Y.q.U........
              0038 - b4 1a b3 0e a7 3d 4e 12-38                  .....=N.8
          issuerUID: <ABSENT>
          subjectUID: <ABSENT>
          extensions:
              object: X509v3 Key Usage (2.5.29.15)
              critical: TRUE
              value:
                0000 - 03 02 07 80                              ....

              object: X509v3 Extended Key Usage (2.5.29.37)
              critical: BOOL ABSENT
              value:
                0000 - 30 0a 06 08 2b 06 01 05-05 07 03 03      0...+.......

              object: X509v3 Basic Constraints (2.5.29.19)
              critical: TRUE
              value:
                0000 - 30                                       0
                0002 - <SPACES/NULS>

              object: X509v3 Subject Key Identifier (2.5.29.14)
              critical: BOOL ABSENT
              value:
                0000 - 04 14 a0 b1 ea 03 c5 08-4a 70 93 21 da   ........Jp.!.
                000d - a3 a0 0b 4c 55 49 d3 06-3d               ...LUI..=

              object: X509v3 Authority Key Identifier (2.5.29.35)
              critical: BOOL ABSENT
              value:
                0000 - 30 16 80 14 58 c0 1e 5f-91 45 a5 66 a9   0...X.._.E.f.
                000d - 7a cc 90 a1 93 22 d0 2a-c5 c5 fa         z....".*...

              object: X509v3 Subject Alternative Name (2.5.29.17)
              critical: TRUE
              value:
                0000 - 30 16 81 14 62 69 6c 6c-79 40 63 68 61   0...billy@cha
                000d - 69 6e 67 75 61 72 64 2e-64 65 76         inguard.dev

              object: undefined (1.3.6.1.4.1.57264.1.1)
              critical: BOOL ABSENT
              value:
                0000 - 68 74 74 70 73 3a 2f 2f-67 69 74 68 75   https://githu
                000d - 62 2e 63 6f 6d 2f 6c 6f-67 69 6e 2f 6f   b.com/login/o
                001a - 61 75 74 68                              auth
        sig_alg:
          algorithm: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
          parameter: <ABSENT>
        signature:  (0 unused bits)
          0000 - 30 65 02 31 00 af be f5-bf e7 05 f5 15 e2 07   0e.1...........
          000f - 85 48 00 ce 81 1e 3e ba-7b 21 d3 e4 a4 8a e6   .H....>.{!.....
          001e - e5 38 9f 01 8a 16 6c 4c-d3 94 af 77 f0 7d 6e   .8....lL...w.}n
          002d - b1 9c f9 29 f9 2c b5 13-02 30 74 eb a5 5a 8a   ...).,...0t..Z.
          003c - 77 a0 95 7f 42 8e df 6a-ed 26 96 cc b4 30 29   w...B..j.&...0)
          004b - b7 94 18 32 c6 8d a5 a4-06 88 e2 01 51 c4 61   ...2........Q.a
          005a - 36 1a 1a 55 ec df a4 0a-84 b5 03 6e 12         6..U.......n.
    crl:
      <EMPTY>
    signer_info:
        version: 1
        issuer_and_serial:
          issuer: O=sigstore.dev, CN=sigstore
          serial: 4061203728062639434060493046878247211328523247
        digest_alg:
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)
          parameter: <ABSENT>
        auth_attr:
            object: contentType (1.2.840.113549.1.9.3)
            value.set:
              OBJECT:pkcs7-data (1.2.840.113549.1.7.1)

            object: signingTime (1.2.840.113549.1.9.5)
            value.set:
              UTCTIME:May  2 20:51:49 2022 GMT

            object: messageDigest (1.2.840.113549.1.9.4)
            value.set:
              OCTET STRING:
                0000 - 66 4e 98 f6 29 46 31 f6-ca 8f 21 44 06   fN..)F1...!D.
                000d - 34 07 2a 8a b2 dd 64 29-4a e9 74 71 d0   4.*...d)J.tq.
                001a - a1 84 ec d5 03 3f                        .....?
        digest_enc_alg:
          algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
          parameter: <ABSENT>
        enc_digest:
          0000 - 30 45 02 20 58 02 c6 8c-30 51 df 4b 14 5e ff   0E. X...0Q.K.^.
          000f - 54 a8 b3 44 0e 32 25 3a-2d 5b cf d9 e4 4e 4c   T..D.2%:-[...NL
          001e - 37 47 af 6e d4 17 02 21-00 81 d9 4c fc b7 e3   7G.n...!...L...
          002d - 92 7e cd a7 c8 84 d6 ae-47 93 88 bd 17 c2 92   .~......G......
          003c - a3 d4 a3 00 ec f6 c9 5b-8b 81 9a               .......[...
        unauth_attr:
          <EMPTY>
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b6:1c:55:19:85:4a:99:bd:57:12:0d:ec:75:bb:9a:1a:4e:cb:ef
    Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=sigstore.dev, CN=sigstore
        Validity
            Not Before: May  2 20:51:47 2022 GMT
            Not After : May  2 21:01:46 2022 GMT
        Subject:
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ec:60:4b:67:aa:28:d9:34:f3:83:9c:17:a5:c8:
                    a5:87:5e:de:db:c2:65:c8:8b:e6:dc:c4:6f:9c:87:
                    60:05:42:18:f7:b7:0d:8f:06:f1:62:ce:9a:59:9d:
                    71:12:55:1b:c3:d4:c7:90:a5:f6:0a:b4:1a:b3:0e:
                    a7:3d:4e:12:38
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                A0:B1:EA:03:C5:08:4A:70:93:21:DA:A3:A0:0B:4C:55:49:D3:06:3D
            X509v3 Authority Key Identifier:
                keyid:58:C0:1E:5F:91:45:A5:66:A9:7A:CC:90:A1:93:22:D0:2A:C5:C5:FA

            X509v3 Subject Alternative Name: critical
                email:billy@chainguard.dev
            1.3.6.1.4.1.57264.1.1:
                https://github.com/login/oauth
    Signature Algorithm: ecdsa-with-SHA384
         30:65:02:31:00:af:be:f5:bf:e7:05:f5:15:e2:07:85:48:00:
         ce:81:1e:3e:ba:7b:21:d3:e4:a4:8a:e6:e5:38:9f:01:8a:16:
         6c:4c:d3:94:af:77:f0:7d:6e:b1:9c:f9:29:f9:2c:b5:13:02:
         30:74:eb:a5:5a:8a:77:a0:95:7f:42:8e:df:6a:ed:26:96:cc:
         b4:30:29:b7:94:18:32:c6:8d:a5:a4:06:88:e2:01:51:c4:61:
         36:1a:1a:55:ec:df:a4:0a:84:b5:03:6e:12
-----BEGIN CERTIFICATE-----
MIICFTCCAZugAwIBAgIUALYcVRmFSpm9VxIN7HW7mhpOy+8wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MDIyMDUxNDdaFw0yMjA1MDIyMTAxNDZaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATsYEtnqijZNPODnBelyKWHXt7bwmXIi+bcxG+ch2AFQhj3tw2PBvFi
zppZnXESVRvD1MeQpfYKtBqzDqc9ThI4o4HIMIHFMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSgseoD
xQhKcJMh2qOgC0xVSdMGPTAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF
+jAiBgNVHREBAf8EGDAWgRRiaWxseUBjaGFpbmd1YXJkLmRldjAsBgorBgEEAYO/
MAEBBB5odHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwCgYIKoZIzj0EAwMD
aAAwZQIxAK++9b/nBfUV4geFSADOgR4+unsh0+SkiublOJ8BihZsTNOUr3fwfW6x
nPkp+Sy1EwIwdOulWop3oJV/Qo7fau0mlsy0MCm3lBgyxo2lpAaI4gFRxGE2GhpV
7N+kCoS1A24S
-----END CERTIFICATE-----
```

### Verifying the Transparency Log

As part of signature verification, `gitsign` not only checks that the given
signature matches the commit, but also that the commit exists within the Rekor
transparency log.

We can manually validate that the commit exists in the transparency log by
running:

```sh
$ uuid=$(rekor-cli search --artifact <(git rev-parse HEAD | tr -d '\n') | tail -n 1)
$ sig=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.HashedRekordObj.signature.content)
$ cert=$(rekor-cli get --uuid=$uuid --format=json | jq -r .Body.HashedRekordObj.signature.publicKey.content)
$ cosign verify-blob --cert <(echo $cert | base64 --decode) --signature <(echo $sig | base64 --decode) <(git rev-parse HEAD | tr -d '\n')
tlog entry verified with uuid: d0444ed9897f31fefc820ade9a706188a3bb030055421c91e64475a8c955ae2c index: 2212633
Verified OK
$ echo $cert | base64 --decode | openssl x509 -text
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            b6:1c:55:19:85:4a:99:bd:57:12:0d:ec:75:bb:9a:1a:4e:cb:ef
    Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=sigstore.dev, CN=sigstore
        Validity
            Not Before: May  2 20:51:47 2022 GMT
            Not After : May  2 21:01:46 2022 GMT
        Subject:
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:ec:60:4b:67:aa:28:d9:34:f3:83:9c:17:a5:c8:
                    a5:87:5e:de:db:c2:65:c8:8b:e6:dc:c4:6f:9c:87:
                    60:05:42:18:f7:b7:0d:8f:06:f1:62:ce:9a:59:9d:
                    71:12:55:1b:c3:d4:c7:90:a5:f6:0a:b4:1a:b3:0e:
                    a7:3d:4e:12:38
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                A0:B1:EA:03:C5:08:4A:70:93:21:DA:A3:A0:0B:4C:55:49:D3:06:3D
            X509v3 Authority Key Identifier:
                keyid:58:C0:1E:5F:91:45:A5:66:A9:7A:CC:90:A1:93:22:D0:2A:C5:C5:FA

            X509v3 Subject Alternative Name: critical
                email:billy@chainguard.dev
            1.3.6.1.4.1.57264.1.1:
                https://github.com/login/oauth
    Signature Algorithm: ecdsa-with-SHA384
         30:65:02:31:00:af:be:f5:bf:e7:05:f5:15:e2:07:85:48:00:
         ce:81:1e:3e:ba:7b:21:d3:e4:a4:8a:e6:e5:38:9f:01:8a:16:
         6c:4c:d3:94:af:77:f0:7d:6e:b1:9c:f9:29:f9:2c:b5:13:02:
         30:74:eb:a5:5a:8a:77:a0:95:7f:42:8e:df:6a:ed:26:96:cc:
         b4:30:29:b7:94:18:32:c6:8d:a5:a4:06:88:e2:01:51:c4:61:
         36:1a:1a:55:ec:df:a4:0a:84:b5:03:6e:12
-----BEGIN CERTIFICATE-----
MIICFTCCAZugAwIBAgIUALYcVRmFSpm9VxIN7HW7mhpOy+8wCgYIKoZIzj0EAwMw
KjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0y
MjA1MDIyMDUxNDdaFw0yMjA1MDIyMTAxNDZaMAAwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAATsYEtnqijZNPODnBelyKWHXt7bwmXIi+bcxG+ch2AFQhj3tw2PBvFi
zppZnXESVRvD1MeQpfYKtBqzDqc9ThI4o4HIMIHFMA4GA1UdDwEB/wQEAwIHgDAT
BgNVHSUEDDAKBggrBgEFBQcDAzAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSgseoD
xQhKcJMh2qOgC0xVSdMGPTAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF
+jAiBgNVHREBAf8EGDAWgRRiaWxseUBjaGFpbmd1YXJkLmRldjAsBgorBgEEAYO/
MAEBBB5odHRwczovL2dpdGh1Yi5jb20vbG9naW4vb2F1dGgwCgYIKoZIzj0EAwMD
aAAwZQIxAK++9b/nBfUV4geFSADOgR4+unsh0+SkiublOJ8BihZsTNOUr3fwfW6x
nPkp+Sy1EwIwdOulWop3oJV/Qo7fau0mlsy0MCm3lBgyxo2lpAaI4gFRxGE2GhpV
7N+kCoS1A24S
-----END CERTIFICATE-----
```

Notice that **the Rekor entry uses the same cert that was used to generate the
git commit signature**. This can be used to correlate the 2 messages, even
though they signed different content!
