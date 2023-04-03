# Gitsign

[![CI](https://github.com/sigstore/gitsign/actions/workflows/ci.yaml/badge.svg)](https://github.com/sigstore/gitsign/actions/workflows/ci.yaml)
[![E2E](https://github.com/sigstore/gitsign/actions/workflows/e2e.yaml/badge.svg)](https://github.com/sigstore/gitsign/actions/workflows/e2e.yaml)

<p align="center">
  <img style="max-width: 100%;width: 300px;" src="https://raw.githubusercontent.com/sigstore/community/main/artwork/Gitsign/Horizontal/Color/sigstore_gitsign-horizontal-color.svg" alt="Gitsign logo"/>
</p>

Keyless Git signing with Sigstore!

This is heavily inspired by <https://github.com/github/smimesign>, but uses
keyless Sigstore to sign Git commits with your own GitHub / OIDC identity.

## Installation

Using Homebrew:

```sh
brew install sigstore/tap/gitsign
```

Using Go:

```sh
go install github.com/sigstore/gitsign@latest
```

## Configuration

Single Repository:

```sh
cd /path/to/my/repository
git config --local commit.gpgsign true  # Sign all commits
git config --local tag.gpgsign true  # Sign all tags
git config --local gpg.x509.program gitsign  # Use gitsign for signing
git config --local gpg.format x509  # gitsign expects x509 args
```

All respositories:

```sh
git config --global commit.gpgsign true  # Sign all commits
git config --global tag.gpgsign true  # Sign all tags
git config --global gpg.x509.program gitsign  # Use gitsign for signing
git config --global gpg.format x509  # gitsign expects x509 args
```

To learn more about these options, see
[`git-config`](https://git-scm.com/docs/git-config#Documentation/git-config.txt).

### File config

Gitsign can be configured with a standard
[git-config](https://git-scm.com/docs/git-config) file. For example, to set the
Fulcio option for a single repo:

```sh
$ git config --local gitsign.fulcio https://fulcio.example.com
```

The following config options are supported:

| Option             | Default                          | Description                                                                                                                                                                                                                                |
| ------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| fulcio             | https://fulcio.sigstore.dev      | Address of Fulcio server                                                                                                                                                                                                                   |
| logPath            |                                  | Path to log status output. Helpful for debugging when no TTY is available in the environment.                                                                                                                                              |
| clientID           | sigstore                         | OIDC client ID for application                                                                                                                                                                                                             |
| issuer             | https://oauth2.sigstore.dev/auth | OIDC provider to be used to issue ID token                                                                                                                                                                                                 |
| matchCommitter     | false                            | If true, verify that the committer matches certificate user identity. See [docs/committer-verification.md](./docs/committer-verification.md) for more details.                                                                             |
| redirectURL        |                                  | OIDC Redirect URL                                                                                                                                                                                                                          |
| rekor              | https://rekor.sigstore.dev       | Address of Rekor server                                                                                                                                                                                                                    |
| connectorID        |                                  | Optional Connector ID to auto-select to pre-select auth flow to use. For the public sigstore instance, valid values are:<br>- `https://github.com/login/oauth`<br>- `https://accounts.google.com`<br>- `https://login.microsoftonline.com` |
| timestampServerURL |                                  | Address of timestamping authority. If set, a trusted timestamp will be included in the signature.                                                                                                                                          |
| timestampCertChain |                                  | Path to PEM encoded certificate chain for RFC3161 Timestamp Authority verification.                                                                                                                                                        |

### Environment Variables

| Environment Variable         | Sigstore<br>Prefix | Default                          | Description                                                                                                                                                                                                                                |
| ---------------------------- | ------------------ | -------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| GITSIGN_CREDENTIAL_CACHE     | ❌                 |                                  | Optional path to [gitsign-credential-cache](cmd/gitsign-credential-cache/README.md) socket.                                                                                                                                                |
| GITSIGN_CONNECTOR_ID         | ✅                 |                                  | Optional Connector ID to auto-select to pre-select auth flow to use. For the public sigstore instance, valid values are:<br>- `https://github.com/login/oauth`<br>- `https://accounts.google.com`<br>- `https://login.microsoftonline.com` |
| GITSIGN_FULCIO_URL           | ✅                 | https://fulcio.sigstore.dev      | Address of Fulcio server                                                                                                                                                                                                                   |
| GITSIGN_LOG                  | ❌                 |                                  | Path to log status output. Helpful for debugging when no TTY is available in the environment.                                                                                                                                              |
| GITSIGN_OIDC_CLIENT_ID       | ✅                 | sigstore                         | OIDC client ID for application                                                                                                                                                                                                             |
| GITSIGN_OIDC_ISSUER          | ✅                 | https://oauth2.sigstore.dev/auth | OIDC provider to be used to issue ID token                                                                                                                                                                                                 |
| GITSIGN_OIDC_REDIRECT_URL    | ✅                 |                                  | OIDC Redirect URL                                                                                                                                                                                                                          |
| GITSIGN_REKOR_URL            | ✅                 | https://rekor.sigstore.dev       | Address of Rekor server                                                                                                                                                                                                                    |
| GITSIGN_TIMESTAMP_SERVER_URL | ✅                 |                                  | Address of timestamping authority. If set, a trusted timestamp will be included in the signature.                                                                                                                                          |
| GITSIGN_TIMESTAMP_CERT_CHAIN | ✅                 |                                  | Path to PEM encoded certificate chain for RFC3161 Timestamp Authority verification.                                                                                                                                                        |
| GITSIGN_FULCIO_ROOT          | ✅                 |                                  | Path to PEM encoded certificate for Fulcio CA (additional alias: SIGSTORE_ROOT_FILE)                                                                                                                                                       |

For environment variables that support `Sigstore Prefix`, the values may be
provided with either a `GITSIGN_` or `SIGSTORE_` prefix - e.g.
`GITSIGN_CONNECTOR_ID` or `SIGSTORE_CONNECTOR_ID`. If both environment variables
are set, `GITSIGN_` prefix takes priority.

#### Other environment variables

| Environment Variable      | Description                                                                     |
| ------------------------- | ------------------------------------------------------------------------------- |
| SIGSTORE_REKOR_PUBLIC_KEY | This specifies an out of band PEM-encoded public key to use for a custom Rekor. |

## Usage

### Signing Commits

Once configured, you can sign commits as usual with `git commit -S` (or
`git config --global commit.gpgsign true` to enable signing for all commits).

```sh
$ git commit --allow-empty --message="Signed commit"
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&...
[main 040b9af] Signed commit
```

This will redirect you through the Sigstore Keyless flow to authenticate and
sign the commit.

### Signing Tags

Once configured, you can sign commits as usual with `git tag -s` (or
`git config --global tag.gpgsign true` to enable signing for all tags).

```sh
$ git tag v0.0.1
Your browser will now be opened to:
https://oauth2.sigstore.dev/auth/auth?access_type=online&client_id=sigstore&...
```

This will redirect you through the Sigstore Keyless flow to authenticate and
sign the tag.

### Verifying commits

Commits can be verified using `gitsign verify`:

```sh
$ gitsign verify --certificate-identity=billy@chainguard.dev --certificate-oidc-issuer=https://accounts.google.com HEAD
tlog index: 16072348
gitsign: Signature made using certificate ID 0xa6c178d9292f70eb5c4ad9e274ead0158e75e484 | CN=sigstore-intermediate,O=sigstore.dev
gitsign: Good signature from [billy@chainguard.dev](https://accounts.google.com)
Validated Git signature: true
Validated Rekor entry: true
Validated Certificate claims: true
```

`HEAD` may be replaced with any
[Git revision](https://git-scm.com/docs/gitrevisions) (e.g. branch, tag, etc.).

**NOTE**: `gitsign verify` is preferred over
[`git verify-commit`](https://git-scm.com/docs/git-verify-commit) and
[`git verify-tag`](https://git-scm.com/docs/git-verify-tag). The git commands
do not pass through any expected identity information to the signing tools, so
they only verify cryptographic integrity and that the data exists on Rekor, but
not **who** put the data there.

Using these commands will still work, but a warning being displayed.

```sh
$ git verify-commit HEAD
tlog index: 16072349
gitsign: Signature made using certificate ID 0xa6c178d9292f70eb5c4ad9e274ead0158e75e484 | CN=sigstore-intermediate,O=sigstore.dev
gitsign: Good signature from [billy@chainguard.dev](https://accounts.google.com)
Validated Git signature: true
Validated Rekor entry: true
Validated Certificate claims: false
WARNING: git verify-commit does not verify cert claims. Prefer using `gitsign verify` instead.
```

### Private Sigstore

Gitsign is compatible with other Sigstore tools cosign for running against other
Sigstore instances besides the default public instance. See
[cosign documentation](https://docs.sigstore.dev/cosign/custom_components/) for
how to configure and use another instance.

## FAQ

### Is there any way to bypass the browser flow?

A browser window is needed to get an OAuth token, since gitsign aims to not
store refresh tokens or other cryptographic material on disk, but there are some
things you can do to make this process a bit easier!

1. Set the `connectorID` config option - This preselects the identity provider
   to use. Assuming you're already signed in, in most cases you'll bounce
   directly to the auth success screen! (and you can clean up the browser tabs
   later)
2. Use the [Credential Cache](cmd/gitsign-credential-cache/README.md). This uses
   an in-memory credential cache over a file socket that allows you to persist
   keys and certificates for their full lifetime (meaning you only need to auth
   once every 10 minutes).

### Why doesn't GitHub show commits as [verified](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification)?

<img src="./images/unverified.png" width="400" />

GitHub doesn't recognize Gitsign signatures as verified at the moment:

1. The sigstore CA root is not a part of
   [GitHub's trust root](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#smime-commit-signature-verification).
2. Because Gitsign's ephemeral keys are only valid for a short time, using
   standard x509 verification would consider the certificate invalid after
   expiration. Verification needs to include validation via Rekor to verify the
   cert was valid at the time it was used.

We hope to work with GitHub to get these types of signatures recognized as
verified in the future!

## Debugging

### Configuration

If `gitsign` is running with unexpected configs, you can validate the config
values that are being ran by running `gitsign --version`:

```sh
$ gitsign --version
gitsign version v0.5.2
parsed config:
{
  "Fulcio": "https://fulcio.sigstore.dev",
  "FulcioRoot": "",
  "Rekor": "https://rekor.sigstore.dev",
  "ClientID": "sigstore",
  "RedirectURL": "",
  "Issuer": "https://oauth2.sigstore.dev/auth",
  "ConnectorID": "",
  "TimestampURL": "",
  "TimestampCert": "",
  "LogPath": ""
}
```

### Signing

If there is an error during signing, you may see an error like:

```
error: gpg failed to sign the data
fatal: failed to write commit object
```

When Git invokes signing tools, both stdout and stderr are captured which means
`gitsign` cannot push back messages to shells interactively. If a TTY is
available, `gitsign` will output information to the TTY output directly. If a
TTY is not available (e.g. in CI runners, etc.), you can use the `GITSIGN_LOG`
environment variable to tee logs into a readable location for debugging.

### Verification

- `failed to verify detached signature: x509: certificate signed by unknown authority`

  This usually means the TUF root used to verify the commit is not the same as
  the root that was used to sign it. This can happen if you use multiple
  sigstore instances frequently (e.g. if you're a sigstore developer - sigstore
  staging). You can double check relevant environment variables by running
  `gitsign --version`.

## Privacy

### What data does Gitsign store?

Gitsign stores data in 2 places:

1. Within the Git commit

   The commit itself contains a signed digest of the user commit content (e.g.
   author, committer, message, parents, etc.) along with the code signing
   certificate. This data is stored within the commit itself as part of your
   repository. See
   [Inspecting the Git commit signature](#inspecting-the-git-commit-signature)
   for more details.

2. Within the Rekor transparency log

   To be able to verify signatures for ephemeral certs past their `Not After`
   time, Gitsign records commits and the code signing certificates to
   [Rekor](https://docs.sigstore.dev/rekor/overview/). This data is a
   [HashedRekord](https://github.com/sigstore/rekor/blob/e375eb461cae524270889b57a249ff086bea6c05/types.md#hashed-rekord)
   containing a SHA256 hash of the commit SHA, as well as the code signing
   certificate. See
   [Verifying the Transparency Log](#verifying-the-transparency-log) for more
   details.

   By default, data is written to the
   [public Rekor instance](https://docs.sigstore.dev/rekor/public-instance). In
   particular, users and organizations may be sensitive to the data contained
   within code signing certificates returned by Fulcio, which may include user
   emails or repo identifiers. See
   [OIDC usage in Fulcio](https://github.com/sigstore/fulcio/blob/6ac6b8c94c3ec6106d68c0f92225016a3a6eef79/docs/oidc.md)
   for more details for what data is contained in the code signing certs, and
   [Deploy a Rekor Server Manually](https://docs.sigstore.dev/rekor/installation/#deploy-a-rekor-server-manually)
   for how to run your own Rekor instance.

## Security

Should you discover any security issues, please refer to the
[security process](https://github.com/sigstore/gitsign/security/policy)

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
$ rekor-cli get --uuid=$uuid --format=json | jq .
LogID: c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d
Index: 2212633
IntegratedTime: 2022-05-02T20:51:49Z
UUID: d0444ed9897f31fefc820ade9a706188a3bb030055421c91e64475a8c955ae2c
Body: {
  "HashedRekordObj": {
    "data": {
      "hash": {
        "algorithm": "sha256",
        "value": "05b4f02a24d1c4c2c95dacaee30de2a6ce4b5b88fa981f4e7b456b76ea103141"
      }
    },
    "signature": {
      "content": "MEYCIQCeZwhnq9dgS7ZvU2K5m785V6PqqWAsmkNzAOsf8F++gAIhAKfW2qReBZL34Xrzd7r4JzUlJbf5eoeUZvKT+qsbbskL",
      "publicKey": {
        "content": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNGVENDQVp1Z0F3SUJBZ0lVQUxZY1ZSbUZTcG05VnhJTjdIVzdtaHBPeSs4d0NnWUlLb1pJemowRUF3TXcKS2pFVk1CTUdBMVVFQ2hNTWMybG5jM1J2Y21VdVpHVjJNUkV3RHdZRFZRUURFd2h6YVdkemRHOXlaVEFlRncweQpNakExTURJeU1EVXhORGRhRncweU1qQTFNREl5TVRBeE5EWmFNQUF3V1RBVEJnY3Foa2pPUFFJQkJnZ3Foa2pPClBRTUJCd05DQUFUc1lFdG5xaWpaTlBPRG5CZWx5S1dIWHQ3YndtWElpK2JjeEcrY2gyQUZRaGozdHcyUEJ2RmkKenBwWm5YRVNWUnZEMU1lUXBmWUt0QnF6RHFjOVRoSTRvNEhJTUlIRk1BNEdBMVVkRHdFQi93UUVBd0lIZ0RBVApCZ05WSFNVRUREQUtCZ2dyQmdFRkJRY0RBekFNQmdOVkhSTUJBZjhFQWpBQU1CMEdBMVVkRGdRV0JCU2dzZW9ECnhRaEtjSk1oMnFPZ0MweFZTZE1HUFRBZkJnTlZIU01FR0RBV2dCUll3QjVma1VXbFpxbDZ6SkNoa3lMUUtzWEYKK2pBaUJnTlZIUkVCQWY4RUdEQVdnUlJpYVd4c2VVQmphR0ZwYm1kMVlYSmtMbVJsZGpBc0Jnb3JCZ0VFQVlPLwpNQUVCQkI1b2RIUndjem92TDJkcGRHaDFZaTVqYjIwdmJHOW5hVzR2YjJGMWRHZ3dDZ1lJS29aSXpqMEVBd01ECmFBQXdaUUl4QUsrKzliL25CZlVWNGdlRlNBRE9nUjQrdW5zaDArU2tpdWJsT0o4QmloWnNUTk9VcjNmd2ZXNngKblBrcCtTeTFFd0l3ZE91bFdvcDNvSlYvUW83ZmF1MG1sc3kwTUNtM2xCZ3l4bzJscEFhSTRnRlJ4R0UyR2hwVgo3TitrQ29TMUEyNFMKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQo="
      }
    }
  }
}

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

Note that for Git tags, the annotated tag object SHA is what is used (i.e. the
output of `git rev-parse <tag>`), **not** the SHA of the underlying tagged
commit.
