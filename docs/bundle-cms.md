# Bundles and CMS

Gitsign stores its signatures as [Cryptographic Message Syntax
(CMS/PKCS7)](https://datatracker.ietf.org/doc/html/rfc5652) objects in the git
`gpgsig` header — the same format git's `gpg.x509.program` interface expects.
The wider Sigstore ecosystem, and the [`sigstore-go`](https://github.com/sigstore/sigstore-go)
libraries gitsign builds on, instead use the
[Sigstore **bundle**](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
format.

To use the shared sigstore-go signing and verification code **without changing
the on-disk signature format**, gitsign converts between the two. This document
explains how the two formats relate and how the conversion works. The
compatibility layer lives in
[`internal/sigstore/compat`](../internal/sigstore/compat).

> **Note:** This conversion is currently experimental and opt-in. See
> [Enabling the sigstore-go path](#enabling-the-sigstore-go-path) below.

## The key insight: the signed artifact is the SignedAttrs

A CMS signature is **not** computed directly over the git object. It is computed
over the CMS **signed attributes** (`SignedAttrs`): a small structure containing
the content type, the message digest (`sha256` of the commit/tag body), and the
signing time. The `SignerInfo` signature is `ECDSA(sha256(DER(SignedAttrs)))`,
and the Rekor `HashedRekord` is also keyed on `sha256(DER(SignedAttrs))`.

This means the **artifact** in sigstore-go terms — the thing the bundle's
signature and transparency log entry are over — is the **marshaled SignedAttrs**,
not the commit body. Everything else follows from that.

## Field mapping

| CMS (`SignerInfo` / `SignedData`)                          | Sigstore bundle                                         |
| ---------------------------------------------------------- | ------------------------------------------------------- |
| `SignerInfo.signature`                                     | `messageSignature.signature`                            |
| `sha256(DER(SignedAttrs))`                                 | `messageSignature.messageDigest` (`SHA2_256`)           |
| leaf certificate (the only cert in the bag)                | `verificationMaterial.certificate` (v0.3, single leaf)  |
| Rekor entry in unsigned attr OID `1.3.6.1.4.1.57264.3.1`   | `verificationMaterial.tlogEntries[0]`                   |
| RFC3161 token in unsigned attr (`1.2.840.113549.1.9.16.2.14`) | `verificationMaterial.timestampVerificationData.rfc3161Timestamps` |
| marshaled `SignedAttrs`                                    | the verification **artifact** (`verify.WithArtifact`)   |

Gitsign emits bundles using media type
`application/vnd.dev.sigstore.bundle.v0.3+json`, which carries a single leaf
certificate (intermediates and roots come from the trusted root, not the
signature). This matches gitsign's CMS, which only ever embeds the leaf cert.

## Direction 1: CMS → bundle (verification)

To verify a signature with sigstore-go, gitsign parses the stored CMS and
projects each signer onto a bundle:

```
ParseSignaturePEM(sig)            -> cms.SignedData
SignerInfoToBundle(sd, signer)    -> { Bundle, Artifact }
```

- `Artifact` is the marshaled `SignedAttrs`; callers MUST pass it as the
  verification artifact, since the bundle's `messageSignature` only carries its
  digest.
- The Rekor entry stored in the CMS clears its canonicalized body on storage, so
  it is recomputed from the signed message + signature + certificate when
  building the bundle's `tlogEntries`.

A CMS signature may contain multiple signers; each becomes its own bundle (a
bundle holds exactly one `messageSignature`), and `SignedDataToBundle` returns
one per signer.

`sigstore-go`'s verifier checks the signature, certificate chain, transparency
log inclusion, and identity. The one thing it cannot do from the bundle alone is
confirm the `SignedAttrs` actually describe **this** git object; gitsign enforces
that separately by comparing `sha256(git object)` against the `SignedAttrs`
message-digest attribute (the "content binding" check). See
[verification.md](./verification.md) for the higher-level verification flow.

## Direction 2: bundle → CMS (signing)

Signing runs the inverse. sigstore-go produces the signature and Rekor entry as
a bundle, which is converted into a CMS object for storage:

```
BuildSignedAttributes(body)               -> (SignedAttrs, marshaled-for-signing)
sign.Bundle(PlainData{marshaled}, ...)    -> bundle (signature + cert + tlog)
BundleToSignedData(body, SignedAttrs, b)  -> cms.SignedData  (stored as the signature)
```

- The signing key and Fulcio certificate come from gitsign's existing identity
  (`fulcio.Identity`), adapted to sigstore-go's `sign.Keypair` and
  `sign.CertificateProvider` (see [`compat.NewKeypair`](../internal/sigstore/compat/keypair.go)
  / [`compat.NewCertificateProvider`](../internal/sigstore/compat/certificate.go)).
  The OIDC + Fulcio flow and the credential cache are unchanged — sigstore-go
  drives signing and the Rekor upload, not credential acquisition.
- The CMS `SignerInfo` is assembled around the externally-computed signature by
  the fork helpers `SignedAttributes` and `AddSignerInfoWithSignature` in
  [`internal/fork/ietf-cms`](../internal/fork/ietf-cms/assemble.go). The result
  is byte-for-byte equivalent to what the fork's own signer would produce for the
  same attributes, signature, and certificate.
- RFC3161 timestamps are applied to the assembled CMS (which stores the RFC3161
  `TimeStampToken`), rather than via sigstore-go (whose timestamp client returns
  the full `TimeStampResp`).

Because the signature is over the `SignedAttrs` — which include the signing time
— the attributes are built **once** and reused for both signing and assembly.

## Enabling the sigstore-go path

Both directions are gated behind a single experimental option, off by default:

```sh
git config gitsign.enableSigstoreGo true
# or: GITSIGN_ENABLE_SIGSTORE_GO=true
```

This requires offline Rekor mode (`gitsign.rekorMode=offline`); gitsign will
error at startup otherwise, since the bundle signing path embeds the Rekor entry
in the signature (which is meaningless in online mode). Online/legacy signing
remains on the existing CMS path.

The on-disk CMS signature format is identical whether or not the option is set;
only the implementation of how signing and verification are performed changes.
