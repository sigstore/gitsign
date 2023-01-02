# Verification

## Offline Verification

In offline Rekor storage mode Gitsign will store a HashedRekord in Rekor
corresponding to the commit content.

Unfortunately this is a bit complex to query manually. Roughly this is:

```
sha256(der(sort(system time | commit data | content type)))
```

The resulting Rekor log entry fields and inclusion proof will be stored in the
PKCS7 object as unauthenticated (i.e. not included in the cryptographic
signature) attributes.

```
unauth_attr:
    object: Rekor TransparencyLogEntry proto (1.3.6.1.4.1.57264.3.1)
    value.set:
      OCTET STRING:
        0000 - 08 af d5 d6 08 12 22 0a-20 c0 d2 3d 6a   ......". ..=j
        000d - d4 06 97 3f 95 59 f3 ba-2d 1c a0 1f 84   ...?.Y..-....
        001a - 14 7d 8f fc 5b 84 45 c2-24 f9 8b 95 91   .}..[.E.$....
        0027 - 80 1d 1a 15 0a 0c 68 61-73 68 65 64 72   ......hashedr
        0034 - 65 6b 6f 72 64 12 05 30-2e 30 2e 31 20   ekord..0.0.1 
        0041 - a1 fc f5 a1 06 2a 49 0a-47 30 45 02 21   .....*I.G0E.!
        004e - 00 fd ab 1a 0d 0b 39 fe-d5 0f f2 4d 87   ......9....M.
        005b - 40 06 bd 2d 84 e8 ca d8-a2 39 99 e5 d9   @..-.....9...
        0068 - 8a 3e b2 48 04 44 67 02-20 15 a5 02 7a   .>.H.Dg. ...z
        0075 - 61 0b d1 58 46 81 b1 ff-53 e8 46 be b3   a..XF...S.F..
        0082 - 70 9b f1 55 07 0c e8 32-bb 61 4e aa ce   p..U...2.aN..
        008f - 61 16 32 81 05 08 c8 c6-d8 06 12 20 3f   a.2........ ?
        009c - 5f bc 03 da 94 4e 17 05-44 a8 c2 1b e9   _....N..D....
        00a9 - a7 6c 84 7d 39 66 4b 07-2f c2 7b 49 3d   .l.}9fK./.{I=
        00b6 - 2b da 9a 84 30 18 c9 c6-d8 06 22 20 34   +...0....." 4
        00c3 - 8d 79 2a f5 5b 0d e8 8f-6e 6b 3f 39 8e   .y*.[...nk?9.
        00d0 - 43 02 2a d3 b3 c3 6b d5-d1 c6 84 cd 7f   C.*...k......
        00dd - 08 24 2f a6 6e 22 20 64-47 c9 39 2b 77   .$/.n" dG.9+w
        00ea - ba 3b b5 36 7f bd ea 8f-36 ef 32 33 14   .;.6....6.23.
        00f7 - 2a e2 ec 2d 57 51 a6 4b-8f 00 59 d2 5e   *..-WQ.K..Y.^
        0104 - 22 20 c0 d8 57 e5 d0 82-b2 b8 cf 26 b0   " ..W......&.
        0111 - 58 e3 85 e5 71 ba 34 ab-5c 1b 49 5a 5e   X...q.4.\.IZ^
        011e - c4 20 7b 7a 47 d6 02 0b-22 20 21 52 30   . {zG..." !R0
        012b - e1 48 37 62 5c 39 56 bc-78 a6 84 d5 c3   .H7b\9V.x....
        0138 - df 3d ea e4 75 80 07 a3-25 b9 c9 42 e6   .=..u...%..B.
        0145 - 34 8e 49 22 20 4a 88 54-e3 e8 ed dd f0   4.I" J.T.....
        0152 - 4b f4 e2 95 55 da a8 44-be 87 85 e6 d9   K...U..D.....
        015f - 57 52 8f 97 b3 3a d3 d7-96 32 f9 22 20   WR...:...2." 
        016c - 35 b2 b6 5b 9f 02 a8 bc-7d d2 f8 64 30   5..[....}..d0
        0179 - d5 04 b1 c4 bb 2e 0c c8-bd 00 18 52 bb   ...........R.
        0186 - 40 ad 84 6c 2d 68 22 20-4c 82 cf f1 63   @..l-h" L...c
        0193 - 90 df b5 b4 3a 8b 0f bf-04 43 3e 52 0e   ....:....C>R.
        01a0 - ef f6 d0 0e d3 c0 01 31-b1 8f 1b 68 82   .......1...h.
        01ad - 74 22 20 ec 4c 65 15 56-3a 67 6a 41 1e   t" .Le.V:gjA.
        01ba - 44 ad 06 b2 df 2d ff da-2c 03 77 87 ee   D....-..,.w..
        01c7 - ba 00 c9 5b c3 b5 34 59-55 22 20 d6 30   ...[..4YU" .0
        01d4 - 92 c2 27 78 05 dc b4 cb-36 1b ea 6e 09   ..'x....6..n.
        01e1 - ac 7e d9 e9 e9 19 27 24-b8 f5 1e 57 e5   .~....'$...W.
        01ee - 4b df 35 31 22 20 9e 04-00 66 df e5 f0   K.51" ...f...
        01fb - 20 04 65 83 86 ac 66 cf-0b b6 ff e8 57    .e...f.....W
        0208 - ed 71 cb 33 7c 7f 55 45-ec f4 55 8b 2a   .q.3|.UE..U.*
        0215 - fe 01 0a fb 01 72 65 6b-6f 72 2e 73 69   .....rekor.si
        0222 - 67 73 74 6f 72 65 2e 64-65 76 20 2d 20   gstore.dev - 
        022f - 32 36 30 35 37 33 36 36-37 30 39 37 32   2605736670972
        023c - 37 39 34 37 34 36 0a 31-34 30 33 33 37   794746.140337
        0249 - 33 37 0a 50 31 2b 38 41-39 71 55 54 68   37.P1+8A9qUTh
        0256 - 63 46 52 4b 6a 43 47 2b-6d 6e 62 49 52   cFRKjCG+mnbIR
        0263 - 39 4f 57 5a 4c 42 79 2f-43 65 30 6b 39   9OWZLBy/Ce0k9
        0270 - 4b 39 71 61 68 44 41 3d-0a 54 69 6d 65   K9qahDA=.Time
        027d - 73 74 61 6d 70 3a 20 31-36 38 31 37 35   stamp: 168175
        028a - 31 35 38 35 32 37 34 35-37 36 37 30 31   1585274576701
        0297 - 0a 0a e2 80 94 20 72 65-6b 6f 72 2e 73   ..... rekor.s
        02a4 - 69 67 73 74 6f 72 65 2e-64 65 76 20 77   igstore.dev w
        02b1 - 4e 49 39 61 6a 42 45 41-69 42 31 56 4a   NI9ajBEAiB1VJ
        02be - 48 46 6e 34 47 4e 63 32-65 38 65 42 78   HFn4GNc2e8eBx
        02cb - 48 6f 4b 41 6c 56 6f 77-44 77 4a 51 72   HoKAlVowDwJQr
        02d8 - 34 32 53 50 56 37 64 2f-6e 72 73 47 34   42SPV7d/nrsG4
        02e5 - 77 49 67 4c 49 73 36 77-2b 59 75 39 42   wIgLIs6w+Yu9B
        02f2 - 2f 35 2b 73 6b 6e 72 51-65 36 58 33 72   /5+sknrQe6X3r
        02ff - 68 6e 6b 41 65 6a 6d 76-55 6d 4d 5a 5a   hnkAejmvUmMZZ
        030c - 69 51 75 4d 53 49 59 3d-0a               iQuMSIY=.
```

These OIDs are defined by [Rekor](https://github.com/sigstore/rekor) and are
used during verification to reconstruct the Rekor log entry and verify the
commit signature.

## Online Verification

In online Rekor storage mode Gitsign will store the Git commit SHA in rekor
rather that persisting the Rekor log details in the commit itself. Gitsign is in
the process of migrating clients to offline verification, but this section
explains how verification used to work.

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

Notice that **the Rekor entry includes the same cert that was used to generate the
git commit signature**. This can be used to correlate the 2 messages, even
though they signed different content!

Note that for Git tags, the annotated tag object SHA is what is used (i.e. the
output of `git rev-parse <tag>`), **not** the SHA of the underlying tagged
commit.
