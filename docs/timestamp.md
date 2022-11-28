# Timestamping

Gitsign includes support for signing commits with a
[RFC 3161 timestamping authority (TSA)](https://datatracker.ietf.org/doc/html/rfc3161).

#### Sign

To use a TSA during signing, set the `timestampURL` config option (one-time
setup) to the RFC 3161 URL to use.

For example, using the
[Digicert TSA](https://knowledge.digicert.com/generalinformation/INFO4231.html):

```sh
$ git config --local gitsign.timestampURL http://timestamp.digicert.com
$ git commit
```

#### Verify

By default, Gitsign will use your system certificate pool to verify TSA
signatures. To specify additional certificates to use for verification, set the
`timestampCert` config option to the path containing a PEM-encoded TSA
certificate chain.

```sh
$ git config --local gitsign.timestampCert tsa.pem
$ git verify-commit head
tlog index: 8031421
gitsign: Signature made using certificate ID 0xe615fa467ce0aaae5f81f1965dd19e89f859f24a | CN=sigstore-intermediate,O=sigstore.dev
gitsign: Good signature from [billy@chainguard.dev]
Validated Git signature: true
Validated Rekor entry: true
```

<details><summary>Sample Signature</summary>

```
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
          serialNumber: 0x0DF7625EECD9A10EB6290E515E1931EAE3AD770C
          signature:
            algorithm: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
            parameter: <ABSENT>
          issuer: O=sigstore.dev, CN=sigstore-intermediate
          validity:
            notBefore: Nov 28 18:34:56 2022 GMT
            notAfter: Nov 28 18:44:56 2022 GMT
          subject:
          key:
            algor:
              algorithm: id-ecPublicKey (1.2.840.10045.2.1)
              parameter: OBJECT:prime256v1 (1.2.840.10045.3.1.7)
            public_key:  (0 unused bits)
              0000 - 04 c3 23 27 2b 1d 8d 28-ef b5 2b 43 7d fa   ..#'+..(..+C}.
              000e - 2d 3e cc 4d a4 9b ee 29-cf 68 3e 20 e1 ce   ->.M...).h> ..
              001c - a5 c8 f4 89 53 57 aa 63-8f 09 da a6 60 88   ....SW.c....`.
              002a - 8e 1b 55 33 77 a7 aa 1b-0f a7 92 73 5c 80   ..U3w......s\.
              0038 - c3 f8 b7 f2 d9 0b 1a 68-bd                  .......h.
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

              object: X509v3 Subject Key Identifier (2.5.29.14)
              critical: BOOL ABSENT
              value:
                0000 - 04 14 9c 25 58 18 16 a0-ae 74 77 51 93   ...%X....twQ.
                000d - fb 6e 63 55 cf 00 a9 24-7f               .ncU...$.

              object: X509v3 Authority Key Identifier (2.5.29.35)
              critical: BOOL ABSENT
              value:
                0000 - 30 16 80 14 df d3 e9 cf-56 24 11 96 f9   0.......V$...
                000d - a8 d8 e9 28 55 a2 c6 2e-18 64 3f         ...(U....d?

              object: X509v3 Subject Alternative Name (2.5.29.17)
              critical: TRUE
              value:
                0000 - 30 16 81 14 62 69 6c 6c-79 40 63 68 61   0...billy@cha
                000d - 69 6e 67 75 61 72 64 2e-64 65 76         inguard.dev

              object: undefined (1.3.6.1.4.1.57264.1.1)
              critical: BOOL ABSENT
              value:
                0000 - 68 74 74 70 73 3a 2f 2f-61 63 63 6f 75   https://accou
                000d - 6e 74 73 2e 67 6f 6f 67-6c 65 2e 63 6f   nts.google.co
                001a - 6d                                       m

              object: undefined (1.3.6.1.4.1.11129.2.4.2)
              critical: BOOL ABSENT
              value:
                0000 - 04 7a 00 78 00 76 00 dd-3d 30 6a c6 c7   .z.x.v..=0j..
                000d - 11 32 63 19 1e 1c 99 67-37 02 a2 4a 5e   .2c....g7..J^
                001a - b8 de 3c ad ff 87 8a 72-80 2f 29 ee 8e   ..<....r./)..
                0027 - 00 00 01 84 bf 85 54 75-00 00 04 03 00   ......Tu.....
                0034 - 47 30 45 02 21 00 ca ea-6a 46 60 ff 87   G0E.!...jF`..
                0041 - 36 2a ec 6c 8d 81 ae 61-a4 83 78 96 59   6*.l...a..x.Y
                004e - b0 57 e3 27 b4 35 8d 49-dd 53 9f 52 02   .W.'.5.I.S.R.
                005b - 20 67 8c b5 4a 35 2c 67-d3 1d db ba 42    g..J5,g....B
                0068 - 09 0d a8 24 e4 65 c1 68-f9 6f 74 25 d9   ...$.e.h.ot%.
                0075 - 6b 3b eb a3 c2 fe e6                     k;.....
        sig_alg:
          algorithm: ecdsa-with-SHA384 (1.2.840.10045.4.3.3)
          parameter: <ABSENT>
        signature:  (0 unused bits)
          0000 - 30 66 02 31 00 99 63 90-80 70 11 6a 56 26 57   0f.1..c..p.jV&W
          000f - 27 3b d8 6b 62 ce 64 88-68 fb 00 01 72 11 f6   ';.kb.d.h...r..
          001e - 33 eb f6 28 c5 b8 5c 15-6e 9e 4a 47 84 d4 24   3..(..\.n.JG..$
          002d - f4 ad fe e5 36 d4 fa 30-02 31 00 d2 81 e0 5b   ....6..0.1....[
          003c - 00 bb c3 8b 0a 3f e2 df-01 47 1c 1a 69 4a 70   .....?...G..iJp
          004b - d7 83 74 60 b8 77 73 e2-11 b0 93 79 45 8a cc   ..t`.ws....yE..
          005a - 99 41 0e fb e5 f3 1b cc-7d 5a f6 c2 f5 3b      .A......}Z...;
    crl:
      <EMPTY>
    signer_info:
        version: 1
        issuer_and_serial:
          issuer: O=sigstore.dev, CN=sigstore-intermediate
          serial: 0x0DF7625EECD9A10EB6290E515E1931EAE3AD770C
        digest_alg:
          algorithm: sha256 (2.16.840.1.101.3.4.2.1)
          parameter: <ABSENT>
        auth_attr:
            object: contentType (1.2.840.113549.1.9.3)
            value.set:
              OBJECT:pkcs7-data (1.2.840.113549.1.7.1)

            object: signingTime (1.2.840.113549.1.9.5)
            value.set:
              UTCTIME:Nov 28 18:34:57 2022 GMT

            object: messageDigest (1.2.840.113549.1.9.4)
            value.set:
              OCTET STRING:
                0000 - a7 50 00 ac c9 64 0f fc-da 55 46 d0 be   .P...d...UF..
                000d - 79 66 f1 e1 68 e2 93 96-95 8d 19 4c f2   yf..h......L.
                001a - 89 44 9c 61 ee 32                        .D.a.2
        digest_enc_alg:
          algorithm: ecdsa-with-SHA256 (1.2.840.10045.4.3.2)
          parameter: <ABSENT>
        enc_digest:
          0000 - 30 46 02 21 00 cf 9e a9-96 f8 1d 47 38 0b 40   0F.!.......G8.@
          000f - 07 1e d0 16 24 98 da d0-e3 81 9a af e9 87 63   ....$.........c
          001e - 4d 6d c1 64 b8 9f 08 02-21 00 e5 b6 d0 49 c5   Mm.d....!....I.
          002d - 55 a7 e0 d7 3b 2c 8e 69-68 ae 86 d3 a9 fa 66   U...;,.ih.....f
          003c - 1c 90 2c fc 74 72 d4 9e-be 72 48 63            ..,.tr...rHc
        unauth_attr:
            object: id-smime-aa-timeStampToken (1.2.840.113549.1.9.16.2.14)
            value.set:
              SEQUENCE:
    0:d=0  hl=4 l=5946 cons: SEQUENCE
    4:d=1  hl=2 l=   9 prim:  OBJECT            :pkcs7-signedData
   15:d=1  hl=4 l=5931 cons:  cont [ 0 ]
   19:d=2  hl=4 l=5927 cons:   SEQUENCE
   23:d=3  hl=2 l=   1 prim:    INTEGER           :03
   26:d=3  hl=2 l=  15 cons:    SET
   28:d=4  hl=2 l=  13 cons:     SEQUENCE
   30:d=5  hl=2 l=   9 prim:      OBJECT            :sha256
   41:d=5  hl=2 l=   0 prim:      NULL
   43:d=3  hl=3 l= 139 cons:    SEQUENCE
   46:d=4  hl=2 l=  11 prim:     OBJECT            :id-smime-ct-TSTInfo
   59:d=4  hl=2 l= 124 cons:     cont [ 0 ]
   61:d=5  hl=2 l= 122 prim:      OCTET STRING      [HEX DUMP]:307802010106096086480186FD6C07013031300D06096086480165030402010500042044EA0D73B5310D94F1698A184F5BADE0A7EC3810049CCA7721792E97241321C6021100D94C446A7368BF029F9C984726957C89180F32303232313132383138333435375A021100F3C335CD7279074B937BC50A9CEEF149
  185:d=3  hl=4 l=4871 cons:    cont [ 0 ]
  189:d=4  hl=4 l=1728 cons:     SEQUENCE
  193:d=5  hl=4 l=1192 cons:      SEQUENCE
  197:d=6  hl=2 l=   3 cons:       cont [ 0 ]
  199:d=7  hl=2 l=   1 prim:        INTEGER           :02
  202:d=6  hl=2 l=  16 prim:       INTEGER           :0C4D69724B94FA3C2A4A3D2907803D5A
  220:d=6  hl=2 l=  13 cons:       SEQUENCE
  222:d=7  hl=2 l=   9 prim:        OBJECT            :sha256WithRSAEncryption
  233:d=7  hl=2 l=   0 prim:        NULL
  235:d=6  hl=2 l=  99 cons:       SEQUENCE
  237:d=7  hl=2 l=  11 cons:        SET
  239:d=8  hl=2 l=   9 cons:         SEQUENCE
  241:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
  246:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
  250:d=7  hl=2 l=  23 cons:        SET
  252:d=8  hl=2 l=  21 cons:         SEQUENCE
  254:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
  259:d=9  hl=2 l=  14 prim:          PRINTABLESTRING   :DigiCert, Inc.
  275:d=7  hl=2 l=  59 cons:        SET
  277:d=8  hl=2 l=  57 cons:         SEQUENCE
  279:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
  284:d=9  hl=2 l=  50 prim:          PRINTABLESTRING   :DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
  336:d=6  hl=2 l=  30 cons:       SEQUENCE
  338:d=7  hl=2 l=  13 prim:        UTCTIME           :220921000000Z
  353:d=7  hl=2 l=  13 prim:        UTCTIME           :331121235959Z
  368:d=6  hl=2 l=  70 cons:       SEQUENCE
  370:d=7  hl=2 l=  11 cons:        SET
  372:d=8  hl=2 l=   9 cons:         SEQUENCE
  374:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
  379:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
  383:d=7  hl=2 l=  17 cons:        SET
  385:d=8  hl=2 l=  15 cons:         SEQUENCE
  387:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
  392:d=9  hl=2 l=   8 prim:          PRINTABLESTRING   :DigiCert
  402:d=7  hl=2 l=  36 cons:        SET
  404:d=8  hl=2 l=  34 cons:         SEQUENCE
  406:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
  411:d=9  hl=2 l=  27 prim:          PRINTABLESTRING   :DigiCert Timestamp 2022 - 2
  440:d=6  hl=4 l= 546 cons:       SEQUENCE
  444:d=7  hl=2 l=  13 cons:        SEQUENCE
  446:d=8  hl=2 l=   9 prim:         OBJECT            :rsaEncryption
  457:d=8  hl=2 l=   0 prim:         NULL
  459:d=7  hl=4 l= 527 prim:        BIT STRING
  990:d=6  hl=4 l= 395 cons:       cont [ 3 ]
  994:d=7  hl=4 l= 391 cons:        SEQUENCE
  998:d=8  hl=2 l=  14 cons:         SEQUENCE
 1000:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Key Usage
 1005:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 1008:d=9  hl=2 l=   4 prim:          OCTET STRING      [HEX DUMP]:03020780
 1014:d=8  hl=2 l=  12 cons:         SEQUENCE
 1016:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Basic Constraints
 1021:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 1024:d=9  hl=2 l=   2 prim:          OCTET STRING      [HEX DUMP]:3000
 1028:d=8  hl=2 l=  22 cons:         SEQUENCE
 1030:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Extended Key Usage
 1035:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 1038:d=9  hl=2 l=  12 prim:          OCTET STRING      [HEX DUMP]:300A06082B06010505070308
 1052:d=8  hl=2 l=  32 cons:         SEQUENCE
 1054:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Certificate Policies
 1059:d=9  hl=2 l=  25 prim:          OCTET STRING      [HEX DUMP]:30173008060667810C010402300B06096086480186FD6C0701
 1086:d=8  hl=2 l=  31 cons:         SEQUENCE
 1088:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Authority Key Identifier
 1093:d=9  hl=2 l=  24 prim:          OCTET STRING      [HEX DUMP]:30168014BA16D96D4D852F7329769A2F758C6A208F9EC86F
 1119:d=8  hl=2 l=  29 cons:         SEQUENCE
 1121:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Subject Key Identifier
 1126:d=9  hl=2 l=  22 prim:          OCTET STRING      [HEX DUMP]:0414628ADED061FC8F3114ED970BCD3D2A9414DF529C
 1150:d=8  hl=2 l=  90 cons:         SEQUENCE
 1152:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 CRL Distribution Points
 1157:d=9  hl=2 l=  83 prim:          OCTET STRING      [HEX DUMP]:3051304FA04DA04B8649687474703A2F2F63726C332E64696769636572742E636F6D2F44696769436572745472757374656447345253413430393653484132353654696D655374616D70696E6743412E63726C
 1242:d=8  hl=3 l= 144 cons:         SEQUENCE
 1245:d=9  hl=2 l=   8 prim:          OBJECT            :Authority Information Access
 1255:d=9  hl=3 l= 131 prim:          OCTET STRING      [HEX DUMP]:308180302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D305806082B06010505073002864C687474703A2F2F636163657274732E64696769636572742E636F6D2F44696769436572745472757374656447345253413430393653484132353654696D655374616D70696E6743412E637274
 1389:d=5  hl=2 l=  13 cons:      SEQUENCE
 1391:d=6  hl=2 l=   9 prim:       OBJECT            :sha256WithRSAEncryption
 1402:d=6  hl=2 l=   0 prim:       NULL
 1404:d=5  hl=4 l= 513 prim:      BIT STRING
 1921:d=4  hl=4 l=1710 cons:     SEQUENCE
 1925:d=5  hl=4 l=1174 cons:      SEQUENCE
 1929:d=6  hl=2 l=   3 cons:       cont [ 0 ]
 1931:d=7  hl=2 l=   1 prim:        INTEGER           :02
 1934:d=6  hl=2 l=  16 prim:       INTEGER           :073637B724547CD847ACFD28662A5E5B
 1952:d=6  hl=2 l=  13 cons:       SEQUENCE
 1954:d=7  hl=2 l=   9 prim:        OBJECT            :sha256WithRSAEncryption
 1965:d=7  hl=2 l=   0 prim:        NULL
 1967:d=6  hl=2 l=  98 cons:       SEQUENCE
 1969:d=7  hl=2 l=  11 cons:        SET
 1971:d=8  hl=2 l=   9 cons:         SEQUENCE
 1973:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 1978:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 1982:d=7  hl=2 l=  21 cons:        SET
 1984:d=8  hl=2 l=  19 cons:         SEQUENCE
 1986:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 1991:d=9  hl=2 l=  12 prim:          PRINTABLESTRING   :DigiCert Inc
 2005:d=7  hl=2 l=  25 cons:        SET
 2007:d=8  hl=2 l=  23 cons:         SEQUENCE
 2009:d=9  hl=2 l=   3 prim:          OBJECT            :organizationalUnitName
 2014:d=9  hl=2 l=  16 prim:          PRINTABLESTRING   :www.digicert.com
 2032:d=7  hl=2 l=  33 cons:        SET
 2034:d=8  hl=2 l=  31 cons:         SEQUENCE
 2036:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 2041:d=9  hl=2 l=  24 prim:          PRINTABLESTRING   :DigiCert Trusted Root G4
 2067:d=6  hl=2 l=  30 cons:       SEQUENCE
 2069:d=7  hl=2 l=  13 prim:        UTCTIME           :220323000000Z
 2084:d=7  hl=2 l=  13 prim:        UTCTIME           :370322235959Z
 2099:d=6  hl=2 l=  99 cons:       SEQUENCE
 2101:d=7  hl=2 l=  11 cons:        SET
 2103:d=8  hl=2 l=   9 cons:         SEQUENCE
 2105:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 2110:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 2114:d=7  hl=2 l=  23 cons:        SET
 2116:d=8  hl=2 l=  21 cons:         SEQUENCE
 2118:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 2123:d=9  hl=2 l=  14 prim:          PRINTABLESTRING   :DigiCert, Inc.
 2139:d=7  hl=2 l=  59 cons:        SET
 2141:d=8  hl=2 l=  57 cons:         SEQUENCE
 2143:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 2148:d=9  hl=2 l=  50 prim:          PRINTABLESTRING   :DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
 2200:d=6  hl=4 l= 546 cons:       SEQUENCE
 2204:d=7  hl=2 l=  13 cons:        SEQUENCE
 2206:d=8  hl=2 l=   9 prim:         OBJECT            :rsaEncryption
 2217:d=8  hl=2 l=   0 prim:         NULL
 2219:d=7  hl=4 l= 527 prim:        BIT STRING
 2750:d=6  hl=4 l= 349 cons:       cont [ 3 ]
 2754:d=7  hl=4 l= 345 cons:        SEQUENCE
 2758:d=8  hl=2 l=  18 cons:         SEQUENCE
 2760:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Basic Constraints
 2765:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 2768:d=9  hl=2 l=   8 prim:          OCTET STRING      [HEX DUMP]:30060101FF020100
 2778:d=8  hl=2 l=  29 cons:         SEQUENCE
 2780:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Subject Key Identifier
 2785:d=9  hl=2 l=  22 prim:          OCTET STRING      [HEX DUMP]:0414BA16D96D4D852F7329769A2F758C6A208F9EC86F
 2809:d=8  hl=2 l=  31 cons:         SEQUENCE
 2811:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Authority Key Identifier
 2816:d=9  hl=2 l=  24 prim:          OCTET STRING      [HEX DUMP]:30168014ECD7E382D2715D644CDF2E673FE7BA98AE1C0F4F
 2842:d=8  hl=2 l=  14 cons:         SEQUENCE
 2844:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Key Usage
 2849:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 2852:d=9  hl=2 l=   4 prim:          OCTET STRING      [HEX DUMP]:03020186
 2858:d=8  hl=2 l=  19 cons:         SEQUENCE
 2860:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Extended Key Usage
 2865:d=9  hl=2 l=  12 prim:          OCTET STRING      [HEX DUMP]:300A06082B06010505070308
 2879:d=8  hl=2 l= 119 cons:         SEQUENCE
 2881:d=9  hl=2 l=   8 prim:          OBJECT            :Authority Information Access
 2891:d=9  hl=2 l= 107 prim:          OCTET STRING      [HEX DUMP]:3069302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D304106082B060105050730028635687474703A2F2F636163657274732E64696769636572742E636F6D2F446967694365727454727573746564526F6F7447342E637274
 3000:d=8  hl=2 l=  67 cons:         SEQUENCE
 3002:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 CRL Distribution Points
 3007:d=9  hl=2 l=  60 prim:          OCTET STRING      [HEX DUMP]:303A3038A036A0348632687474703A2F2F63726C332E64696769636572742E636F6D2F446967694365727454727573746564526F6F7447342E63726C
 3069:d=8  hl=2 l=  32 cons:         SEQUENCE
 3071:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Certificate Policies
 3076:d=9  hl=2 l=  25 prim:          OCTET STRING      [HEX DUMP]:30173008060667810C010402300B06096086480186FD6C0701
 3103:d=5  hl=2 l=  13 cons:      SEQUENCE
 3105:d=6  hl=2 l=   9 prim:       OBJECT            :sha256WithRSAEncryption
 3116:d=6  hl=2 l=   0 prim:       NULL
 3118:d=5  hl=4 l= 513 prim:      BIT STRING
 3635:d=4  hl=4 l=1421 cons:     SEQUENCE
 3639:d=5  hl=4 l=1141 cons:      SEQUENCE
 3643:d=6  hl=2 l=   3 cons:       cont [ 0 ]
 3645:d=7  hl=2 l=   1 prim:        INTEGER           :02
 3648:d=6  hl=2 l=  16 prim:       INTEGER           :0E9B188EF9D02DE7EFDB50E20840185A
 3666:d=6  hl=2 l=  13 cons:       SEQUENCE
 3668:d=7  hl=2 l=   9 prim:        OBJECT            :sha384WithRSAEncryption
 3679:d=7  hl=2 l=   0 prim:        NULL
 3681:d=6  hl=2 l= 101 cons:       SEQUENCE
 3683:d=7  hl=2 l=  11 cons:        SET
 3685:d=8  hl=2 l=   9 cons:         SEQUENCE
 3687:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 3692:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 3696:d=7  hl=2 l=  21 cons:        SET
 3698:d=8  hl=2 l=  19 cons:         SEQUENCE
 3700:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 3705:d=9  hl=2 l=  12 prim:          PRINTABLESTRING   :DigiCert Inc
 3719:d=7  hl=2 l=  25 cons:        SET
 3721:d=8  hl=2 l=  23 cons:         SEQUENCE
 3723:d=9  hl=2 l=   3 prim:          OBJECT            :organizationalUnitName
 3728:d=9  hl=2 l=  16 prim:          PRINTABLESTRING   :www.digicert.com
 3746:d=7  hl=2 l=  36 cons:        SET
 3748:d=8  hl=2 l=  34 cons:         SEQUENCE
 3750:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 3755:d=9  hl=2 l=  27 prim:          PRINTABLESTRING   :DigiCert Assured ID Root CA
 3784:d=6  hl=2 l=  30 cons:       SEQUENCE
 3786:d=7  hl=2 l=  13 prim:        UTCTIME           :220801000000Z
 3801:d=7  hl=2 l=  13 prim:        UTCTIME           :311109235959Z
 3816:d=6  hl=2 l=  98 cons:       SEQUENCE
 3818:d=7  hl=2 l=  11 cons:        SET
 3820:d=8  hl=2 l=   9 cons:         SEQUENCE
 3822:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 3827:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 3831:d=7  hl=2 l=  21 cons:        SET
 3833:d=8  hl=2 l=  19 cons:         SEQUENCE
 3835:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 3840:d=9  hl=2 l=  12 prim:          PRINTABLESTRING   :DigiCert Inc
 3854:d=7  hl=2 l=  25 cons:        SET
 3856:d=8  hl=2 l=  23 cons:         SEQUENCE
 3858:d=9  hl=2 l=   3 prim:          OBJECT            :organizationalUnitName
 3863:d=9  hl=2 l=  16 prim:          PRINTABLESTRING   :www.digicert.com
 3881:d=7  hl=2 l=  33 cons:        SET
 3883:d=8  hl=2 l=  31 cons:         SEQUENCE
 3885:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 3890:d=9  hl=2 l=  24 prim:          PRINTABLESTRING   :DigiCert Trusted Root G4
 3916:d=6  hl=4 l= 546 cons:       SEQUENCE
 3920:d=7  hl=2 l=  13 cons:        SEQUENCE
 3922:d=8  hl=2 l=   9 prim:         OBJECT            :rsaEncryption
 3933:d=8  hl=2 l=   0 prim:         NULL
 3935:d=7  hl=4 l= 527 prim:        BIT STRING
 4466:d=6  hl=4 l= 314 cons:       cont [ 3 ]
 4470:d=7  hl=4 l= 310 cons:        SEQUENCE
 4474:d=8  hl=2 l=  15 cons:         SEQUENCE
 4476:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Basic Constraints
 4481:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 4484:d=9  hl=2 l=   5 prim:          OCTET STRING      [HEX DUMP]:30030101FF
 4491:d=8  hl=2 l=  29 cons:         SEQUENCE
 4493:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Subject Key Identifier
 4498:d=9  hl=2 l=  22 prim:          OCTET STRING      [HEX DUMP]:0414ECD7E382D2715D644CDF2E673FE7BA98AE1C0F4F
 4522:d=8  hl=2 l=  31 cons:         SEQUENCE
 4524:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Authority Key Identifier
 4529:d=9  hl=2 l=  24 prim:          OCTET STRING      [HEX DUMP]:3016801445EBA2AFF492CB82312D518BA7A7219DF36DC80F
 4555:d=8  hl=2 l=  14 cons:         SEQUENCE
 4557:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Key Usage
 4562:d=9  hl=2 l=   1 prim:          BOOLEAN           :255
 4565:d=9  hl=2 l=   4 prim:          OCTET STRING      [HEX DUMP]:03020186
 4571:d=8  hl=2 l= 121 cons:         SEQUENCE
 4573:d=9  hl=2 l=   8 prim:          OBJECT            :Authority Information Access
 4583:d=9  hl=2 l= 109 prim:          OCTET STRING      [HEX DUMP]:306B302406082B060105050730018618687474703A2F2F6F6373702E64696769636572742E636F6D304306082B060105050730028637687474703A2F2F636163657274732E64696769636572742E636F6D2F4469676943657274417373757265644944526F6F7443412E637274
 4694:d=8  hl=2 l=  69 cons:         SEQUENCE
 4696:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 CRL Distribution Points
 4701:d=9  hl=2 l=  62 prim:          OCTET STRING      [HEX DUMP]:303C303AA038A0368634687474703A2F2F63726C332E64696769636572742E636F6D2F4469676943657274417373757265644944526F6F7443412E63726C
 4765:d=8  hl=2 l=  17 cons:         SEQUENCE
 4767:d=9  hl=2 l=   3 prim:          OBJECT            :X509v3 Certificate Policies
 4772:d=9  hl=2 l=  10 prim:          OCTET STRING      [HEX DUMP]:300830060604551D2000
 4784:d=5  hl=2 l=  13 cons:      SEQUENCE
 4786:d=6  hl=2 l=   9 prim:       OBJECT            :sha384WithRSAEncryption
 4797:d=6  hl=2 l=   0 prim:       NULL
 4799:d=5  hl=4 l= 257 prim:      BIT STRING
 5060:d=3  hl=4 l= 886 cons:    SET
 5064:d=4  hl=4 l= 882 cons:     SEQUENCE
 5068:d=5  hl=2 l=   1 prim:      INTEGER           :01
 5071:d=5  hl=2 l= 119 cons:      SEQUENCE
 5073:d=6  hl=2 l=  99 cons:       SEQUENCE
 5075:d=7  hl=2 l=  11 cons:        SET
 5077:d=8  hl=2 l=   9 cons:         SEQUENCE
 5079:d=9  hl=2 l=   3 prim:          OBJECT            :countryName
 5084:d=9  hl=2 l=   2 prim:          PRINTABLESTRING   :US
 5088:d=7  hl=2 l=  23 cons:        SET
 5090:d=8  hl=2 l=  21 cons:         SEQUENCE
 5092:d=9  hl=2 l=   3 prim:          OBJECT            :organizationName
 5097:d=9  hl=2 l=  14 prim:          PRINTABLESTRING   :DigiCert, Inc.
 5113:d=7  hl=2 l=  59 cons:        SET
 5115:d=8  hl=2 l=  57 cons:         SEQUENCE
 5117:d=9  hl=2 l=   3 prim:          OBJECT            :commonName
 5122:d=9  hl=2 l=  50 prim:          PRINTABLESTRING   :DigiCert Trusted G4 RSA4096 SHA256 TimeStamping CA
 5174:d=6  hl=2 l=  16 prim:       INTEGER           :0C4D69724B94FA3C2A4A3D2907803D5A
 5192:d=5  hl=2 l=  13 cons:      SEQUENCE
 5194:d=6  hl=2 l=   9 prim:       OBJECT            :sha256
 5205:d=6  hl=2 l=   0 prim:       NULL
 5207:d=5  hl=3 l= 209 cons:      cont [ 0 ]
 5210:d=6  hl=2 l=  26 cons:       SEQUENCE
 5212:d=7  hl=2 l=   9 prim:        OBJECT            :contentType
 5223:d=7  hl=2 l=  13 cons:        SET
 5225:d=8  hl=2 l=  11 prim:         OBJECT            :id-smime-ct-TSTInfo
 5238:d=6  hl=2 l=  28 cons:       SEQUENCE
 5240:d=7  hl=2 l=   9 prim:        OBJECT            :signingTime
 5251:d=7  hl=2 l=  15 cons:        SET
 5253:d=8  hl=2 l=  13 prim:         UTCTIME           :221128183457Z
 5268:d=6  hl=2 l=  43 cons:       SEQUENCE
 5270:d=7  hl=2 l=  11 prim:        OBJECT            :id-smime-aa-signingCertificate
 5283:d=7  hl=2 l=  28 cons:        SET
 5285:d=8  hl=2 l=  26 cons:         SEQUENCE
 5287:d=9  hl=2 l=  24 cons:          SEQUENCE
 5289:d=10 hl=2 l=  22 cons:           SEQUENCE
 5291:d=11 hl=2 l=  20 prim:            OCTET STRING      [HEX DUMP]:F387224D8633829235A994BCBD8F96E9FE1C7C73
 5313:d=6  hl=2 l=  47 cons:       SEQUENCE
 5315:d=7  hl=2 l=   9 prim:        OBJECT            :messageDigest
 5326:d=7  hl=2 l=  34 cons:        SET
 5328:d=8  hl=2 l=  32 prim:         OCTET STRING      [HEX DUMP]:7ABBAAE033F3BF47F633E1F842029C469CB04ABF495B66404E3823848CB94B3C
 5362:d=6  hl=2 l=  55 cons:       SEQUENCE
 5364:d=7  hl=2 l=  11 prim:        OBJECT            :1.2.840.113549.1.9.16.2.47
 5377:d=7  hl=2 l=  40 cons:        SET
 5379:d=8  hl=2 l=  38 cons:         SEQUENCE
 5381:d=9  hl=2 l=  36 cons:          SEQUENCE
 5383:d=10 hl=2 l=  34 cons:           SEQUENCE
 5385:d=11 hl=2 l=  32 prim:            OCTET STRING      [HEX DUMP]:C7F4E1BE32288920ABE2263ABE1AC4FC4FE6781C2D64D04C807557A023B5B6FA
 5419:d=5  hl=2 l=  13 cons:      SEQUENCE
 5421:d=6  hl=2 l=   9 prim:       OBJECT            :rsaEncryption
 5432:d=6  hl=2 l=   0 prim:       NULL
 5434:d=5  hl=4 l= 512 prim:      OCTET STRING      [HEX DUMP]:89FE4197E5B95156F97B5FB4998A45D78E3C8893158B934076DB2A31D0922CFBD9A6AA5550416501D1BF73196E55B1CF3F253102CFE248017D3763017FDE86FFD829C1635C08B97A72F13157C40380197668842F7BF047A10BA0BC3BAE6685C6CB305C00BFA594BA4DE69134FA43BDA851B06C9B50335C3D5D2BC195F824046A6F7E38E5F53CE945F30C5A08FC44165B96E7259E7CD231AB8DDFE39F3F50AD8CE633543676E7ED21A0991BD793917703F2138B1C6DD51E1BBDD7E5706DD3D982F007DB6D7EF9F06AE2474D31A2FB6FB046636160DA035B266765B15853454DE864D2D50087F1BBB8D52277DB49FF18B6CECEC0061441E721CC376E73808C7DE2CD833CCCCE7254C83FBF085B0D9551A7427D1A6919ECC9816764A53AC51EBA72B8C41A67B8FFC1E2714B80C6A5327781AB60A717C7A6638F18E8865FFE1918347B70DE905BB854EBC2CAC8F418C4920CA49BBD53B6CC46A61CF0BAB077400D9E98BAF0B992EFAF0879FD85A84FB15EFE3ECD7799AF9BB0837F00CB64251E07EF0CA390DC1E33E47DD5A04AF5C267042AABCC4932337E51C4224D33606C556D305E8F3125C675ECBF4D7500DC81068CD95C51E5E330AA5E366896CC7DF41323E976CC1B12444EB17DE7279886E58D0B924E2980767595F733F151FDBEF26FDF3BF512A094B90016C9FEFB22C767357AD8ABFEDBD2FBC7F8750B80E3979620D9D9
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            0d:f7:62:5e:ec:d9:a1:0e:b6:29:0e:51:5e:19:31:ea:e3:ad:77:0c
    Signature Algorithm: ecdsa-with-SHA384
        Issuer: O=sigstore.dev, CN=sigstore-intermediate
        Validity
            Not Before: Nov 28 18:34:56 2022 GMT
            Not After : Nov 28 18:44:56 2022 GMT
        Subject:
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:c3:23:27:2b:1d:8d:28:ef:b5:2b:43:7d:fa:2d:
                    3e:cc:4d:a4:9b:ee:29:cf:68:3e:20:e1:ce:a5:c8:
                    f4:89:53:57:aa:63:8f:09:da:a6:60:88:8e:1b:55:
                    33:77:a7:aa:1b:0f:a7:92:73:5c:80:c3:f8:b7:f2:
                    d9:0b:1a:68:bd
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Subject Key Identifier:
                9C:25:58:18:16:A0:AE:74:77:51:93:FB:6E:63:55:CF:00:A9:24:7F
            X509v3 Authority Key Identifier:
                keyid:DF:D3:E9:CF:56:24:11:96:F9:A8:D8:E9:28:55:A2:C6:2E:18:64:3F

            X509v3 Subject Alternative Name: critical
                email:billy@chainguard.dev
            1.3.6.1.4.1.57264.1.1:
                https://accounts.google.com
            1.3.6.1.4.1.11129.2.4.2:
                .z.x.v..=0j...2c....g7..J^..<....r./)........Tu.....G0E.!...jF`..6*.l...a..x.Y.W.'.5.I.S.R. g..J5,g....B.
.$.e.h.ot%.k;.....
    Signature Algorithm: ecdsa-with-SHA384
         30:66:02:31:00:99:63:90:80:70:11:6a:56:26:57:27:3b:d8:
         6b:62:ce:64:88:68:fb:00:01:72:11:f6:33:eb:f6:28:c5:b8:
         5c:15:6e:9e:4a:47:84:d4:24:f4:ad:fe:e5:36:d4:fa:30:02:
         31:00:d2:81:e0:5b:00:bb:c3:8b:0a:3f:e2:df:01:47:1c:1a:
         69:4a:70:d7:83:74:60:b8:77:73:e2:11:b0:93:79:45:8a:cc:
         99:41:0e:fb:e5:f3:1b:cc:7d:5a:f6:c2:f5:3b
-----BEGIN CERTIFICATE-----
MIICoTCCAiagAwIBAgIUDfdiXuzZoQ62KQ5RXhkx6uOtdwwwCgYIKoZIzj0EAwMw
NzEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MR4wHAYDVQQDExVzaWdzdG9yZS1pbnRl
cm1lZGlhdGUwHhcNMjIxMTI4MTgzNDU2WhcNMjIxMTI4MTg0NDU2WjAAMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEwyMnKx2NKO+1K0N9+i0+zE2km+4pz2g+IOHO
pcj0iVNXqmOPCdqmYIiOG1Uzd6eqGw+nknNcgMP4t/LZCxpovaOCAUUwggFBMA4G
A1UdDwEB/wQEAwIHgDATBgNVHSUEDDAKBggrBgEFBQcDAzAdBgNVHQ4EFgQUnCVY
GBagrnR3UZP7bmNVzwCpJH8wHwYDVR0jBBgwFoAU39Ppz1YkEZb5qNjpKFWixi4Y
ZD8wIgYDVR0RAQH/BBgwFoEUYmlsbHlAY2hhaW5ndWFyZC5kZXYwKQYKKwYBBAGD
vzABAQQbaHR0cHM6Ly9hY2NvdW50cy5nb29nbGUuY29tMIGKBgorBgEEAdZ5AgQC
BHwEegB4AHYA3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4AAAGEv4VU
dQAABAMARzBFAiEAyupqRmD/hzYq7GyNga5hpIN4llmwV+MntDWNSd1Tn1ICIGeM
tUo1LGfTHdu6QgkNqCTkZcFo+W90JdlrO+ujwv7mMAoGCCqGSM49BAMDA2kAMGYC
MQCZY5CAcBFqViZXJzvYa2LOZIho+wABchH2M+v2KMW4XBVunkpHhNQk9K3+5TbU
+jACMQDSgeBbALvDiwo/4t8BRxwaaUpw14N0YLh3c+IRsJN5RYrMmUEO++XzG8x9
WvbC9Ts=
-----END CERTIFICATE-----
```

</details>
