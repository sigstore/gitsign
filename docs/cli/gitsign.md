## gitsign

Keyless Git signing with Sigstore!

```
gitsign [flags]
```

### Options

```
  -a, --armor               create ascii armored output
  -b, --detach-sign         make a detached signature
  -h, --help                help for gitsign
      --include-certs int   -3 is the same as -2, but omits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -2. (default -2)
  -u, --local-user string   use USER-ID to sign
  -s, --sign                make a signature
      --status-fd int       write special status strings to the file descriptor n. (default -1)
  -v, --verify              verify a signature
      --version             print Gitsign version
```

### SEE ALSO

* [gitsign attest](gitsign_attest.md)	 - add attestations to Git objects
* [gitsign show](gitsign_show.md)	 - Show source predicate information
* [gitsign verify](gitsign_verify.md)	 - Verify a commit
* [gitsign version](gitsign_version.md)	 - print Gitsign version

