# smimecosign

Keyless Git signing with cosign!

This is heavily inspired by <https://github.com/github/smimesign>, but uses
keyless cosign to sign Git commits with your own GitHub / OIDC identity.

## Installation

```sh
$ go install github.com/wlynch/smimecosign@latest
```

## Configuration

Single Repository:

```sh
$ cd /path/to/my/repository
$ git config --local gpg.x509.program smimecosign
$ git config --local gpg.format x509
```

All respositories:

```sh
$ git config --global gpg.x509.program smimecosign
$ git config --global gpg.format x509
```

## Security

Should you discover any security issues, please refer to sigstores [security
process](https://github.com/sigstore/community/blob/main/SECURITY.md)
