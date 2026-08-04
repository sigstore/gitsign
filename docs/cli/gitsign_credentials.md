## gitsign credentials

Manage cached signing credentials

### Synopsis

Manage cached signing credentials.

The credential cache backend is selected by gitsign.credentialCacheMode:
the system keyring (`keyring`), or the gitsign-credential-cache daemon
(`socket`). When no mode is configured, the system keyring is used.

### Options

```
  -h, --help   help for credentials
```

### SEE ALSO

* [gitsign](gitsign.md)	 - Keyless Git signing with Sigstore!
* [gitsign credentials clear](gitsign_credentials_clear.md)	 - Remove cached signing credentials
* [gitsign credentials list](gitsign_credentials_list.md)	 - List cached signing credentials

