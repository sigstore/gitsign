## gitsign credentials clear

Remove cached signing credentials

### Synopsis

Remove cached signing credentials.

By default only the credential for the current configuration
(Fulcio URL, OIDC issuer, client ID, connector ID, and committer email)
is removed. Use --all to remove all cached credentials.

```
gitsign credentials clear [flags]
```

### Options

```
      --all    remove all cached credentials
  -h, --help   help for clear
```

### SEE ALSO

* [gitsign credentials](gitsign_credentials.md)	 - Manage cached signing credentials

