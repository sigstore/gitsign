# gitsign-credential-cache

`gitsign-credential-cache` is a **optional** helper binary that allows users to
cache signing credentials. This can be helpful in situations where you need to
perform multiple signing operations back to back.

Credentials are stored in memory, and the cache is exposed via a Unix socket.
Credentials stored in this cache are only as secure as the unix socket
implementation on your OS - any user that can access the socket can access the
data.

⚠️ When in doubt, we recommend **not** using the cache. In particular:

- If you're running on a shared system
  - if other admins have access to the cache socket they can access your keys.
- If you're running in an environment that has ambient OIDC credentials (e.g.
  GCE/GKE, AWS, GitHub Actions, etc.), Gitsign will automatically use the
  environment's OIDC credentials. You don't need caching.

If you understand the risks, read on!

## What's stored in the cache

- Ephemeral Private Key
- Fulcio Code Signing certificate + chain

All data is stored in memory, keyed to your Git working directory (i.e.
different repo paths will cache different keys)

The data that is cached would allow any user with access to sign artifacts as
you, until the signing certificate expires, typically in ten minutes.

## Usage

```
$ gitsign-credential-cache &
$ export GITSIGN_CREDENTIAL_CACHE="$HOME/.cache/.sigstore/gitsign/cache.sock"
$ git commit ...
```

Note: The cache directory will change depending on your OS - the socket file
that is used is output by `gitsign-credential-cache` when it is spawned. See
[os.UserCacheDir](https://pkg.go.dev/os#UserCacheDir) for details on how the
cache directory is selected.
