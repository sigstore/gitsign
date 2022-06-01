# gitsign-credential-cache

`gitsign-credential-cache` is a helper binary that allows users to cache signing
credentials. This can be helpful in situations where you need to perform
multiple signing operations back to back.

Credentials are stored in memory, and the cache is exposed via a Unix socket.
Credentials stored in this cache are only as secure as the unix socket
implementation on your OS - any user that can access the socket can access the
data. When in doubt, we recommend **not** using the cache.

## What's stored in the cache

- Ephemeral Private Key
- Fulcio Code Signing certificate + chain

Data is stored keyed to your Git working directory (i.e. different repo paths will cache different keys)

## Usage

```
$ gitsign-credential-cache &
$ export GITSIGN_CREDENTIAL_CACHE="$HOME/.sigstore/gitsign/cache.sock"
$ git commit ...
```
