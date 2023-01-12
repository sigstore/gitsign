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

```sh
$ gitsign-credential-cache &
$ export GITSIGN_CREDENTIAL_CACHE="$HOME/.cache/sigstore/gitsign/cache.sock"
$ git commit ...
```

Note: The cache directory will change depending on your OS - the socket file
that is used is output by `gitsign-credential-cache` when it is spawned. See
[os.UserCacheDir](https://pkg.go.dev/os#UserCacheDir) for details on how the
cache directory is selected.

### Forwarding cache over SSH

(Requires gitsign >= v0.5)

The credential cache socket can be forwarded over SSH using `RemoteForward`:

```sh
[local]  $ ssh -R /home/wlynch/.sigstore/cache.sock:${GITSIGN_CREDENTIAL_CACHE} <host>
[remote] $ export GITSIGN_CREDENTIAL_CACHE="/home/wlynch/.sigstore/cache.sock"
[remote] $ git commit ...
```

(format is `-R <remote path>:<local path>`)

or in `~/.ssh/config`:

```
Host amazon
    RemoteForward /home/wlynch/.cache/sigstore/cache.sock /Users/wlynch/Library/Caches/sigstore/gitsign/cache.sock
```

where `/home/wlynch/.cache/sigstore/cache.sock` is the location of the socket path on
the remote host (this can be changed, so long as the environment variable is
also updated to match).

#### Common issues

> Warning: remote port forwarding failed for listen path

- The socket directory must exist on the remote, else the socket will fail to
  mount.
- We recommend setting `StreamLocalBindUnlink yes` on the remote
  `/etc/ssh/sshd_config` to allow for sockets to be overwritten on the same path
  for new connections - SSH does not cleanup sockets automatically on exit and
  the socket forwarding will fail if a file already exists on the remote path
  (see [thread](https://marc.info/?l=openssh-unix-dev&m=151998074424424&w=2) for
  more discussion).
