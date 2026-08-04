# System keyring credential cache

Gitsign can cache signing credentials (the ephemeral private key and the
Fulcio-issued certificate) in the operating system keyring:

- macOS Keychain
- Windows Credential Manager
- Linux [Secret Service](https://specifications.freedesktop.org/secret-service/latest/)
  (GNOME Keyring, KWallet, etc.)

Unlike the [gitsign-credential-cache](../cmd/gitsign-credential-cache/README.md)
daemon, no long-running helper process is required. Credentials are cached for
the lifetime of the certificate (~10 minutes on the public Sigstore instance),
so you only need to complete the OIDC browser flow once per certificate
lifetime instead of once per signature.

## Setup

```sh
git config --global gitsign.credentialCacheMode system
```

or via environment variable:

```sh
export GITSIGN_CREDENTIAL_CACHE_MODE=system
```

The first `git commit -S` runs the normal OIDC flow and stores the resulting
credential; subsequent signatures reuse it until the certificate expires.
Expired or invalid entries are removed automatically the next time they are
read. If the keyring is unavailable (e.g. locked, or no D-Bus session on a
headless Linux host), gitsign falls back to the normal OIDC flow.

## Multiple identities

Credentials are cached per identity. Because the OIDC identity is only known
after the auth flow completes, the cache key is derived from the configuration
used to obtain it:

- Fulcio URL (`gitsign.fulcio`)
- OIDC issuer (`gitsign.issuer`)
- OIDC client ID (`gitsign.clientID`)
- Connector ID (`gitsign.connectorID`)
- Committer email (`user.email`)

Repositories that share the same configuration share a cached credential;
repositories with a different `user.email` (or issuer, connector, etc.) get
their own entry. Multiple identities can be cached at the same time.

Note that the key is derived from configuration, not from the identity in the
issued certificate. If you authenticate as a different account without
changing any of the config values above, the previously cached credential is
reused until it expires (use `gitsign credentials clear` to evict it
immediately; `gitsign.matchCommitter` can also be used to reject certificates
that don't match `user.email`).

## Managing cached credentials

```sh
# List cached credentials.
$ gitsign credentials list
EMAIL             ISSUER                            CLIENTID  CONNECTOR  FULCIO                       EXPIRES                    STATUS
you@example.com   https://oauth2.sigstore.dev/auth  sigstore  -          https://fulcio.sigstore.dev  2026-08-04T12:10:00-04:00  valid

# Remove the credential for the current configuration.
$ gitsign credentials clear

# Remove all cached credentials.
$ gitsign credentials clear --all
```

Entries can also be inspected/removed with the platform's native tools — they
are stored under the service/label `gitsign` (e.g. Keychain Access on macOS,
`secret-tool`/Seahorse on Linux, Credential Manager on Windows).

`gitsign credentials` operates on whichever backend
`gitsign.credentialCacheMode` selects — the commands also work against the
[gitsign-credential-cache](../cmd/gitsign-credential-cache/README.md) daemon
in `socket` mode (or when `GITSIGN_CREDENTIAL_CACHE` is set).

## Security considerations

⚠️ The cached private key and certificate are only as secure as your OS
keyring.

- Any process running in your user session that can access the keyring (any
  process on Linux once the Secret Service collection is unlocked; anything
  that can invoke `/usr/bin/security` on macOS) can read the cached private
  key and sign artifacts as you. This is comparable to the
  gitsign-credential-cache daemon's threat model, where any process that can
  open the socket can use your credentials.
- Unlike the in-memory daemon, keyring entries are persisted (encrypted at
  rest by the OS) and survive reboots. The exposure window is bounded by the
  certificate lifetime — expired entries are useless for signing and are
  cleaned up lazily on the next read — but entries for identities you stop
  using may linger until then (or until you run
  `gitsign credentials clear --all`).
- Do not use credential caching on shared systems.
- Environments with ambient OIDC credentials (e.g. CI providers) generally
  don't need credential caching.

## When to prefer the daemon instead

- You want credentials to live in memory only and never touch disk.
- You want to forward a credential cache over SSH
  (`RemoteForward` of the socket — see the
  [daemon docs](../cmd/gitsign-credential-cache/README.md#forwarding-cache-over-ssh)).
- Headless Linux hosts without a Secret Service / D-Bus session.
- SSH sessions to macOS hosts, where keychain access may require unlocking the
  login keychain.
