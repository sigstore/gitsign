# Committer Verification

Gitsign can be optionally configured to verify that the committer user identity
matches the git user configuration (i.e. `user.name` and `user.email`)

To enable committer verification, run `git config gitsign.matchCommitter true`.

Committer verification is done by matching the certificate Subject Alternative
Name (SAN) against the issued Fulcio certificate in the following order:

1. An `EmailAddresses` cert value matches the committer `user.email`. This
   should be used for most human committer verification.
2. A `URI` cert value matches the committer `user.name`. This should be used for
   most automated user committer verification.

In the event that multiple SAN values are provided, verification will succeed if
at least one value matches.

## Configuring Automated Users

If running in an environment where the authenticated user does **not** have a
user email to bind against (i.e. GitHub Actions, other workload identity
workflows), users are expected to be identified by the SAN URI instead.

See https://github.com/sigstore/fulcio/blob/main/docs/oidc.md for more details

### GitHub Actions

```sh
# This configures the SAN URI for the expected identity in the Fulcio cert.
$ git config user.name "https://myorg/myrepo/path/to/workflow"
# This configures GitHub UI to recognize the commit as coming from a GitHub Action.
$ git config user.email 1234567890+github-actions@users.noreply.github.com
```
