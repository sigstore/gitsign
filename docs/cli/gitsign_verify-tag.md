## gitsign verify-tag

Verify a tag

### Synopsis

Verify a tag.

verify-tag verifies a tag against a set of certificate claims.
This should generally be used over git verify-tag, since verify-tag will
check the identity included in the signature's certificate.

```
gitsign verify-tag <tag> [flags]
```

### Options

```
      --certificate-github-workflow-name string         contains the workflow claim from the GitHub OIDC Identity token that contains the name of the executed workflow.
      --certificate-github-workflow-ref string          contains the ref claim from the GitHub OIDC Identity token that contains the git ref that the workflow run was based upon.
      --certificate-github-workflow-repository string   contains the repository claim from the GitHub OIDC Identity token that contains the repository that the workflow run was based upon
      --certificate-github-workflow-sha string          contains the sha claim from the GitHub OIDC Identity token that contains the commit SHA that the workflow run was based upon.
      --certificate-github-workflow-trigger string      contains the event_name claim from the GitHub OIDC Identity token that contains the name of the event that triggered the workflow run
      --certificate-identity string                     The identity expected in a valid Fulcio certificate. Valid values include email address, DNS names, IP addresses, and URIs. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-identity-regexp string              A regular expression alternative to --certificate-identity. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-identity or --certificate-identity-regexp must be set for keyless flows.
      --certificate-oidc-issuer string                  The OIDC issuer expected in a valid Fulcio certificate, e.g. https://token.actions.githubusercontent.com or https://oauth2.sigstore.dev/auth. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
      --certificate-oidc-issuer-regexp string           A regular expression alternative to --certificate-oidc-issuer. Accepts the Go regular expression syntax described at https://golang.org/s/re2syntax. Either --certificate-oidc-issuer or --certificate-oidc-issuer-regexp must be set for keyless flows.
  -h, --help                                            help for verify-tag
      --insecure-ignore-sct                             when set, verification will not check that a certificate contains an embedded SCT, a proof of inclusion in a certificate transparency log
      --sct string                                      path to a detached Signed Certificate Timestamp, formatted as a RFC6962 AddChainResponse struct. If a certificate contains an SCT, verification will check both the detached and embedded SCTs.
```

### SEE ALSO

* [gitsign](gitsign.md)	 - Keyless Git signing with Sigstore!

