## gitsign initialize

Initializes Sigstore root to retrieve trusted certificate and key targets for verification.

### Synopsis

Initializes Sigstore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
 - The current trusted Sigstore TUF root is embedded inside gitsign at the time of release.
 - Sigstore remote TUF repository is pulled from the CDN mirror at tuf-repo-cdn.sigstore.dev.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.
This will enable you to point gitsign to a separate TUF root.

Any updated TUF repository will be written to $HOME/.sigstore/root/.

Trusted keys and certificate used in gitsign verification (e.g. verifying Fulcio issued certificates
with Fulcio root CA) are pulled form the trusted metadata.

```
gitsign initialize [flags]
```

### Examples

```
gitsign initialize -mirror <url> -out <file>

# initialize root with distributed root keys, default mirror, and default out path.
gitsign initialize

# initialize with an out-of-band root key file, using the default mirror.
gitsign initialize -root <url>

# initialize with an out-of-band root key file and custom repository mirror.
gitsign initialize -mirror <url> -root <url>
```

### Options

```
  -h, --help            help for initialize
      --mirror string   GCS bucket to a Sigstore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap) (default "https://tuf-repo-cdn.sigstore.dev")
      --root string     path to trusted initial root. defaults to embedded root
```

### SEE ALSO

* [gitsign](gitsign.md)	 - Keyless Git signing with Sigstore!

