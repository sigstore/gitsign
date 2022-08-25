# gitsign-attest

NOTE: This is an **experimental demo**. This will be added as a subcommand to
gitsign if/when we decide to support this.

`gitsign-attest` will add attestations to the latest commit SHA in your Git
working directory (if using a dirty workspace, the last commit is used). Data is
stored as a commit under `refs/attestations/commits` or
`refs/attestations/trees` (depending what you're attesting to), separate from
the primary source tree. This means that the original commit is **unmodified**.
Within this commit, there contains a folder for each commit SHA attested to.

gitsign-attest will store the following:

- the raw data given by the user
- a signed DSSE message attesting to the file

For now, only public sigstore is supported.

## Usage

### Commit attestations

Commit attestations signs and attaches the given attestation file to the latest
commit. Data is stored in `refs/attestations/commits`

```sh
$ git log
f44de7a (HEAD -> main) commit
2b0ff1e commit 1
760568f initial commit
$ gitsign-attest -f test.json
$ gitsign-attest -f spdx.sbom -type spdx
$ git checkout refs/attestations/commits
$ tree
.
└── f44de7aee552f119f94d70137b3bebb93f6bca5d
    ├── sbom.spdx
    ├── sbom.spdx.sig
    ├── test.json
    └── test.json.sig
```

### Tree attestations

Tree attestations signs and attaches the given attestation file to the latest
commit. Data is stored in `refs/attestations/trees`. This can be used to sign
directory content regardless of the commit they came from. This can be useful to
preserve attestations for squash commits, or between sub-directories.

```sh
$ git log --oneline --format="Commit: %h  Tree: %t" -1
Commit: edd19d9  Tree: 853a6ca
$ gitsign-attest -f test.json -t
$ git checkout refs/attestations/trees
$ tree .
.
├── 853a6ca8dd0e1fb84d67c397f6d8daac5926176c
│   ├── test.json
│   └── test.json.sig
```
