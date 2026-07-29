# Custom URL opener

During the interactive OIDC login flow, Gitsign opens a browser so you can
authenticate with your identity provider. By default it uses your operating
system's default browser.

The `gitsign.urlOpener` config option (or the `GITSIGN_URL_OPENER` environment
variable) lets you override this with a custom command. A common reason to do
this is to force the login to open in a **specific Chrome profile** - for
example, signing commits with the browser profile that is logged into your work
identity provider rather than whichever browser/profile happens to be the system
default.

## How it works

The configured command is split into a program and arguments using shell-style
word splitting (so you can quote arguments that contain spaces). Each resulting
token is then rendered as a Go [`text/template`](https://pkg.go.dev/text/template),
with the login URL exposed as `{{.URL}}`:

```sh
git config --global gitsign.urlOpener 'firefox --new-tab {{.URL}}'
```

A few things to note:

- **`{{.URL}}` is required.** It is where the login URL is substituted. It does
  not have to be the last argument.
- **No shell is invoked.** The parsed tokens are passed directly to the process,
  so pipes, redirects, globbing, `$VAR` expansion, etc. are inert - there is
  nothing for a shell to interpret. Quoting is supported only for grouping
  arguments that contain spaces.
- **Fallback still works.** If the command fails to run, Gitsign falls back to
  the out-of-band flow and prints the URL for you to open manually.

## Forcing a specific Chrome profile

Chrome selects a profile with the `--profile-directory` flag, whose value is the
profile's **directory name** on disk (not its display name). To find it, open
`chrome://version` in the profile you want and look at the last path segment of
`Profile Path`:

- The first/default profile is always `Default`.
- Additional profiles are `Profile 1`, `Profile 2`, ... (note the space).

### macOS

```sh
git config --global gitsign.urlOpener 'open -na "Google Chrome" --args --profile-directory="Profile 1" {{.URL}}'
```

`open -n` launches a new instance and `--args` forwards the remaining arguments
to Chrome. The quotes around `Google Chrome` and `Profile 1` keep each value as
a single argument.

### Linux

```sh
git config --global gitsign.urlOpener 'google-chrome --profile-directory="Profile 1" {{.URL}}'
```

Depending on your distribution the binary may be `google-chrome-stable`,
`chromium`, or `chromium-browser`.

### Windows

Quote any path or argument that contains spaces. Backslashes are treated
literally, so native Windows paths work as-is:

```sh
git config --global gitsign.urlOpener '"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory="Profile 1" {{.URL}}'
```

## Using a wrapper script

If your command is complex (unusual escaping, environment setup, choosing a
profile dynamically, etc.), point `gitsign.urlOpener` at a small script and let
it do the work:

```sh
cat > ~/bin/gitsign-open <<'EOF'
#!/usr/bin/env bash
exec google-chrome --profile-directory="Profile 1" "$1"
EOF
chmod +x ~/bin/gitsign-open

git config --global gitsign.urlOpener '~/bin/gitsign-open {{.URL}}'
```

> **Note:** `~` is not expanded (no shell is involved). Use an absolute path,
> or a bare program name that is resolvable on your `PATH`.

## Environment variable

The same value can be provided via an environment variable, which takes
precedence over the git config value:

```sh
export GITSIGN_URL_OPENER='google-chrome --profile-directory="Profile 1" {{.URL}}'
```
</content>
