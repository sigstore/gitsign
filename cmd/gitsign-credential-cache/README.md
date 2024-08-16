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

### Systemd service

There are systemd user units in contrib

Change path to gitsign-credential-cache in service unit

```sh
${EDITOR:-vi} ./contrib/gitsign-credential-cache.service
```

Install units in home directory for specific user

```sh
install -m 0660 -D -t $HOME/.config/systemd/user/ ./contrib/gitsign-credential-cache.{socket,service}
systemctl --user daemon-reload
```

OR install them for all users

```sh
sudo install -m 0660 -D -t /etc/systemd/user/ ./contrib/gitsign-credential-cache.{socket,service}
sudo systemctl daemon-reload
```

After that you can enable and start socket service

```sh
systemctl --user enable --now gitsign-credential-cache.socket
```

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


## Running it as a launchctl service on macOS

If you are a macOS user, you can run `gitsign-credential-cache` as a launchctl service by running the following commands in your terminal:

```sh
cat <<EOF > /tmp/gitsign-credential-cache.sh
#!/bin/bash
set -euo pipefail

if ! command -v gitsign &> /dev/null; then
    echo "gitsign command not found. Please install it before running this script: https://docs.sigstore.dev/signing/gitsign/"
    exit 1
fi

if ! command -v gitsign-credential-cache &> /dev/null; then
    echo "gitsign-credential-cache command not found. Please install it before running this script: 'go install github.com/sigstore/gitsign/cmd/gitsign-credential-cache@latest'"
    exit 1
fi

launch_agents_dir="${HOME}/Library/LaunchAgents"
plist_name="my.gitsign-credential-cache.plist"
plist_path="${launch_agents_dir}/${plist_name}"
gitsign_cache_dir="${HOME}/Library/Caches/sigstore/gitsign"
gitsign_cache_path="${gitsign_cache_dir}/cache.sock"

if [ -f "${plist_path}" ]; then
    echo "The plist file ${plist_path} already exists. Please remove it or use a different name."
    exit 1
fi

if [ -f "${gitsign_cache_path}" ]; then
    echo "The gitsign cache path ${gitsign_cache_path} already exists. Please remove it or use a different name."
    exit 1
fi

mkdir -pv "${launch_agents_dir}"

# https://github.com/sigstore/gitsign/blob/main/cmd/gitsign-credential-cache/README.md
cat << EOF > "${plist_path}"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>KeepAlive</key>
    <true/>
    <key>Label</key>
    <string>my.gitsign-credential-cache</string>
    <key>ProgramArguments</key>
    <array>
            <string>/opt/homebrew/bin/gitsign-credential-cache</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/opt/homebrew/var/log/gitsign-credential-cache.log</string>
    <key>StandardOutPath</key>
    <string>/opt/homebrew/var/log/gitsign-credential-cache.log</string>
</dict>
</plist>
EOF

chmod 644 "${plist_path}"
chown $(whoami) "${plist_path}"

echo "Created plist file: ${plist_path}"

launchctl load -wF "${plist_path}"
plutil -lint "${plist_path}"

if [ ! -d "${gitsign_cache_dir}" ]; then
    echo "The gitsign cache directory ${gitsign_cache_dir} does not exist. Creating it now."
    mkdir -pv "${gitsign_cache_dir}"
fi

export GITSIGN_CREDENTIAL_CACHE="${gitsign_cache_path}"

if [ -f "${HOME}/.zshrc" ]; then
    shell_config_file="${HOME}/.zshrc"
elif [ -f "${HOME}/.bashrc" ]; then
    shell_config_file="${HOME}/.bashrc"
elif [ -f "${HOME}/.config/fish/config.fish" ]; then
    if [ ! -f "${HOME}/.config/fish/conf.d/gitsign-credential-cache.fish" ]; then
        echo "set -x GITSIGN_CREDENTIAL_CACHE \"${gitsign_cache_path}\"" > "${HOME}/.config/fish/conf.d/gitsign-credential-cache.fish"
        echo "Added GITSIGN_CREDENTIAL_CACHE to ${HOME}/.config/fish/conf.d/gitsign-credential-cache.fish. Please restart your shell to apply the changes."
    else
        echo "GITSIGN_CREDENTIAL_CACHE already exists in ${HOME}/.config/fish/conf.d/gitsign-credential-cache.fish!"
    fi
    shell_config_file=""
else
    echo "No .bashrc or .zshrc found in your home directory."
    exit 1
fi

if [ ! -z "${shell_config_file}" ]; then
    export_line="export GITSIGN_CREDENTIAL_CACHE=\"${gitsign_cache_path}\""
    if ! grep -qF -- "${export_line}" "${shell_config_file}"; then
        echo "${export_line}" >> "${shell_config_file}"
        echo "Added GITSIGN_CREDENTIAL_CACHE to ${shell_config_file}. Please restart your shell to apply the changes: 'source ${shell_config_file}'"
    else
        echo "GITSIGN_CREDENTIAL_CACHE already exists in ${shell_config_file}!"
    fi
fi

EOF
chmod +x /tmp/gitsign-credential-cache.sh
echo "Running the script to create the launchctl service..."
/tmp/gitsign-credential-cache.sh
```

Once you did that now you should be able to see the `gitsign-credential-cache` service running by running the following command:

```sh
$ launchctl list | grep -i "my.gitsign"
2398    0       my.gitsign-credential-cache
```

and of course if you would like to tail the logs of your service you can do so by running the following command:

```sh
tail -f /opt/homebrew/var/log/gitsign-credential-cache.log
```
