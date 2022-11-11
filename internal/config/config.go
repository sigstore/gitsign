// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

var (
	// execFn is a function to get the raw git config.
	// Configurable to allow for overriding for testing.
	execFn = realExec
)

// Config represents configuration options for gitsign.
type Config struct {
	// Address of Fulcio server
	Fulcio string
	// Path to PEM encoded certificate root for Fulcio.
	FulcioRoot string

	// Address of Rekor server
	Rekor string

	// OIDC client ID for application
	ClientID string
	// OIDC Redirect URL
	RedirectURL string
	// OIDC provider to be used to issue ID token
	Issuer string
	// Optional Connector ID to use when fetching Dex OIDC token.
	// See https://github.com/sigstore/sigstore/blob/c645ceb9d075499f3a4b3f183d3a6864640fa956/pkg/oauthflow/flow.go#L49-L53
	// for more details.
	ConnectorID string

	// Timestamp Authority address to use to get a trusted timestamp
	TimestampURL string
	// Timestamp Authority PEM encoded cert(s) to use for verification.
	TimestampCert string

	// Path to log status output. Helpful for debugging when no TTY is available in the environment.
	LogPath string
}

// Get fetches the gitsign config options for the repo in the current working
// directory.
func Get() (*Config, error) {
	r, err := execFn()
	if err != nil {
		return nil, fmt.Errorf("error reading config: %w", err)
	}
	cfg := parseConfig(r)

	// Start with default config
	out := &Config{
		Fulcio:   "https://fulcio.sigstore.dev",
		Rekor:    "https://rekor.sigstore.dev",
		ClientID: "sigstore",
		Issuer:   "https://oauth2.sigstore.dev/auth",
	}

	// Get values from config file.
	applyGitOptions(out, cfg)

	// Get values from env vars.

	// Same as GITSIGN_FULCIO_ROOT, but using legacy cosign value for compatibility.
	// Long term we're likely going to be moving away from this.
	// See https://github.com/sigstore/sigstore/pull/759 for more discussion.
	out.FulcioRoot = envOrValue("SIGSTORE_ROOT_FILE", out.FulcioRoot)

	// Check for common environment variables that could be shared with other
	// Sigstore tools. Gitsign envs should take precedence.
	for _, prefix := range []string{"SIGSTORE", "GITSIGN"} {
		out.Fulcio = envOrValue(fmt.Sprintf("%s_FULCIO_URL", prefix), out.Fulcio)
		out.FulcioRoot = envOrValue(fmt.Sprintf("%s_FULCIO_ROOT", prefix), out.FulcioRoot)
		out.Rekor = envOrValue(fmt.Sprintf("%s_REKOR_URL", prefix), out.Rekor)
		out.ClientID = envOrValue(fmt.Sprintf("%s_OIDC_CLIENT_ID", prefix), out.ClientID)
		out.RedirectURL = envOrValue(fmt.Sprintf("%s_OIDC_REDIRECT_URL", prefix), out.RedirectURL)
		out.Issuer = envOrValue(fmt.Sprintf("%s_OIDC_ISSUER", prefix), out.Issuer)
		out.ConnectorID = envOrValue(fmt.Sprintf("%s_CONNECTOR_ID", prefix), out.ConnectorID)
		out.TimestampURL = envOrValue(fmt.Sprintf("%s_TIMESTAMP_URL", prefix), out.TimestampURL)
		out.TimestampCert = envOrValue(fmt.Sprintf("%s_TIMESTAMP_CERT", prefix), out.TimestampCert)
	}

	out.LogPath = envOrValue("GITSIGN_LOG", out.LogPath)

	return out, nil
}

// realExec forks out to the git binary to read the git config.
// We do this as a hack since go-git has issues parsing global configs
// for custom fields (https://github.com/go-git/go-git/issues/508) and
// doesn't support deprecated subsection syntaxes
// (https://github.com/sigstore/gitsign/issues/142).
func realExec() (io.Reader, error) {
	cmd := exec.Command("git", "config", "--get-regexp", `^gitsign\.`)
	stdout := new(bytes.Buffer)
	stderr := new(bytes.Buffer)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		if cmd.ProcessState.ExitCode() == 1 && stderr.Len() == 0 {
			// git config returning exit code 1 with no stderr message can
			// happen if there are no gitsign related configs set. Treat this
			// like an non-error / empty config.
			return stdout, nil
		}
		return nil, fmt.Errorf("%w: %s", err, stderr)
	}
	return stdout, nil
}

func parseConfig(r io.Reader) map[string]string {
	out := map[string]string{}

	s := bufio.NewScanner(r)
	for s.Scan() {
		raw := s.Text()
		data := strings.Split(raw, " ")
		if len(data) < 2 {
			continue
		}
		out[data[0]] = data[1]
	}
	return out
}

func applyGitOptions(out *Config, cfg map[string]string) {
	for k, v := range cfg {
		switch {
		case strings.EqualFold(k, "gitsign.fulcio"):
			out.Fulcio = v
		case strings.EqualFold(k, "gitsign.fulcioRoot"):
			out.FulcioRoot = v
		case strings.EqualFold(k, "gitsign.rekor"):
			out.Rekor = v
		case strings.EqualFold(k, "gitsign.clientID"):
			out.ClientID = v
		case strings.EqualFold(k, "gitsign.redirectURL"):
			out.RedirectURL = v
		case strings.EqualFold(k, "gitsign.issuer"):
			out.Issuer = v
		case strings.EqualFold(k, "gitsign.logPath"):
			out.LogPath = v
		case strings.EqualFold(k, "gitsign.connectorID"):
			out.ConnectorID = v
		case strings.EqualFold(k, "gitsign.timestampURL"):
			out.TimestampURL = v
		case strings.EqualFold(k, "gitsign.timestampCert"):
			out.TimestampCert = v
		}
	}
}

func envOrValue(env, value string) string {
	// Only override values if the environment variable is set.
	if v, ok := os.LookupEnv(env); ok {
		return v
	}
	return value
}
