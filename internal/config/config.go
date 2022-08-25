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
	"fmt"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	format "github.com/go-git/go-git/v5/plumbing/format/config"
)

// Config represents configuration options for gitsign.
type Config struct {
	// Address of Fulcio server
	Fulcio string
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

	// Path to log status output. Helpful for debugging when no TTY is available in the environment.
	LogPath string
}

// Get fetches the gitsign config options for the repo in the current working
// directory.
func Get() (*Config, error) {
	repo, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{DetectDotGit: true})
	if err != nil {
		return nil, err
	}
	return getWithRepo(repo)
}

// getWithRepo fetches a config for a given repository. This is separated out
// from Get so that we can create in-memory repos for testing.
func getWithRepo(repo *git.Repository) (*Config, error) {
	cfg, err := repo.ConfigScoped(config.GlobalScope)
	if err != nil {
		return nil, err
	}

	out := &Config{
		Fulcio:   "https://fulcio.sigstore.dev",
		Rekor:    "https://rekor.sigstore.dev",
		ClientID: "sigstore",
		Issuer:   "https://oauth2.sigstore.dev/auth",
	}

	// Get values from config file.
	for _, s := range cfg.Raw.Sections {
		if s.IsName("gitsign") {
			applyGitOptions(out, s.Options)
		}
	}

	// Get values from env vars

	// Check for common environment variables that could be shared with other
	// Sigstore tools. Gitsign envs should take precedence.
	for _, prefix := range []string{"SIGSTORE", "GITSIGN"} {
		out.Fulcio = envOrValue(fmt.Sprintf("%s_FULCIO_URL", prefix), out.Fulcio)
		out.Rekor = envOrValue(fmt.Sprintf("%s_REKOR_URL", prefix), out.Rekor)
		out.ClientID = envOrValue(fmt.Sprintf("%s_OIDC_CLIENT_ID", prefix), out.ClientID)
		out.RedirectURL = envOrValue(fmt.Sprintf("%s_OIDC_REDIRECT_URL", prefix), out.RedirectURL)
		out.Issuer = envOrValue(fmt.Sprintf("%s_OIDC_ISSUER", prefix), out.Issuer)
		out.ConnectorID = envOrValue(fmt.Sprintf("%s_CONNECTOR_ID", prefix), out.ConnectorID)
	}

	out.LogPath = envOrValue("GITSIGN_LOG", out.LogPath)

	return out, nil
}

func applyGitOptions(out *Config, opts format.Options) {
	// Iterate over options once instead of using Get (which itself iterates
	// over options until a matching key is found).
	for _, o := range opts {
		switch o.Key {
		case "fulcio":
			out.Fulcio = o.Value
		case "rekor":
			out.Rekor = o.Value
		case "clientID":
			out.ClientID = o.Value
		case "redirectURL":
			out.RedirectURL = o.Value
		case "issuer":
			out.Issuer = o.Value
		case "logPath":
			out.LogPath = o.Value
		case "connectorID":
			out.ConnectorID = o.Value
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
