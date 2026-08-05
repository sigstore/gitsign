//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package credentials

import (
	"errors"
	"fmt"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/keyring"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/spf13/cobra"
)

// New returns the `gitsign credentials` command group for managing cached
// signing credentials (see gitsign.credentialCacheMode).
func New(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "credentials",
		Short: "Manage cached signing credentials",
		Long: "Manage cached signing credentials.\n\n" +
			"The credential cache backend is selected by gitsign.credentialCacheMode:\n" +
			"the system keyring (`system`), or the gitsign-credential-cache daemon\n" +
			"(`socket`). When no mode is configured, the system keyring is used.",
	}
	cmd.AddCommand(newList(cfg))
	cmd.AddCommand(newClear(cfg))
	return cmd
}

// newManager returns the credential cache backend selected by the config.
// Unlike the signing path, no certificate roots are loaded - management
// operations don't validate certs.
func newManager(cfg *config.Config) (cache.Manager, error) {
	switch strings.ToLower(cfg.CredentialCacheMode) {
	case "", "system":
		// Default to the keyring when no mode is set so that entries are
		// inspectable even before caching is enabled.
		if cfg.CredentialCacheMode == "" && cfg.CredentialCache != "" {
			// A socket path without a mode selects the daemon (matching the
			// signing path).
			return cache.NewClient(cfg.CredentialCache, cfg, nil, nil)
		}
		return &keyring.Cache{Config: cfg}, nil
	case "socket":
		if cfg.CredentialCache == "" {
			return nil, fmt.Errorf("credential cache mode %q requires a socket path (set GITSIGN_CREDENTIAL_CACHE)", cfg.CredentialCacheMode)
		}
		return cache.NewClient(cfg.CredentialCache, cfg, nil, nil)
	default:
		return nil, fmt.Errorf("unknown credential cache mode %q (expected one of: system, socket)", cfg.CredentialCacheMode)
	}
}

func newList(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List cached signing credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newManager(cfg)
			if err != nil {
				return err
			}
			entries, err := m.List(cmd.Context())
			if err != nil {
				return err
			}
			if len(entries) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no cached credentials")
				return nil
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 8, 2, ' ', 0)
			fmt.Fprintln(w, "EMAIL\tISSUER\tCLIENTID\tCONNECTOR\tFULCIO\tEXPIRES\tSTATUS")
			for _, e := range entries {
				status := "valid"
				if time.Now().After(e.NotAfter) {
					status = "expired"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					orDash(e.Meta.CommitterEmail),
					orDash(e.Meta.Issuer),
					orDash(e.Meta.ClientID),
					orDash(e.Meta.ConnectorID),
					orDash(e.Meta.Fulcio),
					e.NotAfter.Local().Format(time.RFC3339),
					status,
				)
			}
			return w.Flush()
		},
	}
}

func newClear(cfg *config.Config) *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "clear",
		Short: "Remove cached signing credentials",
		Long: "Remove cached signing credentials.\n\n" +
			"By default only the credential for the current configuration\n" +
			"(Fulcio URL, OIDC issuer, client ID, connector ID, and committer email)\n" +
			"is removed. Use --all to remove all cached credentials.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m, err := newManager(cfg)
			if err != nil {
				return err
			}
			if all {
				if err := m.DeleteAll(cmd.Context()); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "cleared all cached credentials")
				return nil
			}
			if err := m.Delete(cmd.Context()); err != nil {
				if errors.Is(err, cache.ErrNotFound) {
					fmt.Fprintln(cmd.OutOrStdout(), "no cached credential for the current configuration")
					return nil
				}
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "cleared cached credential for the current configuration")
			return nil
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "remove all cached credentials")
	return cmd
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
