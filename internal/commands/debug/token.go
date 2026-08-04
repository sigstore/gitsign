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

package debug

import (
	"context"
	"fmt"

	"github.com/pkg/browser"
	"github.com/spf13/cobra"

	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio"
	gsio "github.com/sigstore/gitsign/internal/io"
)

// newToken returns the "gitsign debug token" command, which runs the configured
// OIDC auth flow and prints the raw ID token gitsign would exchange for a Fulcio
// signing certificate.
func newToken(cfg *config.Config) *cobra.Command {
	return &cobra.Command{
		Use:   "token",
		Short: "Print the OIDC token fetched by gitsign",
		Long: `Print the OIDC token fetched by gitsign.

Runs the same keyless auth flow gitsign uses when signing and prints the raw
OIDC token (a JWT) that would be exchanged for a Fulcio signing certificate.
No certificate is requested and nothing is signed.

The token is written to stdout so it can be piped or inspected; all prompts
and status messages are written to the TTY/stderr. Treat the token as a
credential - it grants the ability to obtain a signing certificate for your
identity.`,
		RunE: func(_ *cobra.Command, _ []string) error {
			s := gsio.New(cfg.LogPath)
			defer s.Close() // nolint:errcheck

			// Configure the browser opener to use the TTY streams so the auth
			// flow prompts don't pollute stdout, which carries the token.
			browser.Stdout = s.TTYOut
			browser.Stderr = s.TTYOut

			return s.Wrap(func() error {
				idf := fulcio.NewIdentityFactory(s.TTYIn, s.TTYOut)
				tok, err := idf.GetToken(context.Background(), cfg)
				if err != nil {
					return fmt.Errorf("failed to get token: %w", err)
				}
				fmt.Fprintln(s.Out, tok.RawString) // nolint:errcheck
				return nil
			})
		},
	}
}
