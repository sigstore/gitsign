//
// Copyright 2022 The Sigstore Authors.
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

package root

import (
	"github.com/spf13/cobra"

	"github.com/sigstore/gitsign/internal/commands/attest"
	"github.com/sigstore/gitsign/internal/commands/initialize"
	"github.com/sigstore/gitsign/internal/commands/show"
	"github.com/sigstore/gitsign/internal/commands/verify"
	verifytag "github.com/sigstore/gitsign/internal/commands/verify-tag"
	"github.com/sigstore/gitsign/internal/commands/version"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/io"
)

type options struct {
	Config *config.Config

	FlagSign    bool
	FlagVerify  bool
	FlagVersion bool

	FlagLocalUser         string
	FlagDetachedSignature bool
	FlagArmor             bool
	FlagStatusFD          int
	FlagIncludeCerts      int
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().BoolVarP(&o.FlagSign, "sign", "s", false, "make a signature")
	cmd.Flags().BoolVarP(&o.FlagVerify, "verify", "v", false, "verify a signature")
	cmd.Flags().BoolVar(&o.FlagVersion, "version", false, "print Gitsign version")

	cmd.Flags().StringVarP(&o.FlagLocalUser, "local-user", "u", "", "use USER-ID to sign")
	cmd.Flags().BoolVarP(&o.FlagDetachedSignature, "detached-sign", "", false, "make a detached signature")
	cmd.Flags().BoolVarP(&o.FlagDetachedSignature, "detach-sign", "b", false, "make a detached signature")
	cmd.Flags().BoolVarP(&o.FlagArmor, "armor", "a", false, "create ascii armored output")
	cmd.Flags().IntVar(&o.FlagStatusFD, "status-fd", -1, "write special status strings to the file descriptor n.")
	cmd.Flags().IntVar(&o.FlagIncludeCerts, "include-certs", -2, "-3 is the same as -2, but omits issuer when cert has Authority Information Access extension. -2 includes all certs except root. -1 includes all certs. 0 includes no certs. 1 includes leaf cert. >1 includes n from the leaf. Default -2.")

	cmd.Flags().MarkDeprecated("detached-sign", "--detached-sign has been deprecated in favor of --detach-sign to match the interface of other signing tools") // nolint:errcheck // nolint:gosec
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{Config: cfg}

	rootCmd := &cobra.Command{
		Use:               "gitsign",
		Short:             "Keyless Git signing with Sigstore!",
		Args:              cobra.ArbitraryArgs,
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			s := io.New(o.Config.LogPath)
			defer s.Close()
			return s.Wrap(func() error {
				switch {
				case o.FlagVersion:
					// Alias root --version with version subcommand
					for _, item := range cmd.Commands() {
						if item.Name() == "version" {
							return item.RunE(item, cmd.Flags().Args())
						}
					}
				case o.FlagSign, o.FlagDetachedSignature:
					return commandSign(o, s, args...)
				case o.FlagVerify:
					return commandVerify(o, s, args...)
				default:
					return cmd.Help()
				}
				return nil
			})
		},
	}

	rootCmd.AddCommand(version.New(cfg))
	rootCmd.AddCommand(show.New(cfg))
	rootCmd.AddCommand(attest.New(cfg))
	rootCmd.AddCommand(verify.New(cfg))
	rootCmd.AddCommand(verifytag.New(cfg))
	rootCmd.AddCommand(initialize.New())
	o.AddFlags(rootCmd)

	return rootCmd
}
