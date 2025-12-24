//
// Copyright 2023 The Sigstore Authors.
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

// Package initialize inits the TUF root for the tool.
// This is intended to replicate the behavior of `gitsign initialize`.
package initialize

import (
	"github.com/sigstore/cosign/v3/cmd/cosign/cli/initialize"
	"github.com/sigstore/sigstore/pkg/tuf"
	"github.com/spf13/cobra"
)

type options struct {
	Mirror string
	Root   string
}

// AddFlags implements Interface
func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&o.Mirror, "mirror", tuf.DefaultRemoteRoot,
		"GCS bucket to a Sigstore TUF repository, or HTTP(S) base URL, or file:/// for local filestore remote (air-gap)")

	cmd.Flags().StringVar(&o.Root, "root", "",
		"path to trusted initial root. defaults to embedded root")
	_ = cmd.Flags().SetAnnotation("root", cobra.BashCompSubdirsInDir, []string{})
}

func New() *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "initialize",
		Short: "Initializes Sigstore root to retrieve trusted certificate and key targets for verification.",
		Long: `Initializes Sigstore root to retrieve trusted certificate and key targets for verification.

The following options are used by default:
 - The current trusted Sigstore TUF root is embedded inside gitsign at the time of release.
 - Sigstore remote TUF repository is pulled from the CDN mirror at tuf-repo-cdn.sigstore.dev.

To provide an out-of-band trusted initial root.json, use the -root flag with a file or URL reference.
This will enable you to point gitsign to a separate TUF root.

Any updated TUF repository will be written to $HOME/.sigstore/root/.

Trusted keys and certificate used in gitsign verification (e.g. verifying Fulcio issued certificates
with Fulcio root CA) are pulled form the trusted metadata.`,
		Example: `gitsign initialize -mirror <url> -out <file>

# initialize root with distributed root keys, default mirror, and default out path.
gitsign initialize

# initialize with an out-of-band root key file, using the default mirror.
gitsign initialize -root <url>

# initialize with an out-of-band root key file and custom repository mirror.
gitsign initialize -mirror <url> -root <url>`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return initialize.DoInitialize(cmd.Context(), o.Root, o.Mirror)
		},
	}

	o.AddFlags(cmd)
	return cmd
}
