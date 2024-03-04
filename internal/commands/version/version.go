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

package version

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/version"
	"github.com/spf13/cobra"
)

func New(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "print Gitsign version",
		RunE: func(_ *cobra.Command, _ []string) error {
			v := version.GetVersionInfo()
			fmt.Println("gitsign version", v.GitVersion)
			if len(v.Env) > 0 {
				fmt.Println("env:")
				for _, e := range v.Env {
					fmt.Println("\t", e)
				}
			}
			fmt.Println("parsed config:")
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")

			return enc.Encode(cfg)
		},
	}
	return cmd
}
