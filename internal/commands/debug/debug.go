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

// Package debug implements the "gitsign debug" family of troubleshooting
// commands.
package debug

import (
	"github.com/spf13/cobra"

	"github.com/sigstore/gitsign/internal/config"
)

// New returns the "gitsign debug" parent command.
func New(cfg *config.Config) *cobra.Command {
	cmd := &cobra.Command{
		Use:    "debug",
		Hidden: true,
		Short:  "Debugging tools for gitsign",
		Long: `Debugging tools for gitsign.

These commands help troubleshoot gitsign configuration and the keyless
signing flow. They are intended for interactive debugging and their CLI
surface may change.`,
	}

	cmd.AddCommand(newToken(cfg))

	return cmd
}
