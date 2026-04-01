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

package show

import (
	"encoding/json"
	"io"
	"os"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/attest"
	"github.com/spf13/cobra"
)

type options struct {
	FlagRemote string
}

func (o *options) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.FlagRemote, "remote", "r", "origin", "git remote (used to populate subject)")
}

func (o *options) Run(w io.Writer, args []string) error {
	repo, err := git.PlainOpenWithOptions(".", &git.PlainOpenOptions{
		DetectDotGit: true,
	})
	if err != nil {
		return err
	}
	revision := "HEAD"
	if len(args) > 0 {
		revision = args[0]
	}

	out, err := statement(repo, o.FlagRemote, revision)
	if err != nil {
		return err
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

// statement resolves the revision and returns a tag or commit attestation
// depending on the object type it points to.
func statement(repo *git.Repository, remote, revision string) (*intoto.Statement, error) {
	// First, try to resolve the revision as a tag reference and check if it
	// points to an annotated tag object.
	ref, err := repo.Reference(plumbing.NewTagReferenceName(revision), false)
	if err == nil {
		// The ref exists under refs/tags/. Check the object type.
		if obj, err := repo.Object(plumbing.AnyObject, ref.Hash()); err == nil {
			if obj.Type() == plumbing.TagObject {
				return attest.TagStatement(repo, remote, revision)
			}
		}
	}

	// Not an annotated tag — resolve as a commit.
	return attest.CommitStatement(repo, remote, revision)
}

func New(_ *config.Config) *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "show [revision]",
		Short: "Show source predicate information",
		Long: `Show source predicate information

Prints an in-toto style predicate for the specified revision.
If no revision is specified, HEAD is used.

This command is experimental, and its CLI surface may change.`,
		RunE: func(_ *cobra.Command, args []string) error {
			return o.Run(os.Stdout, args)
		},
	}

	o.AddFlags(cmd)

	return cmd
}
