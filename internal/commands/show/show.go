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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/in-toto/in-toto-golang/in_toto"
	v02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/predicate"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/spf13/cobra"
)

const (
	predicateType = "https://gitsign.sigstore.dev/predicate/git/v0.1"
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
	if err := enc.Encode(out); err != nil {
		return err
	}

	return nil
}

func statement(repo *git.Repository, remote, revision string) (*in_toto.Statement, error) {
	hash, err := repo.ResolveRevision(plumbing.Revision(revision))
	if err != nil {
		return nil, err
	}
	commit, err := repo.CommitObject(*hash)
	if err != nil {
		return nil, err
	}

	// Extract parent hashes
	parents := make([]string, 0, len(commit.ParentHashes))
	for _, p := range commit.ParentHashes {
		if !p.IsZero() {
			parents = append(parents, p.String())
		}
	}

	// Build initial predicate from the commit.
	predicate := &predicate.GitCommit{
		Commit: &predicate.Commit{
			Tree:    commit.TreeHash.String(),
			Parents: parents,
			Author: &predicate.Author{
				Name:  commit.Author.Name,
				Email: commit.Author.Email,
				Date:  commit.Author.When,
			},
			Committer: &predicate.Author{
				Name:  commit.Committer.Name,
				Email: commit.Committer.Email,
				Date:  commit.Committer.When,
			},
			Message: commit.Message,
		},
		Signature: commit.PGPSignature,
	}

	// We have a PEM encoded signature, try and extract certificate details.
	pem, _ := pem.Decode([]byte(commit.PGPSignature))
	if pem != nil {
		sigs, err := parseSignature(pem.Bytes)
		if err != nil {
			return nil, err
		}
		predicate.SignerInfo = sigs
	}

	// Try and resolve the remote name to use as the subject name.
	// If the repo does not have a remote configured then this will be left
	// blank.
	resolvedRemote, err := repo.Remote(remote)
	if err != nil && !errors.Is(err, git.ErrRemoteNotFound) {
		return nil, err
	}
	remoteName := ""
	if resolvedRemote != nil && resolvedRemote.Config() != nil && len(resolvedRemote.Config().URLs) > 0 {
		remoteName = resolvedRemote.Config().URLs[0]
	}

	// Wrap predicate in in-toto Statement.
	return &in_toto.Statement{
		StatementHeader: in_toto.StatementHeader{
			Type: in_toto.StatementInTotoV01,
			Subject: []in_toto.Subject{{
				Name: remoteName,
				Digest: v02.DigestSet{
					// TODO?: Figure out if/how to support git sha256 - this
					// will likely depend on upstream support in go-git.
					// See https://github.com/go-git/go-git/issues/229.
					"sha1": hash.String(),
				},
			}},
			PredicateType: predicateType,
		},
		Predicate: predicate,
	}, nil
}

func parseSignature(raw []byte) ([]*predicate.SignerInfo, error) {
	ci, err := protocol.ParseContentInfo(raw)
	if err != nil {
		return nil, err
	}

	sd, err := ci.SignedDataContent()
	if err != nil {
		return nil, err
	}

	certs, err := sd.X509Certificates()
	if err != nil {
		return nil, err
	}

	// A signature may have multiple signers associated to it -
	// extract each SignerInfo separately.
	out := make([]*predicate.SignerInfo, 0, len(sd.SignerInfos))
	for _, si := range sd.SignerInfos {
		cert, err := si.FindCertificate(certs)
		if err != nil {
			continue
		}
		b, err := cryptoutils.MarshalCertificateToPEM(cert)
		if err != nil {
			return nil, err
		}
		sa, err := si.SignedAttrs.MarshaledForVerification()
		if err != nil {
			return nil, err
		}
		out = append(out, &predicate.SignerInfo{
			Certificate: string(b),
			Attributes:  base64.StdEncoding.EncodeToString(sa),
		})
	}

	return out, nil
}

func New(cfg *config.Config) *cobra.Command {
	o := &options{}

	cmd := &cobra.Command{
		Use:   "show [revision]",
		Short: "Show source predicate information",
		Long: `Show source predicate information

Prints an in-toto style predicate for the specified revision.
If no revision is specified, HEAD is used.

This command is experimental, and its CLI surface may change.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return o.Run(os.Stdout, args)
		},
	}
	o.AddFlags(cmd)

	return cmd
}
