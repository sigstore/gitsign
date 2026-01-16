// Copyright 2026 The Sigstore Authors
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

package attest

import (
	"encoding/base64"
	"encoding/pem"
	"errors"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/gitsign/pkg/predicate"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// CommitStatement creates an intoto statement representing the git commit
// signature.
//
// Note that the statement has no DSSE envelope, the commit signatures are contained
// in the predicate body,
func CommitStatement(repo *git.Repository, remote, revision string) (*intoto.Statement, error) {
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

	// Build initial predicate from the commit using proto-generated types.
	pred := &predicate.GitCommit{
		Source: &predicate.Commit{
			Tree:    commit.TreeHash.String(),
			Parents: parents,
			Author: &predicate.Author{
				Name:  commit.Author.Name,
				Email: commit.Author.Email,
				Date:  timestamppb.New(commit.Author.When),
			},
			Committer: &predicate.Author{
				Name:  commit.Committer.Name,
				Email: commit.Committer.Email,
				Date:  timestamppb.New(commit.Committer.When),
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
		pred.SignerInfo = sigs
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

	// Convert predicate to structpb.Struct for in-toto Statement.
	jsonBytes, err := protojson.Marshal(pred)
	if err != nil {
		return nil, err
	}
	predicateStruct := &structpb.Struct{}
	if err := protojson.Unmarshal(jsonBytes, predicateStruct); err != nil {
		return nil, err
	}

	// Wrap predicate in in-toto Statement.
	return &intoto.Statement{
		Type: intoto.StatementTypeUri,
		Subject: []*intoto.ResourceDescriptor{
			{
				// TODO?: Figure out if/how to support git sha256 - this
				// will likely depend on upstream support in go-git.
				// See https://github.com/go-git/go-git/issues/229.
				Digest: map[string]string{
					"sha1": hash.String(),
				},
				Name: remoteName,
			},
		},
		Predicate:     predicateStruct,
		PredicateType: predicate.TypeV01,
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
