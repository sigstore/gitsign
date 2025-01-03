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

package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage"
	"github.com/go-openapi/strfmt"
	"github.com/jonboulle/clockwork"
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/v2/pkg/cosign/attestation"
	"github.com/sigstore/cosign/v2/pkg/types"
	utils "github.com/sigstore/gitsign/internal"
	gitsignconfig "github.com/sigstore/gitsign/internal/config"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	dssesig "github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	CommitRef = "refs/attestations/commits"
	TreeRef   = "refs/attestations/trees"
)

var (
	clock = clockwork.NewRealClock()
)

// rekorUpload stubs out cosign.TLogUploadInTotoAttestation for testing.
type rekorUpload func(ctx context.Context, rekorClient *rekorclient.Rekor, signature []byte, pemBytes []byte) (*models.LogEntryAnon, error)

type Attestor struct {
	repo    *git.Repository
	sv      *sign.SignerVerifier
	rekorFn rekorUpload
	config  *gitsignconfig.Config
}

func NewAttestor(repo *git.Repository, sv *sign.SignerVerifier, rekorFn rekorUpload, config *gitsignconfig.Config) *Attestor {
	return &Attestor{
		repo:    repo,
		sv:      sv,
		rekorFn: rekorFn,
		config:  config,
	}
}

// WriteFile is a convenience wrapper around WriteAttestation that takes in a filepath rather than an io.Reader.
func (a *Attestor) WriteFile(ctx context.Context, refName string, sha plumbing.Hash, path, attType string) (plumbing.Hash, error) {
	f, err := os.Open(path)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	defer f.Close()

	return a.WriteAttestation(ctx, refName, sha, f, attType)
}

type Reader interface {
	io.Reader
	Name() string
}

type NamedReader struct {
	io.Reader
	name string
}

func (r NamedReader) Name() string {
	return r.name
}

func NewNamedReader(r io.Reader, name string) Reader {
	return NamedReader{
		Reader: r,
		name:   name,
	}
}

// WriteAttestion writes the given content + a DSSE signed attestation to the corresponding attestation ref.
// The SHA of the created commit is returned.
//
// repo: What repository to write to.
// refName: What ref to write to (e.g. refs/attestations/commits)
// sha: Commit SHA you are attesting to.
// input: Attestation file input.
// attType: Attestation type. See [attestation.GenerateStatement] for allowed values.
func (a *Attestor) WriteAttestation(ctx context.Context, refName string, sha plumbing.Hash, input Reader, attType string) (plumbing.Hash, error) {
	b, err := io.ReadAll(input)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Write the blob we received verbatim.
	// TODO: is this necessary? should we just extract this data from DSSE?
	blobHash, err := writeBlob(a.repo.Storer, b)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Step 1: Write the files

	// Create the DSSE, sign it, store it.
	sig, err := a.signPayload(ctx, sha, b, attType)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	sigHash, err := writeBlob(a.repo.Storer, sig)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Create 2 files: 1 mirroring the original file basename,
	// another using <basename>.sig for the DSSE.
	// TODO: prevent accidental file overwrites.
	filename := filepath.Base(input.Name())
	entries := []object.TreeEntry{
		{
			Name: filename,
			Mode: filemode.Regular,
			Hash: blobHash,
		},
		{
			Name: filename + ".sig",
			Mode: filemode.Regular,
			Hash: sigHash,
		},
	}

	// Step 2: Write the directories

	// Check current attestation ref to see if there is existing data.
	// If so, make sure old data is preserved.
	var attCommit *object.Commit
	attRef, err := a.repo.Reference(plumbing.ReferenceName(refName), true)
	if err != nil {
		if !errors.Is(err, plumbing.ErrReferenceNotFound) {
			return plumbing.ZeroHash, err
		}
	}
	if attRef != nil {
		attCommit, err = a.repo.CommitObject(attRef.Hash())
		if err != nil {
			return plumbing.ZeroHash, err
		}
	}

	tree, err := buildTree(a.repo, attCommit, sha, entries)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Step 3: Make the commit

	// Grab the user from the repository config so we know who to attribute the commit to.
	cfg, err := a.repo.ConfigScoped(gitconfig.GlobalScope)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	commit := &object.Commit{
		TreeHash: tree,
		Message:  fmt.Sprintf("Gitsign attest %s", filename),
		Author: object.Signature{
			Name:  cfg.User.Name,
			Email: cfg.User.Email,
			When:  clock.Now(),
		},
		Committer: object.Signature{
			Name:  cfg.User.Name,
			Email: cfg.User.Email,
			When:  clock.Now(),
		},
	}
	if attCommit != nil {
		commit.ParentHashes = []plumbing.Hash{attCommit.Hash}
	}
	chash, err := encode(a.repo.Storer, commit)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	if err := a.repo.Storer.CheckAndSetReference(plumbing.NewHashReference(plumbing.ReferenceName(refName), chash), attRef); err != nil {
		return plumbing.ZeroHash, err
	}

	return chash, nil
}

type Encoder interface {
	Encode(o plumbing.EncodedObject) error
}

func encode(store storage.Storer, enc Encoder) (plumbing.Hash, error) {
	obj := store.NewEncodedObject()
	if err := enc.Encode(obj); err != nil {
		return plumbing.ZeroHash, err
	}
	return store.SetEncodedObject(obj)
}

func (a *Attestor) signPayload(ctx context.Context, sha plumbing.Hash, b []byte, attType string) ([]byte, error) {
	// Generate attestation
	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewBuffer(b),
		Type:      attType,
		Digest:    sha.String(),
		Time:      clock.Now,
	})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(sh)
	if err != nil {
		return nil, err
	}
	wrapped := dssesig.WrapSigner(a.sv, types.IntotoPayloadType)
	envelope, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	rekorHost, rekorBasePath := utils.StripURL(a.config.Rekor)
	tc := &rekorclient.TransportConfig{
		Host:     rekorHost,
		BasePath: rekorBasePath,
		Schemes:  []string{"https"},
	}
	rcfg := rekorclient.NewHTTPClientWithConfig(strfmt.Default, tc)

	// Upload to rekor
	entry, err := a.rekorFn(ctx, rcfg, envelope, a.sv.Cert)
	if err != nil {
		return nil, err
	}
	fmt.Println("LogEntry ID", *entry.LogID, *entry.LogIndex)

	return envelope, nil
}

func writeBlob(store storage.Storer, b []byte) (plumbing.Hash, error) {
	obj := store.NewEncodedObject()
	obj.SetType(plumbing.BlobObject)
	w, err := obj.Writer()
	if err != nil {
		return plumbing.ZeroHash, err
	}
	if _, err := w.Write(b); err != nil {
		return plumbing.ZeroHash, err
	}
	return store.SetEncodedObject(obj)
}

// buildTree creates the tree directory for the attestation commit, preserving existing data if present.
// attCommit is the value of the commit that holds the current attestations (i.e. refs/attestations) that we will append values to. If the commit is the zero-SHA, a new, parentless commit will be created.
// targetSHA is the value of the target SHA we are attesting to.
func buildTree(repo *git.Repository, attCommit *object.Commit, targetSHA plumbing.Hash, newEntries []object.TreeEntry) (plumbing.Hash, error) {
	attTree := plumbing.ZeroHash
	if attCommit != nil {
		attTree = attCommit.TreeHash
	}

	// If there's an existing attestation commit, resolve the tree.
	var shaTree plumbing.Hash
	if attTree != plumbing.ZeroHash {
		tree, err := repo.TreeObject(attTree)
		if err != nil {
			return plumbing.ZeroHash, err
		}

		// Look for existing entry corresponding to the target SHA in existing attestation tree.
		for _, t := range tree.Entries {
			if t.Name == targetSHA.String() {
				shaTree = t.Hash
				break
			}
		}
	}

	shaTreeNew, err := appendTree(repo, shaTree, newEntries)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	return appendTree(repo, attTree, []object.TreeEntry{{
		Name: targetSHA.String(),
		Mode: filemode.Dir,
		Hash: shaTreeNew,
	}})
}

// appendTree adds a set of entries to an existing tree.
// If the existing tree is the zero-SHA, then a new tree is created.
func appendTree(repo *git.Repository, treeSHA plumbing.Hash, new []object.TreeEntry) (plumbing.Hash, error) {
	// Build set of entries.
	files := map[string]object.TreeEntry{}

	// If there is already a tree, grab all existing entries.
	if treeSHA != plumbing.ZeroHash {
		// Put existing values into the set.
		filetree, err := repo.TreeObject(treeSHA)
		if err != nil {
			return plumbing.ZeroHash, err
		}
		for _, t := range filetree.Entries {
			files[t.Name] = t
		}
	}

	// Append new values - this will overwrite old entries.
	for _, t := range new {
		files[t.Name] = t
	}

	// Convert back to list.
	entries := make([]object.TreeEntry, 0, len(files))
	for _, e := range files {
		entries = append(entries, e)
	}
	// Git expects trees to be sorted by name.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})

	return encode(repo.Storer, &object.Tree{
		Entries: entries,
	})
}
