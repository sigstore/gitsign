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
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/cosign/pkg/cosign/attestation"
	"github.com/sigstore/cosign/pkg/types"
	rekorclient "github.com/sigstore/rekor/pkg/generated/client"
	dssesig "github.com/sigstore/sigstore/pkg/signature/dsse"
	signatureoptions "github.com/sigstore/sigstore/pkg/signature/options"
)

const (
	CommitRef = "refs/attestations/commits"
	TreeRef   = "refs/attestations/trees"
)

// WriteFile writes the given file + a DSSE signed attestation to the corresponding attestation ref.
// The SHA of the created commit is returned.
func WriteFile(ctx context.Context, repo *git.Repository, refName string, sha plumbing.Hash, path, attType string) (plumbing.Hash, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	// Write the blob we received verbatim.
	// TODO: is this necessary? should we just extract this data from DSSE?
	blobHash, err := writeBlob(repo.Storer, b)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Step 1: Write the files

	// Create the DSSE, sign it, store it.
	sig, err := signPayload(ctx, sha, b, attType)
	if err != nil {
		return plumbing.ZeroHash, err
	}
	sigHash, err := writeBlob(repo.Storer, sig)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Create 2 files: 1 mirroring the original file basename,
	// another using <basename>.sig for the DSSE.
	// TODO: prevent accidental file overwrites.
	filename := filepath.Base(path)
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
	attRef, err := repo.Reference(plumbing.ReferenceName(refName), true)
	if err != nil {
		if !errors.Is(err, plumbing.ErrReferenceNotFound) {
			return plumbing.ZeroHash, err
		}
	}
	if attRef != nil {
		attCommit, err = repo.CommitObject(attRef.Hash())
		if err != nil {
			return plumbing.ZeroHash, err
		}
	}

	tree, err := buildTree(repo, attCommit, sha, entries)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	// Step 3: Make the commit

	// Grab the user from the repository config so we know who to attribute the commit to.
	cfg, err := repo.ConfigScoped(config.GlobalScope)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	commit := &object.Commit{
		TreeHash: tree,
		Message:  fmt.Sprintf("Gitsign attest %s", filename),
		Author: object.Signature{
			Name:  cfg.User.Name,
			Email: cfg.User.Email,
			When:  time.Now(),
		},
		Committer: object.Signature{
			Name:  cfg.User.Name,
			Email: cfg.User.Email,
			When:  time.Now(),
		},
	}
	if attCommit != nil {
		commit.ParentHashes = []plumbing.Hash{attCommit.Hash}
	}
	chash, err := encode(repo.Storer, commit)
	if err != nil {
		return plumbing.ZeroHash, err
	}

	if err := repo.Storer.CheckAndSetReference(plumbing.NewHashReference(plumbing.ReferenceName(refName), chash), attRef); err != nil {
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

func signPayload(ctx context.Context, sha plumbing.Hash, b []byte, attType string) ([]byte, error) {
	// Get ephemeral key
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", options.KeyOpts{
		FulcioURL:    "https://fulcio.sigstore.dev",
		RekorURL:     "https://rekor.sigstore.dev",
		OIDCIssuer:   "https://oauth2.sigstore.dev/auth",
		OIDCClientID: "sigstore",
	})
	if err != nil {
		return nil, fmt.Errorf("getting signer: %w", err)
	}
	defer sv.Close()

	// Generate attestation
	sh, err := attestation.GenerateStatement(attestation.GenerateOpts{
		Predicate: bytes.NewBuffer(b),
		Type:      attType,
		Digest:    sha.String(),
		//Repo:      digest.Repository.String(),
	})
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(sh)
	if err != nil {
		return nil, err
	}
	wrapped := dssesig.WrapSigner(sv, types.IntotoPayloadType)
	envelope, err := wrapped.SignMessage(bytes.NewReader(payload), signatureoptions.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	// Upload to rekor
	entry, err := cosign.TLogUploadInTotoAttestation(ctx, rekorclient.Default, envelope, sv.Cert)
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

	return encode(repo.Storer, &object.Tree{
		Entries: entries,
	})
}
