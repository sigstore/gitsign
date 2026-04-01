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
	"fmt"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

// newTestRepo creates an in-memory repo with the given remote configuration.
func newTestRepo(t *testing.T, remoteURL string) (*git.Repository, *memory.Storage) {
	t.Helper()
	storage := memory.NewStorage()
	repo := &git.Repository{
		Storer: storage,
	}
	if err := repo.SetConfig(&config.Config{
		Remotes: map[string]*config.RemoteConfig{
			"origin": {
				Name: "origin",
				URLs: []string{remoteURL},
			},
		},
	}); err != nil {
		t.Fatalf("error setting git config: %v", err)
	}
	return repo, storage
}

// storeObject writes raw object bytes into the storage and returns the hash.
func storeObject(t *testing.T, storage *memory.Storage, objType plumbing.ObjectType, raw []byte) plumbing.Hash {
	t.Helper()
	obj := storage.NewEncodedObject()
	obj.SetType(objType)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("error getting git object writer: %v", err)
	}
	if _, err = w.Write(raw); err != nil {
		t.Fatalf("error writing git object: %v", err)
	}
	h, err := storage.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("error storing git object: %v", err)
	}
	return h
}

func TestCommitStatement(t *testing.T) {
	repo, storage := newTestRepo(t, "git@github.com:wlynch/gitsign.git")

	// Expect files in testdata directory:
	//  foo.in.txt -> foo.out.json
	// IMPORTANT: When generating new test files, use a command like `git cat-file commit main > foo.in.txt`.
	// If you try and copy/paste the content, you may get burned by file encodings and missing \r characters.
	for _, tc := range []string{
		"fulcio-cert",
		"gpg",
	} {
		t.Run(tc, func(t *testing.T) {
			raw, err := os.ReadFile(fmt.Sprintf("testdata/%s.in.txt", tc))
			if err != nil {
				t.Fatalf("error reading input: %v", err)
			}
			h := storeObject(t, storage, plumbing.CommitObject, raw)

			got, err := CommitStatement(repo, "origin", h.String())
			if err != nil {
				t.Fatalf("statement(): %v", err)
			}

			wantRaw, err := os.ReadFile(fmt.Sprintf("testdata/%s.out.json", tc))
			if err != nil {
				t.Fatalf("error reading want json: %v", err)
			}

			want := &intoto.Statement{}
			if err := protojson.Unmarshal(wantRaw, want); err != nil {
				t.Fatalf("error decoding want json: %v", err)
			}

			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestTagStatement(t *testing.T) {
	repo, storage := newTestRepo(t, "git@github.com:wlynch/gitsign.git")

	// IMPORTANT: When generating new test files, use `git cat-file tag <tagname> > foo.in.txt`.
	for _, tc := range []string{
		"fulcio-tag",
	} {
		t.Run(tc, func(t *testing.T) {
			raw, err := os.ReadFile(fmt.Sprintf("testdata/%s.in.txt", tc))
			if err != nil {
				t.Fatalf("error reading input: %v", err)
			}
			h := storeObject(t, storage, plumbing.TagObject, raw)

			// Create a tag reference pointing to the stored tag object.
			tagRef := plumbing.NewHashReference(plumbing.NewTagReferenceName(tc), h)
			if err := storage.SetReference(tagRef); err != nil {
				t.Fatalf("error setting tag reference: %v", err)
			}

			got, err := TagStatement(repo, "origin", tc)
			if err != nil {
				t.Fatalf("TagStatement(): %v", err)
			}

			wantRaw, err := os.ReadFile(fmt.Sprintf("testdata/%s.out.json", tc))
			if err != nil {
				t.Fatalf("error reading want json: %v", err)
			}

			want := &intoto.Statement{}
			if err := protojson.Unmarshal(wantRaw, want); err != nil {
				t.Fatalf("error decoding want json: %v", err)
			}

			if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
				t.Error(diff)
			}
		})
	}
}

func TestTagStatementLightweight(t *testing.T) {
	repo, storage := newTestRepo(t, "git@github.com:wlynch/gitsign.git")

	// Store a commit object so the lightweight tag has something to point to.
	raw, err := os.ReadFile("testdata/fulcio-cert.in.txt")
	if err != nil {
		t.Fatalf("error reading input: %v", err)
	}
	commitHash := storeObject(t, storage, plumbing.CommitObject, raw)

	// Create a lightweight tag (ref pointing directly at the commit).
	tagRef := plumbing.NewHashReference(plumbing.NewTagReferenceName("lightweight"), commitHash)
	if err := storage.SetReference(tagRef); err != nil {
		t.Fatalf("error setting tag reference: %v", err)
	}

	// Lightweight tags are not annotated, so TagStatement should return an error.
	_, err = TagStatement(repo, "origin", "lightweight")
	if err == nil {
		t.Fatal("expected error for lightweight tag, got nil")
	}
}
