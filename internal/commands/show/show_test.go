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
	"fmt"
	"os"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/sigstore/gitsign/pkg/attest"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestShow(t *testing.T) {
	storage := memory.NewStorage()
	repo := &git.Repository{
		Storer: storage,
	}
	if err := repo.SetConfig(&config.Config{
		Remotes: map[string]*config.RemoteConfig{
			"origin": {
				Name: "origin",
				URLs: []string{"git@github.com:wlynch/gitsign.git"},
			},
		},
	}); err != nil {
		t.Fatalf("error setting git config: %v", err)
	}

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
			obj := storage.NewEncodedObject()
			obj.SetType(plumbing.CommitObject)
			w, err := obj.Writer()
			if err != nil {
				t.Fatalf("error getting git object writer: %v", err)
			}
			_, err = w.Write(raw)
			if err != nil {
				t.Fatalf("error writing git commit: %v", err)
			}
			h, err := storage.SetEncodedObject(obj)
			if err != nil {
				t.Fatalf("error storing git commit: %v", err)
			}

			got, err := attest.CommitStatement(repo, "origin", h.String())
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
