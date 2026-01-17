// Copyright 2023 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package gittest

import (
	"io"
	"os"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
)

func ParseCommit(t *testing.T, path string) *object.Commit {
	raw, err := os.ReadFile(path) // nolint:gosec
	if err != nil {
		t.Fatalf("error reading input: %v", err)
	}

	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("error getting git object writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("error writing git commit: %v", err)
	}

	c, err := object.DecodeCommit(storage, obj)
	if err != nil {
		t.Fatalf("error decoding commit: %v", err)
	}
	return c
}

func MarshalCommitBody(t *testing.T, commit *object.Commit) []byte {
	t.Helper()
	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	if err := commit.EncodeWithoutSignature(obj); err != nil {
		t.Fatal(err)
	}
	r, err := obj.Reader()
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	return body
}
