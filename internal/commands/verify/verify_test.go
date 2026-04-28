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

package verify

import (
	"errors"
	"io"
	"testing"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sigstore/gitsign/pkg/git"
)

// TestRun_RejectsUnsupportedSignatureType confirms the sentinel is wrapped
// so callers can errors.Is on it. End-to-end coverage of the GHSA
// trust-confusion attack lives in
// internal/gitsign/invalid_object_test.go::TestDuplicateTreeTrustConfusion.
func TestRun_RejectsUnsupportedSignatureType(t *testing.T) {
	tmpDir := t.TempDir()
	repo, err := gogit.PlainInit(tmpDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	// Well-formed commit but with a PGP SIGNATURE (not SIGNED MESSAGE) in gpgsig.
	raw := []byte(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
gpgsig -----BEGIN PGP SIGNATURE-----
 ZmFrZQ==
 -----END PGP SIGNATURE-----

hi
`)

	obj := repo.Storer.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("obj.Writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	h, err := repo.Storer.SetEncodedObject(obj)
	if err != nil {
		t.Fatalf("SetEncodedObject: %v", err)
	}

	t.Chdir(tmpDir)

	opts := &options{}
	err = opts.Run(io.Discard, []string{h.String()})
	if !errors.Is(err, git.ErrUnsupportedSignatureType) {
		t.Fatalf("want error wrapping ErrUnsupportedSignatureType, got %v", err)
	}
}
