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
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"

	"github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/jonboulle/clockwork"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	tmpl = template.Must(template.ParseFiles("testdata/test.json.provenance"))
)

func TestMain(m *testing.M) {
	clock = clockwork.NewFakeClock()
	os.Exit(m.Run())
}

func TestAttestCommitRef(t *testing.T) {
	sv := &sign.SignerVerifier{SignerVerifier: fakeSV{}}
	ctx := context.Background()

	storer := memory.NewStorage()
	fs := memfs.New()
	repo, err := git.Init(storer, fs)
	if err != nil {
		t.Fatalf("error creating repo: %v", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	sha := writeRepo(t, w, fs, "testdata/foo.txt")

	name := "test.json"
	content := readFile(t, filepath.Join("testdata/", name))

	attestor := NewAttestor(repo, sv, fakeRekor)

	fc := []fileContent{
		{
			Name:    filepath.Join(sha.String(), "test.json"),
			Content: readFile(t, "testdata/test.json"),
		},
		{
			Name:    filepath.Join(sha.String(), "test.json.sig"),
			Content: generateAttestation(t, sha),
		},
	}
	t.Run("base", func(t *testing.T) {
		attest1, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest1, fc)
	})

	t.Run("noop", func(t *testing.T) {
		// Write same attestation to the same commit - should be a no-op.
		attest2, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest2, fc)
	})

	t.Run("new commit", func(t *testing.T) {
		// Make a new commit, write new attestation.

		sha, err = w.Commit("empty commit", &git.CommitOptions{
			Author:    &object.Signature{},
			Committer: &object.Signature{},
		})
		if err != nil {
			t.Fatal(err)
		}

		attest3, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		fc = append(fc,
			fileContent{
				Name:    filepath.Join(sha.String(), "test.json"),
				Content: content,
			},
			fileContent{
				Name:    filepath.Join(sha.String(), "test.json.sig"),
				Content: generateAttestation(t, sha),
			},
		)
		verifyContent(t, repo, attest3, fc)
	})
}

func TestAttestTreeRef(t *testing.T) {
	sv := &sign.SignerVerifier{SignerVerifier: fakeSV{}}
	ctx := context.Background()

	storer := memory.NewStorage()
	fs := memfs.New()
	repo, err := git.Init(storer, fs)
	if err != nil {
		t.Fatalf("error creating repo: %v", err)
	}
	w, err := repo.Worktree()
	if err != nil {
		t.Fatal(err)
	}

	sha := resolveTree(t, repo, writeRepo(t, w, fs, "testdata/foo.txt"))

	name := "test.json"
	content := readFile(t, filepath.Join("testdata", name))

	attestor := NewAttestor(repo, sv, fakeRekor)

	fc := []fileContent{
		{
			Name:    filepath.Join(sha.String(), "test.json"),
			Content: readFile(t, "testdata/test.json"),
		},
		{
			Name:    filepath.Join(sha.String(), "test.json.sig"),
			Content: generateAttestation(t, sha),
		},
	}
	t.Run("base", func(t *testing.T) {
		attest1, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest1, fc)
	})

	t.Run("noop", func(t *testing.T) {
		// Write same attestation to the same commit - should be a no-op.
		attest2, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest2, fc)
	})

	t.Run("new commit same tree", func(t *testing.T) {
		// Make a new commit, but since this will point to the same tree, attestation is a no-op.
		sha, err = w.Commit("empty commit", &git.CommitOptions{
			Author:    &object.Signature{},
			Committer: &object.Signature{},
		})
		if err != nil {
			t.Fatal(err)
		}
		sha = resolveTree(t, repo, sha)

		attest3, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest3, fc)
	})

	t.Run("new commit new tree", func(t *testing.T) {
		// Make a new commit, write new attestation.
		sha = resolveTree(t, repo, writeRepo(t, w, fs, "testdata/bar.txt"))

		attest3, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}

		fc = append(fc,
			fileContent{
				Name:    filepath.Join(sha.String(), "test.json"),
				Content: content,
			},
			fileContent{
				Name:    filepath.Join(sha.String(), "test.json.sig"),
				Content: generateAttestation(t, sha),
			},
		)
		verifyContent(t, repo, attest3, fc)
	})
}

type fileContent struct {
	Name    string
	Content string
}

func verifyContent(t *testing.T, repo *git.Repository, sha plumbing.Hash, want []fileContent) {
	t.Helper()

	commit, err := repo.CommitObject(sha)
	if err != nil {
		t.Fatal(err)
	}

	files, err := commit.Files()
	if err != nil {
		t.Fatal(err)
	}

	got := []fileContent{}
	if err := files.ForEach(func(c *object.File) error {
		content, err := c.Contents()
		if err != nil {
			return err
		}

		got = append(got, fileContent{
			Name:    c.Name,
			Content: content,
		})

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(want, got, cmpopts.SortSlices(func(i, j fileContent) bool {
		return i.Name < j.Name
	})); diff != "" {
		t.Error(diff)
	}
}

type fakeSV struct {
	signature.SignerVerifier
}

func (fakeSV) SignMessage(message io.Reader, opts ...signature.SignOption) ([]byte, error) {
	return []byte("tacocat"), nil
}

func fakeRekor(ctx context.Context, rekorClient *client.Rekor, signature, pemBytes []byte) (*models.LogEntryAnon, error) {
	id := "foo"
	index := int64(1)
	return &models.LogEntryAnon{
		LogID:    &id,
		LogIndex: &index,
	}, nil
}

func readFile(t *testing.T, path string) string {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func writeRepo(t *testing.T, w *git.Worktree, fs billy.Filesystem, path string) plumbing.Hash {
	content := readFile(t, path)
	f, err := fs.Create(filepath.Base(path))
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte(content))
	f.Close()

	w.Add(f.Name())
	sha, err := w.Commit(f.Name(), &git.CommitOptions{
		Author:    &object.Signature{},
		Committer: &object.Signature{},
	})
	if err != nil {
		t.Fatal(err)
	}

	return sha
}

func generateAttestation(t *testing.T, h plumbing.Hash) string {
	t.Helper()

	b := new(bytes.Buffer)
	if err := tmpl.Execute(b, h); err != nil {
		t.Fatal(err)
	}

	att := dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString(b.Bytes()),
		Signatures:  []dsse.Signature{{Sig: "dGFjb2NhdA=="}},
	}

	out, err := json.Marshal(att)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func resolveTree(t *testing.T, repo *git.Repository, h plumbing.Hash) plumbing.Hash {
	t.Helper()
	commit, err := repo.CommitObject(h)
	if err != nil {
		t.Fatal(err)
	}
	return commit.TreeHash
}
