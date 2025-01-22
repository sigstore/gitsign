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
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"text/template"
	"time"

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
	"github.com/sigstore/cosign/v2/cmd/cosign/cli/sign"
	gitsignconfig "github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/signature"
)

var (
	tmpl = template.Must(template.ParseFiles("testdata/test.json.provenance"))
)

func TestMain(m *testing.M) {
	clock = clockwork.NewFakeClockAt(time.Date(1984, time.April, 4, 0, 0, 0, 0, time.UTC))
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

	cfg, err := gitsignconfig.Get()
	if err != nil {
		t.Fatal(err)
	}

	attestor := NewAttestor(repo, sv, fakeRekor, cfg, DigestTypeCommit)

	ad := []gitAttestData{
		{
			sha:         sha,
			predName:    "test.json",
			predicate:   readFile(t, "testdata/test.json"),
			attName:     "test.json.sig",
			attestation: generateAttestation(t, "gitCommit", sha),
		},
	}

	t.Run("base", func(t *testing.T) {
		attest1, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest1, ad)
	})

	t.Run("noop", func(t *testing.T) {
		// Write same attestation to the same commit - should be a no-op.
		attest2, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest2, ad)
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

		attest3, err := attestor.WriteAttestation(ctx, CommitRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		ad = append(ad,
			gitAttestData{
				sha:         sha,
				predName:    "test.json",
				predicate:   readFile(t, "testdata/test.json"),
				attName:     "test.json.sig",
				attestation: generateAttestation(t, "gitCommit", sha),
			},
		)
		verifyContent(t, repo, attest3, ad)
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

	cfg, _ := gitsignconfig.Get()

	attestor := NewAttestor(repo, sv, fakeRekor, cfg, DigestTypeTree)

	ad := []gitAttestData{
		{
			sha:         sha,
			predName:    "test.json",
			predicate:   readFile(t, "testdata/test.json"),
			attName:     "test.json.sig",
			attestation: generateAttestation(t, "gitTree", sha),
		},
	}
	t.Run("base", func(t *testing.T) {
		attest1, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest1, ad)
	})

	t.Run("noop", func(t *testing.T) {
		// Write same attestation to the same commit - should be a no-op.
		attest2, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest2, ad)
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

		attest3, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}
		verifyContent(t, repo, attest3, ad)
	})

	t.Run("new commit new tree", func(t *testing.T) {
		// Make a new commit, write new attestation.
		sha = resolveTree(t, repo, writeRepo(t, w, fs, "testdata/bar.txt"))

		attest3, err := attestor.WriteAttestation(ctx, TreeRef, sha, NewNamedReader(bytes.NewBufferString(content), name), "custom-pred-type")
		if err != nil {
			t.Fatalf("WriteAttestation: %v", err)
		}

		ad = append(ad,
			gitAttestData{
				sha:         sha,
				predName:    "test.json",
				predicate:   readFile(t, "testdata/test.json"),
				attName:     "test.json.sig",
				attestation: generateAttestation(t, "gitTree", sha),
			},
		)
		verifyContent(t, repo, attest3, ad)
	})
}

type gitAttestData struct {
	sha         plumbing.Hash
	predName    string
	predicate   string
	attName     string
	attestation string
}

func verifyContent(t *testing.T, repo *git.Repository, sha plumbing.Hash, want []gitAttestData) {
	t.Helper()

	commit, err := repo.CommitObject(sha)
	if err != nil {
		t.Fatal(err)
	}

	for _, w := range want {
		// We'll just check the raw predicate file that was written,
		// that doesn't get marshaled so it should be untouched.
		fname := fmt.Sprintf("%v/%v", w.sha, w.predName)
		gotPredFile, err := commit.File(fname)
		if err != nil {
			t.Fatal(err)
		}
		gotPred, err := gotPredFile.Contents()
		if err != nil {
			t.Fatal(err)
		}
		diff := cmp.Diff(w.predicate, gotPred)
		if diff != "" {
			t.Errorf("fname %v does not match: %v", fname, diff)
		}

		// The attestation does get marshalled though, so we can't do
		// a simple diff, instead we'll need to parse things...
		fname = fmt.Sprintf("%v/%v", w.sha, w.attName)
		gotE := readDsse(t, commit, fname)
		wantE := parseDsse(t, w.attestation)
		// Ignore payload because we're going to handle that special
		diff = cmp.Diff(gotE, wantE, cmpopts.IgnoreFields(dsse.Envelope{}, "Payload"))
		if diff != "" {
			t.Errorf("fname %v does not match: %v", fname, diff)
		}
		// Now let's check the payload.
		gotJ := parsePayload(t, gotE)
		wantJ := parsePayload(t, wantE)
		diff = cmp.Diff(gotJ, wantJ)
		if diff != "" {
			t.Errorf("fname payload %v does not match: %v", fname, diff)
		}
	}
}

type fakeSV struct {
	signature.SignerVerifier
}

func (fakeSV) SignMessage(_ io.Reader, _ ...signature.SignOption) ([]byte, error) {
	return []byte("tacocat"), nil
}

func fakeRekor(_ context.Context, _ *client.Rekor, _, _ []byte) (*models.LogEntryAnon, error) {
	id := "foo"
	index := int64(1)
	return &models.LogEntryAnon{
		LogID:    &id,
		LogIndex: &index,
	}, nil
}

func parsePayload(t *testing.T, d *dsse.Envelope) interface{} {
	p, err := base64.StdEncoding.DecodeString(d.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var j interface{}
	err = json.Unmarshal(p, &j)
	if err != nil {
		t.Fatal(err)
	}
	return j
}

func parseDsse(t *testing.T, content string) *dsse.Envelope {
	var e dsse.Envelope
	err := json.Unmarshal([]byte(content), &e)
	if err != nil {
		t.Fatal(err)
	}
	return &e
}

func readDsse(t *testing.T, commit *object.Commit, fname string) *dsse.Envelope {
	f, err := commit.File(fname)
	if err != nil {
		t.Fatal(err)
	}
	c, err := f.Contents()
	if err != nil {
		t.Fatal(err)
	}
	return parseDsse(t, c)
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

func generateAttestation(t *testing.T, digestType string, h plumbing.Hash) string {
	t.Helper()

	statement := fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"%s":"%s"}}],"predicateType":"custom-pred-type","predicate":{"foo":"bar"}}`,
		digestType,
		h.String())

	att := dsse.Envelope{
		PayloadType: "application/vnd.in-toto+json",
		Payload:     base64.StdEncoding.EncodeToString([]byte(statement)),
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
