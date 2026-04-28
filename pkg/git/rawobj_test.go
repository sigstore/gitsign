//
// Copyright 2026 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package git

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// fakeSig is a syntactically-valid PEM block used for tests that exercise
// the parser/joiner shape but don't need a real cryptographic signature.
const fakeSig = `-----BEGIN SIGNED MESSAGE-----
ZmFrZXBheWxvYWQ=
-----END SIGNED MESSAGE-----
`

// gpgsigBlock formats a PEM signature as a git gpgsig header block: first
// line preceded by "gpgsig ", subsequent lines by a single space, ending
// with a trailing newline.
func gpgsigBlock(sig string) string {
	sig = strings.TrimSuffix(sig, "\n")
	lines := strings.Split(sig, "\n")
	return "gpgsig " + strings.Join(lines, "\n ") + "\n"
}

// TestSplitCommit_WellFormed runs against a real signed commit
// (testdata/commit.txt = `git cat-file -p HEAD` from a gitsign-signed commit
// in this repo) and confirms split + join round-trips byte-for-byte.
func TestSplitCommit_WellFormed(t *testing.T) {
	raw := loadObject(t, "commit.txt")

	body, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if !bytes.HasPrefix(body, []byte("tree ")) {
		t.Errorf("body should start with 'tree ', got %q", firstLine(body))
	}
	if bytes.Contains(body, []byte("\ngpgsig ")) {
		t.Errorf("body should not contain gpgsig header")
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN ")) {
		t.Errorf("sig should start with PEM marker, got %q", firstLine(sig))
	}

	rejoined, err := JoinCommit(body, sig)
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestSplitCommit_DuplicateGpgsig(t *testing.T) {
	raw := []byte(fmt.Sprintf(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s%s
foo
`, gpgsigBlock(fakeSig), gpgsigBlock(fakeSig)))

	_, _, err := SplitCommit(bytes.NewReader(raw))
	if !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("want ErrMalformedObject, got %v", err)
	}
}

// TestSplitCommit_MergeCommit confirms we don't over-reject: commits with
// multiple parent headers (merge commits) are valid and must parse cleanly.
func TestSplitCommit_MergeCommit(t *testing.T) {
	raw := []byte(fmt.Sprintf(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
parent 2dc0ab59d7f0a7a62423bd181d9e2ab3adb7b56d
parent 1111111111111111111111111111111111111111
parent 2222222222222222222222222222222222222222
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s
merge commit
`, gpgsigBlock(fakeSig)))

	body, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	for _, p := range []string{
		"parent 2dc0ab59d7f0a7a62423bd181d9e2ab3adb7b56d\n",
		"parent 1111111111111111111111111111111111111111\n",
		"parent 2222222222222222222222222222222222222222\n",
	} {
		if !bytes.Contains(body, []byte(p)) {
			t.Errorf("body missing expected parent line %q", p)
		}
	}
	if diff := cmp.Diff([]byte(fakeSig), sig); diff != "" {
		t.Errorf("signature mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_NoSignature documents that an unsigned commit splits without
// error: the entire input becomes payload and the signature is empty. The
// downstream PEM decode + cryptographic check is what surfaces the missing
// signature to the user.
func TestSplitCommit_NoSignature(t *testing.T) {
	raw := []byte(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000

unsigned commit
`)
	body, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if len(sig) != 0 {
		t.Errorf("expected empty sig, got %q", sig)
	}
	if diff := cmp.Diff(raw, body); diff != "" {
		t.Errorf("body should equal input (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_NoHeaderTerminator documents that a malformed input with no
// blank line terminating the headers is not rejected — the bytes flow through
// to the verifier, which will reject them as not matching anything that was
// signed.
func TestSplitCommit_NoHeaderTerminator(t *testing.T) {
	raw := []byte("tree b333504b8cf3d9c314fed2cc242c5c38e89534a5\n")
	body, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if len(sig) != 0 {
		t.Errorf("expected empty sig, got %q", sig)
	}
	if diff := cmp.Diff(raw, body); diff != "" {
		t.Errorf("body should equal input (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_LenientContinuation confirms gpgsig continuation lines with
// extra leading whitespace (or tabs) are accepted, with all leading whitespace
// stripped. git-core requires exactly one space, but the recovered signature
// is cryptographically verified downstream so leniency here is safe.
func TestSplitCommit_LenientContinuation(t *testing.T) {
	raw := []byte("tree b333504b8cf3d9c314fed2cc242c5c38e89534a5\n" +
		"author Alice <alice@example.com> 1700000000 +0000\n" +
		"committer Alice <alice@example.com> 1700000000 +0000\n" +
		"gpgsig -----BEGIN SIGNED MESSAGE-----\n" +
		"  two-space-continuation\n" +
		"\textra-tab\n" +
		" -----END SIGNED MESSAGE-----\n" +
		"\n" +
		"foo\n")

	_, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	want := "-----BEGIN SIGNED MESSAGE-----\ntwo-space-continuation\nextra-tab\n-----END SIGNED MESSAGE-----\n"
	if diff := cmp.Diff([]byte(want), sig); diff != "" {
		t.Errorf("signature mismatch (-want +got):\n%s", diff)
	}
}

// TestJoinCommit_RoundTrip uses the real signed HEAD commit: split it, join
// it back, and confirm the bytes are identical.
func TestJoinCommit_RoundTrip(t *testing.T) {
	raw := loadObject(t, "commit.txt")
	body, sig, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	rejoined, err := JoinCommit(body, sig)
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestJoinCommit_NoHeaderTerminator(t *testing.T) {
	_, err := JoinCommit([]byte("not-a-commit"), []byte("sig"))
	if !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("want ErrMalformedObject, got %v", err)
	}
}

// TestSplitTag_WellFormed runs against a real signed tag (testdata/tag.txt =
// `git cat-file -p v0.1.0`) and confirms split + join round-trips
// byte-for-byte.
func TestSplitTag_WellFormed(t *testing.T) {
	raw := loadObject(t, "tag.txt")

	body, sig, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if !bytes.HasPrefix(body, []byte("object ")) {
		t.Errorf("body should start with 'object ', got %q", firstLine(body))
	}
	if !bytes.HasPrefix(sig, []byte("-----BEGIN ")) {
		t.Errorf("sig should start with PEM marker, got %q", firstLine(sig))
	}

	rejoined := JoinTag(body, sig)
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitTag_MultipleSignatureBlocks confirms that when a tag body contains
// more than one "-----BEGIN " block — e.g. an attacker concatenates a
// fake/canonical signature into the message and appends their own signature
// at the end — only the *last* block is treated as the signature, matching
// git-core's tag verification path. Anything before the last block (including
// any earlier PEM-looking content) is part of the signed payload, so a
// signature over a different earlier block doesn't get treated as "the"
// signature.
func TestSplitTag_MultipleSignatureBlocks(t *testing.T) {
	raw := []byte(`object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag multi-pem
tagger Alice <alice@example.com> 1700000000 +0000

embedded earlier block in the message body:
-----BEGIN SIGNED MESSAGE-----
ZmFrZQ==
-----END SIGNED MESSAGE-----
-----BEGIN SIGNED MESSAGE-----
cmVhbA==
-----END SIGNED MESSAGE-----
`)

	body, sig, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}

	wantSig := []byte(`-----BEGIN SIGNED MESSAGE-----
cmVhbA==
-----END SIGNED MESSAGE-----
`)
	if diff := cmp.Diff(wantSig, sig); diff != "" {
		t.Errorf("sig mismatch (-want +got):\n%s", diff)
	}

	// The earlier PEM block must remain in the body — it's part of what was
	// signed, not the signature itself.
	if !bytes.Contains(body, []byte("ZmFrZQ==")) {
		t.Errorf("body should contain the earlier embedded PEM block")
	}
	if bytes.Contains(body, []byte("cmVhbA==")) {
		t.Errorf("body should not contain the trailing signature payload")
	}

	// Round-trip: body + last block reconstructs the original bytes.
	if diff := cmp.Diff(raw, JoinTag(body, sig)); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitTag_NoSignature documents that an unsigned tag splits without
// error: body holds the input and sig is empty.
func TestSplitTag_NoSignature(t *testing.T) {
	raw := []byte(`object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag unsigned
tagger Alice <alice@example.com> 1700000000 +0000

unsigned tag
`)
	body, sig, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if len(sig) != 0 {
		t.Errorf("expected empty sig, got %q", sig)
	}
	if diff := cmp.Diff(raw, body); diff != "" {
		t.Errorf("body should equal input (-want +got):\n%s", diff)
	}
}

// TestSplitTag_NoHeaderTerminator documents that a tag with no blank line is
// not rejected — the verifier downstream catches the mismatch.
func TestSplitTag_NoHeaderTerminator(t *testing.T) {
	raw := []byte("object 040b9af339e69d18848b7bbe05cb27ee42bb0161\n")
	body, sig, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if len(sig) != 0 {
		t.Errorf("expected empty sig, got %q", sig)
	}
	if diff := cmp.Diff(raw, body); diff != "" {
		t.Errorf("body should equal input (-want +got):\n%s", diff)
	}
}

func TestJoinTag_RoundTrip(t *testing.T) {
	raw := loadObject(t, "tag.txt")
	body, sig, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	rejoined := JoinTag(body, sig)
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// firstLine returns the first line of b for use in error messages.
func firstLine(b []byte) []byte {
	first, _, _ := bytes.Cut(b, []byte{'\n'})
	return first
}
