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

const fakeSig2 = `-----BEGIN SIGNED MESSAGE-----
b3RoZXJwYXlsb2Fk
-----END SIGNED MESSAGE-----
`

// sigHeader formats a PEM signature as a wire-format header block: the first
// line preceded by `prefix` (e.g. "gpgsig "), subsequent lines indented by a
// single space. The result ends with a trailing newline so it can be
// concatenated directly into a header section.
func sigHeader(prefix, sig string) string {
	sig = strings.TrimSuffix(sig, "\n")
	lines := strings.Split(sig, "\n")
	return prefix + strings.Join(lines, "\n ") + "\n"
}

// TestSplitCommit_WellFormed runs against a real signed commit
// (testdata/commit.txt = `git cat-file -p HEAD` from a gitsign-signed commit
// in this repo) and confirms split + join round-trips byte-for-byte.
func TestSplitCommit_WellFormed(t *testing.T) {
	raw := loadObject(t, "commit.txt")

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if !bytes.HasPrefix(c.Payload, []byte("tree ")) {
		t.Errorf("payload should start with 'tree ', got %q", firstLine(c.Payload))
	}
	if bytes.Contains(c.Payload, []byte("\ngpgsig ")) {
		t.Errorf("payload should not contain gpgsig header")
	}
	if c.GpgsigSha256 != nil {
		t.Errorf("expected no gpgsig-sha256 on a SHA-1 only commit, got %q", c.GpgsigSha256)
	}
	if !bytes.HasPrefix(c.Gpgsig, []byte("-----BEGIN ")) {
		t.Errorf("Gpgsig should start with PEM marker, got %q", firstLine(c.Gpgsig))
	}

	rejoined, err := JoinCommit(c)
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestSplitCommit_DuplicateGpgsig(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s%s
foo
`, sigHeader(gpgsigPrefix, fakeSig), sigHeader(gpgsigPrefix, fakeSig))

	_, err := SplitCommit(bytes.NewReader(raw))
	if !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("want ErrMalformedObject, got %v", err)
	}
}

func TestSplitCommit_DuplicateGpgsigSha256(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s%s
foo
`, sigHeader(gpgsigSha256Prefix, fakeSig), sigHeader(gpgsigSha256Prefix, fakeSig))

	_, err := SplitCommit(bytes.NewReader(raw))
	if !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("want ErrMalformedObject, got %v", err)
	}
}

// TestSplitCommit_DualSigned exercises the SHA-256 transition compat shape
// — a commit carrying both gpgsig and gpgsig-sha256
// (https://git-scm.com/docs/hash-function-transition#_signed_commits) — and
// confirms each signature is extracted into its own field with both header
// fields stripped from Payload (the spec says either signature's signed
// payload is the commit content with *both* fields removed).
//
// JoinCommit uses a fixed gpgsig-then-gpgsig-sha256 emission order, so the
// "gpgsig-first" subcase round-trips byte-for-byte while the
// "gpgsig-sha256-first" subcase only checks parse correctness.
func TestSplitCommit_DualSigned(t *testing.T) {
	gpgsig := sigHeader(gpgsigPrefix, fakeSig)
	sha256Sig := sigHeader(gpgsigSha256Prefix, fakeSig2)

	for _, tc := range []struct {
		name      string
		first     string
		second    string
		roundTrip bool
	}{
		{"gpgsig-first", gpgsig, sha256Sig, true},
		{"gpgsig-sha256-first", sha256Sig, gpgsig, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s%s
dual-signed
`, tc.first, tc.second)

			c, err := SplitCommit(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("SplitCommit: %v", err)
			}
			if diff := cmp.Diff([]byte(fakeSig), c.Gpgsig); diff != "" {
				t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff([]byte(fakeSig2), c.GpgsigSha256); diff != "" {
				t.Errorf("GpgsigSha256 mismatch (-want +got):\n%s", diff)
			}
			if bytes.Contains(c.Payload, []byte("\ngpgsig ")) {
				t.Errorf("payload should not contain gpgsig header")
			}
			if bytes.Contains(c.Payload, []byte("\ngpgsig-sha256 ")) {
				t.Errorf("payload should not contain gpgsig-sha256 header")
			}

			if tc.roundTrip {
				rejoined, err := JoinCommit(c)
				if err != nil {
					t.Fatalf("JoinCommit: %v", err)
				}
				if diff := cmp.Diff(raw, rejoined); diff != "" {
					t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}

// TestSplitCommit_Sha256Only covers mode 3 of the transition spec: a commit
// signed only with gpgsig-sha256 (no gpgsig). gitsign should extract the
// signature and report Gpgsig as nil.
func TestSplitCommit_Sha256Only(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s
sha256 only
`, sigHeader(gpgsigSha256Prefix, fakeSig))

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if c.Gpgsig != nil {
		t.Errorf("expected Gpgsig nil, got %q", c.Gpgsig)
	}
	if diff := cmp.Diff([]byte(fakeSig), c.GpgsigSha256); diff != "" {
		t.Errorf("GpgsigSha256 mismatch (-want +got):\n%s", diff)
	}

	rejoined, err := JoinCommit(c)
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_GpgsigInBody confirms that gpgsig-looking lines in the
// commit message body are treated as plain text, not as a second gpgsig
// header. Once the blank line ends the header section, prefix detection and
// duplicate-header rejection are off — body content is opaque to the
// parser.
func TestSplitCommit_GpgsigInBody(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s
This commit message has lines that look like gpgsig headers:
gpgsig pretend-sig-here
gpgsig-sha256 pretend-other-sig
 indented-continuation-shaped-line
gpgsig second-fake
`, sigHeader(gpgsigPrefix, fakeSig))

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if diff := cmp.Diff([]byte(fakeSig), c.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
	if c.GpgsigSha256 != nil {
		t.Errorf("expected GpgsigSha256 nil, got %q", c.GpgsigSha256)
	}
	for _, want := range []string{
		"gpgsig pretend-sig-here",
		"gpgsig-sha256 pretend-other-sig",
		"gpgsig second-fake",
	} {
		if !bytes.Contains(c.Payload, []byte(want)) {
			t.Errorf("body line %q should remain in payload", want)
		}
	}
}

// TestSplitTag_GpgsigInBody confirms that gpgsig-looking lines in the tag
// message body are treated as plain text, not as duplicate header
// signatures.
func TestSplitTag_GpgsigInBody(t *testing.T) {
	raw := fmt.Appendf(nil, `object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag body-noise
tagger Alice <alice@example.com> 1700000000 +0000
%s
Tag message with gpgsig-looking text:
gpgsig pretend-sig-here
gpgsig-sha256 pretend-other-sig

%s`, sigHeader(gpgsigPrefix, fakeSig), fakeSig)

	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if diff := cmp.Diff([]byte(fakeSig), tag.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]byte(fakeSig), tag.InBody); diff != "" {
		t.Errorf("InBody mismatch (-want +got):\n%s", diff)
	}
	for _, want := range []string{
		"gpgsig pretend-sig-here",
		"gpgsig-sha256 pretend-other-sig",
	} {
		if !bytes.Contains(tag.Payload, []byte(want)) {
			t.Errorf("body line %q should remain in payload", want)
		}
	}
}

// TestSplitCommit_GpgsigPrefixedHeaders confirms unrelated headers that share
// the "gpgsig" prefix (e.g. a hypothetical "gpgsig-key-id" extension) don't
// trip the duplicate-gpgsig check or get extracted as a signature: the
// trailing space in gpgsigPrefix / gpgsigSha256Prefix distinguishes them
// from "gpgsig-*".
func TestSplitCommit_GpgsigPrefixedHeaders(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%sgpgsig-key-id ABCDEF0123456789
gpgsig-fingerprint 0011223344556677

foo
`, sigHeader(gpgsigPrefix, fakeSig))

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if diff := cmp.Diff([]byte(fakeSig), c.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
	if c.GpgsigSha256 != nil {
		t.Errorf("expected GpgsigSha256 nil, got %q", c.GpgsigSha256)
	}
	for _, want := range []string{"gpgsig-key-id ABCDEF0123456789", "gpgsig-fingerprint 0011223344556677"} {
		if !bytes.Contains(c.Payload, []byte(want)) {
			t.Errorf("payload should contain %q", want)
		}
	}
}

// TestSplitCommit_MergeCommit confirms we don't over-reject: commits with
// multiple parent headers (merge commits) are valid and must parse cleanly.
func TestSplitCommit_MergeCommit(t *testing.T) {
	raw := fmt.Appendf(nil, `tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
parent 2dc0ab59d7f0a7a62423bd181d9e2ab3adb7b56d
parent 1111111111111111111111111111111111111111
parent 2222222222222222222222222222222222222222
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000
%s
merge commit
`, sigHeader(gpgsigPrefix, fakeSig))

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	for _, p := range []string{
		"parent 2dc0ab59d7f0a7a62423bd181d9e2ab3adb7b56d\n",
		"parent 1111111111111111111111111111111111111111\n",
		"parent 2222222222222222222222222222222222222222\n",
	} {
		if !bytes.Contains(c.Payload, []byte(p)) {
			t.Errorf("payload missing expected parent line %q", p)
		}
	}
	if diff := cmp.Diff([]byte(fakeSig), c.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_NoSignature documents that an unsigned commit splits without
// error: the entire input becomes payload and both signature fields are nil.
// The downstream PEM decode + cryptographic check is what surfaces the
// missing signature to the user.
func TestSplitCommit_NoSignature(t *testing.T) {
	raw := []byte(`tree b333504b8cf3d9c314fed2cc242c5c38e89534a5
author Alice <alice@example.com> 1700000000 +0000
committer Alice <alice@example.com> 1700000000 +0000

unsigned commit
`)
	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if c.Gpgsig != nil || c.GpgsigSha256 != nil {
		t.Errorf("expected both signature fields nil, got Gpgsig=%q GpgsigSha256=%q", c.Gpgsig, c.GpgsigSha256)
	}
	if diff := cmp.Diff(raw, c.Payload); diff != "" {
		t.Errorf("payload should equal input (-want +got):\n%s", diff)
	}
}

// TestSplitCommit_NoHeaderTerminator documents that a malformed input with no
// blank line terminating the headers is not rejected — the bytes flow through
// to the verifier, which will reject them as not matching anything that was
// signed.
func TestSplitCommit_NoHeaderTerminator(t *testing.T) {
	raw := []byte("tree b333504b8cf3d9c314fed2cc242c5c38e89534a5\n")
	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	if c.Gpgsig != nil || c.GpgsigSha256 != nil {
		t.Errorf("expected no signatures, got Gpgsig=%q GpgsigSha256=%q", c.Gpgsig, c.GpgsigSha256)
	}
	if diff := cmp.Diff(raw, c.Payload); diff != "" {
		t.Errorf("payload should equal input (-want +got):\n%s", diff)
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

	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	want := "-----BEGIN SIGNED MESSAGE-----\ntwo-space-continuation\nextra-tab\n-----END SIGNED MESSAGE-----\n"
	if diff := cmp.Diff([]byte(want), c.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
}

// TestJoinCommit_RoundTrip uses the real signed HEAD commit: split it, join
// it back, and confirm the bytes are identical.
func TestJoinCommit_RoundTrip(t *testing.T) {
	raw := loadObject(t, "commit.txt")
	c, err := SplitCommit(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitCommit: %v", err)
	}
	rejoined, err := JoinCommit(c)
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

func TestJoinCommit_NoHeaderTerminator(t *testing.T) {
	_, err := JoinCommit(&CommitSig{Payload: []byte("not-a-commit"), Gpgsig: []byte("sig")})
	if !errors.Is(err, ErrMalformedObject) {
		t.Fatalf("want ErrMalformedObject, got %v", err)
	}
}

// TestJoinCommit_PassthroughNoSig documents that JoinCommit on a CommitSig
// with no signatures returns the payload unchanged — useful for callers that
// want a single code path regardless of whether the input was signed.
func TestJoinCommit_PassthroughNoSig(t *testing.T) {
	in := []byte("not even a real commit, no terminator")
	out, err := JoinCommit(&CommitSig{Payload: in})
	if err != nil {
		t.Fatalf("JoinCommit: %v", err)
	}
	if diff := cmp.Diff(in, out); diff != "" {
		t.Errorf("passthrough mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitTag_WellFormed runs against a real signed tag (testdata/tag.txt =
// `git cat-file -p v0.1.0`) and confirms split + join round-trips
// byte-for-byte.
func TestSplitTag_WellFormed(t *testing.T) {
	raw := loadObject(t, "tag.txt")

	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if !bytes.HasPrefix(tag.Payload, []byte("object ")) {
		t.Errorf("payload should start with 'object ', got %q", firstLine(tag.Payload))
	}
	if !bytes.HasPrefix(tag.InBody, []byte("-----BEGIN ")) {
		t.Errorf("InBody should start with PEM marker, got %q", firstLine(tag.InBody))
	}
	if tag.Gpgsig != nil || tag.GpgsigSha256 != nil {
		t.Errorf("expected no header sigs, got Gpgsig=%q GpgsigSha256=%q", tag.Gpgsig, tag.GpgsigSha256)
	}

	rejoined, err := JoinTag(tag)
	if err != nil {
		t.Fatalf("JoinTag: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitTag_DualSigned exercises a tag with all three signature forms:
// the in-body PEM block (current-algorithm signature) plus gpgsig and
// gpgsig-sha256 headers (alternate-algorithm signatures, per the SHA-256
// transition spec). All three must be extracted into their own fields with
// the payload stripped of all three.
func TestSplitTag_DualSigned(t *testing.T) {
	raw := fmt.Appendf(nil, `object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag dual-signed
tagger Alice <alice@example.com> 1700000000 +0000
%s%s
dual signed tag

%s`,
		sigHeader(gpgsigPrefix, fakeSig),
		sigHeader(gpgsigSha256Prefix, fakeSig2),
		fakeSig)

	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if diff := cmp.Diff([]byte(fakeSig), tag.InBody); diff != "" {
		t.Errorf("InBody mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]byte(fakeSig), tag.Gpgsig); diff != "" {
		t.Errorf("Gpgsig mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]byte(fakeSig2), tag.GpgsigSha256); diff != "" {
		t.Errorf("GpgsigSha256 mismatch (-want +got):\n%s", diff)
	}
	if bytes.Contains(tag.Payload, []byte("\ngpgsig ")) {
		t.Errorf("payload should not contain gpgsig header")
	}
	if bytes.Contains(tag.Payload, []byte("\ngpgsig-sha256 ")) {
		t.Errorf("payload should not contain gpgsig-sha256 header")
	}

	rejoined, err := JoinTag(tag)
	if err != nil {
		t.Fatalf("JoinTag: %v", err)
	}
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

	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}

	wantSig := []byte(`-----BEGIN SIGNED MESSAGE-----
cmVhbA==
-----END SIGNED MESSAGE-----
`)
	if diff := cmp.Diff(wantSig, tag.InBody); diff != "" {
		t.Errorf("InBody mismatch (-want +got):\n%s", diff)
	}

	// The earlier PEM block must remain in the payload — it's part of what
	// was signed, not the signature itself.
	if !bytes.Contains(tag.Payload, []byte("ZmFrZQ==")) {
		t.Errorf("payload should contain the earlier embedded PEM block")
	}
	if bytes.Contains(tag.Payload, []byte("cmVhbA==")) {
		t.Errorf("payload should not contain the trailing signature payload")
	}

	rejoined, err := JoinTag(tag)
	if err != nil {
		t.Fatalf("JoinTag: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// TestSplitTag_NoSignature documents that an unsigned tag splits without
// error: payload holds the input and all signature fields are nil.
func TestSplitTag_NoSignature(t *testing.T) {
	raw := []byte(`object 040b9af339e69d18848b7bbe05cb27ee42bb0161
type commit
tag unsigned
tagger Alice <alice@example.com> 1700000000 +0000

unsigned tag
`)
	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if tag.InBody != nil || tag.Gpgsig != nil || tag.GpgsigSha256 != nil {
		t.Errorf("expected all signatures nil, got InBody=%q Gpgsig=%q GpgsigSha256=%q",
			tag.InBody, tag.Gpgsig, tag.GpgsigSha256)
	}
	if diff := cmp.Diff(raw, tag.Payload); diff != "" {
		t.Errorf("payload should equal input (-want +got):\n%s", diff)
	}
}

// TestSplitTag_NoHeaderTerminator documents that a tag with no blank line is
// not rejected — the verifier downstream catches the mismatch.
func TestSplitTag_NoHeaderTerminator(t *testing.T) {
	raw := []byte("object 040b9af339e69d18848b7bbe05cb27ee42bb0161\n")
	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	if tag.InBody != nil || tag.Gpgsig != nil || tag.GpgsigSha256 != nil {
		t.Errorf("expected all signatures nil, got InBody=%q Gpgsig=%q GpgsigSha256=%q",
			tag.InBody, tag.Gpgsig, tag.GpgsigSha256)
	}
	if diff := cmp.Diff(raw, tag.Payload); diff != "" {
		t.Errorf("payload should equal input (-want +got):\n%s", diff)
	}
}

func TestJoinTag_RoundTrip(t *testing.T) {
	raw := loadObject(t, "tag.txt")
	tag, err := SplitTag(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("SplitTag: %v", err)
	}
	rejoined, err := JoinTag(tag)
	if err != nil {
		t.Fatalf("JoinTag: %v", err)
	}
	if diff := cmp.Diff(raw, rejoined); diff != "" {
		t.Errorf("round-trip mismatch (-want +got):\n%s", diff)
	}
}

// firstLine returns the first line of b for use in error messages.
func firstLine(b []byte) []byte {
	first, _, _ := bytes.Cut(b, []byte{'\n'})
	return first
}
