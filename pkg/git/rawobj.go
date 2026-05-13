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
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"unicode"

	"github.com/go-git/go-git/v5/plumbing"
)

var (
	// ErrMalformedObject is returned for structural ambiguities the
	// downstream signature check can't catch on its own — currently a
	// duplicate gpgsig or gpgsig-sha256 header (where it's unclear which
	// signature to extract) or, on the join side, a payload with no
	// header/body separator.
	ErrMalformedObject = errors.New("malformed git object")
	// ErrUnsupportedSignatureType is returned when the embedded signature is
	// not a format gitsign can verify. gitsign only accepts PEM blocks of type
	// "SIGNED MESSAGE" (CMS/PKCS7).
	ErrUnsupportedSignatureType = errors.New("unsupported signature type")
)

// gpgsigPrefix is the SHA-1 signature header. The trailing space distinguishes
// it from gpgsig-sha256 and any future "gpgsig-*" extension headers, which
// are independently valid header fields.
const gpgsigPrefix = "gpgsig "

// gpgsigSha256Prefix is the SHA-256 transition compat header introduced by
// the hash-function-transition spec. When compatObjectFormat is set, git
// emits this alongside gpgsig — see
// https://git-scm.com/docs/hash-function-transition#_signed_commits.
const gpgsigSha256Prefix = "gpgsig-sha256 "

// CommitSig holds signature material extracted from a commit's raw bytes.
//
// Per the SHA-256 transition spec, the signed payload for either gpgsig or
// gpgsig-sha256 is the commit content with BOTH header fields removed (in
// the commit's own hash algorithm). The two signatures sign different bytes
// — the SHA-1 form vs the SHA-256 form of the same logical commit — but
// they share the same removal rule. Payload here is whatever form the
// caller's input bytes are in, with both header fields stripped, so it
// matches whichever of Gpgsig / GpgsigSha256 corresponds to that form.
type CommitSig struct {
	// Payload is the commit content with gpgsig and gpgsig-sha256 fields
	// (and their continuation lines) removed.
	Payload []byte
	// Gpgsig is the PEM signature from the gpgsig header. It signs the
	// SHA-1 form of the commit. Nil if the header is absent.
	Gpgsig []byte
	// GpgsigSha256 is the PEM signature from the gpgsig-sha256 header. It
	// signs the SHA-256 form of the commit. Nil if the header is absent.
	GpgsigSha256 []byte
}

// TagSig holds signature material extracted from a tag's raw bytes.
//
// Per the SHA-256 transition spec, the in-body PEM block is the signature
// over the tag in its current hash algorithm; the gpgsig and gpgsig-sha256
// headers are signatures over the alternate-algorithm form. All three sign
// the same shape: tag content with both header fields and the in-body PEM
// block removed.
type TagSig struct {
	// Payload is the tag content with both header signature fields and the
	// in-body PEM block removed.
	Payload []byte
	// InBody is the PEM signature appended after the tag message body. It
	// signs the tag in its own (current) hash algorithm. Nil if absent.
	InBody []byte
	// Gpgsig is the PEM signature from the gpgsig header — the
	// alternate-algorithm signature when the tag's stored form is SHA-256,
	// or unused for a SHA-1 tag. Nil if absent.
	Gpgsig []byte
	// GpgsigSha256 is the PEM signature from the gpgsig-sha256 header —
	// the alternate-algorithm signature when the tag's stored form is
	// SHA-1. Nil if absent.
	GpgsigSha256 []byte
}

// SplitCommit parses the raw bytes of a commit object (object-database form,
// without the "commit <len>\0" prefix) into payload + signatures.
//
// It operates purely on the raw bytes, mirroring what git-core feeds to its
// signature verifier, and does not go through go-git's object parser.
//
// The trust-confusion class of attack (GHSA-7rmh-48mx-2vwc) relied on gitsign
// re-encoding through go-git before verification — which normalized away
// duplicate headers and let a signature over the canonical form verify
// against attacker-controlled raw bytes. Verifying directly over the raw
// bytes blocks that: any structural divergence between what was signed and
// what's stored makes the signature fail to verify cryptographically.
// Consequently, SplitCommit doesn't reject merely "weird but git-valid"
// objects (e.g. duplicate tree headers); the signature check below is what
// catches them. The structural things we *do* reject are duplicate gpgsig
// or gpgsig-sha256 headers, because either is ambiguous about which
// signature to extract.
func SplitCommit(r io.Reader) (*CommitSig, error) {
	scanner := bufio.NewScanner(r)

	var (
		payloadBuf bytes.Buffer
		gpgsigBuf  bytes.Buffer
		sha256Buf  bytes.Buffer
		// activeSig points at whichever signature buffer is currently
		// accepting continuation lines, or nil if we're in regular-header
		// territory.
		activeSig *bytes.Buffer
		inBody    bool
	)

	for scanner.Scan() {
		line := scanner.Bytes()

		if inBody {
			payloadBuf.Write(line)
			payloadBuf.WriteByte('\n')
			continue
		}

		if len(line) == 0 {
			// Blank line terminates the header section.
			payloadBuf.WriteByte('\n')
			inBody = true
			activeSig = nil
			continue
		}

		if activeSig != nil {
			// git-core requires exactly one leading space on a signature
			// continuation (see git/commit.c parse_buffer_signed_by_header).
			// We accept any leading whitespace and strip it: the signature
			// is cryptographically verified downstream, so leniency here
			// can't cause trust confusion, and being permissive avoids
			// rejecting signatures produced by tooling that wraps with
			// slightly different indentation.
			if trimmed := bytes.TrimLeftFunc(line, unicode.IsSpace); len(trimmed) < len(line) {
				activeSig.Write(trimmed)
				activeSig.WriteByte('\n')
				continue
			}
			// Non-continuation line -> signature block ended; fall through
			// and process this line as a fresh header.
			activeSig = nil
		}

		// Note: check the longer prefix first so "gpgsig-sha256 " doesn't
		// get misclassified by the "gpgsig " branch. (In practice the two
		// don't overlap because the 7th byte differs, but ordering this way
		// is robust against accidental future widenings of gpgsigPrefix.)
		switch {
		case bytes.HasPrefix(line, []byte(gpgsigSha256Prefix)):
			if sha256Buf.Len() > 0 {
				return nil, fmt.Errorf("%w: duplicate gpgsig-sha256 header", ErrMalformedObject)
			}
			activeSig = &sha256Buf
			activeSig.Write(line[len(gpgsigSha256Prefix):])
			activeSig.WriteByte('\n')
		case bytes.HasPrefix(line, []byte(gpgsigPrefix)):
			if gpgsigBuf.Len() > 0 {
				return nil, fmt.Errorf("%w: duplicate gpgsig header", ErrMalformedObject)
			}
			activeSig = &gpgsigBuf
			activeSig.Write(line[len(gpgsigPrefix):])
			activeSig.WriteByte('\n')
		default:
			payloadBuf.Write(line)
			payloadBuf.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &CommitSig{
		Payload:      payloadBuf.Bytes(),
		Gpgsig:       sigOrNil(&gpgsigBuf),
		GpgsigSha256: sigOrNil(&sha256Buf),
	}, nil
}

// JoinCommit is the inverse of SplitCommit. It re-inserts the gpgsig and
// gpgsig-sha256 headers (those that are non-nil) into c.Payload immediately
// before the blank line separating headers from the message body.
// Continuation lines are indented with a single space, matching git-core's
// wire format.
//
// When both headers are present they are emitted in a fixed order: gpgsig
// first, then gpgsig-sha256. This matches git-core's emission order, so
// objects produced by git-core round-trip byte-for-byte through Split/Join.
func JoinCommit(c *CommitSig) ([]byte, error) {
	if len(c.Gpgsig) == 0 && len(c.GpgsigSha256) == 0 {
		// No signatures to insert; passthrough.
		return c.Payload, nil
	}

	hdrEnd := bytes.Index(c.Payload, []byte("\n\n"))
	if hdrEnd < 0 {
		return nil, fmt.Errorf("%w: payload has no header terminator", ErrMalformedObject)
	}

	var hdr bytes.Buffer
	if len(c.Gpgsig) > 0 {
		writeSigHeader(&hdr, gpgsigPrefix, c.Gpgsig)
	}
	if len(c.GpgsigSha256) > 0 {
		writeSigHeader(&hdr, gpgsigSha256Prefix, c.GpgsigSha256)
	}

	out := make([]byte, 0, len(c.Payload)+hdr.Len())
	out = append(out, c.Payload[:hdrEnd+1]...) // include the \n terminating the last header
	out = append(out, hdr.Bytes()...)
	out = append(out, c.Payload[hdrEnd+1:]...) // the remaining \n + message body
	return out, nil
}

// SplitTag parses the raw bytes of a tag object into payload + signatures.
// Like SplitCommit, it works on raw bytes and does not invoke go-git's
// parser, so any divergence between what was signed and what's stored is
// caught by the cryptographic check downstream rather than by structural
// validation here.
//
// The tag's in-body PEM block (current-algorithm signature) is taken to
// start at the *last* line-anchored "-----BEGIN " marker, matching
// git-core's tag verification path. Anything before it stays in the
// payload, including any earlier PEM-looking lines an attacker might have
// embedded in the message body. Header-style alternate-algorithm
// signatures (gpgsig, gpgsig-sha256) are stripped from the header section
// the same way SplitCommit does.
func SplitTag(r io.Reader) (*TagSig, error) {
	scanner := bufio.NewScanner(r)

	var (
		payloadBuf   bytes.Buffer
		inBodySigBuf bytes.Buffer
		gpgsigBuf    bytes.Buffer
		sha256Buf    bytes.Buffer
		activeSig    *bytes.Buffer
		inBody       bool
	)

	for scanner.Scan() {
		line := scanner.Bytes()

		if inBody {
			switch {
			case bytes.HasPrefix(line, []byte("-----BEGIN ")):
				// New PEM block opens — flush any earlier candidate to
				// payload (it wasn't the trailing block) and start fresh.
				payloadBuf.Write(inBodySigBuf.Bytes())
				inBodySigBuf.Reset()
				inBodySigBuf.Write(line)
				inBodySigBuf.WriteByte('\n')
			case inBodySigBuf.Len() > 0:
				inBodySigBuf.Write(line)
				inBodySigBuf.WriteByte('\n')
			default:
				payloadBuf.Write(line)
				payloadBuf.WriteByte('\n')
			}
			continue
		}

		if len(line) == 0 {
			payloadBuf.WriteByte('\n')
			inBody = true
			activeSig = nil
			continue
		}

		if activeSig != nil {
			if trimmed := bytes.TrimLeftFunc(line, unicode.IsSpace); len(trimmed) < len(line) {
				activeSig.Write(trimmed)
				activeSig.WriteByte('\n')
				continue
			}
			activeSig = nil
		}

		switch {
		case bytes.HasPrefix(line, []byte(gpgsigSha256Prefix)):
			if sha256Buf.Len() > 0 {
				return nil, fmt.Errorf("%w: duplicate gpgsig-sha256 header", ErrMalformedObject)
			}
			activeSig = &sha256Buf
			activeSig.Write(line[len(gpgsigSha256Prefix):])
			activeSig.WriteByte('\n')
		case bytes.HasPrefix(line, []byte(gpgsigPrefix)):
			if gpgsigBuf.Len() > 0 {
				return nil, fmt.Errorf("%w: duplicate gpgsig header", ErrMalformedObject)
			}
			activeSig = &gpgsigBuf
			activeSig.Write(line[len(gpgsigPrefix):])
			activeSig.WriteByte('\n')
		default:
			payloadBuf.Write(line)
			payloadBuf.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &TagSig{
		Payload:      payloadBuf.Bytes(),
		InBody:       sigOrNil(&inBodySigBuf),
		Gpgsig:       sigOrNil(&gpgsigBuf),
		GpgsigSha256: sigOrNil(&sha256Buf),
	}, nil
}

// JoinTag is the inverse of SplitTag. It re-inserts gpgsig / gpgsig-sha256
// headers into the header section (in fixed order: gpgsig, then
// gpgsig-sha256) and appends the in-body PEM block after the message body.
func JoinTag(t *TagSig) ([]byte, error) {
	payload := t.Payload

	if len(t.Gpgsig) > 0 || len(t.GpgsigSha256) > 0 {
		hdrEnd := bytes.Index(payload, []byte("\n\n"))
		if hdrEnd < 0 {
			return nil, fmt.Errorf("%w: payload has no header terminator", ErrMalformedObject)
		}

		var hdr bytes.Buffer
		if len(t.Gpgsig) > 0 {
			writeSigHeader(&hdr, gpgsigPrefix, t.Gpgsig)
		}
		if len(t.GpgsigSha256) > 0 {
			writeSigHeader(&hdr, gpgsigSha256Prefix, t.GpgsigSha256)
		}

		out := make([]byte, 0, len(payload)+hdr.Len()+len(t.InBody))
		out = append(out, payload[:hdrEnd+1]...)
		out = append(out, hdr.Bytes()...)
		out = append(out, payload[hdrEnd+1:]...)
		out = append(out, t.InBody...)
		return out, nil
	}

	out := make([]byte, 0, len(payload)+len(t.InBody))
	out = append(out, payload...)
	out = append(out, t.InBody...)
	return out, nil
}

// writeSigHeader emits a single header field of the form
//
//	prefix line1\n line2\n line3\n...
//
// matching git-core's wire format. sig is a PEM-encoded signature with
// lines separated by "\n"; a trailing newline is ignored.
func writeSigHeader(w *bytes.Buffer, prefix string, sig []byte) {
	s := sig
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	lines := bytes.Split(s, []byte{'\n'})

	w.WriteString(prefix)
	w.Write(lines[0])
	w.WriteByte('\n')
	for _, l := range lines[1:] {
		w.WriteByte(' ')
		w.Write(l)
		w.WriteByte('\n')
	}
}

// sigOrNil returns nil for an empty buffer (so absent signatures surface as
// nil rather than zero-length slices).
func sigOrNil(b *bytes.Buffer) []byte {
	if b.Len() == 0 {
		return nil
	}
	return b.Bytes()
}

// commitSingletons / tagSingletons name the headers a well-formed object
// carries at most once. parent is intentionally absent from the commit set
// (merge commits have several); mergetag and encoding are intentionally
// absent because git accepts repetition of mergetag and we don't audit
// encoding for uniqueness. gpgsig / gpgsig-sha256 are included so the
// attest path matches SplitCommit's duplicate-signature rejection on the
// verify path.
var commitSingletons = map[string]bool{
	"tree":          true,
	"author":        true,
	"committer":     true,
	"gpgsig":        true,
	"gpgsig-sha256": true,
}

var tagSingletons = map[string]bool{
	"object":        true,
	"type":          true,
	"tag":           true,
	"tagger":        true,
	"gpgsig":        true,
	"gpgsig-sha256": true,
}

// ValidateCommit returns ErrMalformedObject if the commit's header
// section carries a duplicate singleton header (tree, author, committer,
// gpgsig, gpgsig-sha256). Other ambiguities — missing required headers,
// unparseable signatures, bad encodings — are out of scope and surface
// later via go-git's decoder or the cryptographic check.
//
// go-git ≥ v5.19.0 silently drops duplicates and takes the first (matching
// git-core's standard_header_field filter). That's safe but ambiguous —
// `git hash-object --literally` and adversarial pushes are the only ways
// such objects appear, and the attest path would rather refuse than emit
// a predicate that obscures the underlying weirdness.
func ValidateCommit(obj plumbing.EncodedObject) error {
	return checkUniqueHeaders(obj, commitSingletons)
}

// ValidateTag is the tag-object counterpart to ValidateCommit, rejecting
// duplicate object / type / tag / tagger / gpgsig / gpgsig-sha256 headers.
func ValidateTag(obj plumbing.EncodedObject) error {
	return checkUniqueHeaders(obj, tagSingletons)
}

// checkUniqueHeaders walks the header section (up to the first blank
// line) and returns ErrMalformedObject on the second occurrence of any
// key in singletons. Lines beginning with whitespace are treated as
// continuations of the previous header and skipped. Lines without a
// space are skipped (git-core ignores them; downstream parsers surface
// the issue if it matters).
func checkUniqueHeaders(obj plumbing.EncodedObject, singletons map[string]bool) error {
	r, err := obj.Reader()
	if err != nil {
		// Storage-layer failure: surface as-is so callers can see the
		// underlying go-git error rather than a generic malformed-object.
		return err
	}
	defer r.Close() // nolint:errcheck

	seen := make(map[string]bool, len(singletons))
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			// Blank line terminates the header section; anything after
			// is the message body, which is opaque text that may
			// legitimately contain "tree foo" etc. Stop here so body
			// content doesn't produce false positives.
			return nil
		}
		if line[0] == ' ' || line[0] == '\t' {
			// Continuation of the previous header (git wraps long values
			// like gpgsig PEM blocks across multiple lines, each prefixed
			// with a leading space). Treat as part of the prior header,
			// not a new one.
			continue
		}
		key, _, ok := bytes.Cut(line, []byte{' '})
		if !ok {
			// Header line with no space separator — git-core's parser
			// skips these silently. We do the same; if it actually
			// matters, go-git's decoder will fail on it downstream.
			continue
		}
		k := string(key)
		if !singletons[k] {
			// Header isn't one we track (parent, mergetag, encoding,
			// arbitrary extra headers). Duplicates of these are allowed
			// or out of scope for this validator.
			continue
		}
		if seen[k] {
			// Second occurrence of a singleton — this is the
			// trust-confusion-adjacent ambiguity we're rejecting.
			return fmt.Errorf("%w: duplicate %s header", ErrMalformedObject, k)
		}
		seen[k] = true
	}
	// Reached EOF without seeing a blank line. No duplicates found, so
	// validation passes; return any scanner I/O error (nil on success).
	return scanner.Err()
}
