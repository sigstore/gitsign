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
)

var (
	// ErrMalformedObject is returned for structural ambiguities the
	// downstream signature check can't catch on its own — currently just
	// multiple gpgsig headers, where it's unclear which signature to extract.
	ErrMalformedObject = errors.New("malformed git object")
	// ErrUnsupportedSignatureType is returned when the embedded signature is
	// not a format gitsign can verify. gitsign only accepts PEM blocks of type
	// "SIGNED MESSAGE" (CMS/PKCS7).
	ErrUnsupportedSignatureType = errors.New("unsupported signature type")
)

const gpgsigPrefix = "gpgsig "

// SplitCommit splits the raw bytes of a commit object (in object-database form,
// without the "commit <len>\0" prefix) into the payload that was signed and
// the PEM-encoded signature. It operates purely on the raw bytes, mirroring
// what git-core feeds to its signature verifier, and does not go through
// go-git's object parser.
//
// The trust-confusion class of attack (GHSA-7rmh-48mx-2vwc) relied on gitsign
// re-encoding through go-git before verification — which normalized away
// duplicate headers and let a signature over the canonical form verify
// against attacker-controlled raw bytes. Verifying directly over the raw
// bytes blocks that: any structural divergence between what was signed and
// what's stored makes the signature fail to verify cryptographically.
// Consequently, SplitCommit doesn't reject merely "weird but git-valid"
// objects (e.g. duplicate tree headers); the signature check below is what
// catches them. The one structural thing we do reject is multiple gpgsig
// headers, since that's ambiguous about which signature to extract.
func SplitCommit(r io.Reader) (payload, sig []byte, err error) {
	scanner := bufio.NewScanner(r)

	var (
		payloadBuf bytes.Buffer
		sigBuf     bytes.Buffer
		inGpgsig   bool
		inBody     bool
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
			inGpgsig = false
			continue
		}

		if inGpgsig {
			// git-core requires exactly one leading space on a gpgsig
			// continuation (see git/commit.c parse_buffer_signed_by_header).
			// We accept any leading whitespace and strip it: the signature
			// is cryptographically verified downstream, so leniency here
			// can't cause trust confusion, and being permissive avoids
			// rejecting signatures produced by tooling that wraps with
			// slightly different indentation.
			if trimmed := bytes.TrimLeftFunc(line, unicode.IsSpace); len(trimmed) < len(line) {
				sigBuf.Write(trimmed)
				sigBuf.WriteByte('\n')
				continue
			}
			// Non-continuation line -> gpgsig block ended; fall through and
			// process this line as a fresh header.
			inGpgsig = false
		}

		if bytes.HasPrefix(line, []byte(gpgsigPrefix)) {
			if sigBuf.Len() > 0 {
				return nil, nil, fmt.Errorf("%w: duplicate gpgsig header", ErrMalformedObject)
			}
			inGpgsig = true
			sigBuf.Write(line[len(gpgsigPrefix):])
			sigBuf.WriteByte('\n')
			continue
		}

		payloadBuf.Write(line)
		payloadBuf.WriteByte('\n')
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return payloadBuf.Bytes(), sigBuf.Bytes(), nil
}

// JoinCommit is the inverse of SplitCommit. It inserts a gpgsig header
// containing sig into payload, immediately before the blank line separating
// headers from message body. Continuation lines are indented with a single
// space to match git-core's wire format.
//
// sig is the PEM-encoded signature with lines separated by "\n". A trailing
// newline on sig is ignored.
func JoinCommit(payload, sig []byte) ([]byte, error) {
	hdrEnd := bytes.Index(payload, []byte("\n\n"))
	if hdrEnd < 0 {
		return nil, fmt.Errorf("%w: payload has no header terminator", ErrMalformedObject)
	}
	// Split signature into lines, drop a single trailing newline if any.
	s := sig
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	lines := bytes.Split(s, []byte{'\n'})

	var hdr bytes.Buffer
	hdr.WriteString(gpgsigPrefix)
	hdr.Write(lines[0])
	hdr.WriteByte('\n')
	for _, l := range lines[1:] {
		hdr.WriteByte(' ')
		hdr.Write(l)
		hdr.WriteByte('\n')
	}

	out := make([]byte, 0, len(payload)+hdr.Len())
	out = append(out, payload[:hdrEnd+1]...) // include the \n terminating the last header
	out = append(out, hdr.Bytes()...)
	out = append(out, payload[hdrEnd+1:]...) // the remaining \n + message body
	return out, nil
}

// SplitTag splits the raw bytes of a tag object into the payload that was
// signed and the trailing PEM signature block. Like SplitCommit, it works on
// raw bytes and does not invoke go-git's parser, so any divergence between
// what was signed and what's stored is caught by the cryptographic check
// downstream rather than by structural validation here. The signature is
// taken to start at the last line-anchored "-----BEGIN " marker, matching
// git-core's tag verification path.
func SplitTag(r io.Reader) (payload, sig []byte, err error) {
	scanner := bufio.NewScanner(r)

	var (
		payloadBuf bytes.Buffer
		sigBuf     bytes.Buffer
		inBody     bool
	)

	for scanner.Scan() {
		line := scanner.Bytes()

		if !inBody {
			payloadBuf.Write(line)
			payloadBuf.WriteByte('\n')
			if len(line) == 0 {
				inBody = true
			}
			continue
		}

		// In body. Track only the last "-----BEGIN " block as the signature
		// — anything before it (including any earlier PEM-looking lines in
		// the message body) belongs in payload.
		switch {
		case bytes.HasPrefix(line, []byte("-----BEGIN ")):
			payloadBuf.Write(sigBuf.Bytes())
			sigBuf.Reset()
			sigBuf.Write(line)
			sigBuf.WriteByte('\n')
		case sigBuf.Len() > 0:
			sigBuf.Write(line)
			sigBuf.WriteByte('\n')
		default:
			payloadBuf.Write(line)
			payloadBuf.WriteByte('\n')
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}

	return payloadBuf.Bytes(), sigBuf.Bytes(), nil
}

// JoinTag is the inverse of SplitTag. The signature is appended verbatim to
// the payload.
func JoinTag(payload, sig []byte) []byte {
	out := make([]byte, 0, len(payload)+len(sig))
	out = append(out, payload...)
	out = append(out, sig...)
	return out
}
