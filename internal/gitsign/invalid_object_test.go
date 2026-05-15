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

package gitsign

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/git"
)

// TestDuplicateTreeTrustConfusion is an end-to-end regression test for the
// parser trust-confusion class of attack: an attacker replays a legitimate
// signature against a malformed commit with two tree headers. Historically,
// go-git's loose parser was last-wins (keeping the second tree, which
// happened to match the signed canonical form) while git-core was
// first-wins, opening a re-encoding window that let the signature verify
// against attacker-controlled raw bytes.
//
// The defense lives in two layers now:
//  1. Upstream go-git ≥ v5.19.0 switched to first-wins matching git-core, so
//     re-encoding through go-git no longer produces canonical bytes.
//  2. gitsign's verify path consumes raw object bytes via SplitCommit and
//     skips go-git entirely, so any divergence between signed and stored
//     bytes fails cryptographically regardless of parser fashion.
//
// The sub-tests assert all three properties: upstream is fixed, raw-byte
// verification still rejects malformed input, and well-formed input still
// passes (no over-aggressive rejection).
func TestDuplicateTreeTrustConfusion(t *testing.T) {
	cert, priv := generateCert(t, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "alice"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	})

	const (
		legitTree    = "b333504b8cf3d9c314fed2cc242c5c38e89534a5"
		attackerTree = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		author       = "author Alice <alice@example.com> 1700000000 +0000"
		committer    = "committer Alice <alice@example.com> 1700000000 +0000"
		message      = "legit commit\n"
	)

	// Canonical commit body — this is what Alice intended to sign. A single
	// tree header, message "legit commit".
	canonical := []byte(fmt.Sprintf("tree %s\n%s\n%s\n\n%s",
		legitTree, author, committer, message))

	id := &identity{cert: cert, priv: priv}
	resp, err := signature.Sign(context.Background(), id, canonical, signature.SignOptions{
		Detached:     true,
		Armor:        true,
		IncludeCerts: 0,
	})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	roots := x509.NewCertPool()
	roots.AddCert(cert)
	gv, err := git.NewCertVerifier(git.WithRootPool(roots))
	if err != nil {
		t.Fatalf("NewCertVerifier: %v", err)
	}

	malformedRaw := []byte(fmt.Sprintf(
		"tree %s\ntree %s\n%s\n%s\n%s\n%s",
		attackerTree, legitTree,
		author, committer,
		indent("gpgsig ", string(resp.Signature)),
		message,
	))

	t.Run("upstream go-git is no longer last-wins", func(t *testing.T) {
		// go-git ≥ v5.19.0 rewrote its commit decoder as a state machine
		// that takes the first tree (matching git-core). Re-encoding the
		// malformed bytes therefore carries attackerTree, not legitTree,
		// so the signature — made over a single-tree commit at legitTree —
		// no longer verifies against the re-encoded form. If this ever
		// starts passing, go-git has regressed to last-wins parsing and
		// the re-encoding attack window is open at the upstream layer
		// again (gitsign's own SplitCommit-based path still blocks it,
		// per the next sub-test).
		reencoded := reencodeViaGoGit(t, malformedRaw)

		if _, err := gv.Verify(context.Background(), reencoded, resp.Signature, true); err == nil {
			t.Fatalf("upstream regression: go-git re-encoded malformed bytes verified against the canonical signature")
		}
	})

	t.Run("fix: signature fails to verify against the raw malformed bytes", func(t *testing.T) {
		// SplitCommit hands the verifier the raw object bytes (with both
		// tree headers intact) instead of the go-git-normalized form. The
		// signature was made over the canonical (single-tree) bytes, so the
		// cryptographic check rejects this.
		c, err := git.SplitCommit(bytes.NewReader(malformedRaw))
		if err != nil {
			t.Fatalf("SplitCommit: %v", err)
		}
		if _, err := gv.Verify(context.Background(), c.Payload, c.Gpgsig, true); err == nil {
			t.Fatalf("expected signature verification to fail against malformed raw bytes, got nil error")
		}
	})

	t.Run("fix accepts the legitimate commit and signature verifies", func(t *testing.T) {
		// Positive control: a well-formed commit with the same signature
		// passes SplitCommit and the signature verifies. Guards against an
		// over-aggressive validator that also rejects legitimate commits.
		wellFormed := []byte(fmt.Sprintf(
			"tree %s\n%s\n%s\n%s\n%s",
			legitTree,
			author, committer,
			indent("gpgsig ", string(resp.Signature)),
			message,
		))

		c, err := git.SplitCommit(bytes.NewReader(wellFormed))
		if err != nil {
			t.Fatalf("SplitCommit: %v", err)
		}
		if _, err := gv.Verify(context.Background(), c.Payload, c.Gpgsig, true); err != nil {
			t.Errorf("signature verify over well-formed bytes: %v", err)
		}
	})
}

// indent formats the first line with the given prefix and subsequent lines
// with a single leading space — the git gpgsig header wire format. The output
// ends with a newline suitable for placement as a commit header followed by
// the blank-line message separator.
func indent(prefix, body string) string {
	body = strings.TrimSuffix(body, "\n")
	lines := strings.Split(body, "\n")
	return prefix + strings.Join(lines, "\n ") + "\n"
}

// reencodeViaGoGit mirrors exactly what the pre-fix gitsign verify path did:
// parse the raw commit through go-git and re-encode it without the signature
// header. This exercises the last-wins normalization that made the GHSA PoC
// work.
func reencodeViaGoGit(t *testing.T, raw []byte) []byte {
	t.Helper()
	obj := memory.NewStorage().NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var c object.Commit
	if err := c.Decode(obj); err != nil {
		t.Fatal(err)
	}
	out := memory.NewStorage().NewEncodedObject()
	if err := c.EncodeWithoutSignature(out); err != nil {
		t.Fatal(err)
	}
	r, err := out.Reader()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close() // nolint:errcheck
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
