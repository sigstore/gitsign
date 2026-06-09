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

package gitsign

import (
	"context"
	"errors"
	"testing"

	"github.com/sigstore/gitsign/internal/git/gittest"
)

// TestVerifyBundleNoEmbeddedRekorEntry covers a legacy "online" signature, which
// embeds no Rekor transparency log entry (its entry lives in Rekor keyed on the
// commit SHA and is found via online search). The sigstore-go bundle path cannot
// verify these from the signature alone, so it must surface
// errNoEmbeddedRekorEntry, which Verify uses to fall back to the legacy path
// rather than failing verification outright.
func TestVerifyBundleNoEmbeddedRekorEntry(t *testing.T) {
	ctx := context.Background()

	commit := gittest.ParseCommit(t, "testdata/online.commit")
	body := gittest.MarshalCommitBody(t, commit)
	sig := []byte(commit.PGPSignature)

	// trustedMaterial is intentionally nil: the no-embedded-entry case is
	// detected and returned before any trust material is consulted.
	v := &Verifier{useBundle: true}

	_, err := v.verifyBundle(ctx, body, sig, true)
	if !errors.Is(err, errNoEmbeddedRekorEntry) {
		t.Fatalf("verifyBundle error = %v, want errNoEmbeddedRekorEntry", err)
	}
}
