// Copyright 2024 The Sigstore Authors.
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

//go:build e2e
// +build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/git/gittest"
	"github.com/sigstore/gitsign/internal/gitsign"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// TestVerifyBundleParity verifies the same offline commit through both the
// legacy verification path and the experimental sigstore-go bundle path
// (GITSIGN_VERIFY_BUNDLE) and asserts they agree on the signing certificate and
// Rekor log entry.
func TestVerifyBundleParity(t *testing.T) {
	ctx := context.Background()

	// Initialize to prod root.
	if err := tuf.Initialize(ctx, tuf.DefaultRemoteRoot, nil); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{
		Fulcio: "https://fulcio.sigstore.dev",
		Rekor:  "https://rekor.sigstore.dev",
	}

	commit := gittest.ParseCommit(t, "testdata/offline.commit")
	body := gittest.MarshalCommitBody(t, commit)
	sig := []byte(commit.PGPSignature)

	// Legacy path.
	legacyVerifier, err := gitsign.NewVerifierWithCosignOpts(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("legacy NewVerifierWithCosignOpts: %v", err)
	}
	legacy, err := legacyVerifier.Verify(ctx, body, sig, true)
	if err != nil {
		t.Fatalf("legacy verify: %v", err)
	}

	// Bundle path.
	t.Setenv("GITSIGN_VERIFY_BUNDLE", "1")
	bundleVerifier, err := gitsign.NewVerifierWithCosignOpts(ctx, cfg, nil)
	if err != nil {
		t.Fatalf("bundle NewVerifierWithCosignOpts: %v", err)
	}
	bundle, err := bundleVerifier.Verify(ctx, body, sig, true)
	if err != nil {
		t.Fatalf("bundle verify: %v", err)
	}

	// Both paths must agree on the signing certificate.
	if !legacy.Cert.Equal(bundle.Cert) {
		t.Error("legacy and bundle paths returned different signing certificates")
	}

	// ...and on the Rekor log entry.
	switch {
	case legacy.LogEntry == nil || bundle.LogEntry == nil:
		t.Errorf("missing log entry: legacy=%v bundle=%v", legacy.LogEntry, bundle.LogEntry)
	case legacy.LogEntry.LogIndex == nil || bundle.LogEntry.LogIndex == nil:
		t.Errorf("missing log index: legacy=%v bundle=%v", legacy.LogEntry.LogIndex, bundle.LogEntry.LogIndex)
	case *legacy.LogEntry.LogIndex != *bundle.LogEntry.LogIndex:
		t.Errorf("log index mismatch: legacy=%d bundle=%d", *legacy.LogEntry.LogIndex, *bundle.LogEntry.LogIndex)
	}
}
