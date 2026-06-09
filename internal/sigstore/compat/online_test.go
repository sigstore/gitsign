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

package compat

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// TestOnlineBundle builds a synthetic commit-SHA HashedRekord entry (as
// git.LegacySHASign would upload) and checks that OnlineBundle reconstructs a
// well-formed bundle whose artifact is the commit SHA, whose MessageSignature
// carries the commit-SHA signature and its digest, and which embeds the entry.
func TestOnlineBundle(t *testing.T) {
	ctx := context.Background()

	const commitSHA = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
	artifact := []byte(commitSHA)
	digest := sha256.Sum256(artifact)

	cert, signer := selfSignedCert(t)

	// The HashedRekord signs the artifact (the commit SHA), keyed on its sha256.
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}

	le := onlineLogEntry(ctx, t, digest[:], sig, cert)

	sb, err := OnlineBundle(commitSHA, le, cert)
	if err != nil {
		t.Fatalf("OnlineBundle: %v", err)
	}

	// The verification artifact must be the commit SHA itself.
	if diff := cmp.Diff(artifact, sb.Artifact); diff != "" {
		t.Errorf("artifact mismatch (-want +got):\n%s", diff)
	}

	// The bundle must be a well-formed sigstore v0.3 bundle.
	if _, err := bundle.NewBundle(sb.Bundle); err != nil {
		t.Fatalf("bundle.NewBundle: %v", err)
	}

	// MessageSignature must carry the commit-SHA signature and its digest.
	ms := sb.Bundle.GetMessageSignature()
	if diff := cmp.Diff(sig, ms.GetSignature()); diff != "" {
		t.Errorf("signature mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(digest[:], ms.GetMessageDigest().GetDigest()); diff != "" {
		t.Errorf("digest mismatch (-want +got):\n%s", diff)
	}

	// The leaf certificate must be carried through.
	if diff := cmp.Diff(cert.Raw, sb.Bundle.GetVerificationMaterial().GetCertificate().GetRawBytes()); diff != "" {
		t.Errorf("certificate mismatch (-want +got):\n%s", diff)
	}

	// The transparency log entry must be present.
	if tles := sb.Bundle.GetVerificationMaterial().GetTlogEntries(); len(tles) != 1 {
		t.Fatalf("expected 1 tlog entry, got %d", len(tles))
	}
}

func TestOnlineBundleNilEntry(t *testing.T) {
	if _, err := OnlineBundle("deadbeef", nil, &x509.Certificate{}); err == nil {
		t.Error("OnlineBundle(nil entry) = nil error, want error")
	}
}

// onlineLogEntry assembles a models.LogEntryAnon for a HashedRekord over the
// given digest/signature/cert, with a synthetic-but-structurally-valid inclusion
// proof, mirroring what an online Rekor search returns.
func onlineLogEntry(ctx context.Context, t *testing.T, digest, sig []byte, cert *x509.Certificate) *models.LogEntryAnon {
	t.Helper()

	certPEM, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		t.Fatal(err)
	}
	re := &hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer("sha256"),
					Value:     conv.Pointer(hex.EncodeToString(digest)),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(sig),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(certPEM),
				},
			},
		},
	}
	body, err := types.CanonicalizeEntry(ctx, re)
	if err != nil {
		t.Fatalf("CanonicalizeEntry: %v", err)
	}

	rootHash := sha256.Sum256([]byte("root"))
	return &models.LogEntryAnon{
		LogID:          conv.Pointer(hex.EncodeToString(sha256.New().Sum(nil))),
		LogIndex:       conv.Pointer(int64(1)),
		IntegratedTime: conv.Pointer(time.Now().Unix()),
		Body:           base64.StdEncoding.EncodeToString(body),
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: []byte("signed-entry-timestamp"),
			InclusionProof: &models.InclusionProof{
				LogIndex:   conv.Pointer(int64(0)),
				RootHash:   conv.Pointer(hex.EncodeToString(rootHash[:])),
				TreeSize:   conv.Pointer(int64(1)),
				Hashes:     []string{},
				Checkpoint: conv.Pointer("checkpoint"),
			},
		},
	}
}
