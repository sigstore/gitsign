//
// Copyright 2024 The Sigstore Authors.
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
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/github/smimesign/ietf-cms/protocol"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// stripTlogAttr removes the embedded Rekor transparency log entry from signer 0,
// producing a CMS skeleton resembling a not-yet-uploaded signature.
func stripTlogAttr(sd *cms.SignedData) {
	si := sd.Raw().SignerInfos[0]
	filtered := make(protocol.Attributes, 0, len(si.UnsignedAttrs))
	for _, a := range si.UnsignedAttrs {
		if a.Type.Equal(rekoroid.OIDRekorTransparencyLogEntry) {
			continue
		}
		filtered = append(filtered, a)
	}
	si.UnsignedAttrs = filtered
	sd.Raw().SignerInfos[0] = si
}

// loadSignedData parses the CMS SignedData from the gpgsig of the test commit
// and injects the transparency log entry from tlog.json into its unsigned
// attributes, mirroring how a real offline-mode gitsign signature looks.
func loadSignedData(t *testing.T) (*cms.SignedData, *models.LogEntryAnon) {
	t.Helper()

	commit := parseCommit(t, "testdata/commit.txt")
	blk, _ := pem.Decode([]byte(commit.PGPSignature))
	if blk == nil {
		t.Fatal("no PEM block in signature")
	}
	sd, err := cms.ParseSignedData(blk.Bytes)
	if err != nil {
		t.Fatalf("ParseSignedData: %v", err)
	}

	tlog := new(models.LogEntryAnon)
	if err := json.Unmarshal(readfile(t, "testdata/tlog.json"), tlog); err != nil {
		t.Fatalf("unmarshal tlog.json: %v", err)
	}

	// Inject the tlog entry as the offline signing path would.
	if !sd.Raw().SignerInfos[0].UnsignedAttrs.HasAttribute(rekoroid.OIDRekorTransparencyLogEntry) {
		attrs, err := rekoroid.ToAttributes(tlog)
		if err != nil {
			t.Fatalf("ToAttributes: %v", err)
		}
		si := sd.Raw().SignerInfos[0]
		si.UnsignedAttrs = append(si.UnsignedAttrs, attrs...)
		sd.Raw().SignerInfos[0] = si
	}

	return sd, tlog
}

func TestSignerInfoToBundle(t *testing.T) {
	ctx := context.Background()
	sd, _ := loadSignedData(t)

	si := sd.Raw().SignerInfos[0]
	wantMessage, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatal(err)
	}
	certs, err := sd.GetCertificates()
	if err != nil {
		t.Fatal(err)
	}
	wantCert := certs[0]

	sb, err := SignerInfoToBundle(ctx, sd, sd.Raw().SignerInfos[0])
	if err != nil {
		t.Fatalf("SignerInfoToBundle: %v", err)
	}
	b := sb.Bundle

	// The returned artifact must be the marshaled SignedAttrs.
	if diff := cmp.Diff(wantMessage, sb.Artifact); diff != "" {
		t.Errorf("artifact mismatch (-want +got):\n%s", diff)
	}

	// The bundle must validate as a well-formed sigstore bundle (v0.3, single
	// cert, inclusion proof present).
	if _, err := bundle.NewBundle(b); err != nil {
		t.Fatalf("bundle.NewBundle: %v", err)
	}

	// Signature, digest, and certificate must map correctly.
	ms := b.GetMessageSignature()
	if !bytes.Equal(ms.GetSignature(), si.Signature) {
		t.Error("bundle signature does not match SignerInfo signature")
	}
	wantDigest := sha256.Sum256(wantMessage)
	if diff := cmp.Diff(wantDigest[:], ms.GetMessageDigest().GetDigest()); diff != "" {
		t.Errorf("digest mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(wantCert.Raw, b.GetVerificationMaterial().GetCertificate().GetRawBytes()); diff != "" {
		t.Errorf("certificate mismatch (-want +got):\n%s", diff)
	}

	// The reconstructed tlog entry must match what oid.ToLogEntry produces from
	// the same signature, validating the canonicalized_body recompute.
	tles := b.GetVerificationMaterial().GetTlogEntries()
	if len(tles) != 1 {
		t.Fatalf("expected 1 tlog entry, got %d", len(tles))
	}
	wantLogEntry, err := rekoroid.ToLogEntry(ctx, wantMessage, si.Signature, wantCert, si.UnsignedAttrs)
	if err != nil {
		t.Fatal(err)
	}
	gotLogEntry := rekoroid.ProtoToLogEntryAnon(tles[0])
	if diff := cmp.Diff(wantLogEntry, gotLogEntry); diff != "" {
		t.Errorf("tlog entry mismatch (-want +got):\n%s", diff)
	}
}

func TestBundleToAttributes(t *testing.T) {
	ctx := context.Background()
	sd, _ := loadSignedData(t)

	// Convert to a bundle, derive attributes from it, append them to a fresh CMS
	// skeleton (one without the OID attr), and confirm we recover an equivalent
	// re-derived bundle.
	sb, err := SignerInfoToBundle(ctx, sd, sd.Raw().SignerInfos[0])
	if err != nil {
		t.Fatalf("SignerInfoToBundle: %v", err)
	}
	b := sb.Bundle

	attrSets, err := BundleToAttributes(b)
	if err != nil {
		t.Fatalf("BundleToAttributes: %v", err)
	}
	if len(attrSets) != 1 {
		t.Fatalf("expected 1 attribute set from BundleToAttributes, got %d", len(attrSets))
	}

	// Fresh skeleton: re-parse the signature and strip the tlog attr.
	commit := parseCommit(t, "testdata/commit.txt")
	blk, _ := pem.Decode([]byte(commit.PGPSignature))
	skeleton, err := cms.ParseSignedData(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	stripTlogAttr(skeleton)
	if skeleton.Raw().SignerInfos[0].UnsignedAttrs.HasAttribute(rekoroid.OIDRekorTransparencyLogEntry) {
		t.Fatal("skeleton still has tlog attr after stripping")
	}

	// Caller-side SignedData manipulation: append each attribute set to the signer.
	si := skeleton.Raw().SignerInfos[0]
	for _, attrs := range attrSets {
		si.UnsignedAttrs = append(si.UnsignedAttrs, attrs...)
	}
	skeleton.Raw().SignerInfos[0] = si

	// Re-deriving a bundle from the updated skeleton must reproduce the same tlog
	// entry, proving BundleToAttributes produced a valid OID attribute.
	gotSB, err := SignerInfoToBundle(ctx, skeleton, skeleton.Raw().SignerInfos[0])
	if err != nil {
		t.Fatalf("SignerInfoToBundle(updated): %v", err)
	}
	got := gotSB.Bundle
	if _, err := bundle.NewBundle(got); err != nil {
		t.Fatalf("bundle.NewBundle(updated): %v", err)
	}

	wantLogEntry := rekoroid.ProtoToLogEntryAnon(b.GetVerificationMaterial().GetTlogEntries()[0])
	gotLogEntry := rekoroid.ProtoToLogEntryAnon(got.GetVerificationMaterial().GetTlogEntries()[0])
	if diff := cmp.Diff(wantLogEntry, gotLogEntry); diff != "" {
		t.Errorf("round-tripped tlog entry mismatch (-want +got):\n%s", diff)
	}
}

func TestBundleToAttributesNoTlog(t *testing.T) {
	ctx := context.Background()

	// A bundle with no transparency log entry yields no attributes.
	commit := parseCommit(t, "testdata/commit.txt")
	blk, _ := pem.Decode([]byte(commit.PGPSignature))
	sd, err := cms.ParseSignedData(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	stripTlogAttr(sd)

	sb, err := SignerInfoToBundle(ctx, sd, sd.Raw().SignerInfos[0])
	if err != nil {
		t.Fatal(err)
	}
	attrSets, err := BundleToAttributes(sb.Bundle)
	if err != nil {
		t.Fatalf("BundleToAttributes: %v", err)
	}
	if len(attrSets) != 0 {
		t.Errorf("expected no attribute sets for a bundle with no tlog, got %d", len(attrSets))
	}
}

func TestSignedDataToBundle(t *testing.T) {
	ctx := context.Background()
	sd, _ := loadSignedData(t)

	bundles, err := SignedDataToBundle(ctx, sd)
	if err != nil {
		t.Fatalf("SignedDataToBundle: %v", err)
	}
	if len(bundles) != len(sd.Raw().SignerInfos) {
		t.Fatalf("expected %d bundles, got %d", len(sd.Raw().SignerInfos), len(bundles))
	}
	for i, sb := range bundles {
		if _, err := bundle.NewBundle(sb.Bundle); err != nil {
			t.Errorf("bundle %d invalid: %v", i, err)
		}
		if len(sb.Artifact) == 0 {
			t.Errorf("bundle %d has empty artifact", i)
		}
	}
}

func TestSignerInfoToBundleNoTlog(t *testing.T) {
	ctx := context.Background()

	// Parse the signature and strip any tlog entry to exercise the no-tlog path.
	commit := parseCommit(t, "testdata/commit.txt")
	blk, _ := pem.Decode([]byte(commit.PGPSignature))
	sd, err := cms.ParseSignedData(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	stripTlogAttr(sd)

	sb, err := SignerInfoToBundle(ctx, sd, sd.Raw().SignerInfos[0])
	if err != nil {
		t.Fatalf("SignerInfoToBundle: %v", err)
	}
	if entries := sb.Bundle.GetVerificationMaterial().GetTlogEntries(); len(entries) != 0 {
		t.Errorf("expected no tlog entries, got %d", len(entries))
	}
	// A bundle with no tlog entries is still a valid v0.3 bundle.
	if _, err := bundle.NewBundle(sb.Bundle); err != nil {
		t.Fatalf("bundle.NewBundle: %v", err)
	}
}

func parseCommit(t *testing.T, path string) *object.Commit {
	t.Helper()

	raw := readfile(t, path)
	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("git object writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("write git commit: %v", err)
	}
	c, err := object.DecodeCommit(storage, obj)
	if err != nil {
		t.Fatalf("decode commit: %v", err)
	}
	return c
}

func readfile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
