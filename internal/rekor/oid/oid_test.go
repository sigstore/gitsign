// Copyright 2023 The Sigstore Authors
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

package oid

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/google/go-cmp/cmp"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func TestOID(t *testing.T) {
	tlog := new(models.LogEntryAnon)
	if err := json.Unmarshal(readfile(t, "testdata/tlog.json"), tlog); err != nil {
		t.Fatal(err)
	}

	attr, err := ToAttributes(tlog)
	if err != nil {
		t.Fatalf("ToAttributes: %v", err)
	}

	commit := parseCommit(t, "testdata/commit.txt")
	message, sig, cert := parseSignature(t, commit)

	ctx := context.Background()
	got, err := ToLogEntry(ctx, message, sig, cert, attr)
	if err != nil {
		t.Fatalf("ToLogEntry: %v", err)
	}

	if diff := cmp.Diff(tlog, got); diff != "" {
		t.Errorf(diff)
	}
}

func readfile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parseCommit(t *testing.T, path string) *object.Commit {
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("error reading input: %v", err)
	}

	storage := memory.NewStorage()
	obj := storage.NewEncodedObject()
	obj.SetType(plumbing.CommitObject)
	w, err := obj.Writer()
	if err != nil {
		t.Fatalf("error getting git object writer: %v", err)
	}
	if _, err := w.Write(raw); err != nil {
		t.Fatalf("error writing git commit: %v", err)
	}

	c, err := object.DecodeCommit(storage, obj)
	if err != nil {
		t.Fatalf("error decoding commit: %v", err)
	}
	return c
}

// Returns: body, sig, cert
func parseSignature(t *testing.T, c *object.Commit) ([]byte, []byte, *x509.Certificate) {
	// Parse signature
	blk, _ := pem.Decode([]byte(c.PGPSignature))
	sd, err := cms.ParseSignedData(blk.Bytes)
	if err != nil {
		t.Fatalf("failed to parse signature: %v", err)
	}
	si := sd.Raw().SignerInfos[0]

	body, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		t.Fatalf("error marshalling commit body for verification: %v", err)
	}

	certs, err := sd.GetCertificates()
	if err != nil {
		t.Fatalf("error getting signature certs: %v", err)
	}
	cert := certs[0]

	return body, si.Signature, cert
}
