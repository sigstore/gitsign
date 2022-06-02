//
// Copyright 2022 The Sigstore Authors.
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
	"context"
	"crypto/x509"
	"fmt"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/rekor"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/rekor/pkg/generated/models"
)

func Sign(ctx context.Context, rekor rekor.Writer, ident *fulcio.Identity, data []byte, opts signature.SignOptions) ([]byte, *x509.Certificate, error) {
	sig, cert, err := signature.Sign(ident, data, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// This uploads the commit SHA + sig(commit SHA) to the tlog using the same
	// key used to sign the commit data itself.
	// Since the commit SHA ~= hash(commit data + sig(commit data)) and we're
	// using the same key, this is probably okay? e.g. even if you could cause a SHA1 collision,
	// you would still need the underlying commit to be valid and using the same key which seems hard.

	commit, err := commitHash(data, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating commit hash: %w", err)
	}

	sv := ident.SignerVerifier()
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		return nil, nil, fmt.Errorf("error signing commit hash: %w", err)
	}
	if _, err := rekor.Write(ctx, commitSig, []byte(commit), sv.Cert); err != nil {
		return nil, nil, fmt.Errorf("error uploading tlog (commit): %w", err)
	}

	return sig, cert, nil
}

type VerificationSummary struct {
	// Certificate used to sign the commit.
	Cert *x509.Certificate
	// Rekor log entry of the commit.
	LogEntry *models.LogEntryAnon
	// List of claims about what succeeded / failed during validation.
	// This can be used to get details on what succeeded / failed during
	// validation. This is not an exhaustive list - claims may be missing
	// if validation ended early.
	Claims []Claim
}

// Claim is a k/v pair representing the status of a given ClaimCondition.
type Claim struct {
	Key   ClaimCondition
	Value bool
}

type ClaimCondition string

const (
	ClaimValidatedSignature  ClaimCondition = "Validated Git signature"
	ClaimValidatedRekorEntry ClaimCondition = "Validated Rekor entry"
)

func NewClaim(c ClaimCondition, ok bool) Claim {
	return Claim{
		Key:   c,
		Value: ok,
	}
}

func Verify(ctx context.Context, rekor rekor.Verifier, data, sig []byte, detached bool) (*VerificationSummary, error) {
	claims := []Claim{}

	cert, err := git.VerifySignature(data, sig, detached)
	if err != nil {
		return nil, err
	}
	claims = append(claims, NewClaim(ClaimValidatedSignature, true))

	commit, err := commitHash(data, sig)
	if err != nil {
		return nil, err
	}

	tlog, err := git.VerifyRekor(ctx, rekor, commit, cert)
	if err != nil {
		return nil, fmt.Errorf("failed to validate rekor entry: %w", err)
	}
	claims = append(claims, NewClaim(ClaimValidatedRekorEntry, true))

	return &VerificationSummary{
		Cert:     cert,
		LogEntry: tlog,
		Claims:   claims,
	}, nil
}

func commitHash(data, sig []byte) (string, error) {
	// Precompute commit hash to store in tlog
	obj := &plumbing.MemoryObject{}
	_, _ = obj.Write(data)
	obj.SetType(plumbing.CommitObject)

	// go-git will compute a hash on decode and preserve that. To work around this,
	// decode into one object then copy everything but the commit into a separate object.
	base := object.Commit{}
	_ = base.Decode(obj)
	c := object.Commit{
		Author:       base.Author,
		Committer:    base.Committer,
		PGPSignature: string(sig),
		Message:      base.Message,
		TreeHash:     base.TreeHash,
		ParentHashes: base.ParentHashes,
	}
	out := &plumbing.MemoryObject{}
	err := c.Encode(out)

	return out.Hash().String(), err
}
