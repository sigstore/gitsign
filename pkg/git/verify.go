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
	"errors"
	"fmt"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// VerificationSummary holds artifacts of the gitsign verification of a Git commit or tag.
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

// Claim is a key value pair representing the status of a given ClaimCondition.
type Claim struct {
	Key   ClaimCondition
	Value bool
}

type ClaimCondition string

const (
	ClaimValidatedSignature  ClaimCondition = "Validated Git signature"
	ClaimValidatedRekorEntry ClaimCondition = "Validated Rekor entry"
	ClaimValidatedCerificate ClaimCondition = "Validated Certificate claims"
)

func NewClaim(c ClaimCondition, ok bool) Claim {
	return Claim{
		Key:   c,
		Value: ok,
	}
}

// Verify takes a context, rekor verifier client, Git object data (everything but the signature), and a Git signature.
// A VerificationSummary is returned with the signing certificate & Rekor transparency log index of the Git object, if found,
// and whether each is valid for the given Git data.
func Verify(ctx context.Context, git Verifier, rekor rekor.Verifier, data, sig []byte, detached bool) (*VerificationSummary, error) {
	claims := []Claim{}

	cert, err := git.Verify(ctx, data, sig, detached)
	if err != nil {
		return nil, err
	}
	claims = append(claims, NewClaim(ClaimValidatedSignature, true))

	if tlog, err := rekor.VerifyInclusion(ctx, sig, cert); err == nil {
		return &VerificationSummary{
			Cert:     cert,
			LogEntry: tlog,
			Claims:   claims,
		}, nil
	}

	// Legacy commit based lookup.
	commit, err := ObjectHash(data, sig)
	if err != nil {
		return nil, err
	}
	tlog, err := rekor.Verify(ctx, commit, cert)
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

// VerifySignature verifies for a given Git data + signature pair.
//
// Data should be the Git data that was signed (i.e. everything in the commit
// besides the signature). Note: passing in the commit object itself will not
// work.
//
// Signatures should be CMS/PKCS7 formatted.
//
// Deprecated: Use CertVerifier.Verify instead.
func VerifySignature(data, sig []byte, detached bool, rootCerts, intermediates *x509.CertPool) (*x509.Certificate, error) {
	v, err := NewCertVerifier(WithRootPool(rootCerts), WithIntermediatePool(intermediates))
	if err != nil {
		return nil, err
	}

	return v.Verify(context.Background(), data, sig, detached)
}

// ObjectHash is a string representation of an encoded Git object. data is the
// signed payload (the bytes fed to the verifier); sig is the PEM-encoded
// signature that was embedded in the object. The returned hash matches what
// git-core computes for the reassembled raw object.
func ObjectHash(data, sig []byte) (string, error) {
	var (
		raw     []byte
		objType plumbing.ObjectType
		err     error
	)
	switch {
	case bytes.HasPrefix(data, []byte("tree ")):
		raw, err = JoinCommit(data, sig)
		if err != nil {
			return "", err
		}
		objType = plumbing.CommitObject
	case bytes.HasPrefix(data, []byte("object ")):
		raw = JoinTag(data, sig)
		objType = plumbing.TagObject
	default:
		return "", errors.New("could not determine Git object type")
	}

	obj := &plumbing.MemoryObject{}
	obj.SetType(objType)
	if _, err := obj.Write(raw); err != nil {
		return "", err
	}
	return obj.Hash().String(), nil
}
