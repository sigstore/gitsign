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
	"encoding/pem"
	"errors"
	"fmt"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/sigstore/gitsign/pkg/rekor"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
)

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

	root, err := fulcioroots.Get()
	if err != nil {
		return nil, fmt.Errorf("getting fulcio root certificate: %w", err)
	}
	intermediates, err := fulcioroots.GetIntermediates()
	if err != nil {
		return nil, fmt.Errorf("getting fulcio intermediate certificates: %w", err)
	}

	cert, err := VerifySignature(data, sig, detached, root, intermediates)
	if err != nil {
		return nil, err
	}
	claims = append(claims, NewClaim(ClaimValidatedSignature, true))

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
func VerifySignature(data, sig []byte, detached bool, rootCerts, intermediates *x509.CertPool) (*x509.Certificate, error) {
	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(sig); blk != nil {
		der = blk.Bytes
	} else {
		der = sig
	}
	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse signature: %w", err)
	}

	// Generate verification options.
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, fmt.Errorf("error getting signature certs: %w", err)
	}
	cert := certs[0]

	opts := x509.VerifyOptions{
		Roots:         rootCerts,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: cert.NotBefore,
	}

	if detached {
		if _, err := sd.VerifyDetached(data, opts); err != nil {
			return nil, fmt.Errorf("failed to verify detached signature: %w", err)
		}
	} else {
		if _, err := sd.Verify(opts); err != nil {
			return nil, fmt.Errorf("failed to verify attached signature: %w", err)
		}
	}

	return cert, nil
}

type encoder interface {
	Encode(o plumbing.EncodedObject) error
}

func ObjectHash(data, sig []byte) (string, error) {
	// Precompute commit hash to store in tlog
	obj := &plumbing.MemoryObject{}
	if _, err := obj.Write(data); err != nil {
		return "", err
	}

	var (
		encoder encoder
		err     error
	)
	// We're making big assumptions here about the ordering of fields
	// in Git objects. Unfortunately go-git does loose parsing of objects,
	// so it will happily decode objects that don't match the unmarshal type.
	// We should see if there's a better way to detect object types.
	switch {
	case bytes.HasPrefix(data, []byte("tree ")):
		encoder, err = commit(obj, sig)
	case bytes.HasPrefix(data, []byte("object ")):
		encoder, err = tag(obj, sig)
	default:
		return "", errors.New("could not determine Git object type")
	}
	if err != nil {
		return "", err
	}

	// go-git will compute a hash on decode and preserve even if we alter the
	// object data. To work around this, re-encode the object into a new object
	// to force a new hash to be computed.
	out := &plumbing.MemoryObject{}
	err = encoder.Encode(out)
	return out.Hash().String(), err
}

func commit(obj *plumbing.MemoryObject, sig []byte) (*object.Commit, error) {
	obj.SetType(plumbing.CommitObject)

	base := object.Commit{}
	if err := base.Decode(obj); err != nil {
		return nil, err
	}
	return &object.Commit{
		Author:       base.Author,
		Committer:    base.Committer,
		PGPSignature: string(sig),
		Message:      base.Message,
		TreeHash:     base.TreeHash,
		ParentHashes: base.ParentHashes,
	}, nil
}

func tag(obj *plumbing.MemoryObject, sig []byte) (*object.Tag, error) {
	obj.SetType(plumbing.TagObject)

	base := object.Tag{}
	if err := base.Decode(obj); err != nil {
		return nil, err
	}
	return &object.Tag{
		Tagger:       base.Tagger,
		Name:         base.Name,
		TargetType:   base.TargetType,
		Target:       base.Target,
		Message:      base.Message,
		PGPSignature: string(sig),
	}, nil
}
