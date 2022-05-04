package git

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/signature"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/wlynch/smimecosign/fulcio"
	"github.com/wlynch/smimecosign/rekor"
)

func Sign(ctx context.Context, ident *fulcio.Identity, data []byte, opts signature.SignOptions) ([]byte, *x509.Certificate, error) {
	sig, cert, err := signature.Sign(ident, data, opts)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign message")
	}

	// This uploads the commit SHA + sig(commit SHA) to the tlog using the same
	// key used to sign the commit data itself.
	// Since the commit SHA ~= hash(commit data + sig(commit data)) and we're
	// using the same key, this is probably okay? e.g. even if you could cause a SHA1 collision,
	// you would still need the underlying commit to be valid and using the same key which seems hard.

	rekor, err := rekor.New("https://rekor.sigstore.dev")
	if err != nil {
		return nil, nil, errors.Wrap(err, "error creating rekor client")
	}

	commit, err := commitHash(data, sig)
	if err != nil {
		return nil, nil, errors.Wrap(err, "error generating commit hash")
	}

	sv := ident.SignerVerifier()
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		return nil, nil, errors.Wrap(err, "error signing commit hash")
	}
	if _, err := rekor.Write(ctx, commitSig, []byte(commit), sv.Cert); err != nil {
		return nil, nil, errors.Wrap(err, "error uploading tlog (commit)")
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
	ClaimParsedSignature     ClaimCondition = "Parsed Git signature"
	ClaimValidatedSignature  ClaimCondition = "Validated Git signature"
	ClaimLocatedRekorEntry   ClaimCondition = "Located Rekor entry"
	ClaimValidatedRekorEntry ClaimCondition = "Validated Rekor entry"
)

func NewClaim(c ClaimCondition, ok bool) Claim {
	return Claim{
		Key:   c,
		Value: ok,
	}
}

func Verify(ctx context.Context, data, sig []byte) (*VerificationSummary, error) {
	claims := []Claim{}
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
		claims = append(claims, NewClaim(ClaimParsedSignature, false))
		return nil, errors.Wrap(err, "failed to parse signature")
	}
	claims = append(claims, NewClaim(ClaimParsedSignature, true))

	// Generate verification options.
	certs, err := sd.GetCertificates()
	if err != nil {
		claims = append(claims, NewClaim(ClaimValidatedSignature, false))
		return nil, errors.Wrap(err, "error getting signature certs")
	}
	opts := x509.VerifyOptions{
		Roots:     fulcioroots.Get(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: certs[0].NotBefore,
	}

	_, err = sd.VerifyDetached(data, opts)
	if err != nil {
		claims = append(claims, NewClaim(ClaimValidatedSignature, false))
		return nil, errors.Wrap(err, "failed to verify signature")
	}
	claims = append(claims, NewClaim(ClaimValidatedSignature, true))

	commit, err := commitHash(data, sig)
	if err != nil {
		claims = append(claims, NewClaim(ClaimLocatedRekorEntry, false))
		return nil, err
	}

	rekor, err := rekor.New("https://rekor.sigstore.dev")
	if err != nil {
		claims = append(claims, NewClaim(ClaimLocatedRekorEntry, false))
		return nil, err
	}
	tlog, err := rekor.Get(ctx, commit, certs[0])
	if err != nil {
		claims = append(claims, NewClaim(ClaimLocatedRekorEntry, false))
		return nil, errors.Wrap(err, "failed to locate rekor entry")
	}
	claims = append(claims, NewClaim(ClaimLocatedRekorEntry, true))

	if err := rekor.Verify(ctx, tlog); err != nil {
		claims = append(claims, NewClaim(ClaimValidatedRekorEntry, true))
		return nil, errors.Wrap(err, "failed to validate rekor entry")
	}
	claims = append(claims, NewClaim(ClaimValidatedRekorEntry, true))

	return &VerificationSummary{
		Cert:     certs[0],
		LogEntry: tlog,
		Claims:   claims,
	}, nil
}

func commitHash(data, sig []byte) (string, error) {
	// Precompute commit hash to store in tlog
	obj := &plumbing.MemoryObject{}
	obj.Write(data)
	obj.SetType(plumbing.CommitObject)

	// go-git will compute a hash on decode and preserve that. To work around this,
	// decode into one object then copy everything but the commit into a separate object.
	base := object.Commit{}
	base.Decode(obj)
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
