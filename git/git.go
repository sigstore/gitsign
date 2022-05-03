package git

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/signature"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/wlynch/smimecosign/fulcio"
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

	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
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
	if _, err := cosign.TLogUpload(ctx, rClient, commitSig, []byte(commit), sv.Cert); err != nil {
		return nil, nil, errors.Wrap(err, "error uploading tlog (commit)")

	}

	return sig, cert, nil
}

func Verify(data, sig []byte) ([][][]*x509.Certificate, *models.LogEntryAnon, error) {
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
		return nil, nil, errors.Wrap(err, "failed to parse signature")
	}

	// Generate verification options.
	certs, err := sd.GetCertificates()
	if err != nil {
		return nil, nil, errors.Wrap(err, "error getting signature certs")
	}
	opts := x509.VerifyOptions{
		Roots:     fulcioroots.Get(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: certs[0].NotBefore,
	}

	chains, err := sd.VerifyDetached(data, opts)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to verify signature")
	}

	commit, err := commitHash(data, sig)
	if err != nil {
		return nil, nil, err
	}

	ctx := context.Background()
	tlog, err := verifyTlog(ctx, commit, certs[0])
	if err != nil {
		return nil, nil, err
	}

	return chains, tlog, nil
}

func verifyTlog(ctx context.Context, commit string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		return nil, err
	}

	pk, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, err
	}
	uuids, err := findTLogEntriesByPayloadAndPK(ctx, rClient, []byte(commit), pk)
	if err != nil {
		return nil, err
	}

	for _, u := range uuids {
		e, err := cosign.GetTlogEntry(ctx, rClient, u)
		if err != nil {
			return nil, err
		}

		if err := cosign.VerifyTLogEntry(ctx, rClient, e); err != nil {
			continue
		}

		// TODO: don't trust rekor response - verify client-side that the
		// public key matches.

		return e, nil
	}

	return nil, errors.New("could not find matching tlog entry")
}

// findTLogEntriesByPayloadAndPK is roughly equivalent to cosign.FindTLogEntriesByPayload,
// but also filters by the public key used.
func findTLogEntriesByPayloadAndPK(ctx context.Context, rekorClient *client.Rekor, payload, pubKey []byte) (uuids []string, err error) {
	params := index.NewSearchIndexParamsWithContext(ctx)
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	params.Query.PublicKey = &models.SearchIndexPublicKey{
		Content: strfmt.Base64(pubKey),
		Format:  swag.String(models.SearchIndexPublicKeyFormatX509),
	}

	searchIndex, err := rekorClient.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return searchIndex.GetPayload(), nil
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

func publicKeyFromCert(cert *x509.Certificate) ([]byte, error) {
	pk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "error marshalling public key")
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk,
	}), nil
}
