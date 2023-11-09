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

package rekor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	cms "github.com/sigstore/gitsign/internal/fork/ietf-cms"
	rekoroid "github.com/sigstore/gitsign/internal/rekor/oid"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// Verifier represents a mechanism to get and verify Rekor entries for the given Git data.
type Verifier interface {
	Verify(ctx context.Context, commitSHA string, cert *x509.Certificate) (*models.LogEntryAnon, error)
	VerifyInclusion(ctx context.Context, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Writer represents a mechanism to write content to Rekor.
type Writer interface {
	Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
	WriteMessage(ctx context.Context, message, signature []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Client implements a basic rekor implementation for writing and verifying Rekor data.
type Client struct {
	*client.Rekor
	publicKeys *cosign.TrustedTransparencyLogPubKeys
}

// Deprecated: Use NewWithOptions instead.
func New(url string, opts ...rekor.Option) (*Client, error) {
	return NewWithOptions(context.TODO(), url, WithClientOption(opts...))
}

func NewWithOptions(ctx context.Context, url string, opts ...Option) (*Client, error) {
	// Defaults
	o := &options{
		rekorPublicKeys: cosign.GetRekorPubs,
	}
	for _, f := range opts {
		f(o)
	}

	c, err := rekor.GetRekorClient(url, o.clientOpts...)
	if err != nil {
		return nil, err
	}

	pubs, err := o.rekorPublicKeys(ctx)
	if err != nil {
		return nil, err
	}
	return &Client{
		Rekor:      c,
		publicKeys: pubs,
	}, nil
}

// Deprecated: Use [WriteMessage] instead.
func (c *Client) Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	return c.WriteMessage(ctx, []byte(commitSHA), sig, cert)
}

func (c *Client) WriteMessage(ctx context.Context, message, signature []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}
	checkSum := sha256.New()
	if _, err := checkSum.Write(message); err != nil {
		return nil, err
	}
	return cosign.TLogUpload(ctx, c.Rekor, signature, checkSum, pem)
}

func (c *Client) get(ctx context.Context, data []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}

	uuids, err := c.findTLogEntriesByPayloadAndPK(ctx, data, pem)
	if err != nil {
		return nil, err
	}

	for _, u := range uuids {
		// Normalize Rekor ID
		u, err := sharding.GetUUIDFromIDString(u)
		if err != nil {
			return nil, fmt.Errorf("invalid rekor UUID: %w", err)
		}

		e, err := cosign.GetTlogEntry(ctx, c.Rekor, u)
		if err != nil {
			return nil, err
		}

		// Verify that the cert used in the tlog matches the cert
		// used to sign the data.
		tlogCerts, err := extractCerts(e)
		if err != nil {
			fmt.Println("could not extract cert", err)
			continue
		}
		for _, c := range tlogCerts {
			if cert.Equal(c) {
				return e, nil
			}
		}
	}

	return nil, errors.New("could not find matching tlog entry")
}

// findTLogEntriesByPayloadAndPK is roughly equivalent to cosign.FindTLogEntriesByPayload,
// but also filters by the public key used.
func (c *Client) findTLogEntriesByPayloadAndPK(ctx context.Context, payload, pubKey []byte) (uuids []string, err error) {
	params := index.NewSearchIndexParamsWithContext(ctx)
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	params.Query.PublicKey = &models.SearchIndexPublicKey{
		Content: strfmt.Base64(pubKey),
		Format:  swag.String(models.SearchIndexPublicKeyFormatX509),
	}

	searchIndex, err := c.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return searchIndex.GetPayload(), nil
}

// Verify verifies a commit using online verification.
//
// This is done by:
// 1. Searching Rekor for an entry matching the commit SHA + cert.
// 2. Use the same cert to verify the commit content.
//
// Note: While not truly deprecated, using offline verification is generally preferred.
// This function relies on non-GA behavior of Rekor, and remains for backwards
// compatibility with older signatures.
func (c *Client) Verify(ctx context.Context, commitSHA string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	e, err := c.get(ctx, []byte(commitSHA), cert)
	if err != nil {
		return nil, err
	}
	return e, cosign.VerifyTLogEntryOffline(ctx, e, c.publicKeys)
}

// extractCerts is taken from cosign's cmd/cosign/cli/verify/verify_blob.go.
// TODO: Refactor this into a shared lib.
func extractCerts(e *models.LogEntryAnon) ([]*x509.Certificate, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}

	eimpl, err := types.CreateVersionedEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord_v001.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord_v001.V001Entry:
		publicKeyB64, err = e.HashedRekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("unexpected tlog entry type")
	}

	publicKey, err := base64.StdEncoding.DecodeString(string(publicKeyB64))
	if err != nil {
		return nil, err
	}

	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(publicKey)
	if err != nil {
		return nil, err
	}

	if len(certs) == 0 {
		return nil, errors.New("no certs found in pem tlog")
	}

	return certs, err
}

func (c *Client) PublicKeys() *cosign.TrustedTransparencyLogPubKeys {
	return c.publicKeys
}

// VerifyInclusion verifies a signature's inclusion in Rekor using offline verification.
// NOTE: This does **not** verify the correctness of the signature against the content.
// Prefer using [git.Verify] instead for complete verification.
func (c *Client) VerifyInclusion(ctx context.Context, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
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

	// Extract signer from signature. The spec allows for multiple signers, but in
	// practice for Git commits there's typically only ever 1 signer (the committer).
	r := sd.Raw()
	if len(r.SignerInfos) == 0 {
		return nil, fmt.Errorf("no signers found in signature")
	}
	si := r.SignerInfos[0]

	// Double check cert matches the signer. This technically isn't needed
	// since if this didn't match then the verify below should also fail,
	// but this helps us distinguish the error in the unlikely event this does happen.
	if _, err := si.FindCertificate([]*x509.Certificate{cert}); err != nil {
		return nil, fmt.Errorf("signer certificate mismatch: %w", err)
	}

	// Get HashedRekord body from the signature.
	// We are assuming here that the signature has already been authenticated against the
	// cert, so it is okay to rely the precomputed checksum in the SignerInfo.
	message, err := si.SignedAttrs.MarshaledForVerification()
	if err != nil {
		return nil, err
	}

	// Reassemble the tlog entry from the signature pieces.
	tlog, err := rekoroid.ToLogEntry(ctx, message, si.Signature, cert, si.UnsignedAttrs)
	if err != nil {
		return nil, err
	}

	if err := cosign.VerifyTLogEntryOffline(ctx, tlog, c.PublicKeys()); err != nil {
		return nil, err
	}

	return tlog, nil
}
