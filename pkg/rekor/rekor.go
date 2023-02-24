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
	"errors"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"

	"github.com/sigstore/cosign/v2/pkg/cosign"
	rekor "github.com/sigstore/rekor/pkg/client"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord_v001 "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// Verifier represents a mechanism to get and verify Rekor entries for the given Git commit.
type Verifier interface {
	Verify(ctx context.Context, commitSHA string, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Writer represents a mechanism to write content to Rekor.
type Writer interface {
	Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error)
}

// Client implements a basic rekor implementation for writing and verifying Rekor data.
type Client struct {
	*client.Rekor
}

func New(url string, opts ...rekor.Option) (*Client, error) {
	c, err := rekor.GetRekorClient(url, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{
		Rekor: c,
	}, nil
}

func (c *Client) Write(ctx context.Context, commitSHA string, sig []byte, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pem, err := cryptoutils.MarshalCertificateToPEM(cert)
	if err != nil {
		return nil, err
	}
	checkSum := sha256.New()
	if _, err := checkSum.Write([]byte(commitSHA)); err != nil {
		return nil, err
	}
	return cosign.TLogUpload(ctx, c.Rekor, sig, checkSum, pem)
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

// rekorPubsFromClient returns a RekorPubKey keyed by the log ID from the Rekor client.
// NOTE: This **must not** be used in the verification path, but may be used in the
// sign path to validate return responses are consistent from Rekor.
func rekorPubsFromClient(rekorClient *client.Rekor) (*cosign.TrustedTransparencyLogPubKeys, error) {
	publicKeys := cosign.NewTrustedTransparencyLogPubKeys()
	pubOK, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch rekor public key from rekor: %w", err)
	}
	if err := publicKeys.AddTransparencyLogPubKey([]byte(pubOK.Payload), tuf.Active); err != nil {
		return nil, fmt.Errorf("constructRekorPubKey: %w", err)
	}
	return &publicKeys, nil
}

func (c *Client) Verify(ctx context.Context, commitSHA string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	e, err := c.get(ctx, []byte(commitSHA), cert)
	if err != nil {
		return nil, err
	}
	rekorPubsFromAPI, err := rekorPubsFromClient(c.Rekor)
	if err != nil {
		return nil, err
	}
	return e, cosign.VerifyTLogEntryOffline(ctx, e, rekorPubsFromAPI)
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
