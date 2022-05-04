package rekor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	rekord "github.com/sigstore/rekor/pkg/types/rekord/v0.0.1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

type Verifier interface {
	Get(ctx context.Context, commit string, cert *x509.Certificate) (*models.LogEntryAnon, error)
	Verify(context.Context, *models.LogEntryAnon) error
}

type Writer interface {
	Write(ctx context.Context, sig, data, cert []byte) (*models.LogEntryAnon, error)
}

type Client struct {
	*client.Rekor
}

func New(url string) (*Client, error) {
	c, err := rekor.NewClient(url)
	if err != nil {
		return nil, err
	}
	return &Client{
		Rekor: c,
	}, nil
}

func (c *Client) Write(ctx context.Context, sig, data, cert []byte) (*models.LogEntryAnon, error) {
	return cosign.TLogUpload(ctx, c.Rekor, sig, data, cert)
}

func (c *Client) Get(ctx context.Context, commit string, cert *x509.Certificate) (*models.LogEntryAnon, error) {
	pk, err := publicKeyFromCert(cert)
	if err != nil {
		return nil, err
	}
	uuids, err := c.findTLogEntriesByPayloadAndPK(ctx, []byte(commit), pk)
	if err != nil {
		return nil, err
	}

	for _, u := range uuids {
		e, err := cosign.GetTlogEntry(ctx, c.Rekor, u)
		if err != nil {
			return nil, err
		}

		// Verify that the cert used in the tlog matches the cert
		// used to sign the commit.
		tlogCerts, err := extractCerts(e)
		if err != nil {
			fmt.Println("could not extract cert", err)
			continue
		}
		for _, c := range tlogCerts {
			if cert.Equal(c) {
				fmt.Println("certs do not match!")
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

func (c *Client) Verify(ctx context.Context, e *models.LogEntryAnon) error {
	return cosign.VerifyTLogEntry(ctx, c.Rekor, e)
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

	eimpl, err := types.NewEntry(pe)
	if err != nil {
		return nil, err
	}

	var publicKeyB64 []byte
	switch e := eimpl.(type) {
	case *rekord.V001Entry:
		publicKeyB64, err = e.RekordObj.Signature.PublicKey.Content.MarshalText()
		if err != nil {
			return nil, err
		}
	case *hashedrekord.V001Entry:
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
