package cache

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/rpc"
	"os"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

type Client struct {
	Client        *rpc.Client
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
}

func (c *Client) GetSignerVerifier(ctx context.Context) (signature.SignerVerifier, []byte, []byte, error) {
	id, err := os.Getwd()
	if err != nil {
		return nil, nil, nil, err
	}

	resp := new(Credential)
	if err := c.Client.Call("Service.GetCredential", GetCredentialRequest{
		ID: id,
	}, resp); err != nil {
		return nil, nil, nil, err
	}

	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(resp.PrivateKey, cryptoutils.SkipPassword)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error unmarshalling private key: %w", err)
	}

	sv, err := signature.LoadSignerVerifier(privateKey, crypto.SHA256)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error creating SignerVerifier: %w", err)
	}

	// Check that the cert is in fact still valid.
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(resp.Cert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("error unmarshalling cert: %w", err)
	}
	// There should really only be 1 cert, but check them all anyway.
	for _, cert := range certs {
		if _, err := cert.Verify(x509.VerifyOptions{
			Roots:         c.Roots,
			Intermediates: c.Intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			// We're going to be using this key immediately, so we don't need a long window.
			// Just make sure it's not about to expire.
			CurrentTime: time.Now().Add(30 * time.Second),
		}); err != nil {
			return nil, nil, nil, fmt.Errorf("stored cert no longer valid: %w", err)
		}
	}

	return sv, resp.Cert, resp.Chain, nil
}

type PrivateKey interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
}

func (c *Client) StoreCert(ctx context.Context, priv PrivateKey, cert, chain []byte) error {
	id, err := os.Getwd()
	if err != nil {
		return err
	}
	privPEM, err := cryptoutils.MarshalPrivateKeyToPEM(priv)
	if err != nil {
		return err
	}

	if err := c.Client.Call("Service.StoreCredential", StoreCredentialRequest{
		ID: id,
		Credential: &Credential{
			PrivateKey: privPEM,
			Cert:       cert,
			Chain:      chain,
		},
	}, new(Credential)); err != nil {
		return err
	}

	return err
}
