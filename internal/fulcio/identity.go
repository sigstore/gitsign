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

package fulcio

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/rpc"
	"os"
	"path/filepath"

	"github.com/sigstore/cosign/v2/pkg/providers"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio/fulcioroots"
	"github.com/sigstore/gitsign/internal/signerverifier"
	"github.com/sigstore/sigstore/pkg/oauth"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/oauth2"
)

// PrivateKey defines the [crypto.PrivateKey] interface. This should be true for all PrivateKeys.
type PrivateKey interface {
	crypto.PrivateKey
	Public() crypto.PublicKey
}

type Identity struct {
	PrivateKey crypto.PrivateKey
	CertPEM    []byte
	ChainPEM   []byte
}

func NewIdentity(ctx context.Context, cfg *config.Config, in io.Reader, out io.Writer) (*Identity, error) {
	var cacheClient *cache.Client

	cachePath := os.Getenv("GITSIGN_CREDENTIAL_CACHE")
	if cachePath != "" {
		absPath, err := filepath.Abs(cachePath)
		if err != nil {
			return nil, fmt.Errorf("error resolving cache path: %w", err)
		}
		rpcClient, err := rpc.Dial("unix", absPath)
		if err != nil {
			return nil, fmt.Errorf("error creating RPC socket client: %w", err)
		}
		roots, intermediates, err := fulcioroots.NewFromConfig(ctx, cfg)
		if err != nil {
			return nil, fmt.Errorf("error loading certificate roots: %w", err)
		}
		cacheClient = &cache.Client{
			Client:        rpcClient,
			Roots:         roots,
			Intermediates: intermediates,
		}
		priv, cert, chain, err := cacheClient.GetCredentials(ctx, cfg)
		if err == nil {
			return &Identity{
				PrivateKey: priv,
				CertPEM:    cert,
				ChainPEM:   chain,
			}, nil
		}
		// Only print error on failure - if there's a problem fetching
		// from the cache just fall through to normal OIDC.
		fmt.Fprintf(out, "error getting cached creds: %v\n", err)
	}

	idf := &IdentityFactory{
		in:  in,
		out: out,
	}
	id, err := idf.NewIdentity(ctx, cfg)
	if err != nil {
		return nil, err
	}

	if cacheClient != nil {
		if err := id.CacheCert(ctx, cacheClient); err != nil {
			fmt.Fprintf(out, "error storing identity in cache: %v", err)
		}
	}

	return id, nil
}

// Certificate gets the identity's certificate.
func (i *Identity) Certificate() (*x509.Certificate, error) {
	p, _ := pem.Decode(i.CertPEM)
	cert, err := x509.ParseCertificate(p.Bytes)
	return cert, err
}

// CertificateChain attempts to get the identity's full certificate chain.
func (i *Identity) CertificateChain() ([]*x509.Certificate, error) {
	p, _ := pem.Decode(i.ChainPEM)
	chain, err := x509.ParseCertificates(p.Bytes)
	if err != nil {
		return nil, err
	}
	// the cert itself needs to be appended to the chain
	cert, err := i.Certificate()
	if err != nil {
		return nil, err
	}

	return append([]*x509.Certificate{cert}, chain...), nil
}

// Signer gets a crypto.Signer that uses the identity's private key.
func (i *Identity) Signer() (crypto.Signer, error) {
	sv, err := i.SignerVerifier()
	if err != nil {
		return nil, err
	}
	s, ok := sv.SignerVerifier.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("could not use signer %T as crypto.Signer", sv)
	}
	return s, nil
}

// Delete deletes this identity from the system.
func (i *Identity) Delete() error {
	// Does nothing - keys are ephemeral
	return nil
}

// Close any manually managed memory held by the Identity.
func (i *Identity) Close() {
	// noop
}

func (i *Identity) PublicKey() (crypto.PublicKey, error) {
	pk, ok := i.PrivateKey.(PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key does not implement public key method")
	}
	return pk.Public(), nil
}

func (i *Identity) SignerVerifier() (*signerverifier.CertSignerVerifier, error) {
	sv, err := signature.LoadSignerVerifier(i.PrivateKey, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("error creating SignerVerifier: %w", err)
	}

	return &signerverifier.CertSignerVerifier{
		SignerVerifier: sv,
		Cert:           i.CertPEM,
		Chain:          i.ChainPEM,
	}, nil
}

func (i *Identity) CacheCert(ctx context.Context, cacheClient *cache.Client) error {
	return cacheClient.StoreCert(ctx, i.PrivateKey, i.CertPEM, i.ChainPEM)
}

// IdentityFactory holds reusable values for configuring how identities are created.
// Values set here are not expected to change per-request.
type IdentityFactory struct {
	in  io.Reader
	out io.Writer
}

func NewIdentityFactory(in io.Reader, out io.Writer) *IdentityFactory {
	return &IdentityFactory{
		in:  in,
		out: out,
	}
}

func (f *IdentityFactory) NewIdentity(ctx context.Context, cfg *config.Config) (*Identity, error) {
	clientID := cfg.ClientID
	defaultFlow := &oauthflow.InteractiveIDTokenGetter{
		HTMLPage: oauth.InteractiveSuccessHTML,
		Input:    f.in,
		Output:   f.out,
	}
	if cfg.ConnectorID != "" {
		defaultFlow.ExtraAuthURLParams = []oauth2.AuthCodeOption{oauthflow.ConnectorIDOpt(cfg.ConnectorID)}
	}
	var authFlow oauthflow.TokenGetter = defaultFlow

	if providers.Enabled(ctx) {
		idToken, err := providers.Provide(ctx, clientID)
		if err != nil {
			fmt.Fprintln(f.out, "error getting id token:", err)
		}
		authFlow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	client, err := NewClient(cfg.Fulcio,
		OIDCOptions{
			Issuer:      cfg.Issuer,
			ClientID:    clientID,
			RedirectURL: cfg.RedirectURL,
			TokenGetter: authFlow,
		})
	if err != nil {
		return nil, fmt.Errorf("error creating Fulcio client: %w", err)
	}

	cert, err := client.GetCert(priv)
	if err != nil {
		fmt.Fprintln(f.out, "error getting signer:", err)
		return nil, err
	}

	return &Identity{
		PrivateKey: priv,
		CertPEM:    cert.CertPEM,
		ChainPEM:   cert.ChainPEM,
	}, nil
}
