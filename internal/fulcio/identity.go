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

	"github.com/sigstore/cosign/pkg/providers"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/sigstore/pkg/fulcioroots"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"github.com/sigstore/sigstore/pkg/signature"
)

type Identity struct {
	sv     *CertSignerVerifier
	stderr io.Writer
}

func NewIdentity(ctx context.Context, debug io.Writer) (*Identity, error) {
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
		roots, err := fulcioroots.Get()
		if err != nil {
			return nil, fmt.Errorf("error getting fulcio roots: %w", err)
		}
		intermediates, err := fulcioroots.GetIntermediates()
		if err != nil {
			return nil, fmt.Errorf("error getting fulcio intermediates: %w", err)
		}
		cacheClient = &cache.Client{
			Client:        rpcClient,
			Roots:         roots,
			Intermediates: intermediates,
		}
		sv, cert, chain, err := cacheClient.GetSignerVerifier(ctx)
		if err == nil && sv != nil {
			return &Identity{
				sv: &CertSignerVerifier{
					SignerVerifier: sv,
					Cert:           cert,
					Chain:          chain,
				},
				stderr: debug,
			}, nil
		}
		// Only print error on failure - if there's a problem fetching
		// from the cache just fall through to normal OIDC.
		fmt.Fprintf(debug, "error getting cached creds: %v\n", err)
	}

	clientID := envOrValue("GITSIGN_OIDC_CLIENT_ID", "sigstore")
	var authFlow oauthflow.TokenGetter = oauthflow.DefaultIDTokenGetter
	if providers.Enabled(ctx) {
		var err error
		idToken, err := providers.Provide(ctx, clientID)
		if err != nil {
			fmt.Fprintln(debug, "error getting id token:", err)
		}
		authFlow = &oauthflow.StaticTokenGetter{RawToken: idToken}
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}

	client, err := NewClient(envOrValue("GITSIGN_FULCIO_URL", "https://fulcio.sigstore.dev"),
		OIDCOptions{
			Issuer:      envOrValue("GITSIGN_OIDC_ISSUER", "https://oauth2.sigstore.dev/auth"),
			ClientID:    clientID,
			RedirectURL: os.Getenv("GITSIGN_OIDC_REDIRECT_URL"),
			TokenGetter: authFlow,
		})
	if err != nil {
		return nil, fmt.Errorf("error creating Fulcio client: %w", err)
	}

	cert, err := client.GetCert(priv)
	if err != nil {
		fmt.Fprintln(debug, "error getting signer:", err)
		return nil, err
	}

	if cachePath != "" {
		if err := cacheClient.StoreCert(ctx, priv, cert.CertPEM, cert.ChainPEM); err != nil {
			fmt.Fprintf(debug, "error storing cert in cache: %v", err)
		}
	}

	sv, err := signature.LoadECDSASignerVerifier(priv, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	return &Identity{
		sv: &CertSignerVerifier{
			SignerVerifier: sv,
			Cert:           cert.CertPEM,
			Chain:          cert.ChainPEM,
		},
		stderr: debug,
	}, nil
}

func envOrValue(env, value string) string {
	if v := os.Getenv(env); v != "" {
		return v
	}
	return value
}

// Certificate gets the identity's certificate.
func (i *Identity) Certificate() (*x509.Certificate, error) {
	p, _ := pem.Decode(i.sv.Cert)
	cert, err := x509.ParseCertificate(p.Bytes)
	return cert, err
}

// CertificateChain attempts to get the identity's full certificate chain.
func (i *Identity) CertificateChain() ([]*x509.Certificate, error) {
	p, _ := pem.Decode(i.sv.Chain)
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
	s, ok := i.sv.SignerVerifier.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("could not use signer %T as crypto.Signer", i.sv.SignerVerifier)
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
	return i.sv.SignerVerifier.PublicKey()
}

func (i *Identity) SignerVerifier() *CertSignerVerifier {
	return i.sv
}
