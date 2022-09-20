// Copyright 2022 The Sigstore authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fulcio

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"net/url"
	"reflect"
	"strings"

	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
)

// Client provides a fulcio client with helpful options for configuring OIDC
// flows.
type Client struct {
	api.LegacyClient
	oidc OIDCOptions
}

// OIDCOptions contains settings for OIDC operations.
type OIDCOptions struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	TokenGetter  oauthflow.TokenGetter
}

func NewClient(fulcioURL string, opts OIDCOptions) (*Client, error) {
	u, err := url.Parse(fulcioURL)
	if err != nil {
		return nil, err
	}
	client := api.NewClient(u, api.WithUserAgent("gitsign"))
	return &Client{
		LegacyClient: client,
		oidc:         opts,
	}, nil
}

// GetCert exchanges the given private key for a Fulcio certificate.
func (c *Client) GetCert(priv crypto.Signer) (*api.CertificateResponse, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		return nil, err
	}

	tok, err := oauthflow.OIDConnect(c.oidc.Issuer, c.oidc.ClientID, c.oidc.ClientSecret, c.oidc.RedirectURL, c.oidc.TokenGetter)
	if err != nil {
		return nil, err
	}

	// Sign the email address as part of the request
	h := sha256.Sum256([]byte(tok.Subject))
	proof, err := priv.Sign(rand.Reader, h[:], nil)
	if err != nil {
		return nil, err
	}

	cr := api.CertificateRequest{
		PublicKey: api.Key{
			Algorithm: keyAlgorithm(priv),
			Content:   pubBytes,
		},
		SignedEmailAddress: proof,
	}

	return c.SigningCert(cr, tok.RawString)
}

// keyAlgorithm returns a string representation of the type of signer.
// Currently this is dervived from the package name -
// e.g. crypto/ecdsa.PrivateKey -> ecdsa.
// if Signer is nil, "" is returned.
func keyAlgorithm(signer crypto.Signer) string {
	// This is a bit of a hack, but let's us use the package name as an approximation for
	// algorithm type.
	// e.g. *ecdsa.PrivateKey -> ecdsa
	t := reflect.TypeOf(signer)
	if t == nil {
		return ""
	}
	s := strings.Split(strings.TrimPrefix(t.String(), "*"), ".")
	return s[0]
}
