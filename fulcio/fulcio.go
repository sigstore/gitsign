// Copyright 2022 Billy Lynch
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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio"
	"github.com/sigstore/cosign/cmd/cosign/cli/options"
	"github.com/sigstore/cosign/cmd/cosign/cli/sign"
	"github.com/sigstore/cosign/pkg/providers"
)

type Identity struct {
	sv     *sign.SignerVerifier
	stderr io.Writer
}

func NewIdentity(ctx context.Context, w io.Writer) (*Identity, error) {

	idToken := ""
	authFlow := fulcio.FlowNormal
	if providers.Enabled(ctx) {
		idToken, _ = providers.Provide(ctx, "sigstore")
		authFlow = fulcio.FlowToken
	}
	sv, err := sign.SignerFromKeyOpts(ctx, "", "", options.KeyOpts{
		FulcioURL:    "https://fulcio.sigstore.dev",
		OIDCIssuer:   "https://oauth2.sigstore.dev/auth",
		OIDCClientID: "sigstore",
		RekorURL:     "https://rekor.sigstore.dev",
		// Force browser based interactive mode - Git captures both stdout and
		// stderr when it invokes the signing tool, so we can't use the
		// code-based flow here for now (may require an upstream Git change to
		// support).
		FulcioAuthFlow: authFlow,
		IDToken:        idToken,
	})
	if err != nil {
		return nil, err
	}
	return &Identity{
		sv:     sv,
		stderr: w,
	}, nil
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
	return
}

func (i *Identity) PublicKey() (crypto.PublicKey, error) {
	return i.sv.SignerVerifier.PublicKey()
}

func (i *Identity) SignerVerifier() *sign.SignerVerifier {
	return i.sv
}
