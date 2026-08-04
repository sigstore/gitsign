// Copyright 2022 The Sigstore Authors
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

package cache

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"net/rpc"
	"path/filepath"
	"strings"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
)

// Client talks to the gitsign-credential-cache daemon over its unix socket.
type Client struct {
	Client        *rpc.Client
	Roots         *x509.CertPool
	Intermediates *x509.CertPool
	// Config is used to derive the identity key for credentials.
	Config *config.Config
}

var _ Manager = (*Client)(nil)

// NewClient dials the gitsign-credential-cache daemon socket. Roots and
// intermediates are only needed for GetCredentials validation and may be nil
// for management operations (List/Delete/DeleteAll).
func NewClient(socketPath string, cfg *config.Config, roots, intermediates *x509.CertPool) (*Client, error) {
	absPath, err := filepath.Abs(socketPath)
	if err != nil {
		return nil, fmt.Errorf("error resolving cache path: %w", err)
	}
	rpcClient, err := rpc.Dial("unix", absPath)
	if err != nil {
		return nil, fmt.Errorf("error creating RPC socket client: %w", err)
	}
	return &Client{
		Client:        rpcClient,
		Roots:         roots,
		Intermediates: intermediates,
		Config:        cfg,
	}, nil
}

func (c *Client) GetCredentials(_ context.Context, cfg *config.Config) (crypto.PrivateKey, []byte, []byte, error) {
	if cfg == nil {
		cfg = c.Config
	}
	resp := new(api.Credential)
	if err := c.Client.Call("Service.GetCredential", api.GetCredentialRequest{
		ID:     CredentialKey(cfg),
		Config: cfg,
	}, resp); err != nil {
		// net/rpc flattens errors to strings, so a plain miss can only be
		// recognized by message.
		if strings.Contains(err.Error(), "not found") {
			return nil, nil, nil, fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		return nil, nil, nil, err
	}

	privateKey, cert, chain, err := DecodeCredential(resp)
	if err != nil {
		return nil, nil, nil, err
	}

	// Check that the cert is in fact still valid.
	if err := ValidateCert(cert, c.Roots, c.Intermediates); err != nil {
		return nil, nil, nil, err
	}

	return privateKey, cert, chain, nil
}

func (c *Client) StoreCert(_ context.Context, priv crypto.PrivateKey, cert, chain []byte) error {
	cred, err := EncodeCredential(priv, cert, chain)
	if err != nil {
		return err
	}

	return c.Client.Call("Service.StoreCredential", api.StoreCredentialRequest{
		ID:         CredentialKey(c.Config),
		Credential: cred,
		Meta:       MetadataFromConfig(c.Config),
	}, new(api.Credential))
}

// List returns info about the credentials stored in the daemon. Requires a
// daemon new enough to support the ListCredentials RPC.
func (c *Client) List(_ context.Context) ([]CredentialInfo, error) {
	var resp []api.CredentialInfo
	if err := c.Client.Call("Service.ListCredentials", api.ListCredentialsRequest{}, &resp); err != nil {
		if strings.Contains(err.Error(), "can't find method") {
			return nil, fmt.Errorf("the gitsign-credential-cache daemon does not support listing credentials - upgrade the daemon: %w", err)
		}
		return nil, err
	}
	return resp, nil
}

// Delete removes the daemon's credential for the identity described by the
// configured Config.
func (c *Client) Delete(_ context.Context) error {
	if err := c.Client.Call("Service.DeleteCredential", api.DeleteCredentialRequest{
		ID: CredentialKey(c.Config),
	}, new(api.DeleteCredentialsResponse)); err != nil {
		if strings.Contains(err.Error(), "not found") {
			return fmt.Errorf("%w: %v", ErrNotFound, err)
		}
		if strings.Contains(err.Error(), "can't find method") {
			return fmt.Errorf("the gitsign-credential-cache daemon does not support deleting credentials - upgrade the daemon: %w", err)
		}
		return err
	}
	return nil
}

// DeleteAll removes all credentials stored in the daemon.
func (c *Client) DeleteAll(_ context.Context) error {
	if err := c.Client.Call("Service.DeleteAllCredentials", api.DeleteAllCredentialsRequest{}, new(api.DeleteCredentialsResponse)); err != nil {
		if strings.Contains(err.Error(), "can't find method") {
			return fmt.Errorf("the gitsign-credential-cache daemon does not support deleting credentials - upgrade the daemon: %w", err)
		}
		return err
	}
	return nil
}
