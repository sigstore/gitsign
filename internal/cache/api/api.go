// Copyright 2023 The Sigstore Authors
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

package api // nolint:revive

import (
	"time"

	"github.com/sigstore/gitsign/internal/config"
)

type Credential struct {
	PrivateKey []byte
	Cert       []byte
	Chain      []byte
}

// Metadata describes the configuration a cached credential was derived from.
type Metadata struct {
	Fulcio         string `json:"fulcio,omitempty"`
	Issuer         string `json:"issuer,omitempty"`
	ClientID       string `json:"clientID,omitempty"`
	ConnectorID    string `json:"connectorID,omitempty"`
	CommitterEmail string `json:"committerEmail,omitempty"`
}

// CredentialInfo describes a stored credential for enumeration
// (e.g. `gitsign credentials list`).
type CredentialInfo struct {
	ID       string    `json:"id"`
	NotAfter time.Time `json:"notAfter"`
	Meta     Metadata  `json:"meta"`
}

type StoreCredentialRequest struct {
	ID         string
	Credential *Credential
	// Meta describes the identity configuration the credential was obtained
	// with. Optional: older clients don't send it.
	Meta Metadata
}

type GetCredentialRequest struct {
	ID     string
	Config *config.Config
}

type ListCredentialsRequest struct{}

type DeleteCredentialRequest struct {
	ID string
}

type DeleteAllCredentialsRequest struct{}

type DeleteCredentialsResponse struct{}
