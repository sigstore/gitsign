// Copyright 2026 The Sigstore Authors
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
	"crypto/sha256"
	"encoding/hex"

	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/config"
)

// Metadata describes the configuration a cached credential was derived from.
type Metadata = api.Metadata

// CredentialInfo describes a stored credential for enumeration.
type CredentialInfo = api.CredentialInfo

// credentialKeyPrefix versions the key format so incompatible changes can
// rotate the namespace.
const credentialKeyPrefix = "credential/v1/"

// CredentialKey derives the cache key for the identity described by the given
// config. The OIDC identity is not known until after the auth flow completes,
// so the key is derived from the configuration used to obtain it. All cache
// backends share this derivation.
func CredentialKey(cfg *config.Config) string {
	h := sha256.New()
	for _, s := range keyFields(MetadataFromConfig(cfg)) {
		h.Write([]byte(s))
		// NUL separator avoids ambiguity between adjacent fields.
		h.Write([]byte{0})
	}
	return credentialKeyPrefix + hex.EncodeToString(h.Sum(nil))
}

// MetadataFromConfig extracts the identity-defining configuration fields.
func MetadataFromConfig(cfg *config.Config) Metadata {
	if cfg == nil {
		return Metadata{}
	}
	return Metadata{
		Fulcio:         cfg.Fulcio,
		Issuer:         cfg.Issuer,
		ClientID:       cfg.ClientID,
		ConnectorID:    cfg.ConnectorID,
		CommitterEmail: cfg.CommitterEmail,
	}
}

// keyFields returns the metadata fields in the (stable) order used for key
// derivation.
func keyFields(m Metadata) []string {
	return []string{m.Fulcio, m.Issuer, m.ClientID, m.ConnectorID, m.CommitterEmail}
}
