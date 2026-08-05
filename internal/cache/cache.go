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
	"context"
	"crypto"
	"errors"

	"github.com/sigstore/gitsign/internal/config"
)

// ErrNotFound is returned by Cache implementations when no credential is
// stored for the requested identity. Callers can use this to distinguish a
// plain cache miss from a real error.
var ErrNotFound = errors.New("credential not found in cache")

// Cache stores and retrieves signing credentials (ephemeral private key,
// Fulcio certificate, and chain).
type Cache interface {
	// GetCredentials returns the cached private key, PEM-encoded leaf
	// certificate, and PEM-encoded chain for the identity described by the
	// given config. Implementations should return an error wrapping
	// ErrNotFound on a cache miss.
	GetCredentials(ctx context.Context, cfg *config.Config) (crypto.PrivateKey, []byte, []byte, error)
	// StoreCert stores the private key, PEM-encoded leaf certificate, and
	// PEM-encoded chain.
	StoreCert(ctx context.Context, priv crypto.PrivateKey, cert, chain []byte) error
}

// Manager extends Cache with enumeration and removal, used by
// `gitsign credentials`.
type Manager interface {
	Cache
	// List returns info about the stored credentials.
	List(ctx context.Context) ([]CredentialInfo, error)
	// Delete removes the credential for the identity described by the
	// backend's configured Config. It returns an error wrapping ErrNotFound
	// if no entry exists.
	Delete(ctx context.Context) error
	// DeleteAll removes all stored credentials.
	DeleteAll(ctx context.Context) error
}
