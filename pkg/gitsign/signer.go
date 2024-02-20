// Copyright 2024 The Sigstore Authors
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

// Package gitsign provides a signer for signing git commits and tags via Gitsign keyless flow.
package gitsign

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/go-git/go-git/v5"
	fulciointernal "github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/fulcio"
	"github.com/sigstore/gitsign/pkg/rekor"
)

type PrivateKeySigner interface {
	crypto.PrivateKey
	crypto.Signer
}

var (
	_ git.Signer = &Signer{}
)

type Signer struct {
	ctx    context.Context
	key    PrivateKeySigner
	fulcio fulcio.Client
	rekor  rekor.Writer
}

func NewSigner(ctx context.Context, fulcio fulcio.Client, rekor rekor.Writer) (*Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating private key: %w", err)
	}
	return &Signer{
		ctx:    ctx,
		key:    priv,
		fulcio: fulcio,
		rekor:  rekor,
	}, nil
}

func (f *Signer) Sign(message io.Reader) ([]byte, error) {
	cert, err := f.fulcio.GetCert(f.key)
	if err != nil {
		return nil, fmt.Errorf("error getting fulcio cert: %w", err)
	}

	id := &fulciointernal.Identity{
		PrivateKey: f.key,
		CertPEM:    cert.CertPEM,
		ChainPEM:   cert.ChainPEM,
	}

	body, err := io.ReadAll(message)
	if err != nil {
		return nil, fmt.Errorf("error reading message: %w", err)
	}

	resp, err := signature.Sign(f.ctx, id, body, signature.SignOptions{
		Rekor: f.rekor,

		// TODO: make SignOptions configurable?
		Armor:        true,
		Detached:     true,
		IncludeCerts: -2,
	})
	if err != nil {
		return nil, err
	}
	return resp.Signature, nil
}
