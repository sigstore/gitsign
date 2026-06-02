//
// Copyright 2024 The Sigstore Authors.
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

package compat

import (
	"context"
	"crypto"
	"crypto/rand"

	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	"github.com/sigstore/sigstore-go/pkg/sign"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Keypair adapts a crypto.Signer to sigstore-go's sign.Keypair so a gitsign
// identity's key can be used to drive sigstore-go signing. The signing and hash
// algorithms are derived from the key (as sign.EphemeralKeypair does), rather
// than hardcoded.
type Keypair struct {
	signer crypto.Signer
	algo   signature.AlgorithmDetails
}

var _ sign.Keypair = (*Keypair)(nil)

// NewKeypair returns a sign.Keypair backed by the given signer, deriving its
// algorithm details from the signer's public key.
func NewKeypair(signer crypto.Signer) (*Keypair, error) {
	algo, err := signature.GetDefaultAlgorithmDetails(signer.Public())
	if err != nil {
		return nil, err
	}
	return &Keypair{signer: signer, algo: algo}, nil
}

func (k *Keypair) GetHashAlgorithm() protocommon.HashAlgorithm {
	return k.algo.GetProtoHashType()
}

func (k *Keypair) GetSigningAlgorithm() protocommon.PublicKeyDetails {
	return k.algo.GetSignatureAlgorithm()
}

func (k *Keypair) GetHint() []byte { return nil }

func (k *Keypair) GetKeyAlgorithm() string {
	switch k.algo.GetKeyType() {
	case signature.ECDSA:
		return "ECDSA"
	case signature.RSA:
		return "RSA"
	case signature.ED25519:
		return "ED25519"
	default:
		return ""
	}
}

func (k *Keypair) GetPublicKey() crypto.PublicKey { return k.signer.Public() }

func (k *Keypair) GetPublicKeyPem() (string, error) {
	pem, err := cryptoutils.MarshalPublicKeyToPEM(k.signer.Public())
	if err != nil {
		return "", err
	}
	return string(pem), nil
}

// SignData signs data and returns the signature and the bytes that were signed
// (a digest, except for pure Ed25519). The hash is derived from the key's
// algorithm details, matching how the CMS signature is computed over the signed
// attributes.
func (k *Keypair) SignData(_ context.Context, data []byte) ([]byte, []byte, error) {
	hf := k.algo.GetHashType()
	toSign := data
	if hf != crypto.Hash(0) {
		h := hf.New()
		h.Write(data)
		toSign = h.Sum(nil)
	}
	sig, err := k.signer.Sign(rand.Reader, toSign, hf)
	if err != nil {
		return nil, nil, err
	}
	return sig, toSign, nil
}
