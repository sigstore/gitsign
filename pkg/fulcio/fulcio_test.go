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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/fulcio/pkg/api"
	"github.com/sigstore/sigstore/pkg/oauthflow"
	"golang.org/x/oauth2"
)

type fakeSigner struct {
	crypto.Signer
}

func TestKeyAlgorithm(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, tc := range []struct {
		signer crypto.Signer
		want   string
	}{
		{
			signer: key,
			want:   "ecdsa",
		},
		{
			signer: fakeSigner{},
			want:   "fulcio",
		},
		{
			signer: nil,
			want:   "",
		},
	} {
		t.Run(tc.want, func(t *testing.T) {
			got := keyAlgorithm(tc.signer)
			if got != tc.want {
				t.Errorf("want %s, got %s", tc.want, got)
			}
		})
	}
}

type fakeFulcio struct {
	api.LegacyClient
	signer *ecdsa.PrivateKey
	email  string
}

func (f *fakeFulcio) SigningCert(cr api.CertificateRequest, _ string) (*api.CertificateResponse, error) {
	if want := keyAlgorithm(f.signer); want != cr.PublicKey.Algorithm {
		return nil, fmt.Errorf("want algorithm %s, got %s", want, cr.PublicKey.Algorithm)
	}
	pem, err := x509.MarshalPKIXPublicKey(f.signer.Public())
	if err != nil {
		return nil, err
	}
	want := api.Key{
		Algorithm: keyAlgorithm(f.signer),
		Content:   pem,
	}
	if diff := cmp.Diff(want, cr.PublicKey); diff != "" {
		return nil, errors.New(diff)
	}

	// Verify checksum separately since this is non-deterministic.
	h := sha256.Sum256([]byte(f.email))
	if !ecdsa.VerifyASN1(&f.signer.PublicKey, h[:], cr.SignedEmailAddress) {
		return nil, errors.New("signed email did not match")
	}

	return &api.CertificateResponse{}, nil
}

type fakeTokenGetter struct {
	email string
}

func (f *fakeTokenGetter) GetIDToken(*oidc.Provider, oauth2.Config) (*oauthflow.OIDCIDToken, error) {
	return &oauthflow.OIDCIDToken{
		Subject: f.email,
	}, nil
}

func TestGetCert(t *testing.T) {
	// Implements a fake OIDC discovery.
	oidc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": fmt.Sprintf("http://%s", r.Host),
		})
	}))
	defer oidc.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	email := "foo@example.com"

	client := &ClientImpl{
		// fakeFulcio is what will be doing the validation.
		LegacyClient: &fakeFulcio{
			signer: key,
			email:  email,
		},
		oidc: OIDCOptions{
			Issuer: oidc.URL,
			TokenGetter: &fakeTokenGetter{
				email: email,
			},
		},
	}

	// fakeFulcio is returning a bogus response, so only check if we returned
	// error.
	if _, err := client.GetCert(key); err != nil {
		t.Fatalf("GetCert: %v", err)
	}
}
