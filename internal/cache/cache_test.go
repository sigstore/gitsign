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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestCache(t *testing.T) {
	ctx := context.Background()

	path := filepath.Join(t.TempDir(), "cache.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	srv := rpc.NewServer()
	srv.Register(NewService())
	go func() {
		for {
			srv.Accept(l)
		}
	}()

	rpcClient, _ := rpc.Dial("unix", path)
	defer rpcClient.Close()
	ca := fakeca.New()
	client := &Client{
		Client: rpcClient,
		Roots:  ca.ChainPool(),
	}

	if _, err := client.GetSignerVerifier(ctx); err == nil {
		t.Fatal("GetSignerVerifier: expected err, got not")
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatalf("StoreCert: %v", err)
	}

	id, _ := os.Getwd()
	cred := new(Credential)
	if err := client.Client.Call("Service.GetCredential", &GetCredentialRequest{ID: id}, cred); err != nil {
		t.Fatal(err)
	}

	privPEM, _ := cryptoutils.MarshalPrivateKeyToPEM(priv)
	want := &Credential{
		PrivateKey: privPEM,
		Cert:       certPEM,
	}

	if diff := cmp.Diff(want, cred); diff != "" {
		t.Error(diff)
	}

	got, err := client.GetSignerVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("SignerVerifier was nil")
	}
	if ok := cmp.Equal(certPEM, got.Cert); !ok {
		t.Error("stored cert does not match")
	}
}
