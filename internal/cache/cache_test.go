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

package cache_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/gitsign/internal/cache"
	"github.com/sigstore/gitsign/internal/cache/api"
	"github.com/sigstore/gitsign/internal/cache/service"
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
	srv.Register(service.NewService())
	go func() {
		for {
			srv.Accept(l)
		}
	}()

	rpcClient, _ := rpc.Dial("unix", path)
	defer rpcClient.Close()
	ca := fakeca.New()
	client := &cache.Client{
		Client: rpcClient,
		Roots:  ca.ChainPool(),
	}

	if _, _, _, err := client.GetCredentials(ctx, nil); err == nil {
		t.Fatal("GetSignerVerifier: expected err, got not")
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatalf("StoreCert: %v", err)
	}

	host, _ := os.Hostname()
	wd, _ := os.Getwd()
	id := fmt.Sprintf("%s@%s", host, wd)
	cred := new(api.Credential)
	if err := client.Client.Call("Service.GetCredential", &api.GetCredentialRequest{ID: id}, cred); err != nil {
		t.Fatal(err)
	}

	privPEM, _ := cryptoutils.MarshalPrivateKeyToPEM(priv)
	want := &api.Credential{
		PrivateKey: privPEM,
		Cert:       certPEM,
	}

	if diff := cmp.Diff(want, cred); diff != "" {
		t.Error(diff)
	}

	gotPriv, gotCert, _, err := client.GetCredentials(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !priv.Equal(gotPriv) {
		t.Fatal("private key did not match")
	}
	if ok := cmp.Equal(certPEM, gotCert); !ok {
		t.Error("stored cert does not match")
	}
}
