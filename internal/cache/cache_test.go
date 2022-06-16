package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"net/rpc"
	"os"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestCache(t *testing.T) {
	ctx := context.Background()

	path := t.TempDir() + "cache.sock"

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

	if _, _, _, err := client.GetSignerVerifier(ctx); err == nil {
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

	sv, gotCert, _, err := client.GetSignerVerifier(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sv == nil {
		t.Error("SignerVerifier was nil")
	}
	if ok := cmp.Equal(certPEM, gotCert); !ok {
		t.Error("stored cert does not match")
	}
}
