package cache

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net"
	"os"
	"testing"

	"github.com/github/smimesign/fakeca"
	"github.com/google/go-cmp/cmp"
	pb "github.com/sigstore/gitsign/internal/cache/cache_go_proto"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestCache(t *testing.T) {
	ctx := context.Background()

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	pb.RegisterCredentialStoreServer(s, NewService())
	go func() {
		s.Serve(l)
	}()

	conn, err := grpc.DialContext(ctx, l.Addr().String(), grpc.WithInsecure())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ca := fakeca.New()
	client := &Client{
		CredentialStoreClient: pb.NewCredentialStoreClient(conn),
		Roots:                 ca.ChainPool(),
	}

	if _, _, _, err := client.GetSignerVerifier(ctx); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v %v", err, status.Code(err))
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	certPEM, _ := cryptoutils.MarshalCertificateToPEM(ca.Certificate)

	if err := client.StoreCert(ctx, priv, certPEM, nil); err != nil {
		t.Fatal(err)
	}

	id, _ := os.Getwd()
	resp, err := client.GetCredential(ctx, &pb.GetCredentialRequest{Id: id})
	if err != nil {
		t.Fatal(err)
	}

	privPEM, _ := cryptoutils.MarshalPrivateKeyToPEM(priv)
	want := &pb.Credential{
		PrivateKey: privPEM,
		CertPem:    certPEM,
	}

	if diff := cmp.Diff(want, resp, protocmp.Transform()); diff != "" {
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
