package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/sigstore/gitsign/internal/cache"
	cachepb "github.com/sigstore/gitsign/internal/cache/cache_go_proto"
	"google.golang.org/grpc"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("error getting user home directory: %v", err)
	}

	dir := filepath.Join(home, ".sigstore", "gitsign")
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("error creating %s: %v", dir, err)
	}

	path := filepath.Join(dir, "cache.sock")
	if _, err := os.Stat(path); err == nil {
		os.Remove(path)
	}
	fmt.Print(path)

	lis, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalln("error connecting server to socket", err)
	}
	defer lis.Close()

	s := grpc.NewServer()
	cachepb.RegisterCredentialStoreServer(s, cache.NewService())
	if err := s.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
