package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"path/filepath"

	"github.com/sigstore/gitsign/internal/cache"
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
	fmt.Println(path)

	l, err := net.Listen("unix", path)
	if err != nil {
		log.Fatalf("error opening socket: %v", err)
	}
	srv := rpc.NewServer()
	srv.Register(cache.NewService())
	for {
		srv.Accept(l)
	}
}
