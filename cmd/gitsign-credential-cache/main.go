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

package main

import (
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"path/filepath"
	"syscall"

	"github.com/sigstore/gitsign/internal/cache"
)

func main() {
	// Override default umask so created files are always scoped to the
	// current user.
	syscall.Umask(0077)

	user, err := os.UserCacheDir()
	if err != nil {
		log.Fatalf("error getting user cache directory: %v", err)
	}

	dir := filepath.Join(user, ".sigstore", "gitsign")
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
	if err := srv.Register(cache.NewService()); err != nil {
		log.Fatalf("error registering RPC service: %v", err)
	}
	for {
		srv.Accept(l)
	}
}
