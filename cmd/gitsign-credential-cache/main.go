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

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/pborman/getopt/v2"

	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/gitsign/pkg/version"
)

var (
	// Action flags
	versionFlag = getopt.BoolLong("version", 'v', "print the version number")
	systemdFlag = getopt.BoolLong("systemd-socket-activation", 's', "use systemd socket activation")
)

func main() {
	getopt.Parse()
	// Override default umask so created files are always scoped to the
	// current user.
	syscall.Umask(0077)

	if *versionFlag {
		v := version.GetVersionInfo()
		fmt.Printf("gitsign-credential-cache version %s\n", v.GitVersion)

		os.Exit(0)
	}

	var connChan = make(chan net.Conn)
	if *systemdFlag {
		// Stop if we're not running under systemd.
		if os.Getenv("LISTEN_PID") == "" {
			log.Fatalf("systemd socket activation requested but not running under systemd")
		}

		listeners, err := activation.Listeners()
		if err != nil {
			log.Fatalf("error getting systemd listeners: %v", err)
		}
		if len(listeners) == 0 {
			log.Fatalf("no systemd listeners found")
		}
		for _, l := range listeners {
			if l == nil {
				continue
			}
			fmt.Println(l.Addr().String())
			go connToChan(l, connChan)
		}
	} else {
		user, err := os.UserCacheDir()
		if err != nil {
			log.Fatalf("error getting user cache directory: %v", err)
		}

		dir := filepath.Join(user, "sigstore", "gitsign")
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
		go connToChan(l, connChan)
	}
	srv := rpc.NewServer()
	if err := srv.Register(service.NewService()); err != nil {
		log.Fatalf("error registering RPC service: %v", err)
	}
	for conn := range connChan {
		go srv.ServeConn(conn)
	}
}

func connToChan(l net.Listener, connChan chan net.Conn) {
	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatalf("error accepting connection: %v", err)
		}
		connChan <- conn
	}
}
