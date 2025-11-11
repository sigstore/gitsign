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

	"github.com/coreos/go-systemd/v22/activation"
	"github.com/spf13/pflag"

	"github.com/sigstore/gitsign/internal/cache/service"
	"github.com/sigstore/gitsign/pkg/version"
)

var (
	// Action flags
	versionFlag = pflag.BoolP("version", "v", false, "print the version number")
	systemdFlag = pflag.Bool("systemd-socket-activation", false, "use systemd socket activation")
)

func main() {
	pflag.Parse()

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
		var validCount int
		for _, l := range listeners {
			if l == nil {
				continue
			}
			fmt.Println(l.Addr().String())
			go connToChan(l, connChan)
			validCount++
		}
		if validCount == 0 {
			log.Fatalf("no valid systemd listeners found")
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
			_ = os.Remove(path)
		}
		fmt.Println(path)

		l, err := net.Listen("unix", path)
		if err != nil {
			log.Fatalf("error opening socket: %v", err)
		}

		// Previously, we used syscall.Umask(0077) to ensure this was
		// permissioned only to the current user. Windows doesn't have this
		// syscall, so we're switching over to an explicit Chmod on the socket
		// path.
		// Also see https://github.com/golang/go/issues/11822
		if err := os.Chmod(path, 0700); err != nil {
			log.Fatalf("error setting socket permissions: %v", err)
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
