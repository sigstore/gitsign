// Copyright 2026 The Sigstore Authors
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

package keyring

import (
	"encoding/base64"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/99designs/keyring"
)

const securityPath = "/usr/bin/security"

// securityCLIKeyring implements keyring.Keyring on top of the
// /usr/bin/security CLI, for macOS builds without cgo (which the native
// Security.framework backend requires).
//
// Item data is stored base64-encoded, since the security CLI mangles
// non-printable/multiline values on read.
type securityCLIKeyring struct {
	service string
}

var _ keyring.Keyring = (*securityCLIKeyring)(nil)

func newSecurityCLIKeyring(service string) *securityCLIKeyring {
	return &securityCLIKeyring{service: service}
}

// validToken reports whether s is safe to embed in a `security -i` command
// without quoting. Keys and payloads used by this package (hex digests,
// "credential/v1/.../chain/N" paths, base64) all satisfy this.
func validToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/', r == '.', r == '_', r == '-', r == '+', r == '=', r == ':':
		default:
			return false
		}
	}
	return true
}

func (k *securityCLIKeyring) Get(key string) (keyring.Item, error) {
	if !validToken(key) {
		return keyring.Item{}, fmt.Errorf("invalid key %q", key)
	}
	out, err := exec.Command(securityPath,
		"find-generic-password",
		"-s", k.service,
		"-wa", key).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "could not be found") {
			return keyring.Item{}, keyring.ErrKeyNotFound
		}
		return keyring.Item{}, fmt.Errorf("security find-generic-password: %w: %s", err, out)
	}
	data, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return keyring.Item{}, fmt.Errorf("error decoding stored value: %w", err)
	}
	return keyring.Item{Key: key, Data: data}, nil
}

func (k *securityCLIKeyring) GetMetadata(_ string) (keyring.Metadata, error) {
	return keyring.Metadata{}, keyring.ErrMetadataNotSupported
}

func (k *securityCLIKeyring) Set(item keyring.Item) error {
	if !validToken(item.Key) {
		return fmt.Errorf("invalid key %q", item.Key)
	}
	encoded := base64.StdEncoding.EncodeToString(item.Data)

	// Run in interactive mode and pass the command via stdin so the secret
	// doesn't show up in process args.
	command := fmt.Sprintf("add-generic-password -U -s %s -a %s -w %s\n", k.service, item.Key, encoded)
	// The security CLI limits interactive commands to 4096 bytes.
	if len(command) > 4096 {
		return fmt.Errorf("value for %q too large for the security CLI", item.Key)
	}

	cmd := exec.Command(securityPath, "-i")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	if _, err := io.WriteString(stdin, command); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("security add-generic-password: %w", err)
	}
	return nil
}

func (k *securityCLIKeyring) Remove(key string) error {
	if !validToken(key) {
		return fmt.Errorf("invalid key %q", key)
	}
	out, err := exec.Command(securityPath,
		"delete-generic-password",
		"-s", k.service,
		"-a", key).CombinedOutput()
	if err != nil {
		if strings.Contains(string(out), "could not be found") {
			return keyring.ErrKeyNotFound
		}
		return fmt.Errorf("security delete-generic-password: %w: %s", err, out)
	}
	return nil
}

func (k *securityCLIKeyring) Keys() ([]string, error) {
	// dump-keychain lists item attributes (not secrets), so it doesn't
	// require authorization.
	out, err := exec.Command(securityPath, "dump-keychain").CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("security dump-keychain: %w", err)
	}
	return parseKeychainDump(k.service, string(out)), nil
}
