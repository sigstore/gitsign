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

//go:build windows

package keyring

import (
	"fmt"

	"github.com/99designs/keyring"
	"github.com/danieljoos/wincred"
)

// winCredKeyring fixes Keys for 99designs' WinCred backend, which discards
// Credential Manager enumeration errors and reports an empty keyring instead
// - making `gitsign credentials list` show nothing and `clear --all` report
// success when enumeration actually failed.
type winCredKeyring struct {
	keyring.Keyring
}

func (k winCredKeyring) Keys() ([]string, error) {
	// FilteredList already maps "no matching credentials" to an empty list.
	creds, err := wincred.FilteredList(winCredTargetPrefix + "*")
	if err != nil {
		return nil, fmt.Errorf("error enumerating Credential Manager entries: %w", err)
	}
	targets := make([]string, 0, len(creds))
	for _, c := range creds {
		targets = append(targets, c.TargetName)
	}
	return keysFromTargets(targets), nil
}

// wrapBackend adapts the opened system keyring. On Windows the only allowed
// backend is WinCred.
func wrapBackend(kr keyring.Keyring) keyring.Keyring {
	return winCredKeyring{Keyring: kr}
}
