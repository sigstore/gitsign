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

//go:build !darwin

package keyring

import (
	"github.com/99designs/keyring"
)

// allowedBackends restricts storage to native OS credential stores - no
// file/pass fallbacks that would need their own password prompts.
var allowedBackends = []keyring.BackendType{
	keyring.WinCredBackend,
	keyring.SecretServiceBackend,
	keyring.KWalletBackend,
}

// openSystemKeyring opens the native OS credential store.
func openSystemKeyring() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName:     serviceName,
		AllowedBackends: allowedBackends,
		// Linux: use the default collection instead of creating a
		// gitsign-specific one (which would prompt for a new password).
		LibSecretCollectionName: "login",
		WinCredPrefix:           serviceName,
		KWalletAppID:            serviceName,
		KWalletFolder:           serviceName,
	})
}
