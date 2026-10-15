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

//go:build linux

package keyring

import "github.com/godbus/dbus"

// defaultCollection returns the name of the Secret Service collection the
// "default" alias points at, so credentials go into the user's existing
// default keyring (whatever it's called) instead of a fixed name that might
// not exist - which would make 99designs/keyring create it, prompting for a
// new password or failing on services that can't create collections.
func defaultCollection() string {
	// The session bus connection is shared; don't close it.
	conn, err := dbus.SessionBus()
	if err != nil {
		return fallbackCollection
	}
	var path dbus.ObjectPath
	err = conn.Object("org.freedesktop.secrets", "/org/freedesktop/secrets").
		// Don't D-Bus-activate a Secret Service just to resolve the alias.
		Call("org.freedesktop.Secret.Service.ReadAlias", dbus.FlagNoAutoStart, "default").
		Store(&path)
	if err != nil {
		return fallbackCollection
	}
	if name, ok := collectionFromAliasPath(string(path)); ok {
		return name
	}
	return fallbackCollection
}
