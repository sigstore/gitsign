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

import "strings"

const (
	// fallbackCollection is used when the Secret Service default collection
	// can't be resolved; it's the usual name of the default collection.
	fallbackCollection = "login"
	// secretCollectionPrefix is the D-Bus object path prefix of Secret Service
	// collections. 99designs/keyring addresses a collection by the name after
	// this prefix.
	secretCollectionPrefix = "/org/freedesktop/secrets/collection/"
)

// collectionFromAliasPath maps the object path the Secret Service "default"
// alias resolves to into a collection name 99designs/keyring can address. It
// reports false if there is no default collection ("/") or the path isn't a
// collection path.
func collectionFromAliasPath(path string) (string, bool) {
	name, ok := strings.CutPrefix(path, secretCollectionPrefix)
	if !ok || name == "" || strings.Contains(name, "/") {
		return "", false
	}
	return name, true
}
