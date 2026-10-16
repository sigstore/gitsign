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

// winCredTargetPrefix is the Credential Manager target name prefix 99designs'
// WinCred backend uses for our entries (<WinCredPrefix>:<ServiceName>:<key>).
const winCredTargetPrefix = serviceName + ":" + serviceName + ":"

// keysFromTargets maps Credential Manager target names to keyring keys,
// ignoring targets that don't belong to us.
func keysFromTargets(targets []string) []string {
	keys := []string{}
	for _, t := range targets {
		if key, ok := strings.CutPrefix(t, winCredTargetPrefix); ok {
			keys = append(keys, key)
		}
	}
	return keys
}
