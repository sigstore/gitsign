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

// parseKeychainDump extracts the account names of generic password items
// belonging to the given service from `security dump-keychain` output.
//
// Items are printed as blocks starting with a `keychain:` line, with
// attribute lines like:
//
//	"acct"<blob>="credential/v1/abc123"
//	"svce"<blob>="gitsign"
//
// This lives in an untagged file so it can be unit tested on any platform;
// it is only exercised by the darwin non-cgo security CLI backend.
func parseKeychainDump(service, dump string) []string {
	var keys []string
	var acct string
	var svce string

	flush := func() {
		if svce == service && acct != "" {
			keys = append(keys, acct)
		}
		acct, svce = "", ""
	}

	for line := range strings.SplitSeq(dump, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "keychain:") {
			// New item block.
			flush()
			continue
		}
		if v, ok := attrValue(trimmed, "acct"); ok {
			acct = v
		}
		if v, ok := attrValue(trimmed, "svce"); ok {
			svce = v
		}
	}
	flush()
	return keys
}

// attrValue parses a dump-keychain attribute line of the form
// `"name"<blob>="value"`, returning the value.
func attrValue(line, name string) (string, bool) {
	prefix := `"` + name + `"<blob>="`
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := strings.TrimPrefix(line, prefix)
	end := strings.LastIndex(rest, `"`)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}
