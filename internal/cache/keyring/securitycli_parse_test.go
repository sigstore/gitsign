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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseKeychainDump(t *testing.T) {
	dump := `keychain: "/Users/user/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    0x00000007 <blob>="gitsign"
    "acct"<blob>="credential/v1/abc123"
    "cdat"<timedate>=0x32303236303830343231343233345A00  "20260804214234Z\000"
    "svce"<blob>="gitsign"
keychain: "/Users/user/Library/Keychains/login.keychain-db"
version: 512
class: "genp"
attributes:
    "acct"<blob>="credential/v1/abc123/chain/0"
    "svce"<blob>="gitsign"
keychain: "/Users/user/Library/Keychains/login.keychain-db"
class: "genp"
attributes:
    "acct"<blob>="some-other-account"
    "svce"<blob>="other-service"
keychain: "/Users/user/Library/Keychains/login.keychain-db"
class: "inet"
attributes:
    "acct"<blob>="no-svce-item"
`

	got := parseKeychainDump("gitsign", dump)
	want := []string{
		"credential/v1/abc123",
		"credential/v1/abc123/chain/0",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("parseKeychainDump mismatch (-want +got):\n%s", diff)
	}
}

func TestAttrValue(t *testing.T) {
	for _, tc := range []struct {
		line   string
		name   string
		want   string
		wantOK bool
	}{
		{`"acct"<blob>="credential/v1/abc"`, "acct", "credential/v1/abc", true},
		{`"svce"<blob>="gitsign"`, "svce", "gitsign", true},
		{`"svce"<blob>=<NULL>`, "svce", "", false},
		{`"desc"<blob>="x"`, "acct", "", false},
	} {
		got, ok := attrValue(tc.line, tc.name)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("attrValue(%q, %q) = (%q, %v), want (%q, %v)", tc.line, tc.name, got, ok, tc.want, tc.wantOK)
		}
	}
}
