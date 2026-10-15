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

func TestCollectionFromAliasPath(t *testing.T) {
	type result struct {
		Name string
		OK   bool
	}
	for _, tc := range []struct {
		path string
		want result
	}{
		{path: "/org/freedesktop/secrets/collection/login", want: result{"login", true}},
		{path: "/org/freedesktop/secrets/collection/Default_5fkeyring", want: result{"Default_5fkeyring", true}},
		// No default collection.
		{path: "/", want: result{}},
		{path: "/org/freedesktop/secrets/collection/", want: result{}},
		{path: "/org/freedesktop/secrets/collection/a/b", want: result{}},
		{path: "/org/freedesktop/secrets/aliases/default", want: result{}},
	} {
		t.Run(tc.path, func(t *testing.T) {
			name, ok := collectionFromAliasPath(tc.path)
			if diff := cmp.Diff(tc.want, result{name, ok}); diff != "" {
				t.Errorf("collectionFromAliasPath(%q) (-want +got):\n%s", tc.path, diff)
			}
		})
	}
}
