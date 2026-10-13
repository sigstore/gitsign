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

func TestKeysFromTargets(t *testing.T) {
	got := keysFromTargets([]string{
		"gitsign:gitsign:credential/v1/abc",
		"gitsign:gitsign:credential/v1/abc/data/0011/0",
		"other:gitsign:credential/v1/abc", // another app's prefix
		"gitsign:other:credential/v1/abc", // another service name
		"unrelated",
	})
	want := []string{
		"credential/v1/abc",
		"credential/v1/abc/data/0011/0",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("keysFromTargets (-want +got):\n%s", diff)
	}
}
