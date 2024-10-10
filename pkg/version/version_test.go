//
// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package version

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestVersionText(t *testing.T) {
	sut := GetVersionInfo()
	if sut.GitVersion != gitVersion {
		t.Errorf("GetVersionInfo: got %q, want %q", sut, gitVersion)
	}
}

func TestEnv(t *testing.T) {
	for _, envVar := range os.Environ() {
		for _, prefix := range envVarPrefixes {
			if strings.HasPrefix(envVar, prefix) {
				t.Setenv(strings.Split(envVar, "=")[0], "") // t.Setenv restores value during cleanup
				break
			}
		}
	}

	os.Setenv("GITSIGN_CONNECTOR_ID", "foobar")
	os.Setenv("GITSIGN_TEST", "foo")
	os.Setenv("TUF_ROOT", "bar")
	got := GetVersionInfo()
	want := []string{
		"GITSIGN_CONNECTOR_ID=foobar",
		"GITSIGN_TEST=foo",
		"TUF_ROOT=bar",
	}

	if diff := cmp.Diff(got.Env, want); diff != "" {
		t.Error(diff)
	}

	// want doesn't change because the variable is set to nothing and must be
	// ignored
	os.Setenv("SIGSTORE_ROOT_FILE", "")
	got = GetVersionInfo()
	if diff := cmp.Diff(got.Env, want); diff != "" {
		t.Error(diff)
	}
}
