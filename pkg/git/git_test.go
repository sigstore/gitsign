// Copyright 2022 The Sigstore Authors
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

package git

import (
	"bytes"
	"os"
	"testing"
)

// loadObject reads a raw object from testdata. The bytes are exactly what
// git's object store holds (i.e. the output of `git cat-file -p <ref>`),
// without the "<type> <size>\0" prefix that git prepends before hashing.
func loadObject(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read testdata/%s: %v", name, err)
	}
	return raw
}

// SHAs of the objects in testdata, verified against git's stored hash:
//
//	printf 'commit %d\0' $(wc -c < testdata/commit.txt) | cat - testdata/commit.txt | shasum
//	printf 'tag %d\0'    $(wc -c < testdata/tag.txt)    | cat - testdata/tag.txt    | shasum
const (
	commitSHA = "4954440f9953588782896a1a473d8968765db82b"
	tagSHA    = "a7c0f87e7d8f475cfe66d9c848b77cf3b85d860b"
)

func TestObjectHash(t *testing.T) {
	for _, tc := range []struct {
		name  string
		file  string
		split func([]byte) ([]byte, []byte, error)
		sha   string
	}{
		{
			name:  "commit",
			file:  "commit.txt",
			split: func(raw []byte) ([]byte, []byte, error) { return SplitCommit(bytes.NewReader(raw)) },
			sha:   commitSHA,
		},
		{
			name:  "tag",
			file:  "tag.txt",
			split: func(raw []byte) ([]byte, []byte, error) { return SplitTag(bytes.NewReader(raw)) },
			sha:   tagSHA,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := loadObject(t, tc.file)
			body, sig, err := tc.split(raw)
			if err != nil {
				t.Fatalf("split: %v", err)
			}
			got, err := ObjectHash(body, sig)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.sha {
				t.Errorf("want %s, got %s", tc.sha, got)
			}
		})
	}
}
