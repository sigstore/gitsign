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

// Package localcache locates a sigstore-go-style TUF cache on disk and
// exposes the trusted_root.json it contains. Used to bypass the embedded
// (short-lived) root.json in sigstore/sigstore's TUF client when a local
// cache - typically populated by sigstore-go-based tooling - is available.
package localcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
)

// TrustedRootPath returns the path to a cached trusted_root.json under
// $TUF_ROOT (or ~/.sigstore/root by default). The mirror URL is read from
// remote.json in the same directory and converted to the on-disk
// subdirectory name using the same scheme-strip / slash-replace rules
// sigstore-go uses (see sigstore-go's tuf.URLToPath). Returns false if any
// prerequisite is missing.
func TrustedRootPath() (string, bool) {
	cacheRoot := os.Getenv("TUF_ROOT")
	if cacheRoot == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return "", false
		}
		cacheRoot = filepath.Join(home, ".sigstore", "root")
	}

	remoteBytes, err := os.ReadFile(filepath.Join(cacheRoot, "remote.json"))
	if err != nil {
		return "", false
	}
	var remote struct {
		Mirror string `json:"mirror"`
	}
	if err := json.Unmarshal(remoteBytes, &remote); err != nil || remote.Mirror == "" {
		return "", false
	}

	dir := urlToCacheDir(remote.Mirror)
	if dir == "" {
		return "", false
	}
	path := filepath.Join(cacheRoot, dir, "targets", "trusted_root.json")
	if _, err := os.Stat(path); err != nil {
		return "", false
	}
	return path, true
}

// urlToCacheDir mirrors sigstore-go's tuf.URLToPath: strip scheme, replace
// '/' and ':' with '-', lowercase. Kept in lock-step (rather than imported)
// so the cache layout stays compatible with any sigstore-go-based tool
// without taking a direct dep on the helper.
func urlToCacheDir(mirror string) string {
	s := mirror
	s = strings.TrimPrefix(s, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	return strings.ToLower(s)
}
