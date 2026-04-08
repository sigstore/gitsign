// Copyright 2024 The Sigstore Authors.
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

package sigstoreroot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// setupFakeHome creates a temp HOME with a .sigstore/root cache directory.
func setupFakeHome(t *testing.T) string {
	t.Helper()
	fakeHome := t.TempDir()
	t.Setenv("HOME", fakeHome)
	cache := filepath.Join(fakeHome, ".sigstore", "root")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	return cache
}

// simulateDoInitialize reproduces the cache layout cosign's DoInitialize creates.
func simulateDoInitialize(t *testing.T, cache, mirror string, rootBytes []byte) {
	t.Helper()

	remote := map[string]string{"mirror": mirror}
	remoteBytes, err := json.Marshal(remote)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "remote.json"), remoteBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	mirrorDir := filepath.Join(cache, tuf.URLToPath(mirror))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(mirrorDir, "root.json"), rootBytes, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTUFOptions(t *testing.T) {
	opts := TUFOptions()
	if opts == nil {
		t.Fatal("TUFOptions() returned nil")
	}
	if opts.CachePath == "" {
		t.Fatal("TUFOptions() CachePath is empty")
	}
}

func TestTUFOptionsCustomMirrorUsesCachedRoot(t *testing.T) {
	cache := setupFakeHome(t)

	customMirror := "https://tuf.custom.example.com"
	customRoot := []byte(`{"signed":{"_type":"root","version":1},"signatures":[]}`)

	simulateDoInitialize(t, cache, customMirror, customRoot)

	opts := TUFOptions()

	if opts.RepositoryBaseURL != customMirror {
		t.Fatalf("RepositoryBaseURL = %q, want %q", opts.RepositoryBaseURL, customMirror)
	}
	if !bytes.Equal(opts.Root, customRoot) {
		t.Fatal("expected cached custom root")
	}
	if bytes.Equal(opts.Root, tuf.DefaultRoot()) {
		t.Fatal("root must differ from embedded default")
	}
}

func TestTUFOptionsDefaultMirrorKeepsEmbeddedRoot(t *testing.T) {
	setupFakeHome(t)

	opts := TUFOptions()

	if opts.RepositoryBaseURL != tuf.DefaultMirror {
		t.Fatalf("RepositoryBaseURL = %q, want %q", opts.RepositoryBaseURL, tuf.DefaultMirror)
	}
	if !bytes.Equal(opts.Root, tuf.DefaultRoot()) {
		t.Fatal("expected embedded default root")
	}
}

func TestTUFOptionsCustomMirrorMissingCachedRootFallsBack(t *testing.T) {
	cache := setupFakeHome(t)

	customMirror := "https://tuf.custom.example.com"
	remote := map[string]string{"mirror": customMirror}
	remoteBytes, _ := json.Marshal(remote)
	os.WriteFile(filepath.Join(cache, "remote.json"), remoteBytes, 0o600)

	opts := TUFOptions()

	if opts.RepositoryBaseURL != customMirror {
		t.Fatalf("RepositoryBaseURL = %q, want %q", opts.RepositoryBaseURL, customMirror)
	}
	if !bytes.Equal(opts.Root, tuf.DefaultRoot()) {
		t.Fatal("expected fallback to embedded default root")
	}
}

func TestTUFOptionsCachePathMatchesDoInitialize(t *testing.T) {
	cache := setupFakeHome(t)
	customMirror := "https://tuf-server.test.svc:8443/rhtas"
	customRoot := []byte(`{"signed":{"_type":"root","version":2},"signatures":[]}`)

	simulateDoInitialize(t, cache, customMirror, customRoot)

	expectedDir := filepath.Join(cache, tuf.URLToPath(customMirror))
	expectedRootPath := filepath.Join(expectedDir, "root.json")
	if _, err := os.Stat(expectedRootPath); err != nil {
		t.Fatalf("cached root.json not found at expected path %q: %v", expectedRootPath, err)
	}

	opts := TUFOptions()
	if !bytes.Equal(opts.Root, customRoot) {
		t.Fatal("expected cached root.json from DoInitialize path")
	}

	tufClientDir := filepath.Join(opts.CachePath, tuf.URLToPath(opts.RepositoryBaseURL))
	if tufClientDir != expectedDir {
		t.Fatalf("TUF client cache dir %q != DoInitialize dir %q", tufClientDir, expectedDir)
	}
}

func TestTUFOptionsCustomMirrorWithPortAndPath(t *testing.T) {
	cache := setupFakeHome(t)

	customMirror := "http://tuf.local:8080/v2/targets"
	customRoot := []byte(`{"signed":{"_type":"root","version":1},"signatures":[]}`)

	simulateDoInitialize(t, cache, customMirror, customRoot)

	opts := TUFOptions()
	if opts.RepositoryBaseURL != customMirror {
		t.Fatalf("RepositoryBaseURL = %q, want %q", opts.RepositoryBaseURL, customMirror)
	}
	if !bytes.Equal(opts.Root, customRoot) {
		t.Fatal("expected cached custom root for URL with port and path")
	}
}

func TestReadRemoteHint(t *testing.T) {
	tmpDir := t.TempDir()

	remoteHint := struct {
		Mirror string `json:"mirror"`
	}{
		Mirror: "https://custom.mirror.example.com",
	}
	data, err := json.Marshal(remoteHint)
	if err != nil {
		t.Fatalf("failed to marshal remote hint: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmpDir, "remote.json"), data, 0644); err != nil {
		t.Fatalf("failed to write remote.json: %v", err)
	}

	mirror, err := readRemoteHint(tmpDir)
	if err != nil {
		t.Fatalf("readRemoteHint() error = %v", err)
	}
	if mirror != "https://custom.mirror.example.com" {
		t.Errorf("readRemoteHint() = %q, want %q", mirror, "https://custom.mirror.example.com")
	}
}

func TestReadRemoteHintMissingFile(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := readRemoteHint(tmpDir)
	if err == nil {
		t.Fatal("readRemoteHint() expected error for missing file, got nil")
	}
}

func TestReadRemoteHintInvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmpDir, "remote.json"), []byte("not json"), 0644); err != nil {
		t.Fatalf("failed to write remote.json: %v", err)
	}

	_, err := readRemoteHint(tmpDir)
	if err == nil {
		t.Fatal("readRemoteHint() expected error for invalid JSON, got nil")
	}
}
