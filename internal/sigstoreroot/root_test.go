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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestTUFOptions(t *testing.T) {
	opts := TUFOptions()
	if opts == nil {
		t.Fatal("TUFOptions() returned nil")
	}
	if opts.CachePath == "" {
		t.Fatal("TUFOptions() CachePath is empty")
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
