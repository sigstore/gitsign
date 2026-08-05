//
// Copyright 2026 The Sigstore Authors.
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

package io // nolint:revive

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mattn/go-tty"
)

func TestWrap(t *testing.T) {
	wantErr := errors.New("boom")

	for _, tc := range []struct {
		name       string
		fn         func() error
		wantErr    error
		wantErrSub string
		wantTTYSub string
	}{
		{
			name:    "no error",
			fn:      func() error { return nil },
			wantErr: nil,
		},
		{
			name:       "returns error",
			fn:         func() error { return wantErr },
			wantErr:    wantErr,
			wantTTYSub: "boom",
		},
		{
			name:       "panic returns error",
			fn:         func() error { panic("kaboom") },
			wantErrSub: "panic: kaboom",
			wantTTYSub: "kaboom",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tty := &bytes.Buffer{}
			s := &Streams{TTYOut: tty}

			err := s.Wrap(tc.fn)

			switch {
			case tc.wantErr != nil:
				if !errors.Is(err, tc.wantErr) {
					t.Errorf("Wrap() error = %v, want %v", err, tc.wantErr)
				}
			case tc.wantErrSub != "":
				if err == nil || !strings.Contains(err.Error(), tc.wantErrSub) {
					t.Errorf("Wrap() error = %v, want error containing %q", err, tc.wantErrSub)
				}
			default:
				if err != nil {
					t.Errorf("Wrap() error = %v, want nil", err)
				}
			}

			if tc.wantTTYSub != "" && !strings.Contains(tty.String(), tc.wantTTYSub) {
				t.Errorf("TTYOut = %q, want it to contain %q", tty.String(), tc.wantTTYSub)
			}
		})
	}
}

func TestNew_LogFileCreateError(t *testing.T) {
	// Force the no-TTY path so output deterministically falls back to
	// stderr, regardless of whether the test process has a real TTY attached.
	origOpenTTY := openTTY
	openTTY = func() (*tty.TTY, error) { return nil, errors.New("no tty") }
	t.Cleanup(func() { openTTY = origOpenTTY })

	// A path under a non-existent directory so os.Create fails.
	logPath := filepath.Join(t.TempDir(), "missing-dir", "gitsign.log")

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	t.Cleanup(func() { os.Stderr = origStderr })

	s := New(logPath)

	w.Close()
	os.Stderr = origStderr

	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(out), logPath) {
		t.Errorf("stderr output = %q, want it to contain the failing log path %q", out, logPath)
	}

	if err := s.Close(); err != nil {
		t.Errorf("Close() = %v, want nil", err)
	}
}
