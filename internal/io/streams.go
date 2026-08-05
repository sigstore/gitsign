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

package io // nolint:revive

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/mattn/go-tty"
)

// openTTY is overridden in tests to avoid depending on a real TTY being
// attached to the test process.
var openTTY = tty.Open

type Streams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	TTYIn  io.Reader
	TTYOut io.Writer

	close []func() error
}

func New(logPath string) *Streams {
	s := &Streams{
		In:  os.Stdin,
		Out: os.Stdout,
		Err: os.Stderr,
	}

	var logErr error
	if logPath != "" {
		// Since Git eats both stdout and stderr, we don't have a good way of
		// getting error information back from clients if things go wrong.
		// As a janky way to preserve error message, tee stderr to
		// a temp file.
		if f, err := os.Create(logPath); err == nil { // nolint:gosec
			s.close = append(s.close, f.Close)
			s.Err = io.MultiWriter(s.Err, f)
		} else {
			logErr = err
		}
	}

	// A TTY may not be available in all environments (e.g. in CI), so only
	// set the input/output if we can actually open it.
	tty, err := openTTY()
	if err == nil {
		s.close = append(s.close, tty.Close)
		s.TTYIn = tty.Input()
		s.TTYOut = tty.Output()
	} else {
		// If we can't connect to a TTY, fall back to stderr for output (which
		// will also log to file if GITSIGN_LOG is set).
		s.TTYOut = s.Err
	}

	// Surface log file creation failures once we know where output can
	// actually be seen (TTY if present, otherwise stderr), since this
	// would otherwise be silently swallowed by Git consuming stdout/stderr.
	if logErr != nil {
		fmt.Fprintf(s.TTYOut, "failed to create log file %q: %v\n", logPath, logErr) // nolint:errcheck
	}
	return s
}

func (s *Streams) Wrap(fn func() error) (retErr error) {
	// Log any panics to ttyout, since otherwise they will be lost to os.Stderr.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(s.TTYOut, r, string(debug.Stack())) // nolint:errcheck
			retErr = fmt.Errorf("panic: %v", r)
		}
	}()

	if err := fn(); err != nil {
		fmt.Fprintln(s.TTYOut, err) // nolint:errcheck
		return err
	}
	return nil
}

func (s *Streams) Close() error {
	for _, fn := range s.close {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}
