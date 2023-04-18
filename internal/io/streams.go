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

package io

import (
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/mattn/go-tty"
)

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

	if logPath != "" {
		// Since Git eats both stdout and stderr, we don't have a good way of
		// getting error information back from clients if things go wrong.
		// As a janky way to preserve error message, tee stderr to
		// a temp file.
		if f, err := os.Create(logPath); err == nil {
			s.close = append(s.close, f.Close)
			s.Err = io.MultiWriter(s.Err, f)
		}
	}

	// A TTY may not be available in all environments (e.g. in CI), so only
	// set the input/output if we can actually open it.
	tty, err := tty.Open()
	if err == nil {
		s.close = append(s.close, tty.Close)
		s.TTYIn = tty.Input()
		s.TTYOut = tty.Output()
	} else {
		// If we can't connect to a TTY, fall back to stderr for output (which
		// will also log to file if GITSIGN_LOG is set).
		s.TTYOut = s.Err
	}
	return s
}

func (s *Streams) Wrap(fn func() error) error {
	// Log any panics to ttyout, since otherwise they will be lost to os.Stderr.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(s.TTYOut, r, string(debug.Stack()))
		}
	}()

	if err := fn(); err != nil {
		fmt.Fprintln(s.TTYOut, err)
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
