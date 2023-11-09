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

package root

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/git"
	"github.com/sigstore/gitsign/internal/gpg"
	gsio "github.com/sigstore/gitsign/internal/io"
	"github.com/sigstore/gitsign/internal/rekor"
	"github.com/sigstore/gitsign/internal/signature"
)

// commandSign implements gitsign commit signing.
// This is implemented as a root command so that user can specify the
// gitsign binary directly in their gitconfigs.
func commandSign(o *options, s *gsio.Streams, args ...string) error {
	ctx := context.Background()

	// Flag validation
	if o.FlagVerify {
		return errors.New("specify --help, --sign, or --verify")
	}
	if len(o.FlagLocalUser) == 0 {
		return errors.New("specify a USER-ID to sign with")
	}

	userIdent, err := fulcio.NewIdentity(ctx, o.Config, s.TTYIn, s.TTYOut)
	if err != nil {
		return fmt.Errorf("failed to get identity: %w", err)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropriate. GPG emits this,
	// though GPGSM does not.
	gpgout := gpg.NewStatusWriterFromFD(uintptr(o.FlagStatusFD))
	gpgout.Emit(gpg.StatusBeginSigning)

	var f io.Reader
	if len(args) == 1 {
		f2, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open message file (%s): %w", args[0], err)
		}
		defer f2.Close()
		f = f2
	} else {
		f = s.In
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return fmt.Errorf("failed to read message from stdin: %w", err)
	}

	rekor, err := rekor.NewClientContext(ctx, o.Config.Rekor)
	if err != nil {
		return fmt.Errorf("failed to create rekor client: %w", err)
	}

	opts := signature.SignOptions{
		Detached:           o.FlagDetachedSignature,
		TimestampAuthority: o.Config.TimestampURL,
		Armor:              o.FlagArmor,
		IncludeCerts:       o.FlagIncludeCerts,
	}
	if o.Config.MatchCommitter {
		opts.UserName = o.Config.CommitterName
		opts.UserEmail = o.Config.CommitterEmail
	}

	var fn git.SignFunc = git.LegacySHASign
	if o.Config.RekorMode == "offline" {
		fn = git.Sign
	}
	resp, err := fn(ctx, rekor, userIdent, dataBuf.Bytes(), opts)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	if tlog := resp.LogEntry; tlog != nil && tlog.LogIndex != nil {
		fmt.Fprintf(s.TTYOut, "tlog entry created with index: %d\n", *tlog.LogIndex)
	}

	gpgout.EmitSigCreated(resp.Cert, o.FlagDetachedSignature)

	if _, err := s.Out.Write(resp.Signature); err != nil {
		return errors.New("failed to write signature")
	}

	return nil
}
