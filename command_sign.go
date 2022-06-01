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

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/git"
	"github.com/sigstore/gitsign/internal/signature"
)

func commandSign() error {
	ctx := context.Background()

	userIdent, err := fulcio.NewIdentity(ctx, stderr)
	if err != nil {
		return fmt.Errorf("failed to get identity: %w", err)
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropriate. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	var f io.ReadCloser
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return fmt.Errorf("failed to open message file (%s): %w", fileArgs[0], err)
		}
		defer f.Close()
	} else {
		f = stdin
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return fmt.Errorf("failed to read message from stdin: %w", err)
	}

	rekor, err := newRekorClient()
	if err != nil {
		return fmt.Errorf("failed to create rekor client: %w", err)
	}

	sig, cert, err := git.Sign(ctx, rekor, userIdent, dataBuf.Bytes(), signature.SignOptions{
		Detached:           *detachSignFlag,
		TimestampAuthority: *tsaOpt,
		Armor:              *armorFlag,
		IncludeCerts:       *includeCertsOpt,
	})
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	emitSigCreated(cert, *detachSignFlag)

	if _, err := stdout.Write(sig); err != nil {
		return errors.New("failed to write signature")
	}

	return nil
}
