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
	"fmt"
	"io"
	"os"

	"github.com/sigstore/gitsign/internal"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/pkg/git"
)

func commandVerify(cfg *config.Config) error {
	ctx := context.Background()
	sNewSig.emit()

	var (
		data, sig []byte
		err       error
	)
	detached := len(fileArgs) >= 2
	if detached {
		data, sig, err = readDetached()
	} else {
		sig, err = readAttached()
	}
	if err != nil {
		return fmt.Errorf("failed to read signature data (detached: %T): %w", detached, err)
	}

	cv, err := git.NewCertVerifier()
	if err != nil {
		return fmt.Errorf("error creating git cert verifier: %w", err)
	}

	rekor, err := newRekorClient(cfg.Rekor)
	if err != nil {
		return fmt.Errorf("failed to create rekor client: %w", err)
	}

	summary, err := git.Verify(ctx, cv, rekor, data, sig, detached)
	if err != nil {
		if summary != nil && summary.Cert != nil {
			emitBadSig(summary.Cert)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	fpr := internal.CertHexFingerprint(summary.Cert)

	fmt.Fprintln(stderr, "tlog index:", *summary.LogEntry.LogIndex)
	fmt.Fprintf(stderr, "gitsign: Signature made using certificate ID 0x%s | %v\n", fpr, summary.Cert.Issuer)
	emitGoodSig(summary.Cert)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "gitsign: Good signature from %v\n", summary.Cert.EmailAddresses)

	for _, c := range summary.Claims {
		fmt.Fprintf(stderr, "%s: %t\n", string(c.Key), c.Value)
	}

	emitTrustFully()

	return nil
}

func readAttached() ([]byte, error) {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return nil, fmt.Errorf("failed to open signature file (%s): %w", fileArgs[0], err)
		}
		defer f.Close()
	} else {
		f = stdin
	}

	sig := new(bytes.Buffer)
	if _, err = io.Copy(sig, f); err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	return sig.Bytes(), nil
}

func readDetached() ([]byte, []byte, error) {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if f, err = os.Open(fileArgs[0]); err != nil {
		return nil, nil, fmt.Errorf("failed to open signature file (%s): %w", fileArgs[0], err)
	}
	defer f.Close()
	sig := new(bytes.Buffer)
	if _, err = io.Copy(sig, f); err != nil {
		return nil, nil, fmt.Errorf("failed to read signature file: %w", err)
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			return nil, nil, fmt.Errorf("failed to open message file (%s): %w", fileArgs[1], err)
		}
		defer f.Close()
	}
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return nil, nil, fmt.Errorf("failed to read message file: %w", err)
	}

	return buf.Bytes(), sig.Bytes(), nil
}
