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
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/gitsign/internal"
	"github.com/sigstore/gitsign/internal/git"
	"github.com/sigstore/gitsign/internal/signature"
)

func commandVerify() error {
	sNewSig.emit()

	if len(fileArgs) < 2 {
		return verifyAttached()
	}

	return verifyDetached()
}

func verifyAttached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return fmt.Errorf("failed to open signature file (%s): %w", fileArgs[0], err)
		}
		defer f.Close()
	} else {
		f = stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return fmt.Errorf("failed to read signature: %w", err)
	}

	chains, err := signature.Verify(buf.Bytes(), nil, false, verifyOpts())
	cert := chains[0][0][0]
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(cert)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	var (
		fpr  = internal.CertHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(cert)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\"\n", subj)
	emitTrustFully()

	return nil
}

func verifyDetached() error {
	var (
		f   io.ReadCloser
		err error
	)

	// Read in signature
	if f, err = os.Open(fileArgs[0]); err != nil {
		return fmt.Errorf("failed to open signature file (%s): %w", fileArgs[0], err)
	}
	defer f.Close()
	sig := new(bytes.Buffer)
	if _, err = io.Copy(sig, f); err != nil {
		return fmt.Errorf("failed to read signature file: %w", err)
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			return fmt.Errorf("failed to open message file (%s): %w", fileArgs[1], err)
		}
		defer f.Close()
	}
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return fmt.Errorf("failed to read message file: %w", err)
	}

	rekor, err := newRekorClient()
	if err != nil {
		return fmt.Errorf("failed to create rekor client: %w", err)
	}

	summary, err := git.Verify(context.Background(), rekor, buf.Bytes(), sig.Bytes())
	if err != nil {
		if summary.Cert != nil {
			emitBadSig(summary.Cert)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return fmt.Errorf("failed to verify signature: %w", err)
	}

	fpr := internal.CertHexFingerprint(summary.Cert)

	fmt.Fprintln(stderr, "tlog index:", *summary.LogEntry.LogIndex)
	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s | %v\n", fpr, summary.Cert.Issuer)
	emitGoodSig(summary.Cert)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "smimesign: Good signature from %v\n", summary.Cert.EmailAddresses)

	for _, c := range summary.Claims {
		fmt.Fprintf(stderr, "%s: %t\n", string(c.Key), c.Value)
	}

	emitTrustFully()

	return nil
}

func verifyOpts() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:     fulcioroots.Get(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}
