package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"os"

	"github.com/github/smimesign/signature"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/wlynch/smimecosign/git"
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
			return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read signature")
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
		return errors.Wrap(err, "failed to verify signature")
	}

	var (
		fpr  = certHexFingerprint(cert)
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
		return errors.Wrapf(err, "failed to open signature file (%s)", fileArgs[0])
	}
	defer f.Close()
	sig := new(bytes.Buffer)
	if _, err = io.Copy(sig, f); err != nil {
		return errors.Wrap(err, "failed to read signature file")
	}

	// Read in signed data
	if fileArgs[1] == "-" {
		f = stdin
	} else {
		if f, err = os.Open(fileArgs[1]); err != nil {
			errors.Wrapf(err, "failed to open message file (%s)", fileArgs[1])
		}
		defer f.Close()
	}
	buf := new(bytes.Buffer)
	if _, err = io.Copy(buf, f); err != nil {
		return errors.Wrap(err, "failed to read message file")
	}

	summary, err := git.Verify(context.Background(), buf.Bytes(), sig.Bytes())
	if err != nil {
		if summary.Cert != nil {
			emitBadSig(summary.Cert)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return errors.Wrap(err, "failed to verify signature")
	}

	fpr := certHexFingerprint(summary.Cert)

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
