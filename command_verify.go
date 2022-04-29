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
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/models"
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

	chains, err := signature.Verify(buf.Bytes(), nil, *detachSignFlag, verifyOpts())
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return errors.Wrap(err, "failed to verify signature")
	}

	var (
		cert = chains[0][0][0]
		fpr  = certHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s\n", fpr)
	emitGoodSig(chains)

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

	chains, err := signature.Verify(buf.Bytes(), sig.Bytes(), *detachSignFlag, verifyOpts())
	if err != nil {
		if len(chains) > 0 {
			emitBadSig(chains)
		} else {
			// TODO: We're omitting a bunch of arguments here.
			sErrSig.emit()
		}
		return errors.Wrap(err, "failed to verify signature")
	}

	commit, err := commitHash(buf.Bytes(), sig.Bytes())
	if err != nil {
		fmt.Fprintln(stderr, "error generating commit hash: ", err)
		return err
	}
	fmt.Fprintln(stderr, "searching tlog for commit:", commit)

	var (
		cert = chains[0][0][0]
		fpr  = certHexFingerprint(cert)
		subj = cert.Subject.String()
	)

	pk, err := publicKeyFromCert(cert)
	if err != nil {
		return err
	}

	ctx := context.Background()
	tlog, err := verifyTlog(ctx, commit, pk)
	if err != nil {
		fmt.Fprintln(stderr, "error verifying tlog: ", err)
		return err
	}
	fmt.Fprintln(stderr, "tlog index:", *tlog.LogIndex)

	fmt.Fprintf(stderr, "smimesign: Signature made using certificate ID 0x%s | %v\n", fpr, cert.Issuer)
	emitGoodSig(chains)

	// TODO: Maybe split up signature checking and certificate checking so we can
	// output something more meaningful.
	fmt.Fprintf(stderr, "smimesign: Good signature from \"%s\" (%v)\n", subj, cert.EmailAddresses)
	emitTrustFully()

	return nil
}

func verifyOpts() x509.VerifyOptions {
	return x509.VerifyOptions{
		Roots:     fulcioroots.Get(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
}

func verifyTlog(ctx context.Context, commit string, publicKey []byte) (*models.LogEntryAnon, error) {
	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		fmt.Fprintln(stderr, "error creating rekor client: ", err)
		return nil, err
	}

	tlogEntry, err := cosign.FindTlogEntry(ctx, rClient, "" /* sig */, []byte(commit), publicKey)
	if err != nil {
		return nil, err
	}
	return tlogEntry, cosign.VerifyTLogEntry(ctx, rClient, tlogEntry)
}
