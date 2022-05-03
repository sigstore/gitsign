package main

import (
	"bytes"
	"context"
	"io"
	"os"

	"github.com/github/smimesign/signature"
	"github.com/pkg/errors"
	"github.com/wlynch/smimecosign/fulcio"
	"github.com/wlynch/smimecosign/git"
)

func commandSign() error {
	ctx := context.Background()
	userIdent, err := fulcio.NewIdentity(ctx, stderr)
	if err != nil {
		return errors.Wrap(err, "failed to get identity")
	}

	// Git is looking for "\n[GNUPG:] SIG_CREATED ", meaning we need to print a
	// line before SIG_CREATED. BEGIN_SIGNING seems appropraite. GPG emits this,
	// though GPGSM does not.
	sBeginSigning.emit()

	var f io.ReadCloser
	if len(fileArgs) == 1 {
		if f, err = os.Open(fileArgs[0]); err != nil {
			return errors.Wrapf(err, "failed to open message file (%s)", fileArgs[0])
		}
		defer f.Close()
	} else {
		f = stdin
	}

	dataBuf := new(bytes.Buffer)
	if _, err = io.Copy(dataBuf, f); err != nil {
		return errors.Wrap(err, "failed to read message from stdin")
	}

	sig, cert, err := git.Sign(ctx, userIdent, dataBuf.Bytes(), signature.SignOptions{
		Detached:           *detachSignFlag,
		TimestampAuthority: *tsaOpt,
		Armor:              *armorFlag,
		IncludeCerts:       *includeCertsOpt,
	})
	if err != nil {
		return errors.Wrap(err, "failed to sign message")
	}

	emitSigCreated(cert, *detachSignFlag)

	if _, err := stdout.Write(sig); err != nil {
		return errors.New("failed to write signature")
	}

	return nil
}
