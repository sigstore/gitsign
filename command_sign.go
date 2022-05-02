package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"os"

	"github.com/github/smimesign/signature"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/wlynch/smimecosign/fulcio"
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

	sig, cert, err := signature.Sign(userIdent, dataBuf.Bytes(), signature.SignOptions{
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

	// This uploads the commit SHA + sig(commit SHA) to the tlog using the same
	// key used to sign the commit data itself.
	// Since the commit SHA ~= hash(commit data + sig(commit data)) and we're
	// using the same key, this is probably okay? e.g. even if you could cause a SHA1 collision,
	// you would still need the underlying commit to be valid and using the same key which seems hard.

	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		fmt.Fprintln(stderr, "error creating rekor client: ", err)
		return err
	}

	commit, err := commitHash(dataBuf.Bytes(), sig)
	if err != nil {
		fmt.Fprintln(stderr, "error generating commit hash: ", err)
		return err
	}
	fmt.Fprintln(stderr, "Predicted commit hash:", commit)

	sv := userIdent.SignerVerifier()
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		fmt.Fprintln(stderr, "error signing commit hash: ", err)
		return err
	}
	pkBytes, err := publicKeyFromCert(cert)
	if err != nil {
		return err
	}
	_, err = cosign.TLogUpload(ctx, rClient, commitSig, []byte(commit), pkBytes)
	if err != nil {
		fmt.Fprintln(stderr, "error uploading tlog (commit): ", err)
		return err
	}

	return nil
}

func commitHash(data, sig []byte) (string, error) {
	// Precompute commit hash to store in tlog
	obj := &plumbing.MemoryObject{}
	obj.Write(data)
	obj.SetType(plumbing.CommitObject)

	// go-git will compute a hash on decode and preserve that. To work around this,
	// decode into one object then copy everything but the commit into a separate object.
	base := object.Commit{}
	base.Decode(obj)
	c := object.Commit{
		Author:       base.Author,
		Committer:    base.Committer,
		PGPSignature: string(sig),
		Message:      base.Message,
		TreeHash:     base.TreeHash,
		ParentHashes: base.ParentHashes,
	}
	out := &plumbing.MemoryObject{}
	err := c.Encode(out)
	return out.Hash().String(), err
}

func publicKeyFromCert(cert *x509.Certificate) ([]byte, error) {
	pk, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		fmt.Fprintln(stderr, "error uploading tlog: ", err)
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pk,
	}), nil
}
