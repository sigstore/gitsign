package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"strings"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/github/smimesign/signature"
	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag"
	"github.com/pkg/errors"
	"github.com/sigstore/cosign/cmd/cosign/cli/fulcio/fulcioroots"
	"github.com/sigstore/cosign/cmd/cosign/cli/rekor"
	"github.com/sigstore/cosign/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/index"
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

	chains, err := signature.Verify(buf.Bytes(), nil, false, verifyOpts())
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

	// Try decoding as PEM
	var der []byte
	if blk, _ := pem.Decode(sig.Bytes()); blk != nil {
		der = blk.Bytes
	} else {
		der = sig.Bytes()
	}
	// Parse signature
	sd, err := cms.ParseSignedData(der)
	if err != nil {
		return errors.Wrap(err, "failed to parse signature")
	}

	// Generate verification options.
	certs, err := sd.GetCertificates()
	if err != nil {
		return errors.Wrap(err, "error getting signature certs")
	}
	opts := x509.VerifyOptions{
		Roots:     fulcioroots.Get(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
		// cosign hack: ignore the current time for now - we'll use the tlog to
		// verify whether the commit was signed at a valid time.
		CurrentTime: certs[0].NotBefore,
	}

	chains, err := sd.VerifyDetached(buf.Bytes(), opts)
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

func verifyTlog(ctx context.Context, commit string, pubKey []byte) (*models.LogEntryAnon, error) {
	rClient, err := rekor.NewClient("https://rekor.sigstore.dev")
	if err != nil {
		fmt.Fprintln(stderr, "error creating rekor client: ", err)
		return nil, err
	}

	//uuids, err := cosign.FindTLogEntriesByPayload(ctx, rClient, []byte(commit))
	uuids, err := findTLogEntriesByPayloadAndPK(ctx, rClient, []byte(commit), pubKey)
	if err != nil {
		return nil, err
	}

	for _, u := range uuids {
		e, err := cosign.GetTlogEntry(ctx, rClient, u)
		if err != nil {
			return nil, err
		}

		if err := cosign.VerifyTLogEntry(ctx, rClient, e); err != nil {
			continue
		}

		// TODO: don't trust rekor response - verify client-side that the
		// public key matches.

		return e, nil
	}

	return nil, errors.New("could not find matching tlog entry")
}

// findTLogEntriesByPayloadAndPK is roughly equivalent to cosign.FindTLogEntriesByPayload,
// but also filters by the public key used.
func findTLogEntriesByPayloadAndPK(ctx context.Context, rekorClient *client.Rekor, payload, pubKey []byte) (uuids []string, err error) {
	params := index.NewSearchIndexParamsWithContext(ctx)
	params.Query = &models.SearchIndex{}

	h := sha256.New()
	h.Write(payload)
	params.Query.Hash = fmt.Sprintf("sha256:%s", strings.ToLower(hex.EncodeToString(h.Sum(nil))))

	params.Query.PublicKey = &models.SearchIndexPublicKey{
		Content: strfmt.Base64(pubKey),
		Format:  swag.String(models.SearchIndexPublicKeyFormatX509),
	}

	searchIndex, err := rekorClient.Index.SearchIndex(params)
	if err != nil {
		return nil, err
	}
	return searchIndex.GetPayload(), nil
}
