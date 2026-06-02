//
// Copyright 2024 The Sigstore Authors.
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

package gitsign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/gitsign/internal/config"
	"github.com/sigstore/gitsign/internal/fulcio/fulcioroots"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

// buildTrustedMaterial assembles a sigstore-go root.TrustedMaterial from
// gitsign's existing trust sources, so the bundle verification path makes the
// same trust decisions as the legacy path:
//   - Fulcio certificate authorities from fulcioroots (TUF or cfg.FulcioRoot).
//   - Rekor logs from the supplied transparency log public keys.
//   - CT logs from cosign's CT log public keys (used for SCT verification).
//
// rekorPubs are the keys the Rekor client was constructed with (see
// pkg/rekor.Client.PublicKeys), keyed by log ID hex - the same keying
// sigstore-go uses to look up a log from a TransparencyLogEntry. ctPubs are the
// CT log keys used for SCT verification; pass nil when SCTs are not required.
func buildTrustedMaterial(ctx context.Context, cfg *config.Config, rekorPubs, ctPubs *cosign.TrustedTransparencyLogPubKeys) (root.TrustedMaterial, error) {
	fulcioRoots, fulcioIntermediates, err := fulcioroots.CertsFromConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("loading fulcio roots: %w", err)
	}
	if len(fulcioRoots) == 0 {
		return nil, fmt.Errorf("no fulcio root certificates found")
	}

	// One CertificateAuthority per root. Validity windows are left zero: the
	// per-certificate NotBefore/NotAfter are enforced by x509 chain verification
	// against the observer timestamp inside FulcioCertificateAuthority.Verify.
	cas := make([]root.CertificateAuthority, 0, len(fulcioRoots))
	for _, r := range fulcioRoots {
		cas = append(cas, &root.FulcioCertificateAuthority{
			Root:          r,
			Intermediates: fulcioIntermediates,
			URI:           cfg.Fulcio,
		})
	}

	rekorLogs := transparencyLogs(rekorPubs, cfg.Rekor)
	ctLogs := transparencyLogs(ctPubs, "")

	tsas, err := timestampAuthorities(cfg)
	if err != nil {
		return nil, fmt.Errorf("building timestamp authorities: %w", err)
	}

	return root.NewTrustedRoot(root.TrustedRootMediaType01, cas, ctLogs, tsas, rekorLogs)
}

// timestampAuthorities builds the RFC3161 timestamping authorities from
// cfg.TimestampCert. Unlike the legacy path, which trusts the system
// certificate pool for TSA roots, the bundle path only trusts an explicitly
// configured TSA certificate - sigstore-go models a timestamping authority as a
// specific chain rather than a pool. When no TSA cert is configured, no
// authorities are returned and a signature carrying an RFC3161 timestamp will
// fail to verify (fail closed) rather than have the timestamp silently ignored.
func timestampAuthorities(cfg *config.Config) ([]root.TimestampingAuthority, error) {
	if cfg.TimestampCert == "" {
		return nil, nil
	}

	b, err := os.ReadFile(cfg.TimestampCert) // nolint:gosec
	if err != nil {
		return nil, err
	}
	certs, err := cryptoutils.UnmarshalCertificatesFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("loading certs from %s: %w", cfg.TimestampCert, err)
	}

	var roots, intermediates []*x509.Certificate
	for _, cert := range certs {
		if bytes.Equal(cert.RawSubject, cert.RawIssuer) {
			roots = append(roots, cert)
		} else {
			intermediates = append(intermediates, cert)
		}
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("timestamp certificate %s must include a root CA", cfg.TimestampCert)
	}

	// One authority per root, each able to chain through the provided
	// intermediates. The leaf (TSA signing cert) is taken from the timestamp
	// token itself at verification time.
	tsas := make([]root.TimestampingAuthority, 0, len(roots))
	for _, r := range roots {
		tsas = append(tsas, &root.SigstoreTimestampingAuthority{
			Root:          r,
			Intermediates: intermediates,
		})
	}
	return tsas, nil
}

// transparencyLogs converts cosign transparency log public keys (keyed by log
// ID hex) into the map sigstore-go's TrustedMaterial expects. gitsign targets
// Rekor v1 / CT v1, both of which use SHA-256 for the Merkle tree and ECDSA
// (P-256) over SHA-256 for signatures.
func transparencyLogs(pubs *cosign.TrustedTransparencyLogPubKeys, baseURL string) map[string]*root.TransparencyLog {
	logs := map[string]*root.TransparencyLog{}
	if pubs == nil {
		return logs
	}
	for id, key := range pubs.Keys {
		idBytes, err := hex.DecodeString(id)
		if err != nil {
			// cosign keys these by hex log ID; a non-hex key would be a bug in
			// the source, not something to verify against, so skip it.
			continue
		}
		logs[id] = &root.TransparencyLog{
			BaseURL:           baseURL,
			ID:                idBytes,
			HashFunc:          crypto.SHA256,
			PublicKey:         key.PubKey,
			SignatureHashFunc: crypto.SHA256,
			// cosign's transparency log public keys carry no validity window,
			// and gitsign (like cosign) trusts the configured key for any entry
			// regardless of time. sigstore-go's SET verification requires a
			// non-zero start, so use the Unix epoch as an open lower bound; the
			// upper bound is left zero (unbounded).
			ValidityPeriodStart: time.Unix(0, 0),
		}
	}
	return logs
}
