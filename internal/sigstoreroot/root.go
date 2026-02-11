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

// Package sigstoreroot loads the Sigstore trusted root via the sigstore-go TUF client.
package sigstoreroot

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	sigstoretuf "github.com/sigstore/sigstore/pkg/tuf"
)

// TUFOptions returns sigstore-go TUF options, reading the mirror URL from remote.json if available.
func TUFOptions() *tuf.Options {
	opts := tuf.DefaultOptions()
	if mirror, err := readRemoteHint(opts.CachePath); err == nil && mirror != "" {
		opts.RepositoryBaseURL = mirror
	}
	return opts
}

// FetchTrustedRoot loads the Sigstore trusted root from the TUF cache.
func FetchTrustedRoot() (*root.TrustedRoot, error) {
	return root.FetchTrustedRootWithOptions(TUFOptions())
}

// GetCTLogPubs returns CT log public keys from the trusted root.
func GetCTLogPubs(trustedRoot *root.TrustedRoot) (*cosign.TrustedTransparencyLogPubKeys, error) {
	return transparencyLogPubKeys(trustedRoot.CTLogs())
}

// GetRekorPubs returns Rekor transparency log public keys from the trusted root.
func GetRekorPubs(trustedRoot *root.TrustedRoot) (*cosign.TrustedTransparencyLogPubKeys, error) {
	return transparencyLogPubKeys(trustedRoot.RekorLogs())
}

// FulcioCertificates extracts Fulcio root and intermediate certificates from the trusted root.
func FulcioCertificates(trustedRoot *root.TrustedRoot) ([]*x509.Certificate, error) {
	cas := trustedRoot.FulcioCertificateAuthorities()
	if len(cas) == 0 {
		return nil, fmt.Errorf("no Fulcio certificate authorities found in trusted root")
	}

	var certs []*x509.Certificate
	for _, ca := range cas {
		fca, ok := ca.(*root.FulcioCertificateAuthority)
		if !ok {
			continue
		}
		if fca.Root != nil {
			certs = append(certs, fca.Root)
		}
		certs = append(certs, fca.Intermediates...)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no Fulcio certificates found in trusted root")
	}
	return certs, nil
}

func transparencyLogPubKeys(logs map[string]*root.TransparencyLog) (*cosign.TrustedTransparencyLogPubKeys, error) {
	pubKeys := cosign.NewTrustedTransparencyLogPubKeys()

	for logID, log := range logs {
		if log.PublicKey == nil {
			continue
		}

		status := sigstoretuf.Active
		if !log.ValidityPeriodEnd.IsZero() && time.Now().After(log.ValidityPeriodEnd) {
			status = sigstoretuf.Expired
		}

		pubKeys.Keys[logID] = cosign.TransparencyLogPubKey{
			PubKey: log.PublicKey,
			Status: status,
		}
	}

	if len(pubKeys.Keys) == 0 {
		return nil, fmt.Errorf("no transparency log public keys found")
	}
	return &pubKeys, nil
}

func readRemoteHint(cachePath string) (string, error) {
	data, err := os.ReadFile(filepath.Join(cachePath, "remote.json"))
	if err != nil {
		return "", err
	}
	var remote struct {
		Mirror string `json:"mirror"`
	}
	if err := json.Unmarshal(data, &remote); err != nil {
		return "", err
	}
	return remote.Mirror, nil
}
