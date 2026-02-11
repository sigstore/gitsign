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

//go:build e2e
// +build e2e

package e2e

import (
	"testing"

	"github.com/sigstore/gitsign/internal/sigstoreroot"
)

func TestFetchTrustedRoot(t *testing.T) {
	trustedRoot, err := sigstoreroot.FetchTrustedRoot()
	if err != nil {
		t.Fatalf("FetchTrustedRoot() error = %v", err)
	}
	if trustedRoot == nil {
		t.Fatal("FetchTrustedRoot() returned nil")
	}

	ctPubs, err := sigstoreroot.GetCTLogPubs(trustedRoot)
	if err != nil {
		t.Fatalf("GetCTLogPubs() error = %v", err)
	}
	if len(ctPubs.Keys) == 0 {
		t.Fatal("GetCTLogPubs() returned no keys")
	}

	rekorPubs, err := sigstoreroot.GetRekorPubs(trustedRoot)
	if err != nil {
		t.Fatalf("GetRekorPubs() error = %v", err)
	}
	if len(rekorPubs.Keys) == 0 {
		t.Fatal("GetRekorPubs() returned no keys")
	}

	certs, err := sigstoreroot.FulcioCertificates(trustedRoot)
	if err != nil {
		t.Fatalf("FulcioCertificates() error = %v", err)
	}
	if len(certs) == 0 {
		t.Fatal("FulcioCertificates() returned no certificates")
	}

	hasCA := false
	for _, cert := range certs {
		if cert.IsCA {
			hasCA = true
			break
		}
	}
	if !hasCA {
		t.Fatal("FulcioCertificates() did not return any CA certificates")
	}
}
