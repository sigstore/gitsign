// Copyright 2026 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cache

import (
	"testing"
	"time"

	"github.com/github/smimesign/fakeca"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func TestValidateCert(t *testing.T) {
	ca := fakeca.New(fakeca.IsCA)
	leaf := ca.Issue()
	leafPEM, err := cryptoutils.MarshalCertificateToPEM(leaf.Certificate)
	if err != nil {
		t.Fatal(err)
	}

	if err := ValidateCert(leafPEM, ca.ChainPool(), nil); err != nil {
		t.Errorf("ValidateCert(valid): %v", err)
	}

	// Wrong roots.
	other := fakeca.New(fakeca.IsCA)
	if err := ValidateCert(leafPEM, other.ChainPool(), nil); err == nil {
		t.Error("ValidateCert(wrong roots): expected error")
	}

	// Expired cert.
	expired := ca.Issue(
		fakeca.NotBefore(time.Now().Add(-2*time.Hour)),
		fakeca.NotAfter(time.Now().Add(-time.Hour)),
	)
	expiredPEM, err := cryptoutils.MarshalCertificateToPEM(expired.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCert(expiredPEM, ca.ChainPool(), nil); err == nil {
		t.Error("ValidateCert(expired): expected error")
	}

	// Cert expiring within the 30s window is rejected.
	almostExpired := ca.Issue(
		fakeca.NotBefore(time.Now().Add(-time.Hour)),
		fakeca.NotAfter(time.Now().Add(10*time.Second)),
	)
	almostExpiredPEM, err := cryptoutils.MarshalCertificateToPEM(almostExpired.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateCert(almostExpiredPEM, ca.ChainPool(), nil); err == nil {
		t.Error("ValidateCert(almost expired): expected error")
	}

	// Garbage input.
	if err := ValidateCert([]byte("not a cert"), ca.ChainPool(), nil); err == nil {
		t.Error("ValidateCert(garbage): expected error")
	}
}
