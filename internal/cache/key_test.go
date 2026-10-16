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

	"github.com/sigstore/gitsign/internal/config"
)

func TestCredentialKey(t *testing.T) {
	base := func() *config.Config {
		return &config.Config{
			Fulcio:         "https://fulcio.example.com",
			Issuer:         "https://oauth2.example.com/auth",
			ClientID:       "sigstore",
			ConnectorID:    "connector",
			CommitterEmail: "user@example.com",
		}
	}

	// Golden value guards against accidental changes to the key derivation -
	// changing it silently orphans users' existing cache entries.
	const want = "credential/v1/9d2bd6aace24024e8f5a7b3472ce2f1a074883aa6fd8bab989692fc18c57f931"
	if got := CredentialKey(base()); got != want {
		t.Errorf("CredentialKey changed:\nwant %s\ngot  %s", want, got)
	}

	// Each config field contributes to the key.
	mutations := []func(*config.Config){
		func(c *config.Config) { c.Fulcio = "other" },
		func(c *config.Config) { c.Issuer = "other" },
		func(c *config.Config) { c.ClientID = "other" },
		func(c *config.Config) { c.ConnectorID = "other" },
		func(c *config.Config) { c.CommitterEmail = "other" },
	}
	seen := map[string]bool{CredentialKey(base()): true}
	for i, mutate := range mutations {
		cfg := base()
		mutate(cfg)
		key := CredentialKey(cfg)
		if seen[key] {
			t.Errorf("mutation %d did not change the key", i)
		}
		seen[key] = true
	}

	// A nil config must not panic.
	if CredentialKey(nil) == CredentialKey(base()) {
		t.Error("nil config key should differ from populated config key")
	}
}
