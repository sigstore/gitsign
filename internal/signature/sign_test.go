// Copyright 2023 The Sigstore Authors
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

package signature

import (
	"crypto/x509"
	"net/url"
	"testing"
)

func TestMatchSAN(t *testing.T) {
	for _, tc := range []struct {
		testname string
		cert     *x509.Certificate
		name     string
		email    string
		want     bool
	}{
		{
			testname: "email match",
			cert: &x509.Certificate{
				EmailAddresses: []string{"foo@example.com"},
			},
			name:  "Foo Bar",
			email: "foo@example.com",
			want:  true,
		},
		{
			testname: "uri match",
			cert: &x509.Certificate{
				URIs: []*url.URL{parseURL("https://github.com/foo/bar")},
			},
			name:  "https://github.com/foo/bar",
			email: "foo@example.com",
			want:  true,
		},
		{
			testname: "no match",
			cert:     &x509.Certificate{},
			name:     "https://github.com/foo/bar",
			email:    "foo@example.com",
			want:     false,
		},
	} {
		t.Run(tc.testname, func(t *testing.T) {
			got := matchSAN(tc.cert, tc.name, tc.email)
			if got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
}

func parseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
