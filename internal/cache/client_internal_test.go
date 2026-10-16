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
	"errors"
	"fmt"
	"net/rpc"
	"testing"
)

func TestIsNotFound(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{{
		name: "daemon miss",
		err:  rpc.ServerError(`"host@credential/v1/abc" not found`),
		want: true,
	}, {
		name: "wrapped daemon miss",
		err:  fmt.Errorf("call: %w", rpc.ServerError(`"id" not found`)),
		want: true,
	}, {
		// The daemon's interactive fallback failing must not look like a miss.
		name: "fallback error mentioning not found",
		err:  rpc.ServerError(`error getting new identity: issuer "https://example.com" not found`),
		want: false,
	}, {
		name: "non-RPC error",
		err:  errors.New(`"id" not found`),
		want: false,
	}} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFound(tc.err); got != tc.want {
				t.Errorf("isNotFound(%q) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
