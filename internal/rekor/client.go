// Copyright 2022 The Sigstore Authors
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

package rekor

import (
	"context"

	gitrekor "github.com/sigstore/gitsign/pkg/rekor"
	rekor "github.com/sigstore/rekor/pkg/client"
)

// NewClient returns a new Rekor client with common client options set.
//
// Deprecated: Use NewClientContext instead.
func NewClient(url string) (*gitrekor.Client, error) {
	return NewClientContext(context.TODO(), url)
}

// NewClientContext returns a new Rekor client with common client options set.
func NewClientContext(ctx context.Context, url string) (*gitrekor.Client, error) {
	return gitrekor.NewWithOptions(ctx, url, gitrekor.WithClientOption(rekor.WithUserAgent("gitsign")))
}
