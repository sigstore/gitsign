//
// Copyright 2023 The Sigstore Authors.
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

package rekor

import (
	"context"

	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/rekor/pkg/client"
)

type Option func(*options)

type options struct {
	rekorPublicKeys CosignRekorKeyProvider
	clientOpts      []client.Option
}

// CosignRekorKeyProvider is a function that returns the Rekor public keys in cosign's specialized format.
type CosignRekorKeyProvider func(ctx context.Context) (*cosign.TrustedTransparencyLogPubKeys, error)

func WithCosignRekorKeyProvider(f CosignRekorKeyProvider) Option {
	return func(o *options) {
		o.rekorPublicKeys = f
	}
}

func WithClientOption(opts ...client.Option) Option {
	return func(o *options) {
		o.clientOpts = opts
	}
}
