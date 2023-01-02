//
// Copyright 2022 The Sigstore Authors.
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

package git

import (
	"bytes"
	"context"
	"fmt"

	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/gitsign/pkg/rekor"
)

func Sign(ctx context.Context, rekor rekor.Writer, ident *fulcio.Identity, data []byte, opts signature.SignOptions) (*signature.SignResponse, error) {
	resp, err := signature.Sign(ctx, ident, data, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// We're using offline verification style signing - nothing more to do.
	if resp.LogEntry != nil {
		return resp, nil
	}

	// Legacy SHA based signing - only do if we didn't get a tlog entry back.

	// This uploads the commit SHA + sig(commit SHA) to the tlog using the same
	// key used to sign the commit data itself.
	// Since the commit SHA ~= hash(commit data + sig(commit data)) and we're
	// using the same key, this is probably okay? e.g. even if you could cause a SHA1 collision,
	// you would still need the underlying commit to be valid and using the same key which seems hard.

	commit, err := git.ObjectHash(data, resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("error generating commit hash: %w", err)
	}

	sv, err := ident.SignerVerifier()
	if err != nil {
		return nil, fmt.Errorf("error getting signer: %w", err)
	}
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		return nil, fmt.Errorf("error signing commit hash: %w", err)
	}
	resp.LogEntry, err = rekor.Write(ctx, commit, commitSig, resp.Cert)
	if err != nil {
		return nil, fmt.Errorf("error uploading tlog (commit): %w", err)
	}

	return resp, nil
}
