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
	"crypto/x509"
	"fmt"

	"github.com/sigstore/gitsign/internal/fulcio"
	"github.com/sigstore/gitsign/internal/signature"
	"github.com/sigstore/gitsign/pkg/git"
	"github.com/sigstore/gitsign/pkg/rekor"
)

func Sign(ctx context.Context, rekor rekor.Writer, ident *fulcio.Identity, data []byte, opts signature.SignOptions) ([]byte, *x509.Certificate, error) {
	sig, cert, err := signature.Sign(ident, data, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// This uploads the commit SHA + sig(commit SHA) to the tlog using the same
	// key used to sign the commit data itself.
	// Since the commit SHA ~= hash(commit data + sig(commit data)) and we're
	// using the same key, this is probably okay? e.g. even if you could cause a SHA1 collision,
	// you would still need the underlying commit to be valid and using the same key which seems hard.

	commit, err := git.ObjectHash(data, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("error generating commit hash: %w", err)
	}

	sv := ident.SignerVerifier()
	commitSig, err := sv.SignMessage(bytes.NewBufferString(commit))
	if err != nil {
		return nil, nil, fmt.Errorf("error signing commit hash: %w", err)
	}
	if _, err := rekor.Write(ctx, commit, commitSig, cert); err != nil {
		return nil, nil, fmt.Errorf("error uploading tlog (commit): %w", err)
	}

	return sig, cert, nil
}
