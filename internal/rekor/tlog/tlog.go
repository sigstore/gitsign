//
// Copyright 2026 The Sigstore Authors.
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

// Package tlog implements uploading to and fetching from a Rekor v1
// transparency log.
//
// These helpers used to live in github.com/sigstore/cosign/v3/pkg/cosign
// (TLogUpload, TLogUploadInTotoAttestation, GetTlogEntry), which dropped them
// in v3.1.0 as part of moving signing over to the Sigstore bundle format.
// Gitsign still writes Rekor v1 entries directly, so they live here now.
package tlog

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/go-openapi/strfmt"
	"github.com/go-openapi/swag/conv"
	"github.com/sigstore/cosign/v3/pkg/cosign"
	"github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/sharding"
	"github.com/sigstore/rekor/pkg/types"
	hashedrekord_v001 "github.com/sigstore/rekor/pkg/types/hashedrekord/v0.0.1"
	"github.com/sigstore/rekor/pkg/types/intoto"
	intoto_v001 "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	"github.com/sigstore/sigstore/pkg/tuf"
)

// Upload uploads a hashedrekord entry for the signature over a message with the
// given SHA-256 checksum, signed by the certificate in pemBytes.
func Upload(ctx context.Context, rekorClient *client.Rekor, signature []byte, sha256Checksum hash.Hash, pemBytes []byte) (*models.LogEntryAnon, error) {
	e := hashedRekordEntry(sha256Checksum, signature, pemBytes)
	return upload(ctx, rekorClient, &models.Hashedrekord{
		APIVersion: conv.Pointer(e.APIVersion()),
		Spec:       e.HashedRekordObj,
	})
}

// UploadInTotoAttestation uploads an intoto entry for the given DSSE envelope,
// signed by the certificate in pemBytes.
func UploadInTotoAttestation(ctx context.Context, rekorClient *client.Rekor, signature, pemBytes []byte) (*models.LogEntryAnon, error) {
	if len(pemBytes) == 0 {
		return nil, errors.New("public key provided has 0 length")
	}
	pe, err := types.NewProposedEntry(ctx, intoto.KIND, intoto_v001.APIVERSION, types.ArtifactProperties{
		ArtifactBytes:  signature,
		PublicKeyBytes: [][]byte{pemBytes},
	})
	if err != nil {
		return nil, err
	}
	return upload(ctx, rekorClient, pe)
}

// GetEntry fetches the log entry for the given UUID (or shard-prefixed entry
// ID), checking that the server returned the entry that was asked for.
func GetEntry(ctx context.Context, rekorClient *client.Rekor, entryUUID string) (*models.LogEntryAnon, error) {
	params := entries.NewGetLogEntryByUUIDParamsWithContext(ctx)
	params.SetEntryUUID(entryUUID)
	resp, err := rekorClient.Entries.GetLogEntryByUUID(params)
	if err != nil {
		return nil, err
	}
	for k, e := range resp.Payload {
		// Validate that the requested entry UUID matches the response UUID and
		// response shard ID.
		if err := checkExpectedUUID(entryUUID, k); err != nil {
			return nil, fmt.Errorf("unexpected entry returned from rekor server: %w", err)
		}
		// Check that the body hash matches the UUID.
		if err := verifyUUID(k, e); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, errors.New("empty response")
}

func upload(ctx context.Context, rekorClient *client.Rekor, pe models.ProposedEntry) (*models.LogEntryAnon, error) {
	params := entries.NewCreateLogEntryParamsWithContext(ctx)
	params.SetProposedEntry(pe)
	resp, err := rekorClient.Entries.CreateLogEntry(params)
	if err != nil {
		// If the entry already exists we get a specific error back. Fetch the
		// existing entry, verify its inclusion proof, and succeed.
		var existsErr *entries.CreateLogEntryConflict
		if errors.As(err, &existsErr) {
			fmt.Fprintln(os.Stderr, "Signature already exists. Fetching and verifying inclusion proof.") // nolint:errcheck
			uriSplit := strings.Split(existsErr.Location.String(), "/")
			uuid := uriSplit[len(uriSplit)-1]
			e, err := GetEntry(ctx, rekorClient, uuid)
			if err != nil {
				return nil, err
			}
			pubs, err := pubsFromClient(rekorClient)
			if err != nil {
				return nil, err
			}
			return e, cosign.VerifyTLogEntryOffline(ctx, e, pubs, nil)
		}
		return nil, err
	}
	for _, p := range resp.Payload {
		return &p, nil
	}
	return nil, errors.New("bad response from server")
}

func hashedRekordEntry(checksum hash.Hash, signature, pubKey []byte) hashedrekord_v001.V001Entry {
	return hashedrekord_v001.V001Entry{
		HashedRekordObj: models.HashedrekordV001Schema{
			Data: &models.HashedrekordV001SchemaData{
				Hash: &models.HashedrekordV001SchemaDataHash{
					Algorithm: conv.Pointer(models.HashedrekordV001SchemaDataHashAlgorithmSha256),
					Value:     conv.Pointer(hex.EncodeToString(checksum.Sum(nil))),
				},
			},
			Signature: &models.HashedrekordV001SchemaSignature{
				Content: strfmt.Base64(signature),
				PublicKey: &models.HashedrekordV001SchemaSignaturePublicKey{
					Content: strfmt.Base64(pubKey),
				},
			},
		},
	}
}

// pubsFromClient fetches the Rekor public key from Rekor itself.
//
// NOTE: This **must not** be used in the verification path, but may be used in
// the sign path to check that responses from Rekor are self-consistent.
func pubsFromClient(rekorClient *client.Rekor) (*cosign.TrustedTransparencyLogPubKeys, error) {
	publicKeys := cosign.NewTrustedTransparencyLogPubKeys()
	pubOK, err := rekorClient.Pubkey.GetPublicKey(nil)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch rekor public key from rekor: %w", err)
	}
	if err := publicKeys.AddTransparencyLogPubKey([]byte(pubOK.Payload), tuf.Active); err != nil {
		return nil, fmt.Errorf("constructRekorPubKey: %w", err)
	}
	return &publicKeys, nil
}

// checkExpectedUUID validates that the response UUID - and the shard, if both
// IDs carry one - match what was requested.
func checkExpectedUUID(requestEntryUUID, responseEntryUUID string) error {
	requestUUID, err := sharding.GetUUIDFromIDString(requestEntryUUID)
	if err != nil {
		return err
	}
	responseUUID, err := sharding.GetUUIDFromIDString(responseEntryUUID)
	if err != nil {
		return err
	}
	if requestUUID != responseUUID {
		return fmt.Errorf("expected EntryUUID %s got UUID %s", requestEntryUUID, responseEntryUUID)
	}

	requestShardID, err := shardID(requestEntryUUID)
	if err != nil {
		return err
	}
	responseShardID, err := shardID(responseEntryUUID)
	if err != nil {
		return err
	}
	// No shard ID prepends the entry UUID, so there's nothing to compare.
	if requestShardID == "" || responseShardID == "" {
		return nil
	}
	if requestShardID != responseShardID {
		return fmt.Errorf("expected UUID %s from shard %s: got UUID %s from shard %s", requestEntryUUID, requestShardID, responseEntryUUID, responseShardID)
	}
	return nil
}

// shardID returns the tree ID prefixed to an entry ID, or the empty string for
// a bare UUID.
func shardID(entryUUID string) (string, error) {
	id, err := sharding.GetTreeIDFromIDString(entryUUID)
	switch {
	case errors.Is(err, sharding.ErrPlainUUID):
		return "", nil
	case err != nil:
		return "", err
	}
	return id, nil
}

// verifyUUID checks that the entry UUID is the Merkle leaf hash of the entry body.
func verifyUUID(entryUUID string, e models.LogEntryAnon) error {
	uid, err := sharding.GetUUIDFromIDString(entryUUID)
	if err != nil {
		return err
	}
	uuid, err := hex.DecodeString(uid)
	if err != nil {
		return err
	}

	computedLeafHash, err := cosign.ComputeLeafHash(&e)
	if err != nil {
		return err
	}
	if !bytes.Equal(computedLeafHash, uuid) {
		return errors.New("computed leaf hash did not match UUID")
	}
	return nil
}
