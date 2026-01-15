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

package oid

import (
	"encoding/hex"
	"fmt"

	"github.com/go-openapi/swag/conv"
	v1 "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	rekorpb "github.com/sigstore/protobuf-specs/gen/pb-go/rekor/v1"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// This file contains helper functions from going to/from Rekor types <-> protobuf-specs.
// This may be pulled out into a more general library in the future.

func logEntryAnonToProto(le *models.LogEntryAnon, kind *rekorpb.KindVersion) (*rekorpb.TransparencyLogEntry, error) {
	if le == nil {
		return nil, nil
	}

	logID, err := hex.DecodeString(*le.LogID)
	if err != nil {
		return nil, fmt.Errorf("error decoding LogID: %w", err)
	}

	hashes := make([][]byte, 0, len(le.Verification.InclusionProof.Hashes))
	for i, h := range le.Verification.InclusionProof.Hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			return nil, fmt.Errorf("error decoding Verification.InclusionProof.Hashes[%d]: %w", i, err)
		}
		hashes = append(hashes, b)
	}

	rootHash, err := hex.DecodeString(*le.Verification.InclusionProof.RootHash)
	if err != nil {
		return nil, fmt.Errorf("error decoding Verification.InclusionProof.RootHash: %w", err)
	}

	out := &rekorpb.TransparencyLogEntry{
		LogIndex: *le.LogIndex,
		LogId: &v1.LogId{
			KeyId: logID,
		},
		IntegratedTime: *le.IntegratedTime,
		InclusionPromise: &rekorpb.InclusionPromise{
			SignedEntryTimestamp: le.Verification.SignedEntryTimestamp,
		},
		InclusionProof: &rekorpb.InclusionProof{
			LogIndex: *le.Verification.InclusionProof.LogIndex,
			RootHash: rootHash,
			TreeSize: *le.Verification.InclusionProof.TreeSize,
			Hashes:   hashes,
			Checkpoint: &rekorpb.Checkpoint{
				Envelope: *le.Verification.InclusionProof.Checkpoint,
			},
		},
		KindVersion: kind,
	}

	switch b := le.Body.(type) {
	case string:
		out.CanonicalizedBody = []byte(b)
	default:
		return nil, fmt.Errorf("unknown body type %T", le.Body)
	}
	return out, nil
}

func logEntryAnonFromProto(in *rekorpb.TransparencyLogEntry) *models.LogEntryAnon {
	out := &models.LogEntryAnon{
		LogID:          conv.Pointer(hex.EncodeToString(in.GetLogId().GetKeyId())),
		LogIndex:       conv.Pointer(in.GetLogIndex()),
		IntegratedTime: conv.Pointer(in.GetIntegratedTime()),
		Verification: &models.LogEntryAnonVerification{
			SignedEntryTimestamp: in.GetInclusionPromise().GetSignedEntryTimestamp(),
			InclusionProof: &models.InclusionProof{
				LogIndex:   conv.Pointer(in.GetInclusionProof().GetLogIndex()),
				Checkpoint: conv.Pointer(in.GetInclusionProof().GetCheckpoint().GetEnvelope()),
				TreeSize:   conv.Pointer(in.GetInclusionProof().GetTreeSize()),
				RootHash:   conv.Pointer(hex.EncodeToString(in.GetInclusionProof().GetRootHash())),
				Hashes:     make([]string, 0, len(in.GetInclusionProof().GetHashes())),
			},
		},
		Body: string(in.GetCanonicalizedBody()),
	}
	for _, h := range in.GetInclusionProof().GetHashes() {
		out.Verification.InclusionProof.Hashes = append(out.Verification.InclusionProof.Hashes, hex.EncodeToString(h))
	}
	return out
}
