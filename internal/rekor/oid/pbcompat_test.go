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
	"encoding/json"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/sigstore/rekor/pkg/generated/models"
)

// Simple test to make sure we can go to/from rekor types to proto types.
func TestConvert(t *testing.T) {
	in := new(models.LogEntryAnon)
	json.Unmarshal(readfile(t, "testdata/tlog.json"), in)

	// Kind is useful debug information, but isn't really used by us since we assume input/output types.
	pb, err := logEntryAnonToProto(in, nil)
	if err != nil {
		t.Fatalf("logEntryAnonToProto(): %v", err)
	}

	out := logEntryAnonFromProto(pb)

	if diff := cmp.Diff(in, out); diff != "" {
		t.Error(diff)
	}
}
