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

package version // nolint:revive

import (
	"os"
	"runtime/debug"
	"strings"
)

// Base version information.
//
// This is the fallback data used when version information from git is not
// provided via go ldflags.
var (
	// Output of "git describe". The prerequisite is that the
	// branch should be tagged using the correct versioning strategy.
	gitVersion = "devel"

	envVarPrefixes = []string{
		"GITSIGN_",
		// Can modify Sigstore/TUF client behavior - https://github.com/sigstore/sigstore/blob/35d6a82c15183f7fe7a07eca45e17e378aa32126/pkg/tuf/client.go#L52
		"SIGSTORE_",
		"TUF_",
	}
)

type Info struct {
	GitVersion string   `json:"gitVersion"`
	Env        []string `json:"env"`
}

func getBuildInfo() *debug.BuildInfo {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}
	return bi
}

func getGitVersion(bi *debug.BuildInfo) string {
	if bi == nil {
		return "unknown"
	}

	// https://github.com/golang/go/issues/29228
	if bi.Main.Version == "(devel)" || bi.Main.Version == "" {
		return gitVersion
	}

	return bi.Main.Version
}

func getGitsignEnv() []string {
	out := []string{}
	for _, e := range os.Environ() {
		// Prefixes to look for. err on the side of showing too much rather
		// than too little. We'll only output things that have values set.
		for _, prefix := range envVarPrefixes {
			if strings.HasPrefix(e, prefix) {
				eComponents := strings.Split(strings.TrimSpace(e), "=")
				if len(eComponents) == 1 || len(eComponents[1]) == 0 {
					// The variable is set to nothing
					// eg: SIGSTORE_ROOT_FILE=
					continue
				}
				out = append(out, e)
			}
		}
	}
	return out
}

// GetVersionInfo represents known information on how this binary was built.
func GetVersionInfo() Info {
	buildInfo := getBuildInfo()
	gitVersion = getGitVersion(buildInfo)
	return Info{
		GitVersion: gitVersion,
		Env:        getGitsignEnv(),
	}
}
