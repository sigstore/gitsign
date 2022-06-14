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

package version

import (
	"runtime/debug"
)

// Base version information.
//
// This is the fallback data used when version information from git is not
// provided via go ldflags.
var (
	// Output of "git describe". The prerequisite is that the
	// branch should be tagged using the correct versioning strategy.
	gitVersion = "devel"
)

type Info struct {
	GitVersion string `json:"gitVersion"`
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

// GetVersionInfo represents known information on how this binary was built.
func GetVersionInfo() Info {
	buildInfo := getBuildInfo()
	gitVersion = getGitVersion(buildInfo)
	return Info{
		GitVersion: gitVersion,
	}
}
