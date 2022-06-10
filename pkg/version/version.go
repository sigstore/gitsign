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
	"fmt"
	"runtime"
	"runtime/debug"
	"time"
)

const unknown = "unknown"

// Base version information.
//
// This is the fallback data used when version information from git is not
// provided via go ldflags.
var (
	// Output of "git describe". The prerequisite is that the
	// branch should be tagged using the correct versioning strategy.
	gitVersion = "devel"
	// SHA1 from git, output of $(git rev-parse HEAD)
	gitCommit = unknown
	// State of git tree, either "clean" or "dirty"
	gitTreeState = unknown
	// Build date in ISO8601 format, output of $(date -u +'%Y-%m-%dT%H:%M:%SZ')
	buildDate = unknown
)

type Info struct {
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

func init() {
	buildInfo := getBuildInfo()
	gitVersion = getGitVersion(buildInfo)
	gitCommit = getCommit(buildInfo)
	gitTreeState = getDirty(buildInfo)
	buildDate = getBuildDate(buildInfo)
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
		return unknown
	}

	// https://github.com/golang/go/issues/29228
	if bi.Main.Version == "(devel)" || bi.Main.Version == "" {
		return gitVersion
	}

	return bi.Main.Version
}

func getCommit(bi *debug.BuildInfo) string {
	return getKey(bi, "vcs.revision")
}

func getDirty(bi *debug.BuildInfo) string {
	modified := getKey(bi, "vcs.modified")
	if modified == "true" {
		return "dirty"
	}
	if modified == "false" {
		return "clean"
	}
	return unknown
}

func getBuildDate(bi *debug.BuildInfo) string {
	buildTime := getKey(bi, "vcs.time")
	t, err := time.Parse("2006-01-02T15:04:05Z", buildTime)
	if err != nil {
		return unknown
	}
	return t.Format("2006-01-02T15:04:05")
}

func getKey(bi *debug.BuildInfo, key string) string {
	if bi == nil {
		return unknown
	}
	for _, iter := range bi.Settings {
		if iter.Key == key {
			return iter.Value
		}
	}
	return unknown
}

// GetVersionInfo represents known information on how this binary was built.
func GetVersionInfo() Info {
	return Info{
		GitVersion:   gitVersion,
		GitCommit:    gitCommit,
		GitTreeState: gitTreeState,
		BuildDate:    buildDate,
		GoVersion:    runtime.Version(),
		Compiler:     runtime.Compiler,
		Platform:     fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
	}
}
