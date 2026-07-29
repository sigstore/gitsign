//
// Copyright 2024 The Sigstore Authors.
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

package fulcio

import (
	"fmt"
	"os/exec"
	"strings"
	"text/template"

	"github.com/pkg/browser"
)

// newCommandURLOpener builds a browser-opener function that runs a user-provided
// command to open the login URL. The command is split into a program and its
// arguments using shell-style word splitting (so quoting can be used to keep
// arguments containing spaces together), and each resulting token is rendered
// as a Go text/template with the URL exposed as {{.URL}}.
//
// The command is NOT executed via a shell - the split tokens are passed
// directly to exec, so shell metacharacters (pipes, redirects, globbing,
// substitution) are inert and there is no shell injection to reason about.
//
// The returned function is suitable for use with
// oauthflow.WithBrowserOpener.
func newCommandURLOpener(command string) (func(url string) error, error) {
	// Validate the template up front so misconfiguration fails before we start
	// the auth flow rather than at browser-open time.
	if _, err := renderURLOpenerCommand(command, ""); err != nil {
		return nil, err
	}

	return func(u string) error {
		args, err := renderURLOpenerCommand(command, u)
		if err != nil {
			return err
		}

		cmd := exec.Command(args[0], args[1:]...) // #nosec G204 -- command is operator-configured local git config
		// Reuse the same output streams the default browser opener is wired to
		// so we don't pollute stdout/stderr used for the signing protocol.
		cmd.Stdout = browser.Stdout
		cmd.Stderr = browser.Stderr
		return cmd.Run()
	}, nil
}

// renderURLOpenerCommand splits command using shell-style word splitting and
// renders each token as a text/template with the login URL available as
// {{.URL}}, returning the resulting argv. It also validates that the command is
// non-empty and actually references the URL, so it doubles as configuration
// validation.
func renderURLOpenerCommand(command, u string) ([]string, error) {
	if strings.ContainsAny(command, "\n\r") {
		return nil, fmt.Errorf("gitsign.urlOpener command %q must not contain newline or carriage return characters", command)
	}

	fields, err := splitCommand(command)
	if err != nil {
		return nil, fmt.Errorf("parsing gitsign.urlOpener command %q: %w", command, err)
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("gitsign.urlOpener is empty")
	}

	data := struct{ URL string }{URL: u}
	args := make([]string, len(fields))
	hasURL := false
	for i, f := range fields {
		t, err := template.New("urlOpener").Option("missingkey=error").Parse(f)
		if err != nil {
			return nil, fmt.Errorf("parsing gitsign.urlOpener command %q: %w", command, err)
		}
		if strings.Contains(f, "{{") {
			hasURL = true
		}
		var b strings.Builder
		if err := t.Execute(&b, data); err != nil {
			return nil, fmt.Errorf("rendering gitsign.urlOpener command %q: %w", command, err)
		}
		args[i] = b.String()
	}
	if !hasURL {
		return nil, fmt.Errorf("gitsign.urlOpener command %q does not reference the {{.URL}} template argument", command)
	}

	return args, nil
}

// splitCommand splits s into tokens using simple shell-like word splitting:
// runs of whitespace separate tokens, and single or double quotes group text
// (including whitespace) into a single token. The surrounding quote characters
// are removed, and a quote of one kind is treated literally inside the other
// kind. Backslashes are treated literally (not as escape characters) so that
// Windows-style paths work without doubling. An unterminated quote is an error.
func splitCommand(s string) ([]string, error) {
	var args []string
	var cur strings.Builder
	inToken := false
	var quote rune // 0 when not in a quote, otherwise the opening quote rune

	flush := func() {
		args = append(args, cur.String())
		cur.Reset()
		inToken = false
	}

	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
		case r == '\'' || r == '"':
			quote = r
			inToken = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			if inToken {
				flush()
			}
		default:
			cur.WriteRune(r)
			inToken = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated %c quote", quote)
	}
	if inToken {
		flush()
	}
	return args, nil
}
