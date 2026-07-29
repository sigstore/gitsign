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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestRenderURLOpenerCommand(t *testing.T) {
	const url = "https://oauth2.sigstore.dev/auth?code=abc123"

	for _, tc := range []struct {
		name    string
		command string
		want    []string
		wantErr bool
	}{
		{
			name:    "simple",
			command: "firefox {{.URL}}",
			want:    []string{"firefox", url},
		},
		{
			name:    "with flags",
			command: "firefox --new-tab {{.URL}}",
			want:    []string{"firefox", "--new-tab", url},
		},
		{
			name:    "url not last arg",
			command: "open -a {{.URL}} Safari",
			want:    []string{"open", "-a", url, "Safari"},
		},
		{
			name:    "url embedded in field",
			command: "myopener --url={{.URL}}",
			want:    []string{"myopener", "--url=" + url},
		},
		{
			name:    "extra whitespace is collapsed",
			command: "  firefox    {{.URL}}  ",
			want:    []string{"firefox", url},
		},
		{
			name:    "quoted argument with spaces is kept together",
			command: `open -na "Google Chrome" --args --profile-directory="Profile 1" {{.URL}}`,
			want:    []string{"open", "-na", "Google Chrome", "--args", "--profile-directory=Profile 1", url},
		},
		{
			name:    "single quotes group and keep double quotes literal",
			command: `myopener --title='a "quoted" name' {{.URL}}`,
			want:    []string{"myopener", `--title=a "quoted" name`, url},
		},
		{
			name:    "backslashes are literal (windows path)",
			command: `"C:\Program Files\Google\Chrome\Application\chrome.exe" --profile-directory="Profile 1" {{.URL}}`,
			want:    []string{`C:\Program Files\Google\Chrome\Application\chrome.exe`, "--profile-directory=Profile 1", url},
		},
		{
			name:    "empty command",
			command: "   ",
			wantErr: true,
		},
		{
			name:    "unbalanced quote",
			command: `firefox "{{.URL}}`,
			wantErr: true,
		},
		{
			name:    "no url reference",
			command: "firefox --new-tab",
			wantErr: true,
		},
		{
			name:    "invalid template",
			command: "firefox {{.URL}",
			wantErr: true,
		},
		{
			name:    "unknown template field",
			command: "firefox {{.Nope}}",
			wantErr: true,
		},
		{
			name:    "newline is rejected",
			command: "firefox {{.URL}}\nrm -rf /",
			wantErr: true,
		},
		{
			name:    "carriage return is rejected",
			command: "firefox\r{{.URL}}",
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := renderURLOpenerCommand(tc.command, url)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got args %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("args mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSplitCommand(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		want    []string
		wantErr bool
	}{
		{
			name: "plain",
			in:   "firefox --new-tab https://example.com",
			want: []string{"firefox", "--new-tab", "https://example.com"},
		},
		{
			name: "double quotes group spaces",
			in:   `open -a "Google Chrome"`,
			want: []string{"open", "-a", "Google Chrome"},
		},
		{
			name: "single quotes group spaces",
			in:   `open -a 'Google Chrome'`,
			want: []string{"open", "-a", "Google Chrome"},
		},
		{
			name: "backslashes are literal",
			in:   `"C:\Program Files\Chrome\chrome.exe"`,
			want: []string{`C:\Program Files\Chrome\chrome.exe`},
		},
		// Quote nesting: quotes do not recurse. A quote of one kind is a
		// literal character inside the other kind.
		{
			name: "single-quoted double quote is literal",
			in:   `'"'`,
			want: []string{`"`},
		},
		{
			name: "double-quoted single quote is literal",
			in:   `"'"`,
			want: []string{`'`},
		},
		{
			name: "single-quoted pair of double quotes",
			in:   `'""'`,
			want: []string{`""`},
		},
		{
			name: "double-quoted pair of single quotes",
			in:   `"''"`,
			want: []string{`''`},
		},
		{
			name: "adjacent quoted and unquoted runs concatenate",
			in:   `foo'bar'"baz"`,
			want: []string{"foobarbaz"},
		},
		{
			name: "quote in the middle of a token with a space",
			in:   `a"b b"c`,
			want: []string{"ab bc"},
		},
		{
			name: "empty double-quoted string is an empty argument",
			in:   `x "" y`,
			want: []string{"x", "", "y"},
		},
		{
			name: "empty single-quoted string is an empty argument",
			in:   `x '' y`,
			want: []string{"x", "", "y"},
		},
		{
			name: "leading and trailing whitespace ignored",
			in:   "  firefox   https://example.com  ",
			want: []string{"firefox", "https://example.com"},
		},
		{
			name: "empty input yields no tokens",
			in:   "   ",
			want: nil,
		},
		{
			name:    "unterminated double quote",
			in:      `firefox "abc`,
			wantErr: true,
		},
		{
			name:    "unterminated single quote",
			in:      `'"''`,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := splitCommand(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got tokens %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("tokens mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewCommandURLOpener_ValidatesUpFront(t *testing.T) {
	// Invalid config should fail when the opener is constructed, before any
	// browser open is attempted.
	if _, err := newCommandURLOpener("firefox --no-url"); err == nil {
		t.Fatal("expected error for command without {{.URL}}, got nil")
	}

	if _, err := newCommandURLOpener("firefox {{.URL}}"); err != nil {
		t.Fatalf("unexpected error for valid command: %v", err)
	}
}

func TestNewCommandURLOpener_RunsCommand(t *testing.T) {
	// 'true' exits 0 and ignores its args - exercises the exec path end to end
	// without depending on a real browser.
	open, err := newCommandURLOpener("true {{.URL}}")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := open("https://example.com"); err != nil {
		t.Fatalf("expected command to succeed, got: %v", err)
	}
}
