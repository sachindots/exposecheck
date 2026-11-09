package main

import (
	"bytes"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"tagged", "v0.1.2", "v0.1.2"},
		{"development", "(devel)", "dev"},
		{"empty", "", "dev"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeVersion(tt.version); got != tt.want {
				t.Errorf("normalizeVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestRunArguments(t *testing.T) {
	tests := []struct {
		name   string
		args   []string
		code   int
		stdout string
		stderr string
	}{
		{"version", []string{"--version"}, 0, "dev\n", ""},
		{"version with json", []string{"--version", "--json"}, 2, "", usage},
		{"json with version", []string{"--json", "--version"}, 2, "", usage},
		{"repeated version", []string{"--version", "--version"}, 2, "", usage},
		{"version with argument", []string{"--version", "extra"}, 2, "", usage},
		{"unknown flag", []string{"--unknown"}, 2, "", usage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tt.args, &stdout, &stderr); got != tt.code {
				t.Errorf("run() = %d, want %d", got, tt.code)
			}
			if got := stdout.String(); got != tt.stdout {
				t.Errorf("stdout = %q, want %q", got, tt.stdout)
			}
			if got := stderr.String(); got != tt.stderr {
				t.Errorf("stderr = %q, want %q", got, tt.stderr)
			}
		})
	}
}
