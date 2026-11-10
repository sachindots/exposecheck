package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sachindots/exposecheck/internal/report"
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
		{"missing only value", []string{"--only"}, 2, "", usage},
		{"unsupported only value", []string{"--only", "local"}, 2, "", usage},
		{"case sensitive only value", []string{"--only", "Public"}, 2, "", usage},
		{"flag as only value", []string{"--only", "--json"}, 2, "", usage},
		{"empty only value", []string{"--only", ""}, 2, "", usage},
		{"repeated only", []string{"--only", "public", "--only", "public"}, 2, "", usage},
		{"repeated json", []string{"--json", "--json"}, 2, "", usage},
		{"only with version", []string{"--only", "public", "--version"}, 2, "", usage},
		{"version with only", []string{"--version", "--only", "public"}, 2, "", usage},
		{"positional argument", []string{"extra"}, 2, "", usage},
		{"trailing argument", []string{"--only", "public", "extra"}, 2, "", usage},
		{"equals syntax", []string{"--only=public"}, 2, "", usage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := runWithCollect(tt.args, &stdout, &stderr, func() (report.Report, error) {
				t.Fatal("unexpected collection")
				return report.Report{}, nil
			}); got != tt.code {
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

func fixtureReport(t *testing.T, name string) report.Report {
	t.Helper()
	out, err := os.ReadFile(filepath.Join("internal", "report", "testdata", name+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var rep report.Report
	if err := json.Unmarshal(out, &rep); err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestRunReport(t *testing.T) {
	full := fixtureReport(t, "mixed")
	public := fixtureReport(t, "public")
	dockerOnly := report.Report{Findings: public.Findings[:1]}
	nonpublic := full
	nonpublic.Listeners = full.Listeners[:1]
	nonpublic.Findings = full.Findings[:1]
	cleanPublic := public
	cleanPublic.Findings = nil
	notesOnly := report.Report{Notes: full.Notes}
	tests := []struct {
		name  string
		args  []string
		input report.Report
		want  report.Report
		json  bool
		code  int
	}{
		{"default text", nil, full, full, false, 1},
		{"default json", []string{"--json"}, full, full, true, 1},
		{"public text", []string{"--only", "public"}, full, public, false, 1},
		{"docker without listener text", []string{"--only", "public"}, dockerOnly, dockerOnly, false, 1},
		{"docker without listener json", []string{"--json", "--only", "public"}, dockerOnly, dockerOnly, true, 1},
		{"json before only", []string{"--json", "--only", "public"}, full, public, true, 1},
		{"json after only", []string{"--only", "public", "--json"}, full, public, true, 1},
		{"nonpublic findings removed text", []string{"--only", "public"}, nonpublic, notesOnly, false, 0},
		{"nonpublic findings removed json", []string{"--json", "--only", "public"}, nonpublic, notesOnly, true, 0},
		{"public without findings", []string{"--only", "public"}, cleanPublic, cleanPublic, false, 0},
		{"empty public json", []string{"--json", "--only", "public"}, report.Report{}, report.Report{}, true, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before, err := tt.input.JSON()
			if err != nil {
				t.Fatal(err)
			}
			var stdout, stderr bytes.Buffer
			calls := 0
			code := runWithCollect(tt.args, &stdout, &stderr, func() (report.Report, error) {
				calls++
				return tt.input, nil
			})
			if code != tt.code || stderr.Len() != 0 || calls != 1 {
				t.Fatalf("code = %d, stderr = %q, collections = %d; want %d, empty stderr, 1", code, stderr.String(), calls, tt.code)
			}
			want := tt.want.Text()
			if tt.json {
				out, err := tt.want.JSON()
				if err != nil {
					t.Fatal(err)
				}
				want = string(out)
			}
			if got := stdout.String(); got != want {
				t.Errorf("stdout = %s\nwant %s", got, want)
			}
			after, err := tt.input.JSON()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Error("collection report was modified")
			}
		})
	}
}

func TestRunCollectionError(t *testing.T) {
	for _, args := range [][]string{nil, {"--json"}, {"--only", "public"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runWithCollect(args, &stdout, &stderr, func() (report.Report, error) {
				return report.Report{}, errors.New("scan /proc: permission denied")
			})
			if code != 2 || stdout.Len() != 0 || stderr.String() != "scan /proc: permission denied\n" {
				t.Errorf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestPublicOnlyPreservesSource(t *testing.T) {
	full := fixtureReport(t, "mixed")
	want := fixtureReport(t, "mixed")
	filtered := publicOnly(full)
	if !reflect.DeepEqual(full, want) {
		t.Fatal("publicOnly modified its input")
	}
	filtered.Listeners[0].Port++
	filtered.Findings[0].Port++
	if !reflect.DeepEqual(full, want) {
		t.Fatal("publicOnly shares listener or finding storage with its input")
	}
}
