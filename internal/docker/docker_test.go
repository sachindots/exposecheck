package docker

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/sachindots/exposecheck/internal/sockets"
)

func TestCheck(t *testing.T) {
	denied := &exec.ExitError{Stderr: []byte("permission denied while trying to connect to the Docker daemon socket")}
	tailnet := []netip.Addr{netip.MustParseAddr("10.9.0.2")}
	tests := []struct {
		name      string
		file      string
		err       error
		want      []string // "addr port/proto"
		wantNotes []sockets.Note
		wantErr   bool
	}{
		{
			name: "public v4 and v6 range, loopback ignored", file: "ps-public-range.txt",
			want: []string{"0.0.0.0 6333/tcp", "0.0.0.0 6334/tcp", ":: 6333/tcp", ":: 6334/tcp"},
		},
		{name: "loopback only", file: "ps-loopback.txt"},
		{name: "tailnet addresses ignored, ipv6 any kept", file: "ps-tailnet.txt", want: []string{":: 9100/tcp"}},
		{name: "unpublished ports", file: "ps-unpublished.txt"},
		{name: "no containers", file: "ps-empty.txt"},
		{name: "docker missing", err: exec.ErrNotFound, wantNotes: []sockets.Note{"docker: not installed, skipped"}},
		{name: "no socket permission", err: denied, wantNotes: []sockets.Note{"docker: permission denied, skipped"}},
		{name: "daemon down", err: errors.New("exit status 1"), wantNotes: []sockets.Note{"docker: failed (exit status 1), skipped"}},
		{name: "unparseable port", file: "ps-bad.txt", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := func(name string, args ...string) ([]byte, error) {
				if tt.err != nil {
					return nil, tt.err
				}
				return os.ReadFile(filepath.Join("..", "..", "testdata", "docker", tt.file))
			}
			findings, notes, err := Check(run, tailnet, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			var got []string
			for _, f := range findings {
				got = append(got, f.Addr.String()+" "+strconv.Itoa(int(f.Port))+"/"+f.Proto)
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("findings = %q, want %q", got, tt.want)
			}
			if !slices.Equal(notes, tt.wantNotes) {
				t.Errorf("notes = %q, want %q", notes, tt.wantNotes)
			}
		})
	}
}

func TestFindingText(t *testing.T) {
	tests := []struct {
		name, ps, reason string
		fixes            []string
	}{
		{
			name: "range maps host ports onto container ports", ps: "q\t0.0.0.0:6333-6334->7333-7334/tcp\n",
			reason: "container q publishes port 6333/tcp on all interfaces; Docker bypasses ufw",
			fixes: []string{
				"publish with -p 127.0.0.1:6333:7333, or filter in the DOCKER-USER chain",
				"publish with -p 127.0.0.1:6334:7334, or filter in the DOCKER-USER chain",
			},
		},
		{
			name: "single port", ps: "web\t0.0.0.0:8080->80/tcp\n",
			reason: "container web publishes port 8080/tcp on all interfaces; Docker bypasses ufw",
			fixes:  []string{"publish with -p 127.0.0.1:8080:80, or filter in the DOCKER-USER chain"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, _, err := Check(func(string, ...string) ([]byte, error) { return []byte(tt.ps), nil }, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			var fixes []string
			for _, f := range findings {
				fixes = append(fixes, f.Fix)
				if f.Kind != "docker" {
					t.Errorf("kind = %q, want docker", f.Kind)
				}
			}
			if !slices.Equal(fixes, tt.fixes) {
				t.Errorf("fixes = %q, want %q", fixes, tt.fixes)
			}
			if findings[0].Reason != tt.reason {
				t.Errorf("reason = %q, want %q", findings[0].Reason, tt.reason)
			}
		})
	}
}
