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
	tests := []struct {
		name      string
		file      string
		err       error
		want      []string // "addr port/proto"
		wantNotes []sockets.Note
		wantErr   bool
	}{
		{name: "public ipv4 and ipv6 of one port count once", file: "ps-public.txt", want: []string{"0.0.0.0 8080/tcp"}},
		{name: "loopback only", file: "ps-loopback.txt"},
		{name: "ipv6 any, both spellings", file: "ps-ipv6.txt", want: []string{":: 3000/tcp", ":: 9100/tcp"}},
		{name: "port range and udp", file: "ps-range.txt", want: []string{"0.0.0.0 9000/tcp", "0.0.0.0 5353/udp", "0.0.0.0 8080/tcp"}},
		{name: "nothing published", file: "ps-none.txt"},
		{name: "no containers", file: "ps-empty.txt"},
		{name: "docker missing", err: exec.ErrNotFound, wantNotes: []sockets.Note{"docker: not installed, skipped"}},
		{name: "no socket permission", err: denied, wantNotes: []sockets.Note{"docker: no permission to the docker socket, skipped"}},
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
			findings, notes, err := Check(run, nil)
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
	run := func(string, ...string) ([]byte, error) { return []byte("web\t0.0.0.0:8080->80/tcp\n"), nil }
	findings, _, err := Check(run, nil)
	if err != nil || len(findings) != 1 {
		t.Fatalf("findings = %v, err = %v", findings, err)
	}
	f := findings[0]
	if f.Kind != "docker" || f.Addr != netip.IPv4Unspecified() ||
		f.Fix != "publish on loopback (-p 127.0.0.1:8080:80), or filter in the DOCKER-USER chain" {
		t.Errorf("finding = %+v", f)
	}
}

func TestRangeFixHint(t *testing.T) {
	run := func(string, ...string) ([]byte, error) { return []byte("q\t0.0.0.0:6333-6334->6333-6334/tcp\n"), nil }
	findings, _, _ := Check(run, nil)
	want := "publish on loopback (-p 127.0.0.1:6333-6334:6333-6334), or filter in the DOCKER-USER chain"
	if len(findings) != 1 || findings[0].Fix != want {
		t.Errorf("findings = %+v, want fix %q", findings, want)
	}
}
