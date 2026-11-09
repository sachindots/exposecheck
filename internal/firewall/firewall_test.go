package firewall

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	"github.com/sachindots/exposecheck/internal/sockets"
)

type result struct {
	file string
	err  error
}

var notRoot = &exec.ExitError{Stderr: []byte("Fatal: can't open lock file: Permission denied (you must be root)")}

func listener(proto string, port uint16, class sockets.Class) sockets.Listener {
	return sockets.Listener{Proto: proto, Addr: netip.IPv4Unspecified(), Port: port, Class: class}
}

func TestCheck(t *testing.T) {
	missing := result{err: exec.ErrNotFound}
	listeners := []sockets.Listener{
		listener("tcp", 22, sockets.Public),
		listener("tcp", 8080, sockets.Public),
		listener("udp", 5353, sockets.Public),
		listener("tcp", 5432, sockets.Local),
	}
	tests := []struct {
		name      string
		tools     map[string]result
		wantPorts []uint16
		wantNotes []sockets.Note
	}{
		{
			name:      "ufw default deny, 22 and 8000-8100 allowed",
			tools:     map[string]result{"ufw": {file: "ufw-default-deny.txt"}, "iptables": missing, "nft": missing},
			wantPorts: []uint16{22, 8080},
			wantNotes: []sockets.Note{"iptables: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "ufw default allow, deny rules",
			tools:     map[string]result{"ufw": {file: "ufw-default-allow.txt"}, "iptables": missing, "nft": missing},
			wantPorts: []uint16{22},
			wantNotes: []sockets.Note{"iptables: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "ufw inactive",
			tools:     map[string]result{"ufw": {file: "ufw-inactive.txt"}, "iptables": missing, "nft": missing},
			wantPorts: []uint16{22, 8080, 5353},
			wantNotes: []sockets.Note{"iptables: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "iptables policy drop",
			tools:     map[string]result{"ufw": missing, "iptables": {file: "iptables-policy-drop.txt"}, "nft": missing},
			wantPorts: []uint16{22},
			wantNotes: []sockets.Note{"ufw: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "iptables accept with port drops",
			tools:     map[string]result{"ufw": missing, "iptables": {file: "iptables-accept-deny-port.txt"}, "nft": missing},
			wantPorts: []uint16{22},
			wantNotes: []sockets.Note{"ufw: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "nft policy drop",
			tools:     map[string]result{"ufw": missing, "iptables": missing, "nft": {file: "nft-policy-drop.txt"}},
			wantPorts: []uint16{22, 8080},
			wantNotes: []sockets.Note{"ufw: not installed, skipped", "iptables: not installed, skipped"},
		},
		{
			name:      "nft accept with port drops",
			tools:     map[string]result{"ufw": missing, "iptables": missing, "nft": {file: "nft-accept-deny-port.txt"}},
			wantPorts: []uint16{22},
			wantNotes: []sockets.Note{"ufw: not installed, skipped", "iptables: not installed, skipped"},
		},
		{
			name:      "one tool blocks, another allows",
			tools:     map[string]result{"ufw": {file: "ufw-inactive.txt"}, "iptables": {file: "iptables-policy-drop.txt"}, "nft": {file: "empty.txt"}},
			wantPorts: []uint16{22},
		},
		{
			name:      "not root: skipped, others still count",
			tools:     map[string]result{"ufw": {file: "ufw-inactive.txt"}, "iptables": {err: notRoot}, "nft": {err: notRoot}},
			wantPorts: []uint16{22, 8080, 5353},
			wantNotes: []sockets.Note{"iptables: not root, skipped", "nft: not root, skipped"},
		},
		{
			name:      "every tool missing: nothing checked, no findings",
			tools:     map[string]result{},
			wantNotes: []sockets.Note{"ufw: not installed, skipped", "iptables: not installed, skipped", "nft: not installed, skipped"},
		},
		{
			name:      "other failure keeps its message",
			tools:     map[string]result{"ufw": {err: errors.New("boom")}, "iptables": missing, "nft": missing},
			wantNotes: []sockets.Note{"ufw: failed (boom), skipped", "iptables: not installed, skipped", "nft: not installed, skipped"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			run := func(name string, args ...string) ([]byte, error) {
				res, ok := tt.tools[name]
				if !ok {
					return nil, exec.ErrNotFound
				}
				if res.err != nil {
					return nil, res.err
				}
				return os.ReadFile(filepath.Join("..", "..", "testdata", "firewall", res.file))
			}
			findings, notes, err := Check(run, listeners)
			if err != nil {
				t.Fatal(err)
			}
			var ports []uint16
			for _, f := range findings {
				ports = append(ports, f.Port)
			}
			if !slices.Equal(ports, tt.wantPorts) {
				t.Errorf("finding ports = %v, want %v", ports, tt.wantPorts)
			}
			if !slices.Equal(notes, tt.wantNotes) {
				t.Errorf("notes = %q, want %q", notes, tt.wantNotes)
			}
		})
	}
}

func TestFindingText(t *testing.T) {
	findings, _, _ := Check(func(string, ...string) ([]byte, error) { return nil, exec.ErrNotFound }, nil)
	if findings != nil {
		t.Fatalf("findings = %v, want none", findings)
	}
	run := func(name string, args ...string) ([]byte, error) {
		if name == "ufw" {
			return []byte("Status: inactive\n"), nil
		}
		return nil, exec.ErrNotFound
	}
	findings, _, _ = Check(run, []sockets.Listener{listener("tcp", 8080, sockets.Public)})
	if len(findings) != 1 || findings[0].Fix != "ufw deny 8080/tcp, or bind to 127.0.0.1" || findings[0].Reason != "public listener not blocked by firewall" || findings[0].Kind != "firewall" {
		t.Errorf("findings = %+v", findings)
	}
}
