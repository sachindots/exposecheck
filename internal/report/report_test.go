package report

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/sachindots/exposecheck/internal/sockets"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

var full = Report{
	Listeners: []sockets.Listener{
		{Proto: "tcp", Addr: addr("127.0.0.1"), Port: 5432, Inode: 3, Class: sockets.Local},
		{Proto: "tcp", Addr: addr("::"), Port: 8080, Inode: 2, Class: sockets.Public},
		{Proto: "tcp", Addr: addr("0.0.0.0"), Port: 22, Inode: 1, Class: sockets.Public, Process: &sockets.Process{PID: 812, Command: "sshd"}},
		{Proto: "tcp", Addr: addr("172.17.0.1"), Port: 2375, Inode: 5, Class: sockets.Bridge},
		{Proto: "udp", Addr: addr("100.64.0.5"), Port: 41641, Inode: 4, Class: sockets.Tailnet},
	},
	Findings: []sockets.Finding{{
		Kind: "firewall", Proto: "tcp", Addr: addr("::"), Port: 8080,
		Reason: "public listener not blocked by firewall",
		Fix:    "ufw deny 8080/tcp, or bind to 127.0.0.1",
	}},
	Notes: []sockets.Note{"iptables: not root, skipped"},
}

func TestOutput(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		golden string
	}{
		{"findings and notes", full, "full"},
		{"clean", Report{}, "clean"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			json, err := tt.report.JSON()
			if err != nil {
				t.Fatal(err)
			}
			for ext, got := range map[string]string{"txt": tt.report.Text(), "json": string(json)} {
				want, err := os.ReadFile(filepath.Join("..", "..", "testdata", "report", tt.golden+"."+ext))
				if err != nil {
					t.Fatal(err)
				}
				if got != string(want) {
					t.Errorf("%s output differs from golden:\n%s", ext, got)
				}
			}
		})
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name   string
		report Report
		want   int
	}{
		{"no findings", Report{Listeners: full.Listeners}, 0},
		{"notes only", Report{Notes: full.Notes}, 0},
		{"firewall finding", full, 1},
		{"docker finding", Report{Findings: []sockets.Finding{{Kind: "docker"}}}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.report.ExitCode(); got != tt.want {
				t.Errorf("ExitCode() = %d, want %d", got, tt.want)
			}
		})
	}
}
