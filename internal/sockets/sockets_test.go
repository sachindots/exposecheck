package sockets_test

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sachindots/exposecheck/internal/sockets"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join("..", "..", "testdata", "sockets", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(contents)
}

func littleEndianFixtures(t *testing.T) {
	t.Helper()
	if binary.NativeEndian.Uint32([]byte{1, 0, 0, 0}) != 1 {
		t.Skip("fixtures use little-endian proc address encoding")
	}
}

func TestParse(t *testing.T) {
	littleEndianFixtures(t)
	tailnet := []netip.Addr{netip.MustParseAddr("fd7a:115c::1")}
	tests := []struct {
		table string
		want  []sockets.Listener
	}{
		{"tcp", []sockets.Listener{
			{Proto: "tcp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 8080, Inode: 110, Class: sockets.Public},
			{Proto: "tcp", Addr: netip.MustParseAddr("127.1.2.3"), Port: 22, Inode: 111, Class: sockets.Local},
			{Proto: "tcp", Addr: netip.MustParseAddr("192.168.1.1"), Port: 443, Inode: 112, Class: sockets.Public},
			{Proto: "tcp", Addr: netip.MustParseAddr("100.64.1.2"), Port: 2222, Inode: 113, Class: sockets.Tailnet},
		}},
		{"tcp6", []sockets.Listener{
			{Proto: "tcp", Addr: netip.MustParseAddr("::"), Port: 8443, Inode: 210, Class: sockets.Public},
			{Proto: "tcp", Addr: netip.MustParseAddr("::1"), Port: 22, Inode: 211, Class: sockets.Local},
			{Proto: "tcp", Addr: netip.MustParseAddr("2001:db8::1"), Port: 443, Inode: 212, Class: sockets.Public},
			{Proto: "tcp", Addr: netip.MustParseAddr("::ffff:127.0.0.1"), Port: 8080, Inode: 213, Class: sockets.Local},
			{Proto: "tcp", Addr: netip.MustParseAddr("::ffff:100.64.1.2"), Port: 2222, Inode: 214, Class: sockets.Tailnet},
			{Proto: "tcp", Addr: netip.MustParseAddr("fd7a:115c::1"), Port: 9000, Inode: 215, Class: sockets.Tailnet},
			{Proto: "tcp", Addr: netip.MustParseAddr("fe80::1"), Port: 9001, Inode: 216, Class: sockets.Public},
		}},
		{"udp", []sockets.Listener{
			{Proto: "udp", Addr: netip.MustParseAddr("0.0.0.0"), Port: 53, Inode: 310, Class: sockets.Public},
			{Proto: "udp", Addr: netip.MustParseAddr("127.0.0.1"), Port: 5353, Inode: 311, Class: sockets.Local},
		}},
		{"udp6", []sockets.Listener{
			{Proto: "udp", Addr: netip.MustParseAddr("::"), Port: 5353, Inode: 410, Class: sockets.Public},
			{Proto: "udp", Addr: netip.MustParseAddr("::1"), Port: 53, Inode: 411, Class: sockets.Local},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.table, func(t *testing.T) {
			got, err := sockets.Parse(strings.NewReader(fixture(t, tt.table)), tt.table, tailnet)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("Parse() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	tailnet := []netip.Addr{
		netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("::"),
		netip.MustParseAddr("::ffff:203.0.113.9"), netip.MustParseAddr("fd7a:115c::1"),
	}
	tests := []struct {
		addr string
		want sockets.Class
	}{
		{"0.0.0.0", sockets.Public}, {"::", sockets.Public}, {"::ffff:0.0.0.0", sockets.Public},
		{"127.0.0.1", sockets.Local}, {"127.255.255.254", sockets.Local},
		{"126.255.255.255", sockets.Public}, {"128.0.0.0", sockets.Public}, {"::1", sockets.Local},
		{"::ffff:127.2.3.4", sockets.Local}, {"100.63.255.255", sockets.Public},
		{"100.64.0.0", sockets.Tailnet}, {"100.127.255.255", sockets.Tailnet}, {"100.128.0.0", sockets.Public},
		{"::ffff:100.64.1.2", sockets.Tailnet}, {"10.1.2.3", sockets.Public},
		{"172.16.0.1", sockets.Public}, {"192.168.1.1", sockets.Public}, {"169.254.1.2", sockets.Public},
		{"fe80::1", sockets.Public}, {"2001:db8::1", sockets.Public},
		{"fd7a:115c::1", sockets.Tailnet}, {"fd7a:115c::2", sockets.Public},
		{"203.0.113.9", sockets.Tailnet}, {"::ffff:203.0.113.9", sockets.Tailnet},
	}
	for _, tt := range tests {
		t.Run(tt.addr, func(t *testing.T) {
			if got := sockets.Classify(netip.MustParseAddr(tt.addr), tailnet); got != tt.want {
				t.Fatalf("Classify() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		file string
		want string
	}{
		{"bad-local", "line 3: local_address"}, {"bad-remote", "line 3: remote_address"},
		{"bad-port", "line 3: local_address: port"}, {"bad-width", "line 3: local_address"},
		{"bad-inode", "line 3: inode"}, {"bad-inode-overflow", "line 3: inode"},
		{"bad-state", "line 3: state"}, {"truncated", "line 3: expected at least 10 fields"},
		{"bad-header", "line 1: invalid socket table header"}, {"missing-header", "line 1: invalid socket table header"},
	}
	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			got, err := sockets.Parse(strings.NewReader(fixture(t, tt.file)), "tcp", nil)
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != nil {
				t.Fatalf("Parse() = %v, %v; want nil and %q", got, err, tt.want)
			}
		})
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseReadBoundaries(t *testing.T) {
	failure := errors.New("read failed")
	tests := []struct {
		name  string
		input io.Reader
		table string
		want  string
	}{
		{"empty", strings.NewReader("\n"), "tcp", "missing socket table header"},
		{"unknown table", strings.NewReader(fixture(t, "tcp")), "raw", "unknown socket table"},
		{"read error", io.MultiReader(strings.NewReader(fixture(t, "tcp")), failingReader{failure}), "tcp", "read failed"},
		{"scanner limit", strings.NewReader(fixture(t, "tcp") + strings.Repeat("x", 65536)), "tcp", "token too long"},
		{"header only", strings.NewReader(fixture(t, "header-only")), "tcp", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sockets.Parse(tt.input, tt.table, nil)
			if tt.want == "" {
				if err != nil || len(got) != 0 {
					t.Fatalf("Parse() = %v, %v; want no listeners", got, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) || got != nil {
				t.Fatalf("Parse() = %v, %v; want nil and %q", got, err, tt.want)
			}
			if tt.name == "read error" && !errors.Is(err, failure) {
				t.Fatalf("Parse() lost read error: %v", err)
			}
		})
	}
}

func TestScan(t *testing.T) {
	littleEndianFixtures(t)
	tests := []struct {
		name    string
		files   map[string]string
		dir     string
		want    int
		wantErr string
	}{
		{"all tables", map[string]string{"tcp": "tcp", "tcp6": "tcp6", "udp": "udp", "udp6": "udp6"}, "", 15, ""},
		{"no IPv6", map[string]string{"tcp": "tcp", "udp": "udp"}, "", 6, ""},
		{"missing tcp", map[string]string{"udp": "udp"}, "", 0, "tcp"},
		{"missing udp", map[string]string{"tcp": "tcp"}, "", 0, "udp"},
		{"malformed", map[string]string{"tcp": "tcp", "udp": "bad-udp"}, "", 0, "udp"},
		{"IPv6 read error", map[string]string{"tcp": "tcp", "udp": "udp"}, "tcp6", 0, "tcp6"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.Mkdir(filepath.Join(root, "net"), 0700); err != nil {
				t.Fatal(err)
			}
			for name, source := range tt.files {
				if err := os.WriteFile(filepath.Join(root, "net", name), []byte(fixture(t, source)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.dir != "" {
				if err := os.Mkdir(filepath.Join(root, "net", tt.dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			got, err := sockets.Scan(root, nil)
			if tt.wantErr != "" {
				path := filepath.Join(root, "net", tt.wantErr)
				if err == nil || !strings.Contains(err.Error(), path) || got != nil {
					t.Fatalf("Scan() = %v, %v; want nil and error containing %q", got, err, path)
				}
				return
			}
			if err != nil || len(got) != tt.want {
				t.Fatalf("Scan() returned %d listeners, %v; want %d", len(got), err, tt.want)
			}
		})
	}
}
