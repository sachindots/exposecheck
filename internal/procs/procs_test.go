package procs

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sachindots/exposecheck/internal/sockets"
)

func TestResolve(t *testing.T) {
	listeners := []sockets.Listener{{Inode: 1001}, {Inode: 1002}, {Inode: 9999}}
	denied, err := Resolve("../../testdata/proc", listeners)
	if err != nil {
		t.Fatal(err)
	}
	if denied {
		t.Error("denied = true, want false")
	}
	want := []*sockets.Process{{PID: 100, Command: "sshd"}, {PID: 200, Command: "my app"}, nil}
	for i, w := range want {
		got := listeners[i].Process
		if (got == nil) != (w == nil) || (w != nil && *got != *w) {
			t.Errorf("listener %d process = %v, want %v", i, got, w)
		}
	}
}

func TestResolveMissingRoot(t *testing.T) {
	if _, err := Resolve("../../testdata/no-such-proc", nil); err == nil {
		t.Error("want error for missing proc root")
	}
}

func TestResolveDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	root := t.TempDir()
	fd := filepath.Join(root, "42", "fd")
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(fd, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(fd, 0o755) })
	listeners := []sockets.Listener{{Inode: 1}}
	denied, err := Resolve(root, listeners)
	if err != nil {
		t.Fatal(err)
	}
	if !denied || listeners[0].Process != nil {
		t.Errorf("denied = %v, process = %v; want true, nil", denied, listeners[0].Process)
	}
}
