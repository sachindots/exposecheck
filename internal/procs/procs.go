package procs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/sachindots/exposecheck/internal/sockets"
)

// Resolve fills Listener.Process by matching socket inodes against
// <procRoot>/<pid>/fd. It reports denied when some pid's fds were unreadable
// (not root), so the caller can say process names need root.
func Resolve(procRoot string, listeners []sockets.Listener) (denied bool, err error) {
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", procRoot, err)
	}
	byInode := make(map[uint64][]int, len(listeners))
	for i, l := range listeners {
		byInode[l.Inode] = append(byInode[l.Inode], i)
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(procRoot, entry.Name())
		fds, err := os.ReadDir(filepath.Join(dir, "fd"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			denied = true
			continue
		}
		var proc *sockets.Process
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
			if err != nil || !strings.HasPrefix(target, "socket:[") {
				continue
			}
			inode, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]"), 10, 64)
			if err != nil {
				continue
			}
			for _, i := range byInode[inode] {
				if proc == nil {
					comm, err := os.ReadFile(filepath.Join(dir, "comm"))
					if err != nil {
						break
					}
					proc = &sockets.Process{PID: pid, Command: strings.TrimSpace(string(comm))}
				}
				if listeners[i].Process == nil {
					listeners[i].Process = proc
				}
			}
		}
	}
	return denied, nil
}
