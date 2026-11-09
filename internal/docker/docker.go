package docker

import (
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sachindots/exposecheck/internal/sockets"
)

// Check lists ports Docker publishes on a public address, one finding per host
// port and address. Docker adds its own iptables rules, so ufw does not block
// them. A nil run executes the command and returns its stdout.
func Check(run func(string, ...string) ([]byte, error), tailnet []netip.Addr) ([]sockets.Finding, []sockets.Note, error) {
	if run == nil {
		run = func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output()
		}
	}
	out, err := run("docker", "ps", "--format", `{{.Names}}\t{{.Ports}}`)
	if err != nil {
		return nil, []sockets.Note{sockets.Note("docker: " + skipReason(err) + ", skipped")}, nil
	}
	var findings []sockets.Finding
	for _, line := range strings.Split(string(out), "\n") {
		name, ports, _ := strings.Cut(line, "\t")
		for _, mapping := range strings.Split(ports, ", ") {
			hostSide, containerSide, published := strings.Cut(mapping, "->")
			if !published {
				continue
			}
			found, err := parseMapping(name, hostSide, containerSide, tailnet)
			if err != nil {
				return nil, nil, fmt.Errorf("parse docker ports %q for %s: %w", mapping, name, err)
			}
			findings = append(findings, found...)
		}
	}
	return findings, nil, nil
}

// parseMapping handles "0.0.0.0:6333-6334" -> "6333-6334/tcp". The host
// address may be written 0.0.0.0, [::] or :::.
func parseMapping(name, hostSide, containerSide string, tailnet []netip.Addr) ([]sockets.Finding, error) {
	i := strings.LastIndex(hostSide, ":")
	if i < 0 {
		return nil, errors.New("no host address")
	}
	addr, err := netip.ParseAddr(strings.Trim(hostSide[:i], "[]"))
	if err != nil {
		return nil, err
	}
	hostLo, hostHi, err := parseRange(hostSide[i+1:])
	if err != nil {
		return nil, fmt.Errorf("host port: %w", err)
	}
	containerPorts, proto, _ := strings.Cut(containerSide, "/")
	containerLo, containerHi, err := parseRange(containerPorts)
	if err != nil {
		return nil, fmt.Errorf("container port: %w", err)
	}
	if sockets.Classify(addr, tailnet) != sockets.Public {
		return nil, nil
	}
	var findings []sockets.Finding
	for p := hostLo; p <= hostHi; p++ {
		target := containerLo
		if containerHi > containerLo {
			target = containerLo + (p - hostLo)
		}
		findings = append(findings, sockets.Finding{
			Kind: "docker", Proto: proto, Addr: addr, Port: uint16(p),
			Reason: fmt.Sprintf("container %s publishes port %d/%s on all interfaces; Docker bypasses ufw", name, p, proto),
			Fix:    fmt.Sprintf("publish with -p 127.0.0.1:%d:%d, or filter in the DOCKER-USER chain", p, target),
		})
	}
	return findings, nil
}

func parseRange(s string) (lo, hi int, err error) {
	first, last, isRange := strings.Cut(s, "-")
	l, err := strconv.ParseUint(first, 10, 16)
	if err != nil {
		return 0, 0, err
	}
	h := l
	if isRange {
		if h, err = strconv.ParseUint(last, 10, 16); err != nil {
			return 0, 0, err
		}
	}
	if h < l {
		return 0, 0, fmt.Errorf("range %q runs backwards", s)
	}
	return int(l), int(h), nil
}

func skipReason(err error) string {
	if errors.Is(err, exec.ErrNotFound) {
		return "not installed"
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && strings.Contains(strings.ToLower(string(exit.Stderr)), "permission denied") {
		return "permission denied"
	}
	return "failed (" + err.Error() + ")"
}
