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

// Check lists ports Docker publishes on a public address. Docker adds its own
// iptables rules, so these are reachable even when ufw denies them. A nil run
// executes the command and returns its stdout. The listeners argument is
// unused; it keeps the signature the same as the other checks.
func Check(run func(string, ...string) ([]byte, error), _ []sockets.Listener) ([]sockets.Finding, []sockets.Note, error) {
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
	seen := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		name, ports, _ := strings.Cut(line, "\t")
		for _, mapping := range strings.Split(ports, ", ") {
			hostSide, containerSide, published := strings.Cut(mapping, "->")
			if !published {
				continue
			}
			addr, hostPorts, err := splitHostSide(hostSide)
			if err != nil {
				return nil, nil, fmt.Errorf("parse docker ports %q for %s: %w", mapping, name, err)
			}
			_, proto, _ := strings.Cut(containerSide, "/")
			lo, _, _ := strings.Cut(hostPorts, "-")
			port, err := strconv.ParseUint(lo, 10, 16)
			if err != nil {
				return nil, nil, fmt.Errorf("parse docker ports %q for %s: host port: %w", mapping, name, err)
			}
			key := name + " " + hostPorts + "/" + proto
			if sockets.Classify(addr, nil) != sockets.Public || seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, sockets.Finding{
				Kind: "docker", Proto: proto, Addr: addr, Port: uint16(port),
				Reason: fmt.Sprintf("container %s publishes %s/%s on a public address; Docker bypasses ufw", name, hostPorts, proto),
				Fix:    fmt.Sprintf("publish on loopback (-p 127.0.0.1:%s:%s), or filter in the DOCKER-USER chain", hostPorts, containerPort(containerSide)),
			})
		}
	}
	return findings, nil, nil
}

// splitHostSide parses "0.0.0.0:8080", "[::]:8080" or ":::8080"; host ports
// may be a range such as "9000-9002".
func splitHostSide(s string) (netip.Addr, string, error) {
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return netip.Addr{}, "", errors.New("no host address")
	}
	addr, err := netip.ParseAddr(strings.Trim(s[:i], "[]"))
	return addr, s[i+1:], err
}

func containerPort(containerSide string) string {
	port, _, _ := strings.Cut(containerSide, "/")
	return port
}

func skipReason(err error) string {
	if errors.Is(err, exec.ErrNotFound) {
		return "not installed"
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && strings.Contains(strings.ToLower(string(exit.Stderr)), "permission denied") {
		return "no permission to the docker socket"
	}
	return "failed (" + err.Error() + ")"
}
