package firewall

import (
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"github.com/sachindots/exposecheck/internal/sockets"
)

// rule covers an inclusive port range. proto is "tcp", "udp" or "" for both.
type rule struct {
	proto  string
	lo, hi uint16
	allow  bool
}

// ruleset is what one firewall tool says about incoming traffic. Rules are in
// listed order and the first match wins; otherwise defaultDrop decides.
// Limits: source addresses, interfaces and jumps to other chains are ignored,
// and iptables is IPv4 only.
type ruleset struct {
	defaultDrop bool
	rules       []rule
}

func (r ruleset) blocks(proto string, port uint16) bool {
	for _, ru := range r.rules {
		if (ru.proto == "" || ru.proto == proto) && port >= ru.lo && port <= ru.hi {
			return !ru.allow
		}
	}
	return r.defaultDrop
}

var tools = []struct {
	name  string
	args  []string
	parse func(string) ruleset
}{
	{"ufw", []string{"status", "verbose"}, parseUFW},
	{"iptables", []string{"-S"}, parseIPTables},
	{"nft", []string{"list", "ruleset"}, parseNFT},
}

// Check reports public listeners that no firewall rule blocks. A nil run
// executes the command and returns its stdout. Tools that are missing or
// need root are skipped with a note; if none could be read, no findings are
// returned because nothing was checked.
func Check(run func(string, ...string) ([]byte, error), listeners []sockets.Listener) ([]sockets.Finding, []sockets.Note, error) {
	if run == nil {
		run = func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).Output()
		}
	}
	var sets []ruleset
	var notes []sockets.Note
	for _, tool := range tools {
		out, err := run(tool.name, tool.args...)
		if err != nil {
			notes = append(notes, sockets.Note(tool.name+": "+skipReason(err)+", skipped"))
			continue
		}
		sets = append(sets, tool.parse(string(out)))
	}
	if len(sets) == 0 {
		return nil, notes, nil
	}
	var findings []sockets.Finding
	for _, l := range listeners {
		if l.Class != sockets.Public || blockedBy(sets, l) {
			continue
		}
		findings = append(findings, sockets.Finding{
			Kind: "firewall", Proto: l.Proto, Addr: l.Addr, Port: l.Port,
			Reason: fmt.Sprintf("public listener on port %d/%s is not blocked by any firewall rule", l.Port, l.Proto),
			Fix:    fmt.Sprintf("ufw deny %d/%s, or bind the service to 127.0.0.1", l.Port, l.Proto),
		})
	}
	return findings, notes, nil
}

func blockedBy(sets []ruleset, l sockets.Listener) bool {
	for _, s := range sets {
		if s.blocks(l.Proto, l.Port) {
			return true
		}
	}
	return false
}

func skipReason(err error) string {
	if errors.Is(err, exec.ErrNotFound) {
		return "not installed"
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		stderr := strings.ToLower(string(exit.Stderr))
		for _, word := range []string{"root", "permission denied", "not permitted"} {
			if strings.Contains(stderr, word) {
				return "not root"
			}
		}
	}
	return "failed (" + err.Error() + ")"
}

// parsePorts reads "22", "80,443", "8000:8100", "8000-8100" or "{ 80, 443 }".
func parsePorts(spec string) ([][2]uint16, bool) {
	spec = strings.NewReplacer("{", "", "}", "", " ", "", ":", "-").Replace(spec)
	var spans [][2]uint16
	for _, part := range strings.Split(spec, ",") {
		lo, hi, isRange := strings.Cut(part, "-")
		first, err := strconv.ParseUint(lo, 10, 16)
		if err != nil {
			return nil, false
		}
		last := first
		if isRange {
			if last, err = strconv.ParseUint(hi, 10, 16); err != nil {
				return nil, false
			}
		}
		spans = append(spans, [2]uint16{uint16(first), uint16(last)})
	}
	return spans, true
}

func addRules(rs *ruleset, proto, ports string, allow bool) {
	spans, ok := parsePorts(ports)
	if !ok {
		return
	}
	for _, s := range spans {
		rs.rules = append(rs.rules, rule{proto: proto, lo: s[0], hi: s[1], allow: allow})
	}
}

func parseUFW(out string) ruleset {
	var rs ruleset
	inRules := false
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(line, "Status:") && fields[1] != "active":
			return ruleset{}
		case strings.HasPrefix(line, "Default:"):
			for _, part := range strings.Split(line, ",") {
				if strings.Contains(part, "(incoming)") {
					f := strings.Fields(strings.TrimPrefix(part, "Default:"))
					rs.defaultDrop = f[0] == "deny" || f[0] == "reject"
				}
			}
		case strings.HasPrefix(line, "--"):
			inRules = true
		case inRules:
			addUFWRule(&rs, fields)
		}
	}
	return rs
}

// addUFWRule handles "22/tcp ALLOW IN Anywhere". Rules for app profiles,
// specific destination addresses and outgoing traffic are skipped.
func addUFWRule(rs *ruleset, fields []string) {
	action := -1
	for i, f := range fields {
		if f == "OUT" {
			return
		}
		if action < 0 && (f == "ALLOW" || f == "DENY" || f == "REJECT" || f == "LIMIT") {
			action = i
		}
	}
	if action < 0 {
		return
	}
	ports, proto, _ := strings.Cut(fields[0], "/")
	addRules(rs, proto, ports, fields[action] == "ALLOW" || fields[action] == "LIMIT")
}

func parseIPTables(out string) ruleset {
	var rs ruleset
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == "-P" && f[1] == "INPUT" {
			rs.defaultDrop = f[2] == "DROP" || f[2] == "REJECT"
		}
		if len(f) < 2 || f[0] != "-A" || f[1] != "INPUT" {
			continue
		}
		var proto, ports, target string
		for i := 2; i+1 < len(f); i++ {
			switch f[i] {
			case "-p":
				proto = f[i+1]
			case "--dport", "--dports":
				ports = f[i+1]
			case "-j":
				target = f[i+1]
			}
		}
		if ports != "" {
			addRules(&rs, proto, ports, target == "ACCEPT")
		}
	}
	return rs
}

func parseNFT(out string) ruleset {
	var rs ruleset
	inInput := false
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " comment "); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		switch {
		case line == "}":
			inInput = false
		case len(f) > 0 && f[0] == "type":
			inInput = strings.Contains(line, "hook input")
			if _, policy, ok := strings.Cut(line, "policy "); ok && inInput {
				verdict := strings.TrimSuffix(strings.Fields(policy)[0], ";")
				rs.defaultDrop = verdict == "drop" || verdict == "reject"
			}
		case inInput && len(f) >= 4 && (f[0] == "tcp" || f[0] == "udp") && f[1] == "dport":
			ports := line[strings.Index(line, "dport ")+len("dport "):]
			if strings.HasPrefix(ports, "{") {
				end := strings.Index(ports, "}")
				if end < 0 {
					continue
				}
				ports = ports[:end+1]
			} else {
				ports, _, _ = strings.Cut(ports, " ")
			}
			if verdict := f[len(f)-1]; verdict == "accept" || verdict == "drop" || verdict == "reject" {
				addRules(&rs, f[0], ports, verdict == "accept")
			}
		}
	}
	return rs
}
