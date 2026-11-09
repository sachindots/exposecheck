package report

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/sachindots/exposecheck/internal/sockets"
)

type Report struct {
	Listeners []sockets.Listener `json:"listeners"`
	Findings  []sockets.Finding  `json:"findings"`
	Notes     []sockets.Note     `json:"notes"`
}

// ExitCode is 1 when any finding exists. Every finding kind (firewall,
// docker) is a risky one, so there is nothing to filter.
func (r Report) ExitCode() int {
	if len(r.Findings) > 0 {
		return 1
	}
	return 0
}

func (r Report) JSON() ([]byte, error) {
	if r.Listeners == nil {
		r.Listeners = []sockets.Listener{}
	}
	if r.Findings == nil {
		r.Findings = []sockets.Finding{}
	}
	if r.Notes == nil {
		r.Notes = []sockets.Note{}
	}
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func (r Report) Text() string {
	var b strings.Builder
	b.WriteString("Listeners\n")
	if len(r.Listeners) == 0 {
		b.WriteString("  none\n")
	}
	for _, class := range []sockets.Class{sockets.Public, sockets.Tailnet, sockets.Bridge, sockets.Local} {
		var group []sockets.Listener
		for _, l := range r.Listeners {
			if l.Class == class {
				group = append(group, l)
			}
		}
		if len(group) == 0 {
			continue
		}
		slices.SortStableFunc(group, func(a, b sockets.Listener) int {
			if a.Port != b.Port {
				return int(a.Port) - int(b.Port)
			}
			if c := strings.Compare(a.Proto, b.Proto); c != 0 {
				return c
			}
			return a.Addr.Compare(b.Addr)
		})
		fmt.Fprintf(&b, "  %s\n", class)
		for _, l := range group {
			line := fmt.Sprintf("    %-4s %-24s", l.Proto, netip.AddrPortFrom(l.Addr, l.Port))
			if l.Process != nil {
				line += fmt.Sprintf(" %s (pid %d)", l.Process.Command, l.Process.PID)
			}
			b.WriteString(strings.TrimRight(line, " ") + "\n")
		}
	}
	if len(r.Findings) == 0 {
		b.WriteString("\nNo findings.\n")
	} else {
		fmt.Fprintf(&b, "\nFindings (%d)\n", len(r.Findings))
		for _, f := range r.Findings {
			fmt.Fprintf(&b, "  [%s] %s %s: %s\n    fix: %s\n",
				f.Kind, f.Proto, netip.AddrPortFrom(f.Addr, f.Port), f.Reason, f.Fix)
		}
	}
	if len(r.Notes) > 0 {
		b.WriteString("\nNotes\n")
		for _, n := range r.Notes {
			fmt.Fprintf(&b, "  %s\n", n)
		}
	}
	return b.String()
}
