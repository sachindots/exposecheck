package main

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime/debug"

	"github.com/sachindots/exposecheck/internal/docker"
	"github.com/sachindots/exposecheck/internal/firewall"
	"github.com/sachindots/exposecheck/internal/procs"
	"github.com/sachindots/exposecheck/internal/report"
	"github.com/sachindots/exposecheck/internal/sockets"
)

const usage = "usage: exposecheck [--json | --version]\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && args[0] == "--version" {
		var version string
		if build, ok := debug.ReadBuildInfo(); ok {
			version = build.Main.Version
		}
		fmt.Fprintln(stdout, normalizeVersion(version))
		return 0
	}
	asJSON := len(args) == 1 && args[0] == "--json"
	if len(args) > 0 && !asJSON {
		fmt.Fprint(stderr, usage)
		return 2
	}
	rep, err := collect()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if asJSON {
		out, err := rep.JSON()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		stdout.Write(out)
	} else {
		fmt.Fprint(stdout, rep.Text())
	}
	return rep.ExitCode()
}

func normalizeVersion(version string) string {
	if version == "" || version == "(devel)" {
		return "dev"
	}
	return version
}

func collect() (report.Report, error) {
	tailnet, err := tailnetAddrs()
	if err != nil {
		return report.Report{}, err
	}
	ifaces, err := sockets.Interfaces()
	if err != nil {
		return report.Report{}, err
	}
	bridge := sockets.BridgeAddrs(ifaces)
	listeners, err := sockets.Scan("/proc", tailnet, bridge)
	if err != nil {
		return report.Report{}, err
	}
	rep := report.Report{Listeners: listeners}
	denied, err := procs.Resolve("/proc", listeners)
	if err != nil {
		return report.Report{}, err
	}
	if denied {
		rep.Notes = append(rep.Notes, "process names need root: run with sudo to see them")
	}
	findings, notes, err := firewall.Check(nil, listeners)
	if err != nil {
		return report.Report{}, err
	}
	rep.Findings, rep.Notes = append(rep.Findings, findings...), append(rep.Notes, notes...)
	findings, notes, err = docker.Check(nil, tailnet, bridge)
	if err != nil {
		return report.Report{}, err
	}
	rep.Findings, rep.Notes = append(rep.Findings, findings...), append(rep.Notes, notes...)
	return rep, nil
}

func tailnetAddrs() ([]netip.Addr, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var tailnet []netip.Addr
	for _, iface := range interfaces {
		if iface.Name != "tailscale0" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list tailscale0 addresses: %w", err)
		}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				return nil, fmt.Errorf("parse tailscale0 address %q: %w", a, err)
			}
			tailnet = append(tailnet, prefix.Addr())
		}
	}
	return tailnet, nil
}
