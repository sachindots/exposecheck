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

const usage = "usage: exposecheck [--json] [--only public] | --version\n"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithCollect(args, stdout, stderr, collect)
}

func runWithCollect(args []string, stdout, stderr io.Writer, collect func() (report.Report, error)) int {
	if len(args) == 1 && args[0] == "--version" {
		var version string
		if build, ok := debug.ReadBuildInfo(); ok {
			version = build.Main.Version
		}
		fmt.Fprintln(stdout, normalizeVersion(version))
		return 0
	}
	var asJSON, onlyPublic bool
	for i := 0; i < len(args); i++ {
		switch {
		case args[i] == "--json" && !asJSON:
			asJSON = true
		case args[i] == "--only" && !onlyPublic && i+1 < len(args) && args[i+1] == "public":
			onlyPublic = true
			i++
		default:
			fmt.Fprint(stderr, usage)
			return 2
		}
	}
	rep, err := collect()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if onlyPublic {
		rep = publicOnly(rep)
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

func publicOnly(rep report.Report) report.Report {
	filtered := report.Report{Notes: rep.Notes}
	for _, listener := range rep.Listeners {
		if listener.Class == sockets.Public {
			filtered.Listeners = append(filtered.Listeners, listener)
		}
	}
	for _, finding := range rep.Findings {
		if finding.Kind == "docker" {
			filtered.Findings = append(filtered.Findings, finding)
			continue
		}
		for _, listener := range filtered.Listeners {
			if finding.Proto == listener.Proto && finding.Addr == listener.Addr && finding.Port == listener.Port {
				filtered.Findings = append(filtered.Findings, finding)
				break
			}
		}
	}
	return filtered
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
