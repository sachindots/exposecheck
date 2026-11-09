package main

import (
	"fmt"
	"net"
	"net/netip"
	"os"

	"github.com/sachindots/exposecheck/internal/sockets"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run() error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("list interfaces: %w", err)
	}
	var tailnet []netip.Addr
	for _, iface := range interfaces {
		if iface.Name != "tailscale0" {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return fmt.Errorf("list tailscale0 addresses: %w", err)
		}
		for _, addr := range addrs {
			prefix, err := netip.ParsePrefix(addr.String())
			if err != nil {
				return fmt.Errorf("parse tailscale0 address %q: %w", addr, err)
			}
			tailnet = append(tailnet, prefix.Addr())
		}
	}
	listeners, err := sockets.Scan("/proc", tailnet)
	if err != nil {
		return err
	}
	for _, listener := range listeners {
		fmt.Printf("%s %s %s %d\n", listener.Proto,
			netip.AddrPortFrom(listener.Addr, listener.Port), listener.Class, listener.Inode)
	}
	return nil
}
