package sockets

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func Classify(addr netip.Addr, tailnet, bridge []netip.Addr) Class {
	addr = addr.Unmap()
	if addr.IsUnspecified() {
		return Public
	}
	if addr.IsLoopback() {
		return Local
	}
	if netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return Tailnet
	}
	for _, ip := range tailnet {
		if addr == ip.Unmap() {
			return Tailnet
		}
	}
	for _, ip := range bridge {
		if addr == ip.Unmap() {
			return Bridge
		}
	}
	return Public
}

// Iface is a network interface with its addresses, so tests can fake the host.
type Iface struct {
	Name  string
	Addrs []netip.Addr
}

func Interfaces() ([]Iface, error) {
	all, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
	}
	var out []Iface
	for _, i := range all {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, fmt.Errorf("list %s addresses: %w", i.Name, err)
		}
		iface := Iface{Name: i.Name}
		for _, a := range addrs {
			prefix, err := netip.ParsePrefix(a.String())
			if err != nil {
				return nil, fmt.Errorf("parse %s address %q: %w", i.Name, a, err)
			}
			iface.Addrs = append(iface.Addrs, prefix.Addr())
		}
		out = append(out, iface)
	}
	return out, nil
}

// BridgeAddrs returns the addresses on docker0, br-* and virbr* interfaces.
func BridgeAddrs(ifaces []Iface) []netip.Addr {
	var bridge []netip.Addr
	for _, i := range ifaces {
		if i.Name == "docker0" || strings.HasPrefix(i.Name, "br-") || strings.HasPrefix(i.Name, "virbr") {
			bridge = append(bridge, i.Addrs...)
		}
	}
	return bridge
}

func Scan(procRoot string, tailnet, bridge []netip.Addr) ([]Listener, error) {
	var listeners []Listener
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		path := filepath.Join(procRoot, "net", table)
		file, err := os.Open(path)
		if err != nil {
			if strings.HasSuffix(table, "6") && errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		rows, err := Parse(file, table, tailnet, bridge)
		file.Close()
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		listeners = append(listeners, rows...)
	}
	return listeners, nil
}

func Parse(r io.Reader, table string, tailnet, bridge []netip.Addr) ([]Listener, error) {
	var width int
	switch table {
	case "tcp", "udp":
		width = 8
	case "tcp6", "udp6":
		width = 32
	default:
		return nil, fmt.Errorf("unknown socket table %q", table)
	}
	proto := strings.TrimSuffix(table, "6")
	scanner := bufio.NewScanner(r)
	var listeners []Listener
	line := 0
	header := false
	for scanner.Scan() {
		line++
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}
		if !header {
			if len(fields) < 12 || fields[0] != "sl" || fields[1] != "local_address" ||
				(fields[2] != "rem_address" && fields[2] != "remote_address") || fields[3] != "st" || fields[11] != "inode" {
				return nil, fmt.Errorf("line %d: invalid socket table header", line)
			}
			header = true
			continue
		}
		if len(fields) < 10 {
			return nil, fmt.Errorf("line %d: expected at least 10 fields, got %d", line, len(fields))
		}
		state, err := strconv.ParseUint(fields[3], 16, 8)
		if err != nil {
			return nil, fmt.Errorf("line %d: state: %w", line, err)
		}
		if (proto == "tcp" && state != 0x0a) || (proto == "udp" && state != 0x07) {
			continue
		}
		remote, err := parseEndpoint(fields[2], width)
		if err != nil {
			return nil, fmt.Errorf("line %d: remote_address: %w", line, err)
		}
		if proto == "udp" && (!remote.Addr().IsUnspecified() || remote.Port() != 0) {
			continue
		}
		local, err := parseEndpoint(fields[1], width)
		if err != nil {
			return nil, fmt.Errorf("line %d: local_address: %w", line, err)
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("line %d: inode: %w", line, err)
		}
		listeners = append(listeners, Listener{
			Proto: proto, Addr: local.Addr(), Port: local.Port(), Inode: inode,
			Class: Classify(local.Addr(), tailnet, bridge),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("line %d: read socket table: %w", line+1, err)
	}
	if !header {
		return nil, fmt.Errorf("line %d: missing socket table header", line+1)
	}
	return listeners, nil
}

func parseEndpoint(field string, width int) (netip.AddrPort, error) {
	if len(field) != width+5 || field[width] != ':' {
		return netip.AddrPort{}, fmt.Errorf("invalid address:port %q", field)
	}
	var raw [16]byte
	for i := 0; i < width; i += 8 {
		word, err := strconv.ParseUint(field[i:i+8], 16, 32)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("address %q: %w", field[:width], err)
		}
		// Linux prints each address word in native byte order, including IPv6.
		binary.NativeEndian.PutUint32(raw[i/2:i/2+4], uint32(word))
	}
	port, err := strconv.ParseUint(field[width+1:], 16, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("port %q: %w", field[width+1:], err)
	}
	addr := netip.AddrFrom16(raw)
	if width == 8 {
		addr = netip.AddrFrom4([4]byte(raw[:4]))
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}
