package sockets

import "net/netip"

type Class string

const (
	Public  Class = "public"
	Local   Class = "local"
	Tailnet Class = "tailnet"
	Bridge  Class = "bridge"
)

type Listener struct {
	Proto   string     `json:"proto"`
	Addr    netip.Addr `json:"addr"`
	Port    uint16     `json:"port"`
	Inode   uint64     `json:"inode"`
	Class   Class      `json:"class"`
	Process *Process   `json:"process,omitempty"`
}

type Process struct {
	PID     int    `json:"pid"`
	Command string `json:"command"`
}

type Finding struct {
	Kind   string     `json:"kind"`
	Proto  string     `json:"proto"`
	Addr   netip.Addr `json:"addr"`
	Port   uint16     `json:"port"`
	Reason string     `json:"reason"`
	Fix    string     `json:"fix"`
}

type Note string
