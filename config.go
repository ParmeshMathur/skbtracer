package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// Config is the configurations for the bpf program.
type Config struct {
	CatchCount uint64
	IP         string
	Proto      string
	proto      int
	IcmpID     uint64
	Port       uint64
	Pid        uint64
	NetNS      uint64
	DropStack  bool
	CallStack  bool
	Iptable    bool
	NoRoute    bool
	Keep       bool
	Time       bool
	Timestamp  bool
	Gops       string
}

var cfg Config

func init() {

	fs := rootCmd.PersistentFlags()
	fs.StringVarP(&cfg.IP, "ipaddr", "H", "", "ip address")
	fs.StringVar(&cfg.Proto, "proto", "", "tcp|udp|icmp|any")
	fs.Uint64Var(&cfg.IcmpID, "icmpid", 0, "trace icmp id")
	fs.Uint64VarP(&cfg.CatchCount, "catch-count", "c", 1000, "catch and print count")
	fs.Uint64VarP(&cfg.Port, "port", "P", 0, "udp or tcp port")
	fs.Uint64VarP(&cfg.Pid, "pid", "p", 0, "trace this PID only")
	fs.Uint64VarP(&cfg.NetNS, "netns", "N", 0, "trace this Network Namespace only")
	fs.BoolVar(&cfg.DropStack, "dropstack", false, "output kernel stack trace when drop packet")
	fs.BoolVar(&cfg.CallStack, "callstack", false, "output kernel stack trace")
	fs.BoolVar(&cfg.Iptable, "iptable", false, "output iptable path")
	fs.BoolVar(&cfg.NoRoute, "noroute", false, "do not output route path")
	fs.BoolVar(&cfg.Keep, "keep", false, "keep trace packet all lifetime")
	fs.BoolVarP(&cfg.Time, "time", "T", true, "show HH:MM:SS timestamp")
	fs.BoolVarP(&cfg.Timestamp, "timestamp", "t", false, "show timestamp in seconds at us resolution")
	fs.StringVar(&cfg.Gops, "gops", "", "gops address")

	fs.Lookup("dropstack").Deprecated = "not supported on Ubuntu 18.04.5 LTS with kernel 5.10.29-051029-generic"
	fs.Lookup("callstack").Deprecated = "not implemented to print the function stack"
	fs.Lookup("keep").Deprecated = "not implemented yet"
}

func (c *Config) parse() error {

	ip := c.IP
	if ip != "" {
		ip := net.ParseIP(ip)
		ip = ip.To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4 addr(%s)", ip)
		}
	}

	port := c.Port
	if port != 0 {
		b := make([]byte, 8)
		*(*uint64)(unsafe.Pointer(&b[0])) = port // ref: github.com/mdlayher/netlink/nlenc
		c.Port = binary.BigEndian.Uint64(b)      // Note: to network byte order
	}

	proto := c.Proto
	if proto != "" {
		switch proto {
		case "tcp":
			c.proto = 6
		case "udp":
			c.proto = 17
		case "icmp":
			c.proto = 1
		case "any":
		default:
			return fmt.Errorf("invalid proto(%s)", proto)
		}
	}

	return nil
}
