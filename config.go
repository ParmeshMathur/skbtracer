package skbtracer

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"
)

// Config is the configurations for the bpf program.
type Config struct {
	IP        string
	ip        uint32
	Proto     string
	proto     int
	IcmpID    uint64
	Port      uint64
	Pid       uint64
	NetNS     uint64
	DropStack bool
	CallStack bool
	Iptable   bool
	NoRoute   bool
	Keep      bool
}

func (c *Config) parse() error {
	ip := c.IP
	if ip != "" {
		ip := net.ParseIP(ip)
		ip = ip.To4()
		if ip == nil {
			return fmt.Errorf("invalid IPv4 addr(%s)", ip)
		}
		c.ip = binary.LittleEndian.Uint32(ip)
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
