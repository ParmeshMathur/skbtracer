package main

import (
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/dropbox/goebpf"
)

const (
	ethProtoIP   = 0x0800
	ethProtoIPv6 = 0x86DD
)

const (
	ipprotoICMP   = 1
	ipprotoTCP    = 6
	ipprotoUDP    = 17
	ipprotoICMPv6 = 58
)

const (
	routeEventIf      = 0x0001
	routeEventIptable = 0x0002
	routeEventDrop    = 0x0004
	routeEventNew     = 0x0010
)

var (
	nfVerdictName = []string{
		"DROP",
		"ACCEPT",
		"STOLEN",
		"QUEUE",
		"REPEAT",
		"STOP",
	}

	hookNames = []string{
		"PREROUTING",
		"INPUT",
		"FORWARD",
		"OUTPUT",
		"POSTROUTING",
	}

	tcpFlagNames = []string{
		"CWR",
		"ECE",
		"URG",
		"ACK",
		"PSH",
		"RST",
		"SYN",
		"FIN",
	}
)

func _get(names []string, idx uint32, defaultVal string) string {

	if int(idx) < len(names) {
		return names[idx]
	}

	return defaultVal
}

type l2Info struct {
	DestMac [6]byte
	L3Proto uint16
	l2pad   [4]byte
}

type l3Info struct {
	Saddr     [16]byte
	Daddr     [16]byte
	TotLen    uint16
	IPVersion uint8
	L4Proto   uint8
	l3pad     [4]byte
}

type l4Info struct {
	Sport    uint16
	Dport    uint16
	TCPFlags uint16
	l4pad    [2]byte
}

type icmpInfo struct {
	IcmpID   uint16
	IcmpSeq  uint16
	IcmpType uint8
	icmpPad  [2]byte
}

type iptablesInfo struct {
	TableName [32]byte
	Hook      uint32
	Verdict   uint32
	IptDelay  uint64
	Pf        uint8
	iptPad    [7]byte
}

type pktInfo struct {
	Ifname  [16]byte
	Len     uint32
	CPU     uint32
	Pid     uint32
	NetNS   uint32
	PktType uint8
	pktPad  [7]byte
}

type perfEvent struct {
	FuncName      [32]byte
	Skb           uint64
	StartNs       uint64
	KernelStackID int32
	Flags         uint8
	pad           [7]byte

	pktInfo
	l2Info
	l3Info
	l4Info
	icmpInfo
	iptablesInfo
}

const sizeofEvent = int(unsafe.Sizeof(perfEvent{}))

func (e *perfEvent) unmarshal(data []byte) error {

	if sizeofEvent > len(data) {
		return fmt.Errorf("event: not enough data to unmarshal, got %d bytes, expected %d bytes",
			len(data), sizeofEvent)
	}

	ev := *(*perfEvent)(unsafe.Pointer(&data[0]))
	*e = ev
	return nil
}

var earliestTs = uint64(0)

func (e *perfEvent) outputTimestamp() string {

	if cfg.Timestamp {
		if earliestTs == 0 {
			earliestTs = e.StartNs
		}
		return fmt.Sprintf("%-7.6f", float64(e.StartNs-earliestTs)/1000000000.0)
	}

	return time.Unix(0, int64(e.StartNs)).Format("15:04:05")
}

func (e *perfEvent) outputTcpFlags() string {

	var flags []string
	tcpFlags := uint8(e.TCPFlags >> 8)
	for i := 0; i < len(tcpFlagNames); i++ {
		if tcpFlags&(1<<i) != 0 {
			flags = append(flags, tcpFlagNames[i])
		}
	}

	return strings.Join(flags, ",")
}

func (e *perfEvent) outputPktInfo() string {

	var saddr, daddr net.IP
	if e.l2Info.L3Proto == ethProtoIP {
		saddr = net.IP(e.Saddr[:4])
		daddr = net.IP(e.Daddr[:4])
	} else {
		saddr = net.IP(e.Saddr[:])
		daddr = net.IP(e.Daddr[:])
	}

	if e.L4Proto == ipprotoTCP {
		tcpFlags := e.outputTcpFlags()
		if tcpFlags == "" {
			return fmt.Sprintf("T:%s:%d->%s:%d",
				saddr, e.Sport, daddr, e.Dport)
		}
		return fmt.Sprintf("T_%s:%s:%d->%s:%d", tcpFlags,
			saddr, e.Sport, daddr, e.Dport)

	} else if e.L4Proto == ipprotoUDP {
		return fmt.Sprintf("U:%s:%d->%s:%d",
			saddr, e.Sport, daddr, e.Dport)

	} else if e.L4Proto == ipprotoICMP || e.L4Proto == ipprotoICMPv6 {
		if e.IcmpType == 8 || e.IcmpType == 128 {
			return fmt.Sprintf("I_request:%s->%s", saddr, daddr)
		} else if e.IcmpType == 0 || e.IcmpType == 129 {
			return fmt.Sprintf("I_reply:%s->%s", saddr, daddr)
		} else {
			return fmt.Sprintf("I:%s->%s", saddr, daddr)
		}

	} else {
		return fmt.Sprintf("%d:%s->%s", e.L4Proto, saddr, daddr)
	}
}

func (e *perfEvent) outputTraceInfo() string {

	iptables := ""
	if e.Flags&routeEventIptable == routeEventIptable {
		iptName := goebpf.NullTerminatedStringToString(e.TableName[:])
		hook := _get(hookNames, e.Hook, "~UNK~")
		verdict := _get(nfVerdictName, e.Verdict, "~UNK~")
		iptables = fmt.Sprintf("pf=%d, table=%s hook=%s verdict=%s", e.Pf, iptName, hook, verdict)
	}

	funcName := goebpf.NullTerminatedStringToString(e.FuncName[:])
	pktType := e.outputPktType(e.PktType)
	if iptables == "" {
		return fmt.Sprintf("pkt_type=%s func=%s", pktType, funcName)
	}
	return fmt.Sprintf("pkt_type=%s iptables=[%s]", pktType, iptables)
}

func (e *perfEvent) outputPktType(pktType uint8) string {

	// See: https://elixir.bootlin.com/linux/latest/source/include/uapi/linux/if_packet.h#L26
	const (
		PACKET_USER   = 6
		PACKET_KERNEL = 7
	)
	pktTypes := map[uint8]string{
		syscall.PACKET_HOST:      "HOST",
		syscall.PACKET_BROADCAST: "BROADCAST",
		syscall.PACKET_MULTICAST: "MULTICAST",
		syscall.PACKET_OTHERHOST: "OTHERHOST",
		syscall.PACKET_OUTGOING:  "OUTGOING",
		syscall.PACKET_LOOPBACK:  "LOOPBACK",
		PACKET_USER:              "USER",
		PACKET_KERNEL:            "KERNEL",
	}
	if s, ok := pktTypes[pktType]; ok {
		return s
	}
	return ""
}

func (e *perfEvent) output() string {
	var s strings.Builder

	// time
	t := e.outputTimestamp()
	s.WriteString(fmt.Sprintf("[%-8s] ", t))

	// skb
	s.WriteString(fmt.Sprintf("[0x%-16x] ", e.Skb))

	// netns
	s.WriteString(fmt.Sprintf("[%-10d] ", e.NetNS))

	// pid
	s.WriteString(fmt.Sprintf("%-8d ", e.Pid))

	// cpu
	s.WriteString(fmt.Sprintf("%-6d ", e.CPU))

	// interface
	ifname := goebpf.NullTerminatedStringToString(e.Ifname[:])
	s.WriteString(fmt.Sprintf("%-18s ", ifname))

	// dest mac
	destMac := net.HardwareAddr(e.DestMac[:]).String()
	s.WriteString(fmt.Sprintf("%-18s ", destMac))

	// ip len
	s.WriteString(fmt.Sprintf("%-6d ", e.TotLen))

	// pkt info
	pktInfo := e.outputPktInfo()
	s.WriteString(fmt.Sprintf("%-54s ", pktInfo))

	// trace info
	traceInfo := e.outputTraceInfo()
	s.WriteString(traceInfo)

	return s.String()
}
