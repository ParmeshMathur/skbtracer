package main

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Asphaltt/skbtracer"
)

const (
	ipprotoICMP = 1
	ipprotoTCP  = 6
	ipprotoUDP  = 17
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

func _get(names []string, idx uint32, dflt string) string {
	if int(idx) < len(names) {
		return names[idx]
	}
	return dflt
}

var earliestTs = uint64(0)

type bpfEvent skbtracer.Event

func (e *bpfEvent) timestamp() string {
	if gCfg.Timestamp {
		if earliestTs == 0 {
			earliestTs = e.StartNs
		}
		return fmt.Sprintf("%-7.6f", float64(e.StartNs-earliestTs)/1000000000.0)
	}
	return time.Unix(0, int64(e.StartNs)).Format("15:04:05")
}

func (e *bpfEvent) tcpFlags() string {
	var flags []string
	tcpFlags := e.TCPFlags
	for i := 0; i < len(tcpFlagNames); i++ {
		if tcpFlags&(1<<i) != 0 {
			flags = append(flags, tcpFlagNames[i])
		}
	}
	return strings.Join(flags, ",")
}

func (e *bpfEvent) pktInfo() string {
	if e.L4Proto == ipprotoTCP {
		tcpFlags := e.tcpFlags()
		return fmt.Sprintf("T_%s:%s:%d->%s:%d", tcpFlags,
			e.Saddr, e.Sport, e.Daddr, e.Dport)
	} else if e.L4Proto == ipprotoUDP {
		return fmt.Sprintf("U:%s:%d->%s:%d",
			e.Saddr, e.Sport, e.Daddr, e.Dport)
	} else if e.L4Proto == ipprotoICMP {
		if e.IcmpType == 8 || e.IcmpType == 128 {
			return fmt.Sprintf("I_request:%s->%s", e.Saddr, e.Daddr)
		} else if e.IcmpType == 0 || e.IcmpType == 129 {
			return fmt.Sprintf("I_reply:%s->%s", e.Saddr, e.Daddr)
		} else {
			return fmt.Sprintf("I:%s->%s", e.Saddr, e.Daddr)
		}
	} else {
		return fmt.Sprintf("%d:%s->%s", e.L4Proto, e.Saddr, e.Daddr)
	}
}

func (e *bpfEvent) traceInfo() string {
	iptables := ""
	if e.Flags&routeEventIptable == routeEventIptable {
		verdict := _get(nfVerdictName, e.Verdict, "~UNK~")
		hook := _get(hookNames, e.Hook, "~UNK~")
		iptName := e.TableName
		iptables = fmt.Sprintf("%d.%s.%s.%s ", e.Pf, iptName, hook, verdict)
	}

	funcName := e.FuncName
	return fmt.Sprintf("%x.%d:%s%s", e.Skb, e.PktType, iptables, funcName)
}

func (e *bpfEvent) String() string {
	var s strings.Builder

	// time
	t := e.timestamp()
	s.WriteString(fmt.Sprintf("[%-8s] ", t))

	// netns
	s.WriteString(fmt.Sprintf("[%-10d] ", e.NetNS))

	// cpu
	s.WriteString(fmt.Sprintf("%-6d ", e.CPU))

	// interface
	ifname := e.Ifname
	s.WriteString(fmt.Sprintf("%-18s ", ifname))

	// dest mac
	destMac := net.HardwareAddr(e.DestMac[:]).String()
	s.WriteString(fmt.Sprintf("%-18s ", destMac))

	// ip len
	s.WriteString(fmt.Sprintf("%-6d ", e.TotLen))

	// pkt info
	pktInfo := e.pktInfo()
	s.WriteString(fmt.Sprintf("%-54s ", pktInfo))

	// trace info
	traceInfo := e.traceInfo()
	s.WriteString(traceInfo)

	return s.String()
}
