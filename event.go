package skbtracer

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/dropbox/goebpf"
)

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
	TCPFlags uint8
	l4pad    [3]byte
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

type bpfEvent struct {
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

const sizeofEvent = int(unsafe.Sizeof(bpfEvent{}))

func (e *bpfEvent) unmarshal(data []byte) error {
	if sizeofEvent > len(data) {
		return fmt.Errorf("event: not enough data to unmarshal, got %d bytes, expected %d bytes",
			len(data), sizeofEvent)
	}

	ev := *(*bpfEvent)(unsafe.Pointer(&data[0]))
	*e = ev
	return nil
}

func b2uint16(b [2]byte) uint16 {
	var v uint16
	v = *(*uint16)(unsafe.Pointer(&b[0]))
	return v
}

func (e *bpfEvent) toEvent() *Event {
	var saddr, daddr net.IP
	if e.IPVersion == 4 {
		saddr, daddr = net.IP(e.Saddr[:4]), net.IP(e.Daddr[:4])
	} else {
		saddr, daddr = net.IP(e.Saddr[:]), net.IP(e.Daddr[:])
	}

	return &Event{
		FuncName:  goebpf.NullTerminatedStringToString(e.FuncName[:]),
		Flags:     e.Flags,
		CPU:       e.CPU,
		Ifname:    goebpf.NullTerminatedStringToString(e.Ifname[:]),
		NetNS:     e.NetNS,
		Len:       e.Len,
		DestMac:   net.HardwareAddr(e.DestMac[:]),
		Saddr:     saddr,
		Daddr:     daddr,
		Sport:     int(e.Sport),
		Dport:     int(e.Dport),
		IPVersion: e.IPVersion,
		L4Proto:   e.L4Proto,
		TotLen:    e.TotLen,
		IcmpID:    e.IcmpID,
		IcmpSeq:   e.IcmpSeq,
		IcmpType:  e.IcmpType,
		PktType:   e.PktType,
		TCPFlags:  e.TCPFlags,
		Pf:        e.Pf,
		Hook:      e.Hook,
		Verdict:   e.Verdict,
		TableName: goebpf.NullTerminatedStringToString(e.TableName[:]),
		IptDelay:  e.IptDelay,
		Skb:       e.Skb,
		StartNs:   e.StartNs,
	}
}

// Event an event is some information emited from bpf program.
type Event struct {
	FuncName string
	Flags    uint8
	CPU      uint32

	Ifname string
	NetNS  uint32

	Len          uint32
	DestMac      net.HardwareAddr
	Saddr, Daddr net.IP
	Sport, Dport int
	IPVersion    uint8
	L4Proto      uint8
	TotLen       uint16
	IcmpID       uint16
	IcmpSeq      uint16
	IcmpType     uint8
	TCPFlags     uint8
	PktType      uint8

	// iptable
	Pf        uint8
	_pad1     uint32
	Hook      uint32
	Verdict   uint32
	TableName string
	IptDelay  uint64

	Skb uint64

	StartNs uint64

	CallStack []byte
}
