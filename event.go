package skbtracer

import (
	"encoding/binary"
	"fmt"
	"net"
	"unsafe"

	"github.com/dropbox/goebpf"
)

type bpfEvent struct {
	FuncName [64]byte
	Flags    byte
	CPU      byte
	_pad     [2]byte

	KernelStackID int32

	Ifname [16]byte
	NetNS  uint32

	Len       uint32
	DestMac   [6]byte
	IPVersion byte
	L4Proto   byte
	Saddr     [16]byte // network byte order
	Daddr     [16]byte // network byte order
	TotLen    [2]byte  // network byte order
	ICMPID    [2]byte  // network byte order
	ICMPSeq   [2]byte  // network byte order
	Sport     [2]byte  // network byte order
	Dport     [2]byte  // network byte order
	TCPFlags  [2]byte  // network byte order
	ICMPType  byte
	PktType   byte
	_pad1     byte

	Pf        byte
	Hook      uint32
	Verdict   uint32
	TableName [32]byte
	IptDelay  uint64

	Skb uint64

	StartNs uint64
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
	be := binary.BigEndian // network byte order is big endian

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
		Sport:     int(be.Uint16(e.Sport[:])),
		Dport:     int(be.Uint16(e.Dport[:])),
		IPVersion: e.IPVersion,
		L4Proto:   e.L4Proto,
		TotLen:    be.Uint16(e.TotLen[:]),
		IcmpID:    b2uint16(e.ICMPID),
		IcmpSeq:   b2uint16(e.ICMPSeq),
		IcmpType:  e.ICMPType,
		PktType:   e.PktType,
		TCPFlags:  e.TCPFlags[0],
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
	CPU      uint8
	_pad     [6]byte

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
