package main

import (
	"bytes"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/dropbox/goebpf"
)

type bpfProgram struct {
	bpf goebpf.System
	pe  *goebpf.PerfEvents
	wg  sync.WaitGroup

	stopCh chan struct{}

	err error
}

func newBpfProgram(bpfProg []byte) (*bpfProgram, error) {

	// create system
	bpf := goebpf.NewDefaultEbpfSystem()

	// load compiled ebpf elf file
	if err := bpf.Load(bytes.NewReader(bpfProg)); err != nil {
		return nil, fmt.Errorf("failed to load elf file, err: %w", err)
	}

	var bp bpfProgram
	bp.bpf = bpf
	bp.stopCh = make(chan struct{})

	return &bp, nil
}

func (p *bpfProgram) start() error {

	p.err = p.storeConfig()
	p.err = p.loadPrograms()
	p.err = p.attachProbes()
	p.err = p.startPerfEvent()

	return p.err
}

func (p *bpfProgram) filterBpfProg(progName string) bool {

	// filter route
	if cfg.NoRoute && strings.HasPrefix(progName, "k_") {
		return true
	}

	// filter iptables
	if !cfg.Iptable && strings.HasPrefix(progName, "ipt_") {
		return true
	}

	return false
}

func (p *bpfProgram) loadPrograms() error {
	if p.err != nil {
		return p.err
	}

	for _, prog := range p.bpf.GetPrograms() {
		progName := prog.GetName()
		if p.filterBpfProg(progName) {
			continue
		}

		if err := prog.Load(); err != nil {
			return fmt.Errorf("failed to load prog(%s), err: %w",
				progName, err)
		}
	}

	return nil
}

type BpfConfig struct {
	NetNS     uint32
	Pid       uint32
	IP        uint32
	Port      uint16
	IcmpID    uint16
	DropStack uint8
	CallStack uint8
	Keep      uint8
	Proto     uint8
}

const sizeOfBpfConfig = int(unsafe.Sizeof(BpfConfig{}))

func (p *bpfProgram) storeConfig() error {
	if p.err != nil {
		return p.err
	}

	m := p.bpf.GetMapByName("skbtracer_cfg")
	if m == nil {
		return fmt.Errorf("bpf map(tracer_cfg) not found")
	}

	bool2uint8 := func(b bool) uint8 {
		if b {
			return 1
		}
		return 0
	}

	bc := BpfConfig{
		NetNS:     cfg.NetNS,
		Pid:       cfg.Pid,
		IP:        cfg.ip,
		Port:      (cfg.Port >> 8) & (cfg.Port << 8),
		IcmpID:    (cfg.IcmpID >> 8) & (cfg.IcmpID << 8),
		DropStack: bool2uint8(cfg.DropStack),
		CallStack: bool2uint8(cfg.CallStack),
		Keep:      bool2uint8(cfg.Keep),
		Proto:     cfg.proto,
	}

	var h reflect.SliceHeader
	h.Data = uintptr(unsafe.Pointer(&bc))
	h.Len = sizeOfBpfConfig
	h.Cap = sizeOfBpfConfig
	val := *(*[]byte)(unsafe.Pointer(&h))

	err := m.Upsert(uint32(0), val)
	if err != nil {
		return fmt.Errorf("failed to update bpf config, err: %w", err)
	}

	return nil
}

func (p *bpfProgram) attachProbes() error {
	if p.err != nil {
		return p.err
	}

	// attach all probe programs
	for _, prog := range p.bpf.GetPrograms() {
		progName := prog.GetName()
		if p.filterBpfProg(progName) {
			continue
		}

		if err := prog.Attach(nil); err != nil {
			return fmt.Errorf("failed to attach prog(%s), err: %w",
				progName, err)
		}
	}

	return nil
}

func (p *bpfProgram) startPerfEvent() (err error) {
	if p.err != nil {
		return p.err
	}

	defer func() {
		if err != nil {
			p.detachProbes()
		}
	}()

	// get handles to perf event map
	m := p.bpf.GetMapByName("skbtracer_event")
	if m == nil {
		return fmt.Errorf("bpf map(skbtracer_event) not found")
	}

	// create perf events
	p.pe, err = goebpf.NewPerfEvents(m)
	if err != nil {
		return fmt.Errorf("failed to new perf-event, err: %w", err)
	}
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		return fmt.Errorf("failed to start perf-event, err: %w", err)
	}

	// start event listeners
	p.recvPerfEvent(events)

	return nil
}

func (p *bpfProgram) recvPerfEvent(events <-chan []byte) {

	p.wg.Add(1)
	go func(events <-chan []byte) {

		fmt.Printf("%-10s %-20s %-12s %-8s %-6s %-18s %-18s %-6s %-54s %s\n",
			"TIME", "SKB", "NETWORK_NS", "PID", "CPU", "INTERFACE", "DEST_MAC", "IP_LEN",
			"PKT_INFO", "TRACE_INFO")

		runForever := cfg.CatchCount == 0
		for i := cfg.CatchCount; i > 0 || runForever; i-- {
			var data []byte
			select {
			case <-p.stopCh:
				break
			case b, ok := <-events:
				if !ok {
					break
				}
				data = b
			}

			var ev perfEvent
			err := ev.unmarshal(data)
			if err != nil {
				continue
			}

			fmt.Println(ev.output())

			callStack := p.getCallStack(ev.KernelStackID)
			if len(callStack) != 0 {
				// TODO: deal callstack
				_ = callStack
			}

			select {
			case <-p.stopCh:
				break
			default:
			}
		}

		go func() {
			for range events {
			}
		}()

		p.wg.Done()
		p.stop()
	}(events)
}

func (p *bpfProgram) getCallStack(id int32) []byte {

	if !cfg.CallStack || id < 0 {
		return nil
	}

	m := p.bpf.GetMapByName("skbtracer_stack")
	if m == nil {
		return nil
	}

	callStack, _ := m.Lookup(id)
	return callStack
}

var stopOnce sync.Once
var stopping uint32

func (p *bpfProgram) stop() {

	if !atomic.CompareAndSwapUint32(&stopping, 0, 1) {
		return
	}

	stopOnce.Do(func() {

		p.pe.Stop()
		close(p.stopCh)
		p.wg.Wait()

		p.detachProbes()
	})
}

func (p *bpfProgram) detachProbes() {
	for _, prog := range p.bpf.GetPrograms() {
		prog.Detach()
		prog.Close()
	}
}

func (p *bpfProgram) printStat() {

	fmt.Println()
	fmt.Printf("%d event(s) received\n", p.pe.EventsReceived)
	fmt.Printf("%d event(s) lost (e.g. small buffer, delays in processing)\n", p.pe.EventsLost)
}
