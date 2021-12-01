package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"

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

func (p *bpfProgram) storeConfig() error {
	if p.err != nil {
		return p.err
	}

	m := p.bpf.GetMapByName("skbtracer_cfg")
	if m == nil {
		return fmt.Errorf("bpf map(tracer_cfg) not found")
	}

	update := func(k byte, v uint64, key string) error {
		err := m.Upsert(k, v)
		if err != nil {
			err = fmt.Errorf("failed to store bpf config(%s), err: %w", key, err)
		}
		return err
	}
	bool2uint64 := func(b bool) uint64 {
		if b {
			return 1
		}
		return 0
	}

	configs := []struct {
		name string
		k    byte
		v    uint64
	}{
		{"pid", 1, uint64(cfg.Pid)},
		{"ip", 2, uint64(ip2uint32(cfg.IP))},
		{"port", 3, uint64(cfg.Port)},
		{"icmpid", 4, uint64(cfg.IcmpID)},
		{"dropstack", 5, bool2uint64(cfg.DropStack)},
		{"callstack", 6, bool2uint64(cfg.CallStack)},
		{"iptable", 7, bool2uint64(cfg.Iptable)},
		{"noroute", 8, bool2uint64(cfg.NoRoute)},
		{"keep", 9, bool2uint64(cfg.Keep)},
		{"proto", 10, uint64(cfg.proto)},
		{"netns", 11, uint64(cfg.NetNS)},
	}
	for _, c := range configs {
		if c.v != 0 {
			if err := update(c.k, c.v, c.name); err != nil {
				return err
			}
		}
	}

	return nil
}

func ip2uint32(ip string) uint32 {
	_ip := net.ParseIP(ip).To4()
	if _ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(_ip)
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
