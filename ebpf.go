package skbtracer

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"github.com/dropbox/goebpf"
)

var (
	eventReceived uint64
	eventLost     uint64
	eventAbnormal uint64
)

// EventStat is the statistics of bpf perf event.
type EventStat struct {
	Received uint64
	Lost     uint64
	Abnormal uint64
}

// GetEventStat you should get event stat after the cancel function calling.
func GetEventStat() EventStat {
	return EventStat{eventReceived, eventLost, eventAbnormal}
}

type bpfProgram struct {
	bpf goebpf.System
	pe  *goebpf.PerfEvents
	wg  sync.WaitGroup

	ev   chan *Event
	stop chan struct{}

	withCallstack bool
}

// Start loads bpf programs from bpfProg with config.
// It loads the kprobes from bpfProg, and attaches the kprobes into the kernel.
// Return an event channel and a cancel function, the cancel funtion is for
// detaching the kprobes from the kernel.
func Start(bpfProg []byte, c *Config) (<-chan *Event, func(), error) {
	bp, err := loadProgram(bpfProg, c)
	if err != nil {
		return nil, nil, err
	}

	return bp.ev, bp.detachProbes, nil
}

func loadProgram(bpfProg []byte, c *Config) (*bpfProgram, error) {

	// create system
	bpf := goebpf.NewDefaultEbpfSystem()

	// load compiled ebpf elf file
	if err := bpf.Load(bytes.NewReader(bpfProg)); err != nil {
		return nil, fmt.Errorf("failed to load elf file, err: %w", err)
	}

	// load programs
	for _, prog := range bpf.GetPrograms() {
		if err := prog.Load(); err != nil {
			return nil, fmt.Errorf("failed to load prog(%s), err: %w",
				prog.GetName(), err)
		}
	}

	var bp bpfProgram
	bp.bpf = bpf
	bp.ev = make(chan *Event)
	bp.stop = make(chan struct{})
	bp.withCallstack = c.CallStack

	err := bp.storeConfig(c)
	if err != nil {
		return nil, fmt.Errorf("failed to store config, err: %w", err)
	}

	if err := bp.attachProbes(c); err != nil {
		return nil, fmt.Errorf("failed to attach kprobes, err: %w", err)
	}

	return &bp, nil
}

func (p *bpfProgram) storeConfig(c *Config) error {
	if err := c.parse(); err != nil {
		return err
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
		{"pid", 1, uint64(c.Pid)},
		{"ip", 2, uint64(c.ip)},
		{"port", 3, uint64(c.Port)},
		{"icmpid", 4, uint64(c.IcmpID)},
		{"dropstack", 5, bool2uint64(c.DropStack)},
		{"callstack", 6, bool2uint64(c.CallStack)},
		{"iptable", 7, bool2uint64(c.Iptable)},
		{"noroute", 8, bool2uint64(c.NoRoute)},
		{"keep", 9, bool2uint64(c.Keep)},
		{"proto", 10, uint64(c.proto)},
		{"netns", 11, uint64(c.NetNS)},
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

func (p *bpfProgram) startPerfEvents(events <-chan []byte) {
	p.wg.Add(1)
	go func(events <-chan []byte) {
		defer p.wg.Done()

		for {
			var data []byte
			select {
			case <-p.stop:
				return
			case b, ok := <-events:
				if !ok {
					return
				}
				data = b
			}

			var ev bpfEvent
			err := ev.unmarshal(data)
			if err != nil {
				eventAbnormal++
				continue
			}

			e := ev.toEvent()
			p.getCallStack(ev.KernelStackID, e)

			select {
			case p.ev <- e:
			case <-p.stop:
				return
			}
		}
	}(events)
}

func (p *bpfProgram) getCallStack(id int32, e *Event) {

	if !p.withCallstack || id < 0 {
		return
	}

	m := p.bpf.GetMapByName("skbtracer_stack")
	if m == nil {
		return
	}

	e.CallStack, _ = m.Lookup(id)
}

func (p *bpfProgram) stopPerfEvents() {
	p.pe.Stop()
	close(p.stop)
	p.wg.Wait()

	eventReceived = uint64(p.pe.EventsReceived)
	eventLost = uint64(p.pe.EventsLost)
}

func (p *bpfProgram) attachProbes(c *Config) error {

	// attach all probe programs
	for _, prog := range p.bpf.GetPrograms() {
		progName:=prog.GetName()

		// filter route
		if c.NoRoute && strings.HasPrefix(progName, "k_") {
			continue
		}

		// filter iptables
		if !c.Iptable && strings.HasPrefix(progName, "ipt_") {
			continue
		}

		if err := prog.Attach(nil); err != nil {
			return fmt.Errorf("failed to attach prog(%s), err: %w",
				progName, err)
		}
	}

	// get handles to perf event map
	m := p.bpf.GetMapByName("skbtracer_event")
	if m == nil {
		return fmt.Errorf("bpf map(skbtracer_event) not found")
	}

	// create perf events
	var err error
	p.pe, err = goebpf.NewPerfEvents(m)
	if err != nil {
		return fmt.Errorf("failed to new perf-event, err: %w", err)
	}
	events, err := p.pe.StartForAllProcessesAndCPUs(4096)
	if err != nil {
		return fmt.Errorf("failed to start perf-event, err: %w", err)
	}

	// start event listeners
	p.startPerfEvents(events)

	return nil
}

func (p *bpfProgram) detachProbes() {
	p.stopPerfEvents()
	for _, prog := range p.bpf.GetPrograms() {
		prog.Detach()
		prog.Close()
	}
}
