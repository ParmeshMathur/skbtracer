// Reference: github.com/dropbox/goebpf/examples/kprobe/exec_dump

package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"

	"github.com/Asphaltt/skbtracer"
	"github.com/spf13/cobra"
)

var usage = `examples:
skbtracer                                      # trace all packets
skbtracer --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
skbtracer --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
skbtracer --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
skbtracer -t -T -p 1 -P 80 -H 127.0.0.1 --proto=tcp --callstack --icmpid=100 -N 10000
`

var rootCmd = cobra.Command{
	Use:   "skbtracer",
	Short: "Trace any packet through TCP/IP stack",
	Long:  usage,
	Run: func(cmd *cobra.Command, args []string) {
		if err := parseConfig(); err != nil {
			fmt.Println("failed to parse cmdline params, err:", err)
			return
		}

		fmt.Printf("run with config: %+v\n", gCfg.Config)

		runBpf()
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

//go:embed skbtracer.elf
var bpfProg []byte

// runBpf attaches the kprobes and prints the kprobes' info.
func runBpf() {

	// cleanup old probes
	// if err := goebpf.CleanupProbes(); err != nil {
	// 	log.Println(err)
	// }

	ev, stop, err := skbtracer.Start(bpfProg, &gCfg.Config)
	if err != nil {
		log.Fatalf("failed to start skbtracer, err: %v", err)
	}

	sig := make(chan os.Signal, 1)
	go handleEvent(ev, sig)

	// wait until Ctrl+C pressed
	signal.Notify(sig, os.Interrupt)
	<-sig
	stop()

	// display some stats
	stat := skbtracer.GetEventStat()
	fmt.Println()
	fmt.Printf("%d event(s) received\n", stat.Received)
	fmt.Printf("%d event(s) lost (e.g. small buffer, delays in processing)\n", stat.Lost)
}

func handleEvent(ch <-chan *skbtracer.Event, sig chan os.Signal) {
	fmt.Printf("%-10s %-12s %-6s %-18s %-18s %-6s %-54s %s\n",
		"TIME", "NETWORK_NS", "CPU", "INTERFACE", "DEST_MAC", "IP_LEN",
		"PKT_INFO", "TRACE_INFO")
	for n := gCfg.CatchCount; n != 0; n-- {
		ev, ok := <-ch
		if !ok {
			return
		}

		fmt.Println((*bpfEvent)(ev).String())
		// if len(ev.CallStack) != 0 {
		// 	spew.Dump(ev.CallStack)
		// }
	}

	sig <- os.Interrupt

	for {
		// Note: try to receive from the channel, or it will trap in
		// sending event to the channel.
		_, ok := <-ch
		if !ok {
			return
		}

		runtime.Gosched()
	}
}
