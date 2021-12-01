package main

import (
	_ "embed"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

		if err := cfg.parse(); err != nil {
			fmt.Println(err)
			return
		}

		runGops()
		runEbpf()
	},
}

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

//go:embed skbtracer.elf
var bpfProg []byte

// runEbpf attaches the kprobes and prints the kprobes' info.
func runEbpf() {

	// cleanup old probes
	// if err := goebpf.CleanupProbes(); err != nil {
	// log.Println("failed to clean old probes, err:", err)
	// }

	bpf, err := newBpfProgram(bpfProg)
	if err != nil {
		fmt.Println("failed to new bpf program, err:", err)
		return
	}

	if err := bpf.start(); err != nil {
		fmt.Println("failed to start, err:", err)
		return
	}
	defer bpf.printStat()

	// wait until Ctrl+C pressed
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sig:
		fmt.Println("Received signal, exiting...")
		bpf.stop()
	case <-bpf.stopCh:
		fmt.Printf("Printed %d events, exiting...\n", cfg.CatchCount)
	}
}
