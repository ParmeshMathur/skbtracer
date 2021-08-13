package main

import (
	"fmt"

	"github.com/Asphaltt/skbtracer"
)

type ebpfConfig struct {
	skbtracer.Config
	CatchCount uint64
	Time       bool
	Timestamp  bool
}

var gCfg ebpfConfig

func init() {
	fs := rootCmd.PersistentFlags()
	fs.StringVarP(&gCfg.IP, "ipaddr", "H", "", "ip address")
	fs.StringVar(&gCfg.Proto, "proto", "", "tcp|udp|icmp|any")
	fs.Uint64Var(&gCfg.IcmpID, "icmpid", 0, "trace icmp id")
	fs.Uint64VarP(&gCfg.CatchCount, "catch-count", "c", 1000, "catch and print count")
	fs.Uint64VarP(&gCfg.Port, "port", "P", 0, "udp or tcp port")
	fs.Uint64VarP(&gCfg.Pid, "pid", "p", 0, "trace this PID only")
	fs.Uint64VarP(&gCfg.NetNS, "netns", "N", 0, "trace this Network Namespace only")
	fs.BoolVar(&gCfg.DropStack, "dropstack", false, "output kernel stack trace when drop packet")
	fs.BoolVar(&gCfg.CallStack, "callstack", false, "output kernel stack trace")
	fs.BoolVar(&gCfg.Iptable, "iptable", false, "output iptable path")
	fs.BoolVar(&gCfg.NoRoute, "noroute", false, "do not output route path")
	fs.BoolVar(&gCfg.Keep, "keep", false, "keep trace packet all lifetime")
	fs.BoolVarP(&gCfg.Time, "time", "T", true, "show HH:MM:SS timestamp")
	fs.BoolVarP(&gCfg.Timestamp, "timestamp", "t", false, "show timestamp in seconds at us resolution")

	fs.Lookup("dropstack").Deprecated = "not supported on Ubuntu 18.04.5 LTS with kernel 5.10.29-051029-generic"
	fs.Lookup("callstack").Deprecated = "not implemented to print the function stack"
	fs.Lookup("keep").Deprecated = "not implemented yet"
}

func parseConfig() error {

	if gCfg.CatchCount == 0 {
		return fmt.Errorf("catch-count cannot be zero")
	}

	return nil
}
