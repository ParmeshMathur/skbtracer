# skbtracer

skbtracer 基于 ebpf 技术的 skb 网络包路径追踪利器， 参考 Python 版本 [skbtracer](https://github.com/DavadDi/skbtracer) 实现的一个 Go 版本，代码基于 [goebpf](https://github.com/dropbox/goebpf) , [libbpf-bootstrap](https://github.com/libbpf/libbpf-bootstrap) (required Linux Kernel 4.15+ with CONFIG_DEBUG_INFO_BTF=y, Go 1.16+)。

## 使用样例

```bash
$ ./skbtracer -h
examples:
skbtracer                                      # trace all packets
skbtracer --proto=icmp -H 1.2.3.4 --icmpid 22  # trace icmp packet with addr=1.2.3.4 and icmpid=22
skbtracer --proto=tcp  -H 1.2.3.4 -P 22        # trace tcp  packet with addr=1.2.3.4:22
skbtracer --proto=udp  -H 1.2.3.4 -P 22        # trace udp  packet wich addr=1.2.3.4:22
skbtracer -t -T -p 1 -P 80 -H 127.0.0.1 --proto=tcp --callstack --icmpid=100 -N 10000

Usage:
  skbtracer [flags]

Flags:
      --callstack          output kernel stack trace (DEPRECATED: not implemented to print the function stack)
  -c, --catch-count uint   catch and print count (default 1000)
      --dropstack          output kernel stack trace when drop packet (DEPRECATED: not supported on Ubuntu 18.04.5 LTS with kernel 5.10.29-051029-generic)
  -h, --help               help for skbtracer
      --icmpid uint        trace icmp id
  -H, --ipaddr string      ip address
      --iptable            output iptable path
      --keep               keep trace packet all lifetime (DEPRECATED: not implemented yet)
  -N, --netns uint         trace this Network Namespace only
      --noroute            do not output route path
  -p, --pid uint           trace this PID only
  -P, --port uint          udp or tcp port
      --proto string       tcp|udp|icmp|any
  -T, --time               show HH:MM:SS timestamp (default true)
  -t, --timestamp          show timestamp in seconds at us resolution
```

运行效果

```bash
$ sudo ./skbtracer -c 10
TIME       NETWORK_NS   CPU    INTERFACE          DEST_MAC           IP_LEN PKT_INFO                                               TRACE_INFO
[13:43:45] [0         ] 3      nil                00:00:00:00:00:00  168    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b3ae0.0:ip_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  168    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b3ae0.0:ip_finish_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  168    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b3ae0.0:__dev_queue_xmit
[13:43:45] [0         ] 3      nil                00:00:00:00:00:00  248    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b36e0.0:ip_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  248    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b36e0.0:ip_finish_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  248    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b36e0.0:__dev_queue_xmit
[13:43:45] [0         ] 3      nil                00:00:00:00:00:00  120    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b2ce0.0:ip_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  120    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b2ce0.0:ip_finish_output
[13:43:45] [0         ] 3      ens18              00:00:00:00:00:00  120    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b2ce0.0:__dev_queue_xmit
[13:43:45] [0         ] 3      nil                00:00:00:00:00:00  120    T_ACK,PSH:10.0.1.10:22->10.0.4.15:55343                ffff9a271b1b30e0.0:ip_output

15 event(s) received
0 event(s) lost (e.g. small buffer, delays in processing)
```

## 功能增强

1. 调整基于抓取数量的实现（更加精准，避免了部分环境下异常被忽略）
2. 增加了 ip 长度的字段
3. 增加了运行 cpu 的字段

本文代码来自于 [gist](https://gist.github.com/chendotjs/194768c411f15ecfec11e7235c435fa0)

更通用的网络方案参见仓库 [WeaveWorks tcptracer-bpf](https://github.com/weaveworks/tcptracer-bpf)

## 相关文档

* [使用 ebpf 深入分析容器网络 dup 包问题](https://blog.csdn.net/alex_yangchuansheng/article/details/104058072)
* [使用 Linux tracepoint、perf 和 eBPF 跟踪数据包 (2017)](https://github.com/DavadDi/bpf_study/blob/master/trace-packet-with-tracepoint-perf-ebpf/index_zh.md)

## TODO

- [ ] 打印函数调用栈，需要根据地址找到对应的函数名称
- [ ] 支持 `kprobe deliver_clone`
- [ ] 支持 `kprobe __kfree_skb`

## 测试环境

Good:

- [x] Ubuntu 18.04.5 LTS, kernel 5.10.29-051029-generic
- [x] Ubuntu 21.04, kernel 5.11.0-25-generic, with CONFIG_DEBUG_INFO_BTF=m

Bad:

- Centos, kernel 4.19.163
- Ubuntu 18.04.3 LTS, kernel 4.19.0-9, no CONFIG_DEBUG_INFO_BTF=y

