#include "skbtracer.h"

INLINE void get_stack(struct pt_regs *ctx, struct event_t *event)
{
    event->kernel_stack_id = bpf_get_stackid(ctx, &stacks, 0);
    return;
}

INLINE int _has_callstack(void)
{
    return 0 != get_cfg_callstack();
}

#define CALL_STACK(ctx, event)     \
    do                             \
    {                              \
        if (_has_callstack())      \
            get_stack(ctx, event); \
    } while (0)

INLINE void bpf_strncpy(char *dst, const char *src, int n)
{
    int i = 0, j;
#define CPY(n)               \
    do                       \
    {                        \
        for (; i < n; i++)   \
        {                    \
            if (src[i] == 0) \
                return;      \
            dst[i] = src[i]; \
        }                    \
    } while (0)

    for (j = 10; j < 64; j += 10)
        CPY(j);
    CPY(64);
#undef CPY
}

/**
  * Common tracepoint handler. Detect IPv4/IPv6 and
  * emit event with address, interface and namespace.
  */
INLINE int
do_trace_skb(struct event_t *event, void *ctx, struct sk_buff *skb, void *netdev)
{
    struct net_device *dev;

    char *head;
    char *l2_header_address;
    char *l3_header_address;
    char *l4_header_address;

    __u16 mac_header;
    __u16 network_header;

    __u8 proto_icmp_echo_request;
    __u8 proto_icmp_echo_reply;
    __u8 l4_offset_from_ip_header;

    struct icmphdr icmphdr;
    union tcp_word_hdr tcphdr;
    struct udphdr udphdr;

    // Get device pointer, we'll need it to get the name and network namespace
    event->ifname[0] = 0;
    if (netdev)
        dev = netdev;
    else
        member_read(&dev, skb, dev);

    bpf_probe_read(&event->ifname, IFNAMSIZ, dev->name);

    if (event->ifname[0] == 0 || dev == NULL)
        bpf_strncpy(event->ifname, "nil", IFNAMSIZ);

    event->flags |= ROUTE_EVENT_IF;

#ifdef CONFIG_NET_NS
    struct net *net;

    // Get netns id. The code below is equivalent to: event->netns = dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common *ns = member_address(net, ns);
    member_read(&event->netns, ns, inum);

    // maybe the skb->dev is not init, for this situation, we can get ns by sk->__sk_common.skc_net.net->ns.inum
    if (event->netns == 0)
    {
        struct sock *sk;
        struct sock_common __sk_common;
        struct ns_common *ns2;
        member_read(&sk, skb, sk);
        if (sk != NULL)
        {
            member_read(&__sk_common, sk, __sk_common);
            ns2 = member_address(__sk_common.skc_net.net, ns);
            member_read(&event->netns, ns2, inum);
        }
    }

#endif
    event->cpu = bpf_get_smp_processor_id();
    member_read(&event->len, skb, len);
    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);

    if (network_header == 0)
    {
        network_header = mac_header + MAC_HEADER_SIZE;
    }

    l2_header_address = mac_header + head;
    bpf_probe_read(&event->dest_mac, 6, l2_header_address);

    l3_header_address = head + network_header;
    bpf_probe_read(&event->ip_version, sizeof(__u8), l3_header_address);
    event->ip_version = event->ip_version >> 4 & 0xf;

    if (event->ip_version == 4)
    {
        struct iphdr iphdr;
        bpf_probe_read(&iphdr, sizeof(iphdr), l3_header_address);

        l4_offset_from_ip_header = iphdr.ihl * 4;
        event->l4_proto = iphdr.protocol;
        event->saddr[0] = iphdr.saddr;
        event->daddr[0] = iphdr.daddr;
        event->tot_len = (iphdr.tot_len);

        if (event->l4_proto == IPPROTO_ICMP)
        {
            proto_icmp_echo_request = ICMP_ECHO;
            proto_icmp_echo_reply = ICMP_ECHOREPLY;
        }
    }
    else if (event->ip_version == 6)
    {
        // Assume no option header --> fixed size header
        struct ipv6hdr *ipv6hdr = (struct ipv6hdr *)l3_header_address;
        l4_offset_from_ip_header = sizeof(*ipv6hdr);

        bpf_probe_read(&event->l4_proto, sizeof(ipv6hdr->nexthdr), (char *)ipv6hdr + offsetof(struct ipv6hdr, nexthdr));
        bpf_probe_read(event->saddr, sizeof(ipv6hdr->saddr), (char *)ipv6hdr + offsetof(struct ipv6hdr, saddr));
        bpf_probe_read(event->daddr, sizeof(ipv6hdr->daddr), (char *)ipv6hdr + offsetof(struct ipv6hdr, daddr));
        bpf_probe_read(&event->tot_len, sizeof(ipv6hdr->payload_len), (char *)ipv6hdr + offsetof(struct ipv6hdr, payload_len));
        event->tot_len = (event->tot_len);

        if (event->l4_proto == IPPROTO_ICMPV6)
        {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply = ICMPV6_ECHO_REPLY;
        }
    }
    else
    {
        return -1;
    }

    l4_header_address = l3_header_address + l4_offset_from_ip_header;
    switch (event->l4_proto)
    {
    case IPPROTO_ICMPV6:
    case IPPROTO_ICMP:
        bpf_probe_read(&icmphdr, sizeof(icmphdr), l4_header_address);
        if (icmphdr.type != proto_icmp_echo_request && icmphdr.type != proto_icmp_echo_reply)
        {
            return -1;
        }
        event->icmptype = icmphdr.type;
        event->icmpid = (icmphdr.un.echo.id);
        event->icmpseq = (icmphdr.un.echo.sequence);
        break;
    case IPPROTO_TCP:
        bpf_probe_read(&tcphdr, sizeof(tcphdr), l4_header_address);
        init_tcpflags_bits(event->tcpflags, tcp_flag_word(&tcphdr));
        event->sport = (tcphdr.hdr.source);
        event->dport = (tcphdr.hdr.dest);
        break;
    case IPPROTO_UDP:
        bpf_probe_read(&udphdr, sizeof(udphdr), l4_header_address);
        event->sport = (udphdr.source);
        event->dport = (udphdr.dest);
        break;
    default:
        return -1;
    }

    /*
     * netns filter
     */
    __u64 _cfg_netns = get_cfg_netns();
    if (0 != _cfg_netns && event->netns != 0 && event->netns != _cfg_netns)
    {
        return -1;
    }

    /*
     * pid filter
     */
    __u64 tgid = bpf_get_current_pid_tgid() >> 32;
    __u64 _cfg_pid = get_cfg_pid();
    if (0 != _cfg_pid && tgid != _cfg_pid)
        return -1;

    /*
     * skb filter
     */
    __u64 _cfg_ipaddr = get_cfg_ip();
    if (event->ip_version == 4)
    {
        if (0 != _cfg_ipaddr && _cfg_ipaddr != event->saddr[0] && _cfg_ipaddr != event->daddr[0])
            return -1;
    }
    else
    {
        return -1;
    }

    __u64 _cfg_proto = get_cfg_proto();
    if (0 != _cfg_proto && _cfg_proto != event->l4_proto)
        return -1;

    __u16 _cfg_port = (__u16)get_cfg_port();
    if ((event->l4_proto == IPPROTO_UDP || event->l4_proto == IPPROTO_TCP) &&
        (0 != _cfg_port && _cfg_port != event->sport && _cfg_port != event->dport))
        return -1;

    __u64 _cfg_icmpid = get_cfg_icmpid();
    if (0 != _cfg_proto && 0 != _cfg_icmpid && _cfg_proto == IPPROTO_ICMP && _cfg_icmpid != event->icmpid)
        return -1;

    return 0;
}

INLINE int
do_trace(void *ctx, struct sk_buff *skb, const char *func_name, void *netdev)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};
    __u64 _cfg_noroute = get_cfg_noroute();

    if (0 != _cfg_noroute)
        return 0;

    if (do_trace_skb(&event, ctx, skb, netdev) < 0)
        return 0;

    event.skb = (__u64)skb;
    bpf_probe_read(&type.value, 1, ((char *)skb) + offsetof(typeof(*skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;

    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, func_name, FUNCNAME_MAX_LEN);
    CALL_STACK(ctx, &event);
    bpf_perf_event_output(ctx, &route_event, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));

    return 0;
}

/*
 * netif rcv hook:
 * 1) int netif_rx(struct sk_buff *skb)
 * 2) int __netif_receive_skb(struct sk_buff *skb)
 * 3) gro_result_t napi_gro_receive(struct napi_struct *napi, struct sk_buff *skb)
 * 4) ...
 */
SEC("kprobe/netif_rx")
int k_netif_rx(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    return do_trace(ctx, skb, "netif_rx", NULL);
}

SEC("kprobe/__netif_receive_skb")
int k_nif_rcv_skb(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    return do_trace(ctx, skb, "__netif_receive_skb", NULL);
}

SEC("kprobe/tpacket_rcv")
int k_tpacket_rcv(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    GET_ARG(struct net_device *, orig_dev, args[3]);
    return do_trace(ctx, skb, "tpacket_rcv", orig_dev);
}

SEC("kprobe/packet_rcv")
int k_packet_rcv(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    GET_ARG(struct net_device *, orig_dev, args[3]);
    return do_trace(ctx, skb, "packet_rcv", orig_dev);
}

SEC("kprobe/napi_gro_receive")
int k_napi_gro_rcv(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "napi_gro_receive", NULL);
}

/*
 * netif send hook:
 * 1) int __dev_queue_xmit(struct sk_buff *skb, struct net_device *sb_dev)
 * 2) ...
 */

SEC("kprobe/__dev_queue_xmit")
int k_dev_q_xmit(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    return do_trace(ctx, skb, "__dev_queue_xmit", NULL);
}

/*
 * br process hook:
 * 1) rx_handler_result_t br_handle_frame(struct sk_buff **pskb)
 * 2) int br_handle_frame_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) unsigned int br_nf_pre_routing(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
 * 4) int br_nf_pre_routing_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int br_pass_frame_up(struct sk_buff *skb)
 * 6) int br_netif_receive_skb(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 7) void br_forward(const struct net_bridge_port *to, struct sk_buff *skb, bool local_rcv, bool local_orig)
 * 8) int br_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 9) unsigned int br_nf_forward_ip(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 10)int br_nf_forward_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 11)unsigned int br_nf_post_routing(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
 * 12)int br_nf_dev_queue_xmit(struct net *net, struct sock *sk, struct sk_buff *skb)
 */

SEC("kprobe/br_handle_frame_finish")
int k_br_handle_ff(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_handle_frame_finish", NULL);
}

SEC("kprobe/br_nf_pre_routing")
int k_br_nf_prero(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "br_nf_pre_routing", NULL);
}

SEC("kprobe/br_nf_pre_routing_finish")
int k_brnf_prero_f(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_nf_pre_routing_finish", NULL);
}

SEC("kprobe/br_pass_frame_up")
int k_br_pass_f_up(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    return do_trace(ctx, skb, "br_pass_frame_up", NULL);
}

SEC("kprobe/br_netif_receive_skb")
int k_br_nif_rcv(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_netif_receive_skb", NULL);
}

SEC("kprobe/br_forward")
int k_br_forward(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "br_forward", NULL);
}

SEC("kprobe/__br_forward")
int k___br_fwd(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "__br_forward", NULL);
}

SEC("kprobe/br_forward_finish")
int k_br_fwd_f(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_forward_finish", NULL);
}

SEC("kprobe/br_nf_forward_ip")
int k_br_nf_fwd_ip(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "br_nf_forward_ip", NULL);
}

SEC("kprobe/br_nf_forward_finish")
int k_br_nf_fwd_fin(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_nf_forward_finish", NULL);
}

SEC("kprobe/br_nf_post_routing")
int k_br_nf_post_ro(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "br_nf_post_routing", NULL);
}

SEC("kprobe/br_nf_dev_queue_xmit")
int k_br_nf_q_xmit(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "br_nf_dev_queue_xmit", NULL);
}

/*
 * ip layer:
 * 1) int ip_rcv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
 * 2) int ip_rcv_finish(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 3) int ip_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 4) int ip_finish_output(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 5) int ip_finish_output2(struct net *net, struct sock *sk, struct sk_buff *skb)
 * 6) ...
 */

SEC("kprobe/ip_rcv")
int k_ip_rcv(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    return do_trace(ctx, skb, "ip_rcv", NULL);
}

SEC("kprobe/ip_rcv_finish")
int k_ip_rcv_finish(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "ip_rcv_finish", NULL);
}

SEC("kprobe/ip_output")
int k_ip_output(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "ip_output", NULL);
}

SEC("kprobe/ip_finish_output")
int k_ip_finish_out(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[2]);
    return do_trace(ctx, skb, "ip_finish_output", NULL);
}

#if 0
SEC("kprobe/deliver_clone")
int k_deliver_clone(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[1]);
    return do_trace(ctx, skb, "deliver_clone", NULL);
}
#endif

INLINE int
__ipt_do_table_in(struct pt_regs *ctx, struct sk_buff *skb,
                  const struct nf_hook_state *state, struct xt_table *table)
{
    __u32 pid;
    __u64 _cfg_ipt = get_cfg_iptable();

    if (0 == _cfg_ipt)
        return 0;

    pid = bpf_get_current_pid_tgid();

    struct ipt_do_table_args args = {
        .skb = skb,
        .state = state,
        .table = table,
    };
    args.start_ns = bpf_ktime_get_ns();
    bpf_map_update_elem(&cur_ipt_args, &pid, &args, BPF_ANY);

    return 0;
};

INLINE int
__ipt_do_table_out(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct event_t event = {};
    union ___skb_pkt_type type = {};
    struct ipt_do_table_args *args;
    __u32 pid;
    __u64 _cfg_ipt = get_cfg_iptable();

    if (0 == _cfg_ipt)
        return 0;

    pid = bpf_get_current_pid_tgid();

    args = bpf_map_lookup_elem(&cur_ipt_args, &pid);
    if (args == 0)
        return 0;

    bpf_map_delete_elem(&cur_ipt_args, &pid);

    if (do_trace_skb(&event, ctx, args->skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_IPTABLE;
    event.ipt_delay = bpf_ktime_get_ns() - args->start_ns;
    member_read(&event.hook, args->state, hook);
    member_read(&event.pf, args->state, pf);
    member_read(&event.tablename, args->table, name);
    event.verdict = PT_REGS_RC(ctx);
    event.skb = (__u64)args->skb;
    bpf_probe_read(&type.value, 1, ((char *)args->skb) + offsetof(typeof(*args->skb), __pkt_type_offset));
    event.pkt_type = type.pkt_type;

    event.start_ns = bpf_ktime_get_ns();
    CALL_STACK(ctx, &event);
    bpf_perf_event_output(ctx, &route_event, BPF_F_CURRENT_CPU,
                          &event, sizeof(event));

    return 0;
}

SEC("kprobe/ipt_do_table")
int k_ipt_do_table(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    const GET_ARG(struct nf_hook_state *, state, args[1]);
    GET_ARG(struct xt_table *, table, args[2]);
    return __ipt_do_table_in(ctx, skb, state, table);
};

/*
 * tricky: use ebx as the 1st parms, thus get skb
 */
SEC("kretprobe/ipt_do_table")
int kr_ipt_do_table(struct pt_regs *ctx)
{
    struct sk_buff *skb = (void *)ctx->bx;
    return __ipt_do_table_out(ctx, skb);
}

#if 0
SEC("kprobe/__kfree_skb") // failed to load on Ubuntu 18.04.5 LTS with kernel 5.10.29-051029-generic
int k___kfree_skb(struct pt_regs *ctx, struct sk_buff *skb)
{
    struct event_t event = {};
    __u64 _cfg_dropstack = get_cfg_dropstack();

    if (0 != _cfg_dropstack)
        return 0;

    if (do_trace_skb(&event, ctx, skb, NULL) < 0)
        return 0;

    event.flags |= ROUTE_EVENT_DROP;
    event.start_ns = bpf_ktime_get_ns();
    bpf_strncpy(event.func_name, __func__+8, FUNCNAME_MAX_LEN);
    get_stack(ctx, &event);
    bpf_perf_event_output(ctx, &route_event, BPF_F_CURRENT_CPU,
        &event, sizeof(event));
    return 0;
}

SEC("kprobe/ip6t_do_table")
int k_ip6t_do_table(struct pt_regs *ctx)
{
    GET_ARGS();
    GET_ARG(struct sk_buff *, skb, args[0]);
    const GET_ARG(struct nf_hook_state *, state, args[1]);
    GET_ARG(struct xt_table *, table, args[2]);
    return __ipt_do_table_in(ctx, skb, state, table);
};

SEC("kretprobe/ip6t_do_table")
int kr_ip6t_do_table(struct pt_regs *ctx)
{
    return __ipt_do_table_out(ctx);
}
#endif
