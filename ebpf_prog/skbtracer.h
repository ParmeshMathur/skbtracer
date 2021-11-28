#include "vmlinux_508.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

char _license[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800   /* Internet Protocol packet	*/
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook		*/

#define IPPROTO_HOPOPTS 0   /* IPv6 hop-by-hop options      */
#define IPPROTO_ROUTING 43  /* IPv6 routing header          */
#define IPPROTO_FRAGMENT 44 /* IPv6 fragmentation header    */
#define IPPROTO_ICMPV6 58   /* ICMPv6                       */
#define IPPROTO_NONE 59     /* IPv6 no next header          */
#define IPPROTO_DSTOPTS 60  /* IPv6 destination options     */
#define IPPROTO_MH 135      /* IPv6 mobility header         */

#define ICMP_ECHOREPLY 0       /* Echo Reply                   */
#define ICMP_DEST_UNREACH 3    /* Destination Unreachable      */
#define ICMP_SOURCE_QUENCH 4   /* Source Quench                */
#define ICMP_REDIRECT 5        /* Redirect (change route)      */
#define ICMP_ECHO 8            /* Echo Request                 */
#define ICMP_TIME_EXCEEDED 11  /* Time Exceeded                */
#define ICMP_PARAMETERPROB 12  /* Parameter Problem            */
#define ICMP_TIMESTAMP 13      /* Timestamp Request            */
#define ICMP_TIMESTAMPREPLY 14 /* Timestamp Reply              */
#define ICMP_INFO_REQUEST 15   /* Information Request          */
#define ICMP_INFO_REPLY 16     /* Information Reply            */
#define ICMP_ADDRESS 17        /* Address Mask Request         */
#define ICMP_ADDRESSREPLY 18   /* Address Mask Reply           */

#define ICMPV6_ECHO_REQUEST 128
#define ICMPV6_ECHO_REPLY 129
#define ICMPV6_MGM_QUERY 130
#define ICMPV6_MGM_REPORT 131
#define ICMPV6_MGM_REDUCTION 132

#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#define tcp_flag_word(tp) (((union tcp_word_hdr *)(tp))->words[3])

#define IFNAMSIZ 16
#define ADDRSIZE 16
#define FUNCNAME_MAX_LEN 32
#define XT_TABLE_MAXNAMELEN 32

#define NULL ((void *)0)
#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6

typedef unsigned long args_t;

INLINE void get_args(struct pt_regs *ctx, unsigned long *args) {
    // if registers are valid then use them directly (kernel version < 4.17)
    if (ctx->orig_ax || ctx->bx || ctx->cx || ctx->dx) {
        args[0] = PT_REGS_PARM1(ctx);
        args[1] = PT_REGS_PARM2(ctx);
        args[2] = PT_REGS_PARM3(ctx);
        args[3] = PT_REGS_PARM4(ctx);
        args[4] = PT_REGS_PARM5(ctx);
        args[5] = PT_REGS_PARM6(ctx);
    } else {
        // otherwise it's a later kernel version so load register values from
        // ctx->di.
        struct pt_regs *regs = (struct pt_regs *)ctx->di;
        bpf_probe_read(&args[0], sizeof(*args), &regs->di);
        bpf_probe_read(&args[1], sizeof(*args), &regs->si);
        bpf_probe_read(&args[2], sizeof(*args), &regs->dx);
        bpf_probe_read(&args[3], sizeof(*args), &regs->r10);
        bpf_probe_read(&args[4], sizeof(*args), &regs->r8);
        bpf_probe_read(&args[5], sizeof(*args), &regs->r9);
    }
}

#define GET_ARGS()           \
    args_t args[NARGS] = {}; \
    get_args(ctx, args)

#define GET_ARG(type, name, arg) type name = (type)arg

BPF_MAP_DEF(skbtracer_cfg) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u8),
    .value_size = sizeof(u64),
    .max_entries = 8,
};
BPF_MAP_ADD(skbtracer_cfg);

#define cfg_pid 1
#define cfg_ip 2
#define cfg_port 3
#define cfg_icmpid 4
#define cfg_dropstack 5
#define cfg_callstack 6
#define cfg_iptable 7
#define cfg_noroute 8
#define cfg_keep 9
#define cfg_proto 10
#define cfg_netns 11

#define DEF_GET_CFG(name)                              \
    INLINE u64 get_cfg_##name(void) {                  \
        u8 key = cfg_##name;                           \
        u64 *v;                                        \
        v = bpf_map_lookup_elem(&skbtracer_cfg, &key); \
        return NULL == v ? 0 : *v;                     \
    }

DEF_GET_CFG(pid)
DEF_GET_CFG(ip)
DEF_GET_CFG(port)
DEF_GET_CFG(icmpid)
DEF_GET_CFG(dropstack)
DEF_GET_CFG(callstack)
DEF_GET_CFG(iptable)
DEF_GET_CFG(noroute)
DEF_GET_CFG(keep)
DEF_GET_CFG(proto)
DEF_GET_CFG(netns)

union addr {
    u32 v4addr;
    struct {
        u64 pre;
        u64 post;
    } v6addr;
    u64 pad[2];
};

struct l2_info_t {
    u8 dest_mac[6];
    u16 l3_proto;
    u8 pad[4];
};

struct l3_info_t {
    union addr saddr;
    union addr daddr;
    u16 tot_len;
    u8 ip_version;
    u8 l4_proto;
    u8 pad[4];
};

struct l4_info_t {
    u16 sport;
    u16 dport;
    u8 tcpflags;
    u8 pad[3];
};

struct icmp_info_t {
    u16 icmpid;
    u16 icmpseq;
    u8 icmptype;
    u8 pad[3];
};

struct iptables_info_t {
    char tablename[XT_TABLE_MAXNAMELEN];
    u32 hook;
    u32 verdict;
    u64 delay;
    u8 pf;
    u8 pad[7];
};

struct pkt_info_t {
    char ifname[IFNAMSIZ];
    u32 len;
    u32 cpu;
    u32 pid;
    u32 netns;
    u8 pkt_type; // skb->pkt_type
    u8 pad[7];
};

struct event_t {
    char func_name[FUNCNAME_MAX_LEN];
    u64 skb;
    u64 start_ns;
    __s32 kernel_stack_id;
    u8 flags;
    u8 pad[7];

    struct pkt_info_t pkt_info;
    struct l2_info_t l2_info;
    struct l3_info_t l3_info;
    struct l4_info_t l4_info;
    struct icmp_info_t icmp_info;
    struct iptables_info_t ipt_info;
};

BPF_MAP_DEF(event_buf) = {
    .map_type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct event_t),
    .max_entries = 1,
};
BPF_MAP_ADD(event_buf);

INLINE struct event_t *get_event_buf(void) {
    u32 ev_buff_id = 0;
    struct event_t *ev;
    ev = bpf_map_lookup_elem(&event_buf, &ev_buff_id);
    if (!ev) return NULL;
    return ev;
}

#define SKBTRACER_EVENT_IF 0x0001
#define SKBTRACER_EVENT_IPTABLE 0x0002
#define SKBTRACER_EVENT_DROP 0x0004
#define SKBTRACER_EVENT_NEW 0x0010

BPF_MAP_DEF(skbtracer_event) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 1024,
};
BPF_MAP_ADD(skbtracer_event);

struct ipt_do_table_args {
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    u64 start_ns;
};
BPF_MAP_DEF(skbtracer_ipt) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct ipt_do_table_args),
    .max_entries = 1024,
};
BPF_MAP_ADD(skbtracer_ipt);

BPF_MAP_DEF(skbtracer_stack) = {
    .map_type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = 4,
    .value_size = 1000,
    .max_entries = 2048,
};
BPF_MAP_ADD(skbtracer_stack);

#define MAC_HEADER_SIZE 14
#define member_address(source_struct, source_member)                                                 \
    ({                                                                                               \
        void *__ret;                                                                                 \
        __ret = (void *)(((char *)source_struct) + offsetof(typeof(*source_struct), source_member)); \
        __ret;                                                                                       \
    })

#define member_read(destination, source_struct, source_member)            \
    do {                                                                  \
        bpf_probe_read(destination, sizeof(source_struct->source_member), \
                       member_address(source_struct, source_member));     \
    } while (0)

enum {
    __TCP_FLAG_CWR,
    __TCP_FLAG_ECE,
    __TCP_FLAG_URG,
    __TCP_FLAG_ACK,
    __TCP_FLAG_PSH,
    __TCP_FLAG_RST,
    __TCP_FLAG_SYN,
    __TCP_FLAG_FIN
};

#define TCP_FLAGS_INIT(new_flags, orig_flags, flag) \
    do {                                            \
        if (orig_flags & flag) {                    \
            new_flags |= (1U << __##flag);          \
        }                                           \
    } while (0)

#define init_tcpflags_bits(new_flags, orig_flags)            \
    ({                                                       \
        new_flags = 0;                                       \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_CWR); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ECE); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_URG); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_ACK); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_PSH); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_RST); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_SYN); \
        TCP_FLAGS_INIT(new_flags, orig_flags, TCP_FLAG_FIN); \
    })

INLINE void get_stack(struct pt_regs *ctx, struct event_t *event) {
    event->kernel_stack_id = bpf_get_stackid(ctx, &skbtracer_stack, 0);
    return;
}

INLINE int _has_callstack(void) {
    return 0 != get_cfg_callstack();
}

#define CALL_STACK(ctx, event)                       \
    do {                                             \
        if (_has_callstack()) get_stack(ctx, event); \
    } while (0)

INLINE void bpf_strncpy(char *dst, const char *src, int n) {
    int i = 0, j;
#define CPY(n)                       \
    do {                             \
        for (; i < n; i++) {         \
            if (src[i] == 0) return; \
            dst[i] = src[i];         \
        }                            \
    } while (0)

    for (j = 10; j < 64; j += 10) CPY(j);
    CPY(64);
#undef CPY
}

INLINE struct net_device *get_net_device(struct sk_buff *skb, void *netdev) {
    struct net_device *dev;
    if (netdev)
        dev = (struct net_device *)netdev;
    else
        member_read(&dev, skb, dev);
    return dev;
}

INLINE u32 get_netns(struct sk_buff *skb, struct net_device *dev) {
    struct net *net;
    u32 netns;

    // Get netns id. The code below is equivalent to: netns =
    // dev->nd_net.net->ns.inum
    possible_net_t *skc_net = &dev->nd_net;
    member_read(&net, skc_net, net);
    struct ns_common *ns = member_address(net, ns);
    member_read(&netns, ns, inum);

    // maybe the skb->dev is not init, for this situation, we can get ns by
    // sk->__sk_common.skc_net.net->ns.inum
    if (netns == 0) {
        struct sock *sk;
        struct sock_common __sk_common;
        struct ns_common *ns2;
        member_read(&sk, skb, sk);
        if (sk != NULL) {
            member_read(&__sk_common, sk, __sk_common);
            ns2 = member_address(__sk_common.skc_net.net, ns);
            member_read(&netns, ns2, inum);
        }
    }

    return netns;
}

union ___skb_pkt_type {
    u8 value;
    struct {
        u8 __pkt_type_offset[0];
        u8 pkt_type : 3;
        u8 pfmemalloc : 1;
        u8 ignore_df : 1;

        u8 nf_trace : 1;
        u8 ip_summed : 2;
    };
};

INLINE u8 get_pkt_type(struct sk_buff *skb) {
    union ___skb_pkt_type type = {};
    bpf_probe_read(&type.value, 1,
                   ((char *)skb) + offsetof(struct sk_buff, __pkt_type_offset));
    return type.pkt_type;
}

INLINE u8 get_ip_version(void *hdr) {
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte >> 4) & 0x0f;
}

INLINE u8 get_ipv4_header_len(void *hdr) {
    u8 first_byte;
    bpf_probe_read(&first_byte, 1, hdr);
    return (first_byte & 0x0f) * 4;
}

INLINE char *get_l2_header(struct sk_buff *skb) {
    char *head;
    u16 mac_header;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    return head + mac_header;
}

INLINE char *get_l3_header(struct sk_buff *skb) {
    char *head;
    u16 mac_header, network_header;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);
    if (network_header == 0) network_header = mac_header + MAC_HEADER_SIZE;
    return head + network_header;
}

INLINE char *get_l4_header(struct sk_buff *skb) {
    char *head;
    u8 ip_version, ihl;
    u16 mac_header, network_header, transport_header;

    member_read(&head, skb, head);
    member_read(&mac_header, skb, mac_header);
    member_read(&network_header, skb, network_header);
    if (network_header == 0) network_header = mac_header + MAC_HEADER_SIZE;
    member_read(&transport_header, skb, transport_header);
    if (transport_header == 0) {
        ip_version = get_ip_version(head + network_header);
        if (ip_version == 6)
            transport_header = network_header + sizeof(struct ipv6hdr);
        else {
            ihl = get_ipv4_header_len(head + network_header);
            transport_header = network_header + ihl;
        }
    }
    return head + transport_header;
}

INLINE void set_event_info(struct sk_buff *skb, struct pt_regs *ctx,
                           struct event_t *ev) {
    ev->skb = (u64)skb;
    ev->start_ns = bpf_ktime_get_ns();
    CALL_STACK(ctx, ev);
}

INLINE void set_pkt_info(struct sk_buff *skb, struct pkt_info_t *pkt_info,
                         void *netdev) {
    char *dev_name;

    struct net_device *dev = get_net_device(skb, netdev);
    member_read(&pkt_info->len, skb, len);
    pkt_info->cpu = bpf_get_smp_processor_id();
    pkt_info->pid = bpf_get_current_pid_tgid() & 0xffff;
    pkt_info->netns = get_netns(skb, dev);
    pkt_info->pkt_type = get_pkt_type(skb);

    pkt_info->ifname[0] = 0;
    member_read(&dev_name, dev, name);
    bpf_probe_read(&pkt_info->ifname, IFNAMSIZ, dev_name);
    if (pkt_info->ifname[0] == 0) bpf_strncpy(pkt_info->ifname, "nil", IFNAMSIZ);
}

INLINE void set_ether_info(struct sk_buff *skb, struct l2_info_t *l2_info) {
    char *dest;

    struct ethhdr *eh = (struct ethhdr *)get_l2_header(skb);
    member_read(&dest, eh, h_dest);
    bpf_probe_read(&l2_info->dest_mac, 6, dest);
    member_read(&l2_info->l3_proto, eh, h_proto);
    l2_info->l3_proto = bpf_ntohs(l2_info->l3_proto);
}

INLINE void set_ipv4_info(struct sk_buff *skb, struct l3_info_t *l3_info) {
    struct iphdr *iph = (struct iphdr *)get_l3_header(skb);
    member_read(&l3_info->saddr.v4addr, iph, saddr);
    member_read(&l3_info->daddr.v4addr, iph, daddr);
    member_read(&l3_info->tot_len, iph, tot_len);
    l3_info->tot_len = bpf_ntohs(l3_info->tot_len);
    member_read(&l3_info->l4_proto, iph, protocol);
    l3_info->ip_version = get_ip_version(iph);
}

INLINE void set_ipv6_info(struct sk_buff *skb, struct l3_info_t *l3_info) {
    struct ipv6hdr *iph = (struct ipv6hdr *)get_l3_header(skb);
    bpf_probe_read(&l3_info->saddr.v6addr, ADDRSIZE,
                   (char *)iph + offsetof(struct ipv6hdr, saddr));
    bpf_probe_read(&l3_info->daddr.v6addr, ADDRSIZE,
                   (char *)iph + offsetof(struct ipv6hdr, daddr));
    member_read(&l3_info->tot_len, iph, payload_len);
    member_read(&l3_info->l4_proto, iph, nexthdr);
    l3_info->ip_version = get_ip_version(iph);
}

INLINE void set_tcp_info(struct sk_buff *skb, struct l4_info_t *l4_info) {
    __be32 tcpflags;

    struct tcphdr *th = (struct tcphdr *)get_l4_header(skb);
    member_read(&l4_info->sport, th, source);
    l4_info->sport = bpf_ntohs(l4_info->sport);
    member_read(&l4_info->dport, th, dest);
    l4_info->dport = bpf_ntohs(l4_info->dport);

    tcpflags = tcp_flag_word(th);
    init_tcpflags_bits(l4_info->tcpflags, tcpflags);
    l4_info->tcpflags = bpf_ntohs(l4_info->tcpflags);
}

INLINE void set_udp_info(struct sk_buff *skb, struct l4_info_t *l4_info) {
    struct udphdr *uh = (struct udphdr *)get_l4_header(skb);
    member_read(&l4_info->sport, uh, source);
    l4_info->sport = bpf_ntohs(l4_info->sport);
    member_read(&l4_info->dport, uh, dest);
    l4_info->dport = bpf_ntohs(l4_info->dport);
}

INLINE void set_icmp_info(struct sk_buff *skb, struct icmp_info_t *icmp_info) {
    struct icmphdr ih;
    char *l4_header = get_l4_header(skb);
    bpf_probe_read(&ih, sizeof(ih), l4_header);

    icmp_info->icmptype = ih.type;
    icmp_info->icmpid = bpf_ntohs(ih.un.echo.id);
    icmp_info->icmpseq = bpf_ntohs(ih.un.echo.sequence);
}

INLINE void set_iptables_info(struct xt_table *table,
                              const struct nf_hook_state *state, u32 verdict,
                              u64 delay, struct iptables_info_t *ipt_info) {
    member_read(&ipt_info->tablename, table, name);
    member_read(&ipt_info->hook, state, hook);
    ipt_info->verdict = verdict;
    ipt_info->delay = delay;
    member_read(&ipt_info->pf, state, pf);
}

INLINE bool filter_l3_and_l4_info(struct sk_buff *skb) {
    u64 addr = get_cfg_ip();
    u64 proto = get_cfg_proto();
    u64 port = get_cfg_port();
    u64 icmpid = get_cfg_icmpid();

    char *l2_header = get_l2_header(skb);
    char *l3_header;
    char *l4_header;

    struct ethhdr *eh = (struct ethhdr *)l2_header;
    u8 ip_version;
    u16 l3_proto;

    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    u32 saddr, daddr;
    u8 l4_proto;

    struct tcphdr *th;
    struct udphdr *uh;
    u16 sport, dport;

    struct icmphdr ih;
    u16 ev_icmpid;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;

    l3_header = get_l3_header(skb);
    member_read(&l3_proto, eh, h_proto);
    l3_proto = bpf_ntohs(l3_proto);

    if (l3_proto != ETH_P_IP && l3_proto != ETH_P_IPV6) return true;

    // filter ip addr
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        iph = (struct iphdr *)l3_header;
        if (addr != 0) {
            member_read(&saddr, iph, saddr);
            member_read(&daddr, iph, daddr);
            return addr != saddr && addr != daddr;
        }

        member_read(&l4_proto, iph, protocol);
        if (l4_proto == IPPROTO_ICMP) {
            proto_icmp_echo_request = ICMP_ECHO;
            proto_icmp_echo_reply = ICMP_ECHOREPLY;
        }
    } else if (ip_version == 6) {
        ip6h = (struct ipv6hdr *)l3_header;
        member_read(&l4_proto, ip6h, nexthdr);
        if (l4_proto == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply = ICMPV6_ECHO_REPLY;
        }
    } else {
        return true;
    }

    switch (l4_proto) {
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        l4_header = get_l4_header(skb);
        bpf_probe_read(&ih, sizeof(ih), l4_header);
        if (ih.type != proto_icmp_echo_request && ih.type != proto_icmp_echo_reply)
            return true;
        break;
    case IPPROTO_TCP:
    case IPPROTO_UDP:
        l4_header = get_l4_header(skb);
        break;
    default:
        return true;
    }

    // filter layer 4 protocol
    if (proto != 0) {
        return proto != l4_proto;
    }

    // filter layer 4 port
    if (port != 0) {
        if (l4_proto == IPPROTO_TCP) {
            th = (struct tcphdr *)l4_header;
            member_read(&sport, th, source);
            member_read(&dport, th, dest);
            return port != sport && port != dport;
        } else if (l4_proto == IPPROTO_UDP) {
            uh = (struct udphdr *)l4_header;
            member_read(&sport, uh, source);
            member_read(&dport, uh, dest);
            return port != sport && port != dport;
        }
    }

    // filter icmp id
    if (proto != 0 && icmpid != 0) {
        if (proto != IPPROTO_ICMP || (l4_proto != IPPROTO_ICMP && l4_proto != IPPROTO_ICMPV6)) {
            return false;
        }

        ev_icmpid = ih.un.echo.id;
        return icmpid != ev_icmpid;
    }

    return false;
}

INLINE bool filter_pid(void) {
    u64 cfg = get_cfg_pid();
    u64 tgid = bpf_get_current_pid_tgid() >> 32;
    return cfg != 0 && cfg != tgid;
}

INLINE bool filter_netns(struct sk_buff *skb, struct net_device *netdev) {
    u64 cfg = get_cfg_netns();
    struct net_device *dev = get_net_device(skb, netdev);
    u32 netns = get_netns(skb, dev);
    return cfg != 0 && netns != 0 && cfg != netns;
}

INLINE bool filter_route(void) {
    u64 cfg = get_cfg_noroute();
    return cfg != 0;
}

INLINE bool filter_iptables(void) {
    u64 cfg = get_cfg_iptable();
    return cfg == 0;
}

INLINE bool filter_dropstack(void) {
    u64 cfg = get_cfg_dropstack();
    return cfg == 0;
}