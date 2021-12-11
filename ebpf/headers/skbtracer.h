#include "vmlinux.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

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

#define IFNAMSIZ 16
#define ADDRSIZE 16
#define MAC_HEADER_SIZE 14
#define FUNCNAME_MAX_LEN 32
#define XT_TABLE_MAXNAMELEN 32

#define NULL ((void *)0)
#define MAX_STACKDEPTH 50

struct config {
    u32 netns;
    u32 pid;
    u32 ip;
    u16 port;
    u16 icmpid;
    u8 dropstack;
    u8 callstack;
    u8 keep;
    u8 proto;
};

BPF_MAP_DEF(skbtracer_cfg) = {
    .map_type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(u32),
    .value_size = sizeof(struct config),
    .max_entries = 1,
};
BPF_MAP_ADD(skbtracer_cfg);

#define GET_CFG()                                      \
    u32 index = 0;                                     \
    struct config *cfg = NULL;                         \
    cfg = bpf_map_lookup_elem(&skbtracer_cfg, &index); \
    if (cfg == NULL) return 0;                         \
    cfg->ip = bpf_htonl(cfg->ip)

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
    u16 tcpflags;
    u8 pad[2];
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
    memset(ev, 0, sizeof(*ev));
    return ev;
}

#define GET_EVENT_BUF()      \
    struct event_t *event;   \
    event = get_event_buf(); \
    if (event == NULL) return 0

#define SKBTRACER_EVENT_IF 0x01
#define SKBTRACER_EVENT_IPTABLE 0x02
#define SKBTRACER_EVENT_DROP 0x04
#define SKBTRACER_EVENT_NEW 0x10

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
    .key_size = sizeof(u32),
    .value_size = MAX_STACKDEPTH * sizeof(u64),
    .max_entries = 256,
};
BPF_MAP_ADD(skbtracer_stack);

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

INLINE u32 get_netns(struct sk_buff *skb) {
    u32 netns;

    // Get netns inode. The code below is equivalent to: netns =
    // skb->dev->nd_net.net->ns.inum
    netns = BPF_CORE_READ(skb, dev, nd_net.net, ns.inum);

    // maybe the skb->dev is not init, for this situation, we can get netns inode by
    // skb->sk->__sk_common.skc_net.net->ns.inum
    if (netns == 0) {
        struct sock *sk = BPF_CORE_READ(skb, sk);
        if (sk != NULL)
            netns = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);
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
    bpf_probe_read(&type.value, 1, &skb->__pkt_type_offset);
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

INLINE unsigned char *get_l2_header(struct sk_buff *skb) {
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    return head + mac_header;
}

INLINE unsigned char *get_l3_header(struct sk_buff *skb) {
    unsigned char *head = BPF_CORE_READ(skb, head);
    u16 mac_header = BPF_CORE_READ(skb, mac_header);
    u16 network_header = BPF_CORE_READ(skb, network_header);
    if (network_header == 0) network_header = mac_header + MAC_HEADER_SIZE;
    return head + network_header;
}

INLINE unsigned char *get_l4_header(struct sk_buff *skb) {
    u16 transport_size = 0;
    unsigned char *l3_header = get_l3_header(skb);
    u8 ip_version = get_ip_version(l3_header);
    if (ip_version == 6)
        transport_size = sizeof(struct ipv6hdr);
    else
        transport_size = get_ipv4_header_len(l3_header);
    return l3_header + transport_size;
}

INLINE void set_event_info(struct sk_buff *skb, struct event_t *ev) {
    ev->skb = (u64)skb;
    ev->start_ns = bpf_ktime_get_ns();
}

INLINE void set_callstack(struct event_t *event, struct pt_regs *ctx) {
    event->kernel_stack_id = bpf_get_stackid(ctx, &skbtracer_stack, 0);
    return;
}

INLINE void set_pkt_info(struct sk_buff *skb, struct pkt_info_t *pkt_info) {
    struct net_device *dev = BPF_CORE_READ(skb, dev);
    pkt_info->len = BPF_CORE_READ(skb, len);
    pkt_info->cpu = bpf_get_smp_processor_id();
    pkt_info->pid = bpf_get_current_pid_tgid() & 0xffff;
    pkt_info->netns = get_netns(skb);
    pkt_info->pkt_type = get_pkt_type(skb);

    pkt_info->ifname[0] = 0;
    bpf_probe_read(&pkt_info->ifname, IFNAMSIZ, &dev->name);
    if (pkt_info->ifname[0] == 0) bpf_strncpy(pkt_info->ifname, "nil", IFNAMSIZ);
}

INLINE void set_ether_info(struct sk_buff *skb, struct l2_info_t *l2_info) {
    unsigned char *l2_header = get_l2_header(skb);
    bpf_probe_read(&l2_info->dest_mac, 6, l2_header);
}

INLINE void set_ipv4_info(struct sk_buff *skb, struct l3_info_t *l3_info) {
    struct iphdr *iph = (struct iphdr *)get_l3_header(skb);
    l3_info->saddr.v4addr = BPF_CORE_READ(iph, saddr);
    l3_info->daddr.v4addr = BPF_CORE_READ(iph, daddr);
    l3_info->tot_len = BPF_CORE_READ(iph, tot_len);
    l3_info->tot_len = bpf_ntohs(l3_info->tot_len);
    l3_info->l4_proto = BPF_CORE_READ(iph, protocol);
    l3_info->ip_version = get_ip_version(iph);
}

INLINE void set_ipv6_info(struct sk_buff *skb, struct l3_info_t *l3_info) {
    struct ipv6hdr *iph = (struct ipv6hdr *)get_l3_header(skb);
    bpf_probe_read(&l3_info->saddr.v6addr, ADDRSIZE, &iph->saddr);
    bpf_probe_read(&l3_info->daddr.v6addr, ADDRSIZE, &iph->daddr);
    l3_info->tot_len = BPF_CORE_READ(iph, payload_len);
    l3_info->l4_proto = BPF_CORE_READ(iph, nexthdr);
    l3_info->ip_version = get_ip_version(iph);
}

INLINE void set_tcp_info(struct sk_buff *skb, struct l4_info_t *l4_info) {
    struct tcphdr *th = (struct tcphdr *)get_l4_header(skb);
    l4_info->sport = BPF_CORE_READ(th, source);
    l4_info->sport = bpf_ntohs(l4_info->sport);
    l4_info->dport = BPF_CORE_READ(th, dest);
    l4_info->dport = bpf_ntohs(l4_info->dport);
    bpf_probe_read(&l4_info->tcpflags, 2, (char *)th + 12);
}

INLINE void set_udp_info(struct sk_buff *skb, struct l4_info_t *l4_info) {
    struct udphdr *uh = (struct udphdr *)get_l4_header(skb);
    l4_info->sport = BPF_CORE_READ(uh, source);
    l4_info->sport = bpf_ntohs(l4_info->sport);
    l4_info->dport = BPF_CORE_READ(uh, dest);
    l4_info->dport = bpf_ntohs(l4_info->dport);
}

INLINE void set_icmp_info(struct sk_buff *skb, struct icmp_info_t *icmp_info) {
    struct icmphdr ih;
    unsigned char *l4_header = get_l4_header(skb);
    bpf_probe_read(&ih, sizeof(ih), l4_header);

    icmp_info->icmptype = ih.type;
    icmp_info->icmpid = bpf_ntohs(ih.un.echo.id);
    icmp_info->icmpseq = bpf_ntohs(ih.un.echo.sequence);
}

INLINE void set_iptables_info(struct xt_table *table,
                              const struct nf_hook_state *state, u32 verdict,
                              u64 delay, struct iptables_info_t *ipt_info) {
    bpf_probe_read(&ipt_info->tablename, XT_TABLE_MAXNAMELEN, &table->name);
    ipt_info->hook = BPF_CORE_READ(state, hook);
    ipt_info->verdict = verdict;
    ipt_info->delay = delay;
    ipt_info->pf = BPF_CORE_READ(state, pf);
}

INLINE bool filter_l3_and_l4_info(struct config *cfg, struct sk_buff *skb) {
    u32 addr = cfg->ip;
    u8 proto = cfg->proto;
    u16 port = cfg->port;
    u16 icmpid = cfg->icmpid;

    unsigned char *l3_header;
    unsigned char *l4_header;

    u8 ip_version;

    struct iphdr *iph;
    struct ipv6hdr *ip6h;
    u32 saddr, daddr;
    u8 l4_proto = 0;

    struct tcphdr *th;
    struct udphdr *uh;
    u16 sport, dport;

    struct icmphdr ih;
    u16 ev_icmpid;
    u8 proto_icmp_echo_request;
    u8 proto_icmp_echo_reply;

    // filter ip addr
    l3_header = get_l3_header(skb);
    ip_version = get_ip_version(l3_header);
    if (ip_version == 4) {
        iph = (struct iphdr *)l3_header;
        if (addr != 0) {
            saddr = BPF_CORE_READ(iph, saddr);
            daddr = BPF_CORE_READ(iph, daddr);
            return addr != saddr && addr != daddr;
        }

        // l4_proto = BPF_CORE_READ(iph, protocol);
        bpf_probe_read(&l4_proto, 1, &iph->protocol);
        if (l4_proto == IPPROTO_ICMP) {
            proto_icmp_echo_request = ICMP_ECHO;
            proto_icmp_echo_reply = ICMP_ECHOREPLY;
        }
    } else if (ip_version == 6) {
        ip6h = (struct ipv6hdr *)l3_header;
        // l4_proto = BPF_CORE_READ(ip6h, nexthdr);
        bpf_probe_read(&l4_proto, 1, &ip6h->nexthdr);
        if (l4_proto == IPPROTO_ICMPV6) {
            proto_icmp_echo_request = ICMPV6_ECHO_REQUEST;
            proto_icmp_echo_reply = ICMPV6_ECHO_REPLY;
        }
    } else {
        return true;
    }

    // filter layer 4 protocol
    if (proto != 0 && proto != l4_proto)
        return true;

    if (l4_proto == IPPROTO_ICMP || l4_proto == IPPROTO_ICMPV6) {
        l4_header = get_l4_header(skb);
        bpf_probe_read(&ih, sizeof(ih), l4_header);
        ev_icmpid = ih.un.echo.id;
        if (ih.type != proto_icmp_echo_request && ih.type != proto_icmp_echo_reply)
            return true;
    } else if (l4_proto == IPPROTO_TCP || l4_proto == IPPROTO_UDP) {
        l4_header = get_l4_header(skb);
    } else {
        return true;
    }

    // filter layer 4 port
    if (port != 0) {
        if (l4_proto == IPPROTO_TCP) {
            th = (struct tcphdr *)l4_header;
            sport = BPF_CORE_READ(th, source);
            dport = BPF_CORE_READ(th, dest);
            return port != sport && port != dport;
        } else if (l4_proto == IPPROTO_UDP) {
            uh = (struct udphdr *)l4_header;
            sport = BPF_CORE_READ(uh, source);
            dport = BPF_CORE_READ(uh, dest);
            return port != sport && port != dport;
        }
    }

    // filter icmp id
    if (proto != 0 && icmpid != 0) {
        if (proto != IPPROTO_ICMP)
            return false;
        if (l4_proto != IPPROTO_ICMP && l4_proto != IPPROTO_ICMPV6)
            return false;

        if (icmpid != ev_icmpid)
            return true;
    }

    return false;
}

INLINE bool filter_netns(struct config *cfg, struct sk_buff *skb) {
    u32 netns = get_netns(skb);
    return cfg->netns != 0 && netns != 0 && cfg->netns != netns;
}

INLINE bool filter_pid(struct config *cfg) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    return cfg->pid != 0 && cfg->pid != tgid;
}

INLINE bool filter_dropstack(struct config *cfg) {
    return cfg->dropstack == 0;
}

INLINE bool filter_callstack(struct config *cfg) {
    return cfg->callstack == 0;
}