#include "vmlinux_508.h"
#include "bpf_helpers.h"


char _license[] SEC("license") = "GPL";


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
#define FUNCNAME_MAX_LEN 64
#define XT_TABLE_MAXNAMELEN 32

#define NULL ((void *)0)
#define MAX_ARGLEN 256
#define MAX_ARGS 20
#define NARGS 6

typedef unsigned long args_t;

INLINE void get_args(struct pt_regs *ctx, unsigned long *args)
{
    // if registers are valid then use them directly (kernel version < 4.17)
    if (ctx->orig_ax || ctx->bx || ctx->cx || ctx->dx)
    {
        args[0] = PT_REGS_PARM1(ctx);
        args[1] = PT_REGS_PARM2(ctx);
        args[2] = PT_REGS_PARM3(ctx);
        args[3] = PT_REGS_PARM4(ctx);
        args[4] = PT_REGS_PARM5(ctx);
        args[5] = PT_REGS_PARM6(ctx);
    }
    else
    {
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


#define ROUTE_EVENT_IF 0x0001
#define ROUTE_EVENT_IPTABLE 0x0002
#define ROUTE_EVENT_DROP 0x0004
#define ROUTE_EVENT_NEW 0x0010

BPF_MAP_DEF(tracer_cfg) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8),
    .value_size = sizeof(__u64),
    .max_entries = 8,
};
BPF_MAP_ADD(tracer_cfg);

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

#define DEF_GET_CFG(name)                           \
    INLINE __u64 get_cfg_##name(void)               \
    {                                               \
        __u8 key = cfg_##name;                      \
        __u64 *v;                                   \
        v = bpf_map_lookup_elem(&tracer_cfg, &key); \
        return NULL == v ? 0 : *v;                  \
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

struct event_t
{
    char func_name[FUNCNAME_MAX_LEN];
    __u8 flags;
    __u32 cpu;

    __s32 kernel_stack_id;

    // route info
    char ifname[IFNAMSIZ];
    __u32 netns;

    // pkt info
    __u32 len;
    __u8 dest_mac[6];
    __u8 ip_version;
    __u8 l4_proto;

    __u64 saddr[2];
    __u64 daddr[2];

    __u16 tot_len;
    __u16 icmpid;
    __u16 icmpseq;
    __u16 sport;

    __u16 dport;
    __u16 tcpflags;
    __u8 icmptype;

    __u8 pkt_type; //skb->pkt_type
    __u8 _pad1;

    // ipt info
    __u8 pf;
    __u32 hook;
    __u32 verdict;
    char tablename[XT_TABLE_MAXNAMELEN];
    __u64 ipt_delay;

    __u64 skb;

    //time
    __u64 start_ns;
};

BPF_MAP_DEF(route_event) = {
    .map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .max_entries = 1024,
};
BPF_MAP_ADD(route_event);

struct ipt_do_table_args
{
    struct sk_buff *skb;
    const struct nf_hook_state *state;
    struct xt_table *table;
    __u64 start_ns;
};
BPF_MAP_DEF(cur_ipt_args) = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ipt_do_table_args),
    .max_entries = 1024,
} BPF_MAP_ADD(cur_ipt_args);


BPF_MAP_DEF(stacks) = {
    .map_type = BPF_MAP_TYPE_STACK_TRACE,
    .key_size = 4,
    .value_size = 1000,
    .max_entries = 2048,
} BPF_MAP_ADD(stacks);


union ___skb_pkt_type
{
    __u8 value;
    struct
    {
        __u8 __pkt_type_offset[0];
        __u8 pkt_type : 3;
        __u8 pfmemalloc : 1;
        __u8 ignore_df : 1;

        __u8 nf_trace : 1;
        __u8 ip_summed : 2;
    };
};

#define MAC_HEADER_SIZE 14;
#define member_address(source_struct, source_member)                                                     \
    (                                                                                                    \
        {                                                                                                \
            void *__ret;                                                                                 \
            __ret = (void *)(((char *)source_struct) + offsetof(typeof(*source_struct), source_member)); \
            __ret;                                                                                       \
        })

#define member_read(destination, source_struct, source_member) \
    do                                                         \
    {                                                          \
        bpf_probe_read(                                        \
            destination,                                       \
            sizeof(source_struct->source_member),              \
            member_address(source_struct, source_member));     \
    } while (0)

enum
{
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
    do                                              \
    {                                               \
        if (orig_flags & flag)                      \
        {                                           \
            new_flags |= (1U << __##flag);          \
        }                                           \
    } while (0)

#define init_tcpflags_bits(new_flags, orig_flags)                \
    (                                                            \
        {                                                        \
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
