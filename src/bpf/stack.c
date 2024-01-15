/*
 */

#include "shared/vmlinux.h"
#include "shared/event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

static inline get_arg_test(struct sk_buff *skb)
{
    bpf_printk("%d", skb->protocol);
    return BPF_OK;
}

SEC("?fentry/ip_rcv")
int BPF_PROG(func_arg_1, struct sk_buff *skb)
{
    return get_arg_test(skb);
}

SEC("?fentry/ip_output")
int BPF_PROG(func_arg_2, void *, struct sk_buff *skb)
{
    return get_arg_test(skb);
}

SEC("?fentry/tcp_data_ready")
int BPF_PROG(func_arg_3, void *, void *, struct sk_buff *skb)
{
    return get_arg_test(skb);
}