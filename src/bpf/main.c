/*
This is the main attach ebpf program for this program
*/

#include "shared/vmlinux.h"
#include "shared/event.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "GPL";

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, sizeof(event_t) * 1024 /* 256 KB */);
} entry_rb SEC(".maps");

SEC("fentry")
int BPF_PROG(fentry_prog)
{
    // struct sk_buff *skb = NULL;
    __u64 skb = 0;
    int err = bpf_get_func_arg(ctx, 0, &skb);
    // check first
    event_t *e = bpf_ringbuf_reserve(&entry_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = 0;
    // if (!err)
    e->skb = (__u64)skb;
    e->addr = bpf_get_func_ip(ctx);
    e->ksize = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
    e->time = bpf_ktime_get_ns();

    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}

SEC("fexit")
int BPF_PROG(fexit_prog)
{
    // struct sk_buff *skb = NULL;
    __u64 skb = 0;
    int err = bpf_get_func_arg(ctx, 0, &skb);
    // check first
    event_t *e = bpf_ringbuf_reserve(&entry_rb, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = 1;
    // if (!err)
    e->skb = (__u64)skb;
    e->addr = bpf_get_func_ip(ctx);
    e->ksize = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
    e->time = bpf_ktime_get_ns();
    __u64 ret = 0;
    bpf_get_func_ret(ctx, &ret);
    e->ret = ret;

    bpf_ringbuf_submit(e, 0);
    return BPF_OK;
}