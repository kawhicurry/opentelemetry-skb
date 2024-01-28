#ifndef __EVENT_H__
#define __EVENT_H__

struct skb_event
{
    __u32 ptr;
    __u32 func;
    __u32 skb;
    __u32 skb_t;
};

#define MAX_STACK_SIZE 64
struct stack_event
{
    __u64 ip;
    __u64 ksize;
    __u64 kstack[MAX_STACK_SIZE];
};

typedef struct
{
    __u64 type;                   // 0 for fentry, 1 for fexit
    __u64 addr;                   // tracing function ip
    __u64 time;                   // kernel nanoseconds
    __u64 ksize;                  // kstack size
    __u64 kstack[MAX_STACK_SIZE]; // current kernel stack
    __u64 skb;
    __u64 timestamp; // skb's tstamp
} event_t;

#endif