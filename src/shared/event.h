#ifndef __EVENT_H__
#define __EVENT_H__

struct skb_event
{
    __u32 ptr;
    __u32 func;
    __u32 skb;
    __u32 skb_t;
};

#define MAX_STACK_SIZE 31
struct stack_event
{
    __u64 ksize;
    __u64 kstack[MAX_STACK_SIZE];
};

#endif