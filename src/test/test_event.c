#include <stdlib.h>
#include <stdio.h>
#include <bpf/btf.h>
#include <sys/epoll.h>
#include "bpf/main.skel.h"
#include "shared/event.h"
#include "user/otlp.h"
#include "user/trace_helpers.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int handle_entry_event(void *ctx, void *data, size_t size)
{
    int count = 0;
    event_t *e = data;
    long offset = e->ksize / sizeof(__u64);
    struct ksym *func_sym = ksym_search(e->addr);
    if (e->type)
    {
        // fexit
        fprintf(stderr, "=== %llu %llu %llu\n", e->addr, e->time, e->skb);
    }
    else
    {
        // fentry
        int trace_offset;
        for (int i = 0; i < offset; i++)
        {
            struct ksym *stack_sym;
            stack_sym = ksym_search(e->kstack[i]);
            if (stack_sym == func_sym)
            {
                trace_offset = i;
            }
            fprintf(stderr, "### %2d %-30s %-30s\n", i, stack_sym->name, func_sym->name);
        }
        fprintf(stderr, "@@@ %s %llu %lluT%llu %ld\n",
                func_sym->name, e->time, e->skb, e->timestamp, offset - trace_offset);
    }
    // static int event_size = 0;
    // static event_t *events;
    // event_size += 1;
    // realloc(events, event_size * sizeof(event_t));
}

int check_pos(const struct btf *btf, char *funcname)
{
    int func_id, len, i;
    const struct btf_type *func, *func_proto;
    const struct btf_param *params;
    int skb_id = btf__find_by_name(btf, "sk_buff");
    const struct btf_type *skb_type = btf__type_by_id(btf, skb_id);
    char *c = strchr(funcname, '\n');
    if (c)
        *c = 0;
    else
        return -1;
    func_id = btf__find_by_name(btf, funcname);
    if (func_id < 0)
        return -1;
    func = btf__type_by_id(btf, func_id);
    if (!func)
        return -1;
    func_proto = btf__type_by_id(btf, func->type);
    if (!func_proto)
        return -1;
    params = btf_params(func_proto);
    len = btf_vlen(func_proto);
    // fprintf(stderr, "%s %p %p %p\n", funcname, func, func_proto, params);
    for (i = 0; i < len; i++, params++)
    {
        // fprintf(stderr, "%d %d\n", params->type, params->name_off);
        const char *name;
        const struct btf_type *t, *tt;
        t = btf__type_by_id(btf, params->type);
        tt = btf__type_by_id(btf, t->type);
        name = btf__name_by_offset(btf, tt->name_off);
        // fprintf(stderr, "%s %d %d\n", name, t->type, skb_id);
        if (t->type == skb_id)
            return i;
    }
    return -1;
}

int relocate_skb(struct bpf_program *prog, int pos)
{
    int insn_cnt = bpf_program__insn_cnt(prog);
    const struct bpf_insn *insns = bpf_program__insns(prog);
    struct bpf_insn *new_insns = malloc(sizeof(struct bpf_insn) * insn_cnt);
    for (int i = 0; i < insn_cnt; i++)
    {
        if (insns[i].code == 121)
        {
            new_insns[i].off = pos * 4;
            break;
        }
    }
    memcpy(new_insns, insns, sizeof(struct bpf_insn) * insn_cnt);
    bpf_program__set_insns(prog, new_insns, insn_cnt);
}

int main()
{
    libbpf_set_print(libbpf_print_fn);

    int err;
    FILE *f = fopen("../misc/func-list/func_list.txt", "r");
    load_kallsyms();
    const struct btf *btf = btf__load_vmlinux_btf();
    int epfd = epoll_create1(0);
    char funcname[30];
    int mb_cnt = 0;
    struct main_bpf *mbs[10240];
    struct ring_buffer *entry_rb[10240];
    while (fgets(funcname, 30, f))
    {
        int pos = check_pos(btf, funcname);
        if (pos < 0)
            continue;
        int err;
        struct main_bpf *mb = main_bpf__open();
        struct bpf_program *prog;
        struct bpf_object *obj;
        bpf_object__for_each_program(prog, mb->obj)
        {
            relocate_skb(prog, pos);
            err = bpf_program__set_attach_target(prog, 0, funcname);
            if (err)
                fprintf(stderr, "!!! Failed set attach: %s\n", funcname);
        }
        main_bpf__load(mb);
        err = main_bpf__attach(mb);
        if (err)
        {
            fprintf(stderr, "= failed load and attach %s\n", funcname);
            continue;
        }
        fprintf(stderr, "@ load and attach %s\n", funcname);
        mbs[mb_cnt] = main_bpf__open();
        entry_rb[mb_cnt] = ring_buffer__new(bpf_map__fd(mb->maps.entry_rb), handle_entry_event, NULL, NULL);
        mb_cnt++;
    }
    while (true)
    {
        // collect data from ringbuf
        for (int i = 0; i < mb_cnt; i++)
        {
            ring_buffer__poll(entry_rb[i], 10);
            // ring_buffer__consume(entry_rb[i]);
        }
        // send data
    }
}
