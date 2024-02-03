#include <stdlib.h>
#include <stdio.h>
#include <bpf/btf.h>
#include <sys/epoll.h>
#include <sys/resource.h>
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
    long trace_offset;
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
    if (e->type)
    {
        // fexit
        fprintf(stderr, "=== %s %llu %llu %lu %llu\n",
                func_sym->name, e->time, e->skb, offset - trace_offset, e->ret);
    }
    else
    {
        // fentry
        fprintf(stderr, "@@@ %s %llu %llu %ld\n",
                func_sym->name, e->time, e->skb, offset - trace_offset);
    }
    // static int event_size = 0;
    // static event_t *events;
    // event_size += 1;
    // realloc(events, event_size * sizeof(event_t));
}

int check_pos(const struct btf *btf, const struct btf_type *func)
{
    int func_id, len, i;
    const struct btf_type *func_proto;
    const struct btf_param *params;
    int skb_id = btf__find_by_name(btf, "sk_buff");
    const struct btf_type *skb_type = btf__type_by_id(btf, skb_id);
    if (!btf_is_func(func))
        return -2;
    func_proto = btf__type_by_id(btf, func->type);
    if (!func_proto)
        return -2;
    const struct btf_type *ret_type = btf__type_by_id(btf, func_proto->type);
    if (func_proto->type == skb_id)
    {
        const char *name = btf__name_by_offset(btf, ret_type->name_off);
        fprintf(stderr, "%s %d %d\n", name, ret_type->type, skb_id);
        return -1; // func that return skb
    }
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
    return -2;
}

int relocate_skb(struct bpf_program *prog, int pos)
{
    int insn_cnt = bpf_program__insn_cnt(prog);
    const struct bpf_insn *insns = bpf_program__insns(prog);
    struct bpf_insn *new_insns = malloc(sizeof(struct bpf_insn) * insn_cnt);
    int latest_mov = -1;
    for (int i = 0; i < insn_cnt; i++)
    {
        if (insns[i].code == 183) // mov
        {
            latest_mov = i;
        }
        if (insns[i].code == 133 && insns[i].imm == 183)
        {
            new_insns[i].imm = pos;
            break;
        }
    }
    memcpy(new_insns, insns, sizeof(struct bpf_insn) * insn_cnt);
    bpf_program__set_insns(prog, new_insns, insn_cnt);
}

int unlimit_fd()
{
    struct rlimit rlim;
    // rlim.rlim_cur = rlim.rlim_max = RLIM_INFINITY;
    rlim.rlim_cur = rlim.rlim_max = 1048576;
    setrlimit(RLIMIT_NOFILE, &rlim);
}

int main()
{
    // libbpf_set_print(libbpf_print_fn);

    int err;
    unlimit_fd();
    load_kallsyms();
    const struct btf *btf = btf__load_vmlinux_btf();
    int epfd = epoll_create1(0);
    int mb_cnt = 0;
    struct main_bpf *mbs[10240];
    struct ring_buffer *entry_rb[10240];
    int type_cnt = btf__type_cnt(btf);
    for (int i = 1; i < type_cnt; i++) // 0 is void
    {
        const struct btf_type *t = btf__type_by_id(btf, i);
        int pos = check_pos(btf, t);
        if (pos < 0)
            continue;
        int err;
        const char *funcname = btf__name_by_offset(btf, t->name_off);
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
        err = main_bpf__load(mb);
        if (err)
        {
            fprintf(stderr, "= failed to load %s\n", funcname);
            continue;
        }
        err = main_bpf__attach(mb);
        if (err)
        {
            fprintf(stderr, "= failed to attach %s\n", funcname);
            continue;
        }
        fprintf(stderr, "@ load and attach %s %d/%d\n", funcname, i, type_cnt);
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
