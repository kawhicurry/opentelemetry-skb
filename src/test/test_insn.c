#include <stdlib.h>
#include <stdio.h>
#include <bpf/btf.h>
#include <sys/epoll.h>
#include "bpf/main.skel.h"
#include "shared/event.h"

int main()
{
    struct main_bpf *mb = main_bpf__open();
    const struct bpf_program *prog = mb->progs.fexit_prog;
    int insn_cnt = bpf_program__insn_cnt(prog);
    const struct bpf_insn *insns = bpf_program__insns(prog);
    for (int i = 0; i < insn_cnt; i++)
    {
        fprintf(stderr, "%u %u %u %d %d\n",
                insns[i].code,
                insns[i].src_reg,
                insns[i].dst_reg,
                insns[i].off,
                insns[i].imm);
    }
    return 0;
    struct bpf_insn *new_insns = malloc(sizeof(struct bpf_insn) * insn_cnt);
    memcpy(new_insns, insns, sizeof(struct bpf_insn) * insn_cnt);
    new_insns[0].off = 8;
    bpf_program__set_insns(prog, insns, insn_cnt);
    for (int i = 0; i < insn_cnt; i++)
    {
        fprintf(stderr, "%u %u %u %d %d\n",
                new_insns[i].code,
                new_insns[i].src_reg,
                new_insns[i].dst_reg,
                new_insns[i].off,
                new_insns[i].imm);
    }
}