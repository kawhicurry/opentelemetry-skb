#include <stdio.h>
#include <bpf/btf.h>
#include <linux/bpf.h>

#include "user/trace_helpers.h"

int main()
{
    FILE *f;
    int skb_id;
    char funcname[50];
    unsigned long long offset = 18446744071816726816;
    int err = load_kallsyms();
    fprintf(stderr, "err: %d\n", err);
    struct ksym *k = ksym_search(offset);
    fprintf(stderr, "%s\n", k->name);
}