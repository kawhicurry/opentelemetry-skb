#include <stdio.h>
#include <bpf/btf.h>

int main()
{
    FILE *f;
    int skb_id;
    char funcname[50];
    f = fopen("../misc/func-list/func_list.txt", "r");
    if (!f)
        return -1;
    const struct btf *btf = btf__load_vmlinux_btf();
    const struct btf_type *skb_type;
    skb_id = btf__find_by_name(btf, "sk_buff");
    skb_type = btf__type_by_id(btf, skb_id);
    while (fgets(funcname, 50, f))
    {
        int func_id, len, i;
        const struct btf_type *func, *func_proto;
        const struct btf_param *params;
        char *c;
        c = strchr(funcname, '\n');
        if (c)
            *c = 0;
        else
            continue;
        func_id = btf__find_by_name(btf, funcname);
        if (func_id < 0)
        {
            i = -2;
            goto output;
        }
        func = btf__type_by_id(btf, func_id);
        if (!func)
            continue;
        func_proto = btf__type_by_id(btf, func->type);
        if (!func_proto)
            continue;
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
            {
                break;
            }
        }
        if (i == len)
        {
            i = -1;
        }
    output:
        fprintf(stderr, "%s:%d\n", funcname, i);
    }
    // fprintf(stderr, "%d %d\n", len, params->name_off);
}