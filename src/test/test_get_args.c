#include "bpf/stack.skel.h"
#include "shared/event.h"
#include <bpf/libbpf.h>

#include <gelf.h>
#include <zlib.h>

struct elf_state
{
    int fd;
    const void *obj_buf;
    size_t obj_buf_sz;
    Elf *elf;
    Elf64_Ehdr *ehdr;
    Elf_Data *symbols;
    Elf_Data *st_ops_data;
    Elf_Data *st_ops_link_data;
    size_t shstrndx; /* section index for section name strings */
    size_t strtabidx;
    struct elf_sec_desc *secs;
    size_t sec_cnt;
    int btf_maps_shndx;
    __u32 btf_maps_sec_btf_id;
    int text_shndx;
    int symbols_shndx;
    int st_ops_shndx;
    int st_ops_link_shndx;
};

struct bpf_object
{
    char name[BPF_OBJ_NAME_LEN];
    char license[64];
    __u32 kern_version;

    struct bpf_program *programs;
    size_t nr_programs;
    struct bpf_map *maps;
    size_t nr_maps;
    size_t maps_cap;

    char *kconfig;
    struct extern_desc *externs;
    int nr_extern;
    int kconfig_map_idx;

    bool loaded;
    bool has_subcalls;
    bool has_rodata;

    struct bpf_gen *gen_loader;

    /* Information when doing ELF related work. Only valid if efile.elf is not NULL */
    struct elf_state efile;

    struct btf *btf;
    struct btf_ext *btf_ext;

    /* Parse and load BTF vmlinux if any of the programs in the object need
     * it at load time.
     */
    struct btf *btf_vmlinux;
    /* Path to the custom BTF to be used for BPF CO-RE relocations as an
     * override for vmlinux BTF.
     */
    char *btf_custom_path;
    /* vmlinux BTF override for CO-RE relocations */
    struct btf *btf_vmlinux_override;
    /* Lazily initialized kernel module BTFs */
    struct module_btf *btf_modules;
    bool btf_modules_loaded;
    size_t btf_module_cnt;
    size_t btf_module_cap;

    /* optional log settings passed to BPF_BTF_LOAD and BPF_PROG_LOAD commands */
    char *log_buf;
    size_t log_size;
    __u32 log_level;

    int *fd_array;
    size_t fd_array_cap;
    size_t fd_array_cnt;

    struct usdt_manager *usdt_man;

    char path[];
};

#define ERR(err)                                              \
    if (err)                                                  \
    {                                                         \
        fprintf(stderr, "error:%d line:%d\n", err, __LINE__); \
        goto clean;                                           \
    }

int handle_event(void *ctx, void *data, size_t data_size)
{
    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

int check_arg_pos(char *hook, int pos)
{
    int err;
    struct stack_bpf *sb = stack_bpf__open();
    struct bpf_program *prog;

    switch (pos)
    {
    case 1:
        prog = sb->progs.func_arg_1;
        break;
    case 2:
        prog = sb->progs.func_arg_2;
        break;
    case 3:
        prog = sb->progs.func_arg_3;
        break;
    default:
        goto clean;
    }
    err = bpf_program__set_autoload(prog, true);
    ERR(err)
    err = bpf_program__set_expected_attach_type(prog, BPF_TRACE_FENTRY);
    ERR(err)
    err = bpf_program__set_attach_target(prog, 0, hook);
    ERR(err)
    err = stack_bpf__load(sb);
clean:
    stack_bpf__destroy(sb);
    if (err)
        return err;
    return 0;
}

int main()
{
    libbpf_set_print(libbpf_print_fn);
    FILE *f = fopen("../misc/func-list/func_list.txt", "r");
    char funcname[30];
    // check_arg_pos("ip_rcv",1);
    // return 0;
    while (fgets(funcname, 30, f))
    {
        char *c = strchr(funcname, '\n');
        if (c)
            *c = 0;
        int err;
        int pos;
        for (pos = 1; pos < 4; pos++)
        {
            // fprintf(stderr, "debug: Try   func:%s pos:%d err:%d \n", funcname, pos, 0);
            err = check_arg_pos(funcname, pos);
            if (!err)
            {
                // fprintf(stderr, "info: Found func:%s pos:%d\n", funcname, pos);
                fprintf(stdout, "info: Found %s:%d\n", funcname, pos - 1);
                break;
            }
            char errinfo[30];
            libbpf_strerror(err, errinfo, 30);
            // fprintf(stderr, "debug: Not found func:%s pos:%d err:%d errinfo:%s\n", funcname, pos, err, errinfo);
        }
        // fprintf(stderr, "debug: Failed func:%s pos:%d err:%d\n", funcname, pos, err);
    }
    fclose(f);
    // while (true)
    // {
    // }
    return 0;
}