find_program(CLANG clang REQUIRED)
find_program(BPFTOOL bpftool REQUIRED)

file(GLOB BPF_SOURCES *.c)
set(BPF_SKEL "")
foreach(bpf_source ${BPF_SOURCES})
    get_filename_component(bpf_name ${bpf_source} NAME_WE)
    add_custom_command(
        OUTPUT ${bpf_name}
        PRE_LINK
        COMMAND ${CLANG} -D__TARGET_ARCH_x86-64 -g -O2 -target bpf -I${CMAKE_SOURCE_DIR}/src/ -c ${bpf_source} -o ${bpf_name}.bpf.o
        COMMAND ${BPFTOOL} gen skeleton ${bpf_name}.bpf.o > ${PROJECT_SOURCE_DIR}/src/bpf/${bpf_name}.skel.h
        DEPENDS ${CLANG} ${BPFTOOL}
    )
    add_custom_target(bpf-${bpf_name} DEPENDS ${bpf_name})
    list(APPEND BPF_SKEL bpf-${bpf_name})
endforeach(bpf_source ${BPF_SOURCES})

add_custom_target(bpf-skel DEPENDS ${BPF_SKEL})

add_custom_command(OUTPUT ${PROJECT_SOURCE_DIR}/shared/vmlinux.h
    PRE_LINK
    COMMAND ${BPFTOOL} btf dump file /sys/kernel/btf/vmlinux format c > ${PROJECT_SOURCE_DIR}/src/shared/vmlinux.h
    DEPENDS BPFTOOL
)

add_custom_target(vmlinux DEPENDS ${PROJECT_SOURCE_DIR}/src/shared/vmlinux.h)
