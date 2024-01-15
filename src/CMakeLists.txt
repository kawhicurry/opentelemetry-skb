find_library(elf libelf)
find_library(curl libcurl)
find_library(bpf libbpf)

add_subdirectory(user)
add_subdirectory(test)
add_subdirectory(bpf)

add_executable(otlp-skb main.c)
target_link_libraries(otlp-skb PRIVATE otlp-skb-user)
