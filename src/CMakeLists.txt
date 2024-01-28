find_library(libelf elf)
find_library(libbpf bpf PATHS /usr/lib64 REQUIRED)
find_library(libcurl curl REQUIRED)

add_subdirectory(user)
add_subdirectory(test)
add_subdirectory(bpf)

add_executable(otlp-skb main.c)
target_include_directories(otlp-skb PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(otlp-skb PRIVATE otlp-skb-user)
