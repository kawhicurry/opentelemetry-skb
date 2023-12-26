add_subdirectory(user)
add_subdirectory(test)

add_executable(otlp-skb main.c)
target_link_libraries(otlp-skb PRIVATE otlp-skb-user)
