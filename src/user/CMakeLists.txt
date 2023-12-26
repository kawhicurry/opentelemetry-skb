FILE(GLOB SOURCE_FILES *.c)

add_library(otlp-skb-user STATIC ${SOURCE_FILES})

find_library(elf libelf)
find_library(curl libcurl)
target_link_libraries(otlp-skb-user elf)
target_link_libraries(otlp-skb-user curl)