FILE(GLOB SOURCE_FILES *.c)

add_library(otlp-skb-user STATIC ${SOURCE_FILES})

add_library(libelf STATIC IMPORTED)
set_target_properties(libelf PROPERTIES IMPORTED_LOCATION /usr/lib/x86_64-linux-gnu/libelf.a)
set_target_properties(libelf PROPERTIES INTERFACE_INCLUDE_DIRECTORIES /usr/include)
target_link_libraries(otlp-skb-user libelf)