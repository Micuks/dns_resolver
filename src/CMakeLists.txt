add_subdirectory(linked_list)
add_subdirectory(resolver)

add_executable(DNS_resolver main.c)

target_link_libraries(DNS_resolver
    PUBLIC
        linked_list
        resolver
)