add_library(resolver resolver.c)

target_sources(resolver
    PRIVATE
        resolver.c
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/resolver.h
    )

target_include_directories(resolver
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
    )

target_link_libraries(resolver
    PUBLIC
        linked_list
    )