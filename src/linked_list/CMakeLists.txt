add_library(linked_list linked_list.c)

target_sources(linked_list
    PRIVATE
        linked_list.c
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}/linked_list.h
    )

target_include_directories(linked_list
    PUBLIC
        ${CMAKE_CURRENT_LIST_DIR}
    )