#include "linked_list.h"

inline void linked_list_init(struct ll *linked_list) {
    linked_list->next = linked_list;
    linked_list->prev = linked_list;
}

inline void linked_list_add_to_front(struct ll *head, struct ll *node) {
    node->prev = head;
    node->next = head->next;
    head->next->prev = node;
    head->next = node;
}

inline void linked_list_add_to_rear(struct ll *head, struct ll *node) {
    node->next = head;
    node->prev = head->prev;
    head->prev->next = node;
    head->prev = node;
}

inline int linked_list_empty(struct ll *head) {
    return head->prev == head;
}

inline void linked_list_remove(struct ll *node) {
    node->prev->next = node->next;
    node->next->prev = node->prev;
    linked_list_init(node);
}