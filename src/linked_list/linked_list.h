#ifndef LINKED_LIST_H
#define LINKED_LIST_H

#include <stddef.h>

struct ll {
    struct ll *prev;
    struct ll *next;
};

void linked_list_init(struct ll *linked_list);

void linked_list_add_to_front(struct ll *head, struct ll *node);

void linked_list_add_to_rear(struct ll *head, struct ll *node);

int linked_list_empty(struct ll *head);

void linked_list_remove(struct ll *node);

#define LINKED_LIST_FOREACH(head, node, tmp) \
    for(node = (head)->next, tmp = (node)->next; node != (head); node = tmp, tmp = (node)->next)

#define LINKED_LIST_FRONT(node, container, node_pos) \
    ((container *)((char *)(node) - offsetof(container, node_pos)))

#endif