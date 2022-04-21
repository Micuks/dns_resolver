#ifndef RESOLVER_H
#define RESOLVER_H

#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <unistd.h>

#include "linked_list.h"

enum resolver_error {
    RESO_OK,
    RESO_DOES_NOT_EXIST,
    RESO_TIMEOUT,
    RESO_ERROR
};

enum dns_query_type {
    DNS_TYPE_A = 0x01,
    DNS_TYPE_AAAA = 0x1c
};

struct resolver {
    int sock;
    struct sockaddr_in sa;
    uint16_t transaction_id;

    struct ll active;
    struct ll cached;
    int num_active;
    int num_cached;
};

struct act_data {
	enum resolver_error error;
    enum dns_query_type query_type;
    const char *name;
    const unsigned char *addr;
    size_t addr_len;
};

typedef void(*action_t)(struct act_data *);

struct resolver *resolver_init(void);

void resolver_queue(struct resolver *resolver, const char *name,
                    enum dns_query_type query_type, action_t action);

int resolver_poll(struct resolver *resolver, int timeout_ms);

void free_resolver(struct resolver **ptr_resolver);

void action(struct act_data *acd);

#endif