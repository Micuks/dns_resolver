#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <assert.h>
#include <errno.h>

#include "resolver.h"

#define RECV_BUFFER_SIZE 64 * 1024
#define HOST_NAME_MAXN 1024
#define DNS_HEADER_MAXN 2048
#define PKT_MAXN 2048
#define CACHE_MAXN 16384
#define DNS_QUERY_TIMEOUT 60 /* IN SECONDS */

#define PORT 53

/* little endian */
struct query {
    struct ll link;
    time_t expiration_time;
    uint16_t transaction_id;
    uint16_t query_type;
    char name[HOST_NAME_MAXN];
    action_t action;
    uint8_t addr[HOST_NAME_MAXN]; /* the only big endian */
    size_t addrlen;
};

void action(struct act_data *acd) {
    switch(acd->error) {
        case(RESO_OK):
            switch(acd->query_type) {
                case(DNS_TYPE_A):
                    printf("domain name: %s\n", acd->name);
                    printf("    ipv4 address: %u.%u.%u.%u\n", acd->addr[0], acd->addr[1], acd->addr[2], acd->addr[3]);
                    break;

                case(DNS_TYPE_AAAA):
                    printf("domain name: %s\n", acd->name);
                    printf("    ipv6 address:"
                            "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                            "%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
                            acd->addr[0], acd->addr[1],acd->addr[2], acd->addr[3],
                            acd->addr[4], acd->addr[5], acd->addr[6], acd->addr[7],
                            acd->addr[8], acd->addr[9], acd->addr[10], acd->addr[11],
                            acd->addr[12], acd->addr[13], acd->addr[14], acd->addr[15]);
                    break;
                
                default:
                    fprintf(stderr, "Invalid query type: 0x%02x\n", acd->query_type);
                    break;
            }
            break;
        
        case(RESO_DOES_NOT_EXIST):
            fprintf(stderr, "can't find address of name %s\n", acd->name);
            break;

        case(RESO_TIMEOUT):
            fprintf(stderr, "query time out for name %s\n", acd->name);
            break;

        case(RESO_ERROR):
            fprintf(stderr, "resolver error!\n");
            break;

        default:
            break;
    }

    // exit(EXIT_SUCCESS);
}

struct dns_header {
    uint16_t transaction_id;
    uint16_t flags;
    uint16_t num_questions;
    uint16_t num_answers;
    uint16_t num_authorities;
    uint16_t num_additionals;
    uint8_t data[1];
};

static int set_non_blocking_mode(int sockfd) {
    int flags;
    flags = fcntl(sockfd, F_GETFL, 0);
    flags = fcntl(sockfd, F_SETFD, flags | O_NONBLOCK);
    return flags;
}

static int get_name_server(struct resolver *resolver) {
    int ret = 0;
    FILE *fp;
    char buffer[512];
    int addr[4];

    if((fp = fopen("/etc/resolv.conf", "r")) == NULL) {
        ret = -1;
    } else {
        for(ret = -1; fgets(buffer, sizeof(buffer), fp) != NULL; ) {
            if(sscanf(buffer, "nameserver %d.%d.%d.%d",
                    addr, addr+1, addr+2, addr+3) == 4) {
                ret = 0;
                resolver->sa.sin_addr.s_addr =
                    htonl(addr[0] << (3 * 8) | addr[1] << (2 * 8) |
                        addr[2] << (1 * 8) | addr[3]);
                break;
            }
        }
        fclose(fp);
    }

    return ret;
}



struct resolver *resolver_init(void) {
    struct resolver *resolver;
    int buffersize = RECV_BUFFER_SIZE;

    if((resolver = (struct resolver *)calloc(1, sizeof(*resolver))) == NULL) {
        fprintf(stderr, "failed to init resolver.\n");
        return NULL;
    } else if((resolver->sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        fprintf(stderr, "failed to init socket\n");
        return NULL;
    } else if(set_non_blocking_mode(resolver->sock) != 0) {
        fprintf(stderr, "failed to set non blocking mode\n");
        return NULL;
    } else if(get_name_server(resolver) != 0) {
        fprintf(stderr, "failed to get name server ip address\n");
        return NULL;
    }

    resolver->sa.sin_family = AF_INET;
    resolver->sa.sin_port = htons(PORT);

    setsockopt(resolver->sock, SOL_SOCKET, SO_RCVBUF,
            &buffersize, sizeof(buffersize));
    // bind(resolver->sock, (const struct sockaddr *)&resolver->sa, sizeof(resolver->sa));
    linked_list_init(&resolver->cached);
    linked_list_init(&resolver->active);

    return resolver;
}

static void free_query(struct query *query) {
    linked_list_remove(&query->link);
    free(query);
}

static struct query *find_cached_query(struct resolver *resolver,
                                enum dns_query_type query_type,
                                const char *name) {
    struct ll *pl, *ptmp;
    struct query *query;

    LINKED_LIST_FOREACH(&resolver->cached, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        if(query->query_type == query_type && !strcasecmp(name, query->name)) {
            /* put the most recently used query at the top */
            linked_list_remove(&query->link);
            linked_list_add_to_front(&resolver->cached, &query->link);
            return query;
        }
    }

    return NULL;
}

static struct query *find_active_query(struct resolver *resolver, uint16_t transaction_id) {
    struct ll *pl, *ptmp;
    struct query *query;

    LINKED_LIST_FOREACH(&resolver->active, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        if(transaction_id == htons(query->transaction_id))
            return query;
    }

    return NULL;
}

static void call_action(struct resolver *resolver, struct query *query,
                        enum resolver_error error) {
    struct act_data actd;
    actd.addr = query->addr;
    actd.addr_len = query->addrlen;
    actd.error = error;
    actd.name = query->name;
    actd.query_type = query->query_type;

    query->action(&actd);

    /* move query to cached list */
    linked_list_remove(&query->link);
    linked_list_add_to_front(&resolver->cached, &query->link);
    resolver->num_cached++;
    if(resolver->num_cached > CACHE_MAXN) {
        query = LINKED_LIST_FRONT(resolver->cached.prev, struct query, link);
        free_query(query);
        resolver->num_cached--;
    }
}

static void parse_pkt(struct resolver *resolver,
                    const unsigned char *pkt,
                    int len) {
    struct dns_header *header = (struct dns_header *)pkt;

    /* single question query */
    if(ntohs(header->num_questions) != 0x01)
        return;
    
    struct query* query = NULL;
    /* return if the query doesn't exist in active query list */
    if((query = find_active_query(resolver, header->transaction_id)) == NULL) {
        fprintf(stderr, "failed to find the query in active list\n");
        return;
    }
    
    /* at least one answer */
    if(header->num_answers == 0) {
        query->addrlen = 0;
        call_action(resolver, query, RESO_DOES_NOT_EXIST);
        return;
    }

    const unsigned char *end, *pos, *bgn;
    int name_len = 0;
    /* skip domain name */
    for(end = pkt + len, bgn = header->data, pos = bgn; pos < end && *pos != '\0'; pos++) {
        name_len++;
    }

    /* check if the query is complete */
    if(pos+5 > end)
        return;

    pos--;
    /* check if the query type matches */
    if(ntohs(((uint16_t *)pos)[1]) != query->query_type) {
        printf("question query type = %u\n", ((uint16_t *)pos)[1]);
        return;
    }

    /* check if the query class is 0x0001(IN) */
    if(ntohs(((uint16_t *)pos)[2]) != 0x0001) {
        printf("question class is 0x%02x\n", ((uint16_t *)pos)[2]);
        return;
    }

    /* jump to answer section */
    pos += 6;

    /* skip possible CNAME answers to find first answer with expected type */
    int found = 0;
    int stop = 0;
    uint16_t qtype = 0;
    uint16_t dlen = 0;
    uint32_t ttl = 0;

    for( ; !stop && pos+12 <= end; ) {
        /* if the name is not in pointer form */
        if(*pos != 0xc0) {
            while(*pos != '\0' && pos+10 <= end) {
                pos++;
            }
            pos--;
        }
        /* little endian */
        qtype = ntohs(((uint16_t *)pos)[1]);

        if(qtype == 5) {
            /* cname length */
            dlen = ntohs(((uint16_t *)pos)[5]);
            /* CNAME type, jump to next answer */
            pos += 12 + dlen;
        } else if(qtype == query->query_type) {
            found = stop = 1;
        } else {
            stop = 1;
        }
    }

    if(found && pos+12 < end) {
        dlen = ntohs(((uint16_t *)pos)[5]);
        /* jump to address */
        pos += 12;
        
        if(pos+dlen <= end) {
            pos -= 6;
            ttl = ntohl(((uint32_t *)pos)[0]);
            query->expiration_time = time(NULL) + (time_t)ttl;
            pos += 6;
            query->addrlen = dlen;
            if(query->addrlen > sizeof(query->addr))
                query->addrlen = sizeof(query->addr);
            memcpy(query->addr, pos, query->addrlen); /* big endian address */
            call_action(resolver, query, RESO_OK);
        }
    }

}

static void bound_check(void *ptr, void *container, size_t consiz) {
    if(ptr > container+consiz) {
        fprintf(stderr, "writing out of bounds\n");
    }
}

void resolver_queue(struct resolver *resolver, const char *name,
                    enum dns_query_type query_type, action_t action) {
    struct query *query;
    time_t now = time(NULL);

    /* find in cached query */
    if((query = find_cached_query(resolver, query_type, name)) != NULL) {
        call_action(resolver, query, RESO_OK);
        if(query->expiration_time < now) {
            linked_list_remove(&query->link);
            resolver->num_cached--;
        }

        return;
    }

    struct act_data atd;
    /* construct a new query and put it in active list */
    if((query = (struct query *)calloc(1, sizeof(struct query))) == NULL) {
        memset(&atd, 0, sizeof(atd));
        atd.error = RESO_ERROR;
        action(&atd);

        return;
    }

    query->query_type = query_type;
    query->transaction_id = ++resolver->transaction_id;
    query->expiration_time = now + DNS_QUERY_TIMEOUT;
    query->action = action;

    char *pos, *end;
    /* case-insensitive domain name */
    for(pos = query->name, end = query->name + sizeof(query->name) - 1;
        *name != '\0' && pos < end; name++, pos++) {
            *pos = tolower(*name);
    }
    *pos = '\0';
    name = query->name;

    char pkt[DNS_HEADER_MAXN];
    struct dns_header *header = (struct dns_header *)pkt;
    /* construct dns query header */
    memset(pkt, 0, sizeof(pkt));
    header->transaction_id = htons(query->transaction_id);
    header->flags = htons(0x0100); /* standard query */
    header->num_questions = htons(0x0001);

    /* encode query zone */
    int len = strlen(name);
    int cnt = 0;
    pos = (char *)header->data;
    const char *sep = name;

    while(*sep != '\0') {
        if((sep = strchr(name, '.')) == NULL) {
            sep = name + strlen(name);
        }
        cnt = sep - name; 
        *(pos++) = (uint8_t)cnt;

        for(int i = 0; i < cnt; i++) {
            *(pos++) = name[i];
        }

        name += cnt + 1;
    }

    *(pos++) = 0x00; /* mark end of domain name */
    *(pos++) = 0x00;
    *(pos++) = (uint8_t) query_type;
    *(pos++) = 0x00;
    *(pos++) = (uint8_t) 0x01;

    bound_check(pos, pkt, sizeof(pkt));
    /* now len is packet len */
    len = pos - pkt;
    if(sendto(resolver->sock, pkt, len, 0,
            (const struct sockaddr *)&resolver->sa, sizeof(resolver->sa)) != len) {
                memset(&atd, 0, sizeof(atd));
                atd.error = RESO_ERROR;
                action(&atd);
                free_query(query);
    }
    linked_list_add_to_rear(&resolver->active, &query->link);
}

static int socket_ready(struct resolver *resolver, int timeout_ms) {
    struct timeval tv;
    fd_set read_set; /* only readable file descripter needed */

    FD_ZERO(&read_set);
    FD_SET(resolver->sock, &read_set);

    tv.tv_sec = (time_t)timeout_ms / 1000;
    tv.tv_usec = (suseconds_t)timeout_ms % 1000 * 1000;

    return select(resolver->sock+1, &read_set, NULL, NULL, &tv);
}

int resolver_poll(struct resolver *resolver, int timeout_ms) {
    /* whether response arrives */
    if(socket_ready(resolver, timeout_ms) <= 0)
        return 0;
    
    /* receive new responses from server */
    int len = 0;
    unsigned char pkt[PKT_MAXN];
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    int num_pkt = 0;
    int flags = fcntl(resolver->sock, F_GETFD, 0);
    fcntl(resolver->sock, F_SETFD, flags | O_NONBLOCK);
    /* already called sendto() before recvfrom() so system has already called bind() automatically */
    while((len = recvfrom(resolver->sock, pkt, sizeof(pkt), 0,
                            (struct sockaddr *)&sa, &sa_len)) > 0 &&
            len > (int) sizeof(struct dns_header)) {
        parse_pkt(resolver, pkt, len);
        num_pkt++;
    }

    struct ll *pl, *ptmp;
    struct query *query;
    time_t now = time(NULL);
    /* clean up died active queries */
    LINKED_LIST_FOREACH(&resolver->active, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        if(query->expiration_time < now) {
            call_action(resolver, query, RESO_TIMEOUT);
            free_query(query);
        }
    }

    /* clean up died cached queries */
    LINKED_LIST_FOREACH(&resolver->cached, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        if(query->expiration_time < now) {
            free_query(query);
            resolver->num_cached--;
        }
    }

    return num_pkt;
}

void free_resolver(struct resolver **ptr_resolver) {
    struct ll *pl, *ptmp;
    struct query *query;
    /* free all cached queries */
    LINKED_LIST_FOREACH(&(*ptr_resolver)->cached, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        free_query(query);
    }

    /* free all active queries */
    LINKED_LIST_FOREACH(&(*ptr_resolver)->active, pl, ptmp) {
        query = LINKED_LIST_FRONT(pl, struct query, link);
        free_query(query);
    }

    free(*ptr_resolver);
    *ptr_resolver = NULL;
}