#include "resolver.h"

#define PKT_MAXN 2048

void parse_client(struct client *client, char *pkt, int len) {
    /* parse pkt */

    /* queue in client->cached */
}

int client_poll(struct client *client, int timeout_ms) {
    int num_pkt = 0;

    /* check is client socket ready */

    char pkt[PKT_MAXN];
    int len;
    /* check client socket for new queries */
/*     while(recvfrom())
        parse_client(client, pkt, len);
        num_pkt++;
 */
}