#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "resolver.h"

int main(int argc, char *argv[]) {
    for(int i = 0; i < argc; i++) {
        printf("%s\n", argv[i]);
    }

    if(argc < 2) {
        fprintf(stderr, "no name given\n");
        return -1;
    }
    char *name = argv[1];
    enum dns_query_type query_type = DNS_TYPE_A;
    struct resolver *resolver;

    if((resolver = resolver_init()) == NULL) {
        fprintf(stderr, "failed to init resolver\n");
        exit(EXIT_FAILURE);
    }

    resolver_queue(resolver, name, query_type, action);
    resolver_queue(resolver, name, query_type, action);

    resolver_poll(resolver, 3000);

    free_resolver(&resolver);
    
    return EXIT_SUCCESS;
}

// int main(int argc, char *argv[]) {
//     /* Init socket used to communicate with client */
//     int sockfd;
//     char buffer[MAX_BUFFER];
//     struct sockaddr_in servaddr, cliaddr;

//     if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
//         perror("socket creation failed");
//         exit(EXIT_FAILURE);
//     }

//     memset(&servaddr, 0, sizeof(servaddr));
//     memset(&cliaddr, 0, sizeof(cliaddr));

//     servaddr.sin_family = AF_INET;
//     servaddr.sin_addr.s_addr = inet_addr(LOCALHOST);
//     servaddr.sin_port = htons(PORT);

//     if (bind(sockfd, (const struct sockaddr *)&servaddr,
//              sizeof(servaddr)) < 0) {
//         perror("bind failed");
//         exit(EXIT_FAILURE);
//     }

//     int len, n;

//     /* Init socket used to communicate with server */
//     const char *domain = argv[1];
//     const char *server = NULL;
//     enum dns_query_type query_type = DNS_TYPE_A;
//     struct resolver *resolver;

//     if((resolver = resolver_init()) == NULL) {
//         fprintf(stderr, "failed to init resolver.\n");
//         exit(EXIT_FAILURE);
//     }

//     while(1) {
//         /* poll cached query and reply in poll function */
//         client_poll(client, 5 * 1000);

//         /* resolver takes action among client->cached queries */

//     }

//     close(sockfd);

//     /* destroy resolver */

//     return 0;
// }