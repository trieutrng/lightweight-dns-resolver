#include "dns_resolver.h"

int main(int argc, char *args[]) {
    if (argc < 3) {
        printhelp();
        exit(1);
    }

    struct Query query;
    int rs = getqueryinfo(argc, args, &query);

    if (rs != 0) {
        printhelp();
        exit(1);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    
    int status;
    struct addrinfo *info;

    if ((status = getaddrinfo(query.dns_host, query.dns_port, &hints, &info)) != 0) {
        printf("DNS host can't be resolved: err %s", gai_strerror(status));
        exit(1);
    }

    return 0;
}