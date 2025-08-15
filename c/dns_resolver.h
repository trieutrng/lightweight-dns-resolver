#ifndef DNS_RESOLVER_H
#define DNS_RESOLVER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h> 
#include <sys/socket.h>
#include<errno.h>

#define A       0x01
#define NS      0x02
#define CNAME   0x05
#define MX      0x0F
#define TXT     0x10
#define AAAA    0x1C

#define BUFFER 1024

// Define structs
struct Query {
    char dns_host[256];
    char dns_port[10];
    char domain[256];
    int type;
};
// End define

// Define methods
int getquerytype(const char *type, struct Query *query); 
int getqueryinfo(int argc, char *args[], struct Query *query);
int buildDNSQuery(struct Query *query);
// End define

int getqueryinfo(int argc, char *args[], struct Query *query) {
    strncpy(query->domain, args[1], sizeof(query->domain));

    for (int i=2; i<argc; i++) {
        if (strcmp("-t", args[i]) == 0) {
            if (i+1 < argc) {
                int typers = getquerytype(args[++i], query);
                if (typers != 0) {
                    return -1;
                }
            } else {
                return -1;
            }
        } else if (strcmp("-s", args[i]) == 0) {
            if (i+1 < argc) {
                strncpy(query->dns_host, args[++i], sizeof(query->dns_host));
            } else {
                return -1;
            }
        } else if (strcmp("-p", args[i]) == 0) {
            if (i+1 < argc) {
                strncpy(query->dns_port, args[++i], sizeof(query->dns_port));
            } else {
                return -1;
            }
        }
    }

    return 0;
}

int getquerytype(const char *type, struct Query *query) {
    if (strcasecmp("A", type) == 0) {
        query->type = A;
    } else if (strcasecmp("NS", type) == 0) {
        query->type = NS;
    } else if (strcasecmp("CNAME", type) == 0) {
        query->type = CNAME;
    } else if (strcasecmp("MX", type) == 0) {
        query->type = MX;
    } else if (strcasecmp("TXT", type) == 0) {
        query->type = TXT;
    } else if (strcasecmp("AAAA", type) == 0) {
        query->type = AAAA;
    } else {
        printf("invalid query type: %s\n", type);
        return -1;
    }
    return 0;
}

void printhelp() {
    printf("usage: dns_resolver domain\n");
    printf("flags: \n");
    printf("\t -t: record type a | aaaa | txt | mx\n");
    printf("\t -s: dns server\n");
    printf("\t -p: dns server port\n");
    printf("example: dns_resolver google.com -t aaaa -s 8.8.8.8 -p 53\n");
}

char* type_str(int type) {
    switch (type) {
        case A: return "A";
        case NS: return "NS";
        case CNAME: return "CNAME";
        case MX: return "MX";
        case TXT: return "TXT";
        case AAAA: return "AAAA";
        default: return "null";
    }
}

#endif