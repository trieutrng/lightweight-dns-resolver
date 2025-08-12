#include "dns_resolver.h"

u_int8_t message_size(char *domain) {
    uint8_t header = 12;
    uint8_t question = 0;
    char* p = domain;
    while (*p) {
        if (question == 0) {
            question++;
        }
        question++; 
        p++;
    }
    question += 1; // name end with 0
    return header + question;
}

char* build_dns_packet(struct Query *query) {

    uint8_t size = message_size(query->dns_host);
    char *buf = malloc(size);
    char *p_start = buf;

    // header
    *buf++ = 0xAB; *buf++ = 0xCD;           // ID
    *buf++ = 0x01; *buf++ = 0x00;           // set RD bit
    *buf++ = 0x00; *buf++ = 0x01;           // QDCOUNT = 1
    *buf++ = 0x00; *buf++ = 0x00;           // ANCOUNT = 0
    *buf++ = 0x00; *buf++ = 0x00;           // QDCOUNT = 0
    *buf++ = 0x00; *buf++ = 0x00;           // ARCOUNT = 0

    // question
    char *p_size = buf++, *p_char = query->dns_host;
    while (*p_char) {
        if (*p_char == '.') {
            *p_size = buf - p_size - 1;
            p_size = buf;
        } else {
            *buf = *p_char;
        }
        buf++;
        p_char++;
    }
    *buf++ += 0x00;                         // end name
    *buf++ = 0x00; *buf++ = query->type;    // QTYPE
    *buf++ = 0x00; *buf++ = 0x01;           // QCLASS = 1, internet

    return p_start;
}

int open_udp_connection(char *host, char *port, struct addrinfo *addrinfo) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    

    if (getaddrinfo(host, port, &hints, &addrinfo) != 0) {
        printf("DNS host can't be resolved: %s", strerror(errno));
        exit(1);
    }

    int sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if (sockfd < 0) {
        printf("Can't not open socket");
        exit(1);
    }

    // if (connect(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen) == -1) {
    //     printf("DNS host can't be resolved: %s", strerror(errno));
    //     exit(1);
    // }

    return sockfd;
}

int queryUDP(char *host, char *port, char *packet, int *istruncated) {
    struct addrinfo *addrinfo;

    int udp = open_udp_connection(host, port, addrinfo);

    printf("udp fd: %d\n", udp);

    return -1;
}

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
    char *dns_packet = build_dns_packet(&query);

    return 0;
}