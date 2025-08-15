#include "dns_resolver.h"

int message_size(char *domain) {
    int header = 12;
    int question = 0;
    char *p = domain;
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

int build_dns_packet(struct Query *query, char *packet) {
    int size = message_size(query->domain);
    memset(packet, 0, size);
    char *buf = packet;

    // header
    *buf++ = 0xAB; *buf++ = 0xCD;           // ID
    *buf++ = 0x01; *buf++ = 0x00;           // QR=0,OPCODE=0,AA=0,TC=0,RD=1,RA=0,Z=0,RCODE=0
    *buf++ = 0x00; *buf++ = 0x01;           // QDCOUNT = 1
    *buf++ = 0x00; *buf++ = 0x00;           // ANCOUNT = 0
    *buf++ = 0x00; *buf++ = 0x00;           // QDCOUNT = 0
    *buf++ = 0x00; *buf++ = 0x00;           // ARCOUNT = 0

    // question
    char *p_size = buf++, *p_char = query->domain;
    while (*p_char) {
        if (*p_char == '.') {
            *p_size = (buf - p_size - 1);
            p_size = buf;
        } else {
            *buf = *p_char;
        }
        buf++;
        p_char++;
    };

    *p_size = (buf - p_size - 1);
    *buf++ = 0x00;                          // end name
    *buf++ = 0x00; *buf++ = query->type;    // QTYPE
    *buf++ = 0x00; *buf++ = 0x01;           // QCLASS = 1, internet

    return buf - packet;
}

int open_udp_connection(char *host, char *port, struct addrinfo **addrinfo) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host, port, &hints, addrinfo) != 0) {
        printf("DNS host can't be resolved: %s", strerror(errno));
        exit(1);
    }

    int sockfd = socket((*addrinfo)->ai_family, (*addrinfo)->ai_socktype, (*addrinfo)->ai_protocol);
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

int queryUDP(char *host, char *port, char *packet, int packet_size, char *res_buf, int *truncated) {
    struct addrinfo *addrinfo;
    int udp = open_udp_connection(host, port, &addrinfo);
    int sent = sendto(
        udp, 
        packet, packet_size,
        0,
        addrinfo->ai_addr, addrinfo->ai_addrlen
    );
    if (sent == -1) {
        perror("sendto failed");
        return -1;    
    }
    printf("sent %d bytes\n", sent);
    int read = recvfrom(udp, res_buf, BUFFER, 0, NULL, NULL);
    if (read < 3) { // 3 to ensure response contains truncated flag
        printf("DNS query failed: %s\n", strerror(errno));
        return -1;
    }
    freeaddrinfo(addrinfo);
    *truncated = (res_buf[2] >> 1) & 1;
    return read;
}

unsigned char* extract_name(unsigned char *p_name, unsigned char **res) {
    unsigned char name[BUFFER];
    int size = *p_name++, i=0;
    while (size) {
        for (int j=0; j<size; j++) {
            name[i++] = *(p_name++);
        }
        name[i] = '.';
        size = *(p_name++);
        if (size) {
            i++;
        }
    }
    name[i] = '\0'; // overwrite last '.'
    
    // allocate memory for result (+1 for '\0')
    unsigned char *copy = malloc(i + 1);
    memcpy(copy, name, i + 1);
    *res = copy;

    return p_name;
}

unsigned char* get_name(unsigned char *msg, unsigned char *p_name, unsigned char **res) {
    if ((*p_name & 0xC0) == 0xC0) {
        // pointer name
        int offset = ((*p_name & 0x3F) << 8) + p_name[1];
        printf("\tpointer: offset %d - ", offset);
        extract_name(msg + offset, res);
        return p_name + 2;
    }

    return extract_name(p_name, res);
}

void resolve_dns_response(char *dns_res, int res_size) {
    unsigned char *res = (unsigned char *) dns_res;

    printf("recv: %d bytes\n", res_size);
    printf("\n");
    printf("ID: %0X %0X\n", res[0], res[1]);

    const int RQ = (res[2] >> 7) & 1;
    const int OPCODE = (res[2] >> 3) & 0x0F;
    const int AA = (res[2] >> 2) & 0x01;
    const int TC = (res[2] >> 1) & 0x01;
    const int RD = res[2] & 0x01;
    const int RA = (res[3] >> 7) & 1;
    const int Z = (res[3] >> 4) & 0x07;
    const int RCODE = res[3] & 0x0F;

    const int QDCOUNT = (res[4] << 8) + res[5];
    const int ANCOUNT = (res[6] << 8) + res[7];
    const int NSCOUNT = (res[8] << 8) + res[9];
    const int ARCOUNT = (res[10] << 8) + res[11];
    
    printf("RCODE: %d ", RCODE);
    switch (RCODE) {
        case 0: printf("success\n"); break;
        case 1: printf("format error\n"); break;
        case 2: printf("server failure\n"); break;
        case 3: printf("name error\n"); break;
        case 4: printf("not implemented\n"); break;
        case 5: printf("refused\n"); break;
        default: printf("?\n"); break;
    }

    printf("QDCOUNT: %d\n", QDCOUNT);
    printf("ANCOUNT: %d\n", ANCOUNT);
    printf("NSCOUNT: %d\n", NSCOUNT);
    printf("ARCOUNT: %d\n", ARCOUNT);

    unsigned char *p = res + 12;

    if (QDCOUNT) {
        printf("\nQueries: \n");
        unsigned char *p_quest = p;
        for (int i=0; i<QDCOUNT; i++) {
            unsigned char *name;
            p_quest = get_name(res, p_quest, &name);
            printf("\tname: %s\n", name);

            printf("\ttype: %s\n", type_str((*p_quest << 8) + p_quest[1]));
            p_quest += 2;

            printf("\tclass: %d\n", (*p_quest << 8) + p_quest[1]);
            p_quest += 2;
        }
        p = p_quest;
    }

    if (ANCOUNT || NSCOUNT) {
        printf("\nAnswers: \n");
        unsigned char *p_ans = p;
        for (int i=0; i<ANCOUNT + NSCOUNT; i++) {
            unsigned char *name;
            p_ans = get_name(res, p_ans, &name);
            printf("%s\n", name);

            const unsigned int type = (*p_ans << 8) + p_ans[1];
            printf("\ttype: %d - %s\n", type, type_str(type));
            p_ans += 2;

            const int class = (*p_ans << 8) + p_ans[1];
            printf("\tclass: %d\n", class);
            p_ans += 2;
            
            const unsigned int ttl = (*p_ans << 24) + (p_ans[1] << 16) + (p_ans[2] << 8) + p_ans[3];
            printf("\tttl: %u\n", ttl);
            p_ans += 4;

            const int rdlen = (*p_ans << 8) + p_ans[1];
            printf("\trdlen: %d\n", rdlen);
            p_ans += 2;

            if (rdlen == 4 && type == A) {
                printf("\taddress: ");
                printf("%d.%d.%d.%d\n", p_ans[0], p_ans[1], p_ans[2], p_ans[3]);

            } else if (rdlen == 16 && type == AAAA) {
                printf("\taddress: ");
                int j;
                for (j = 0; j < rdlen; j+=2) {
                    printf("%02x%02x", p_ans[j], p_ans[j+1]);
                    if (j + 2 < rdlen) printf(":");
                }
                printf("\n");

            } else if (type == TXT) {
                printf("\tTXT: '%.*s'\n", rdlen-1, p_ans+1);
            }  else if (type == CNAME) {
                /* CNAME Record */
                printf("CNAME: ");
                unsigned char *name;
                p_ans = get_name(res, p_ans, &name);
                printf("%s\n", name);
            }

            p_ans += rdlen;

            printf("\n");
        }
        p = p_ans;    
    }
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

    char dns_packet[BUFFER], dns_res[BUFFER];
    int truncated = 0;
    int packet_len = build_dns_packet(&query, dns_packet);

    int recv = queryUDP(
        query.dns_host, query.dns_port, 
        dns_packet, packet_len,
        dns_res,
        &truncated);

    if (recv >= 12 && !truncated) {
        // print result
        resolve_dns_response(dns_res, recv);
        return 0;
    }

    if (truncated) {
        printf("packet truncated!\n");
    }

    // fallback tcp

    printf("falling back to TCP query\n");

    return 0;
}