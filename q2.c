#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_SIZE 512
#define SERVER "8.8.8.8"
#define PORT 53
#define WIDTH 16

int createSocket();
void createRequest(char *url);
void hexdump(char *desc, void *addr, int len);
void lookUp();

struct query {
    uint16_t length;
    char *url;
    unsigned char request[BUF_SIZE];
    uint16_t reqType;
};

struct query dnsQuery = {
    .length = 12,
    .url = "",
    .reqType = 0x01,
    .request = {0xDB, 0x42, 0x01, 0x00, 0x00, 0x01,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
};

int main() {
    char url[256];

    printf("Enter the hostname to resolve: ");
    scanf("%s", url);

    createRequest(url);
    lookUp();

    return 0;
}

int createSocket() {
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        printf("Error creating socket!\n");
        exit(1);
    }

    return sockfd;
}

void createRequest(char *url) {
    char *word;
    int i;
    printf("Asking DNS server %s about %s\n", SERVER, url);
    dnsQuery.url = strdup(url);
    dnsQuery.reqType = 0x01;

    word = strtok(url, ".");
    while (word) {
        printf("parsing hostname: \"%s\" is %ld characters\n", word, strlen(word));
        dnsQuery.request[dnsQuery.length++] = strlen(word);
        for (i = 0; i < strlen(word); i++) {
            dnsQuery.request[dnsQuery.length++] = word[i];
        }
        word = strtok(NULL, ".");
    }

    dnsQuery.request[dnsQuery.length++] = 0x00; // End of the host name
    dnsQuery.request[dnsQuery.length++] = 0x00; // 0x0001 - Query is a Type A query (host address)
    dnsQuery.request[dnsQuery.length++] = dnsQuery.reqType;
    dnsQuery.request[dnsQuery.length++] = 0x00; // 0x0001 - Query is class IN (Internet address)
    dnsQuery.request[dnsQuery.length++] = 0x01;
}

void hexdump(char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = addr;

    if (desc != NULL)
        printf("%s:\n", desc);

    for (i = 0; i < len; i++) {
        if ((i % 16) == 0) {
            if (i != 0)
                printf("  %s\n", buff);
            printf("  %04x ", i);
        }

        printf(" %02x", pc[i]);

        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }

    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }

    printf("  %s\n", buff);
}

void lookUp() {
    struct sockaddr_in addr;
    int socket;
    int ret, rcode, size, i;
    int ip = 0, dom = 0;
    int length;
    unsigned char buffer[BUF_SIZE];
    unsigned char tempBuf[3];
    uint16_t QDCOUNT; //No. of items in Question Section
    uint16_t ANCOUNT; //No. of items in Answer Section
    uint16_t NSCOUNT; //No. of items in Authority Section
    uint16_t ARCOUNT; //No. of items in Additional Section
    uint16_t QCLASS; //Specifies the class of the query
    uint16_t ATYPE; //Specifies the meaning of the data in the RDATA field
    uint16_t ACLASS; //Specifies the class of the data in the RDATA field
    uint32_t TTL; //The number of seconds the results can be cached
    uint16_t RDLENGTH; //The length of the RDATA field
    uint16_t MSGID;

    socket = createSocket();

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr(SERVER);
    addr.sin_port = htons(PORT);
    size = sizeof(addr);

    hexdump("sending packet", &dnsQuery.request, dnsQuery.length);
    ret = sendto(socket, dnsQuery.request, dnsQuery.length, 0,
                 (struct sockaddr *)&addr, size);
    if (ret < 0) {
        printf("Error Sending Request");
        exit(1);
    }

    memset(&buffer, 0, BUF_SIZE);
    ret = recvfrom(socket, buffer, BUF_SIZE, 0, (struct sockaddr *)&addr,
                   &size);
    if (ret < 0) {
        printf("Error Receiving Response");
        exit(1);
    }

    hexdump("received packet", &buffer, ret);

    close(socket);

    rcode = (buffer[3] & 0x0F);

    QDCOUNT = (uint16_t) buffer[4] * 0x100 + buffer[5];
    printf("entries in question section: %u\n", QDCOUNT);
    ANCOUNT = (uint16_t) buffer[6] * 0x100 + buffer[7];
    printf("records in answer section: %u\n", ANCOUNT);
    NSCOUNT = (uint16_t) buffer[8] * 0x100 + buffer[9];
    printf("name server resource record count: %u\n", NSCOUNT);
    ARCOUNT = (uint16_t) buffer[10] * 0x100 + buffer[11];
    printf("additional records count: %u\n", ARCOUNT);

    printf("query type: %u\n", dnsQuery.reqType);
    QCLASS = (uint16_t) dnsQuery.request[dnsQuery.length - 2] * 0x100 +
             dnsQuery.request[dnsQuery.length - 1];
    printf("query class: %u\n", QCLASS);
    length = dnsQuery.length + 1; // to skip 0xc00c
    ATYPE = (uint16_t) buffer[length + 1] * 0x100 + buffer[length + 2];
    printf("answer type: %u\n", ATYPE);
    ACLASS = (uint16_t) buffer[length + 3] * 0x100 + buffer[length + 4];
    printf("answer class: %u\n", ACLASS);
    TTL = (uint32_t) buffer[length + 5] * 0x1000000 + buffer[length + 6] *
                                                     0x10000 + buffer[length + 7] * 0x100 + buffer[length + 8];
    printf("seconds to cache: %u\n", TTL);
    RDLENGTH = (uint16_t) buffer[length + 9] * 0x100 + buffer[length + 10];
    printf("bytes in answer: %u\n", RDLENGTH);
    MSGID = (uint16_t) buffer[0] * 0x100 + buffer[1];
    printf("answer msg id: %u\n", MSGID);

    if (rcode == 2) {
        printf("nameserver %s returned SERVFAIL:\n", SERVER);
        printf("  the name server was unable to process this query due to  a\n  problem with the name server.\n");
        exit(1);
    } else if (rcode == 3) {
        printf("nameserver %s returned NXDOMAIN for %s:\n", SERVER,
               dnsQuery.url);
        printf("  the domain name referenced in the query does not exist\n");
        exit(1);
    }

    if (dnsQuery.reqType == 0x01) {
        printf("DNS server's answer is: (type#=%u):", ATYPE);
        for (i = 0; i < ret; i++) {
            if (buffer[i] == 0xC0 && buffer[i + 3] == 0x01) {
                ip++;
                i += 12;
                printf(" %u.%u.%u.%u\n", buffer[i], buffer[i + 1],
                       buffer[i + 2], buffer[i + 3]);
            }
        }

        if (!ip) {
            printf("  No IPv4 address found in the DNS response!\n");
            exit(1);
        }
    }
}