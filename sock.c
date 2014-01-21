
#include <sock.h>
#include <log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

int sock_create()
{
    int s;
    int on = 1;

    s = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (s == -1)
        return s;

    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        return -1;
    }

    return s;
}


struct iphdr sock_set_iphdr(int socket, uint32_t saddr)
{
    struct iphdr iphdr;

    iphdr.ihl = 5;
    iphdr.version = 4;
    iphdr.tos = 16;
    iphdr.tot_len = 0;
    iphdr.id = 0;
    iphdr.frag_off = 0;
    iphdr.ttl = 64;
    iphdr.protocol = IPPROTO_UDP;
    iphdr.check = 0;
    iphdr.daddr = 0;
    iphdr.saddr = saddr;

    if (saddr == 0) {
        // we are not spoofing. Set the source address from localhost
        struct sockaddr_in sa;
        unsigned sa_len = sizeof(sa);
        getsockname(socket, (struct sockaddr*)&sa, &sa_len);
        iphdr.saddr = sa.sin_addr.s_addr;
    }

    return iphdr;
}

struct udphdr sock_set_udphdr()
{
    struct udphdr udphdr;

    udphdr.source = 0;
    udphdr.dest = htons(53);
    udphdr.len = sizeof(udphdr);
    udphdr.check = 0;

    return udphdr;
}

int sock_send(int socket, struct sockaddr_in* sin, struct iphdr iphdr,
    struct udphdr udphdr, char* dns, unsigned dnslen)
{
    char* data = malloc(sizeof(iphdr) + sizeof(udphdr) + dnslen);
    unsigned datalen = 0;
    int c;

    if (connect(socket, (struct sockaddr*)sin, sizeof(*sin)) < 0) {
        return -1;
    }

    udphdr.len = htons(sizeof(udphdr) + dnslen);
    iphdr.tot_len = htons(sizeof(iphdr) + sizeof(udphdr) + dnslen);

    memcpy(data, &iphdr, sizeof(iphdr));
    datalen += sizeof(iphdr);
    memcpy(data + datalen, &udphdr, sizeof(udphdr));
    datalen += sizeof(udphdr);
    memcpy(data + datalen, dns, dnslen);
    datalen += dnslen;

    c = send(socket, data, datalen, 0);
    free(data);
    if (c < 0) {
        return -1;
    }
    return 0;
}
