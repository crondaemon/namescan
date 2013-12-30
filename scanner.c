
#include <scanner.h>
#include <fingerprint.h>
#include <dns.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sock.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

scanner_params_t scanner_params;

static unsigned tot = 0;
static unsigned partial = 0;

void print_stats(int signo)
{
    static unsigned old_partial = 0;
    unsigned rate = partial - old_partial;

    LOG_INFO("%u/%u (%.2f%%) ", partial, tot, (float)partial/(float)tot*100);
    LOG_INFO("%u pkt/s ", rate);

    unsigned left = (tot - partial) / rate;

    LOG_INFO("- ETA: %u secs\n", left);
    fflush(stdout);
    old_partial = partial;
    alarm(1);
}

void scanner(scanner_params_t* sp)
{
    int i;
    int j;

    uint32_t ip;
    uint32_t off = 7;
    uint32_t ptr;
    uint32_t diff;

    int sock;

    struct iphdr iphdr;
    struct udphdr udphdr;

    char* dns = malloc(1000);
    unsigned dnslen;

    sock = sock_create();
    if (sock == -1) {
        LOG_ERROR("Can't create socket\n");
        return;
    }

    struct sockaddr_in sin;
    memset(&sin, 0x0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);
    sin.sin_addr.s_addr = inet_addr("8.8.8.8");

    iphdr = sock_set_iphdr(sock, sp->saddr);
    udphdr = sock_set_udphdr();

    for (i = 0; i < sp->ranges_count; i++) {
        tot += ntohl(sp->ranges[i].ip_to) - ntohl(sp->ranges[i].ip_from) + 1;
    }

    LOG_INFO("%u addresses to probe\n", tot);

    signal(SIGALRM, print_stats);
    alarm(1);

    dns_pack(sp->qname, sp->qtype, sp->qclass, dns, &dnslen);

    for (i = 0; i < sp->ranges_count; i++) {
        diff = ntohl(sp->ranges[i].ip_to) - ntohl(sp->ranges[i].ip_from) + 1;
        ptr = ntohl(sp->ranges[i].ip_from);

        if (diff % off == 0) {
            printf("%u %u\n", diff, off);
            LOG_ERROR("Collision detected. Specify another offset\n");
            return;
        }

        for (j = 0; j < diff; j++) {
            ptr = (ptr + off) % diff;
            ip = ptr + ntohl(sp->ranges[i].ip_from);

            //uint32_t ipn = htonl(ip);
            //LOG_DEBUG("Probing %s\n", inet_ntop(AF_INET, &ipn, buf, INET_ADDRSTRLEN));

            sin.sin_addr.s_addr = htonl(ip);
            iphdr.daddr = sin.sin_addr.s_addr;

            // add a fingerprint into txid and source port
            fingerprint_gen(&udphdr.source, (uint16_t*)dns);

            if (sock_send(sock, &sin, iphdr, udphdr, dns, dnslen) == -1) {
                LOG_ERROR("Can't send datagram: %s\n", strerror(errno));
                return;
            }

            if (sp->delay > 0) {
                usleep(sp->delay);
            }

            partial++;
        }
    }

    LOG_DEBUG("Waiting timeout...\n");
    usleep(sp->timeout);
}
