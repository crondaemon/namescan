
#include <scanner.h>
#include <fingerprint.h>
#include <dns.h>
#include <millerrabin.h>

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
#include <net/ethernet.h>
#include <time.h>

scanner_params_t scanner_params;

static unsigned tot = 0;
static unsigned partial = 0;

unsigned probesize = 0;

int scanner_set_defaults(scanner_params_t* sp)
{
    #define BUFLEN 100
    char name[BUFLEN];
    char domain[BUFLEN];
    unsigned size;

    sp->ranges_count = 0;
    sp->ranges = NULL;
    sp->delay = 0;
    sp->timeout = 3;
    sp->saddr = 0;
    sp->qtype = 1;
    sp->qclass = 1;
    sp->randomize = true;
    sp->edns0 = true;

    if (gethostname(name, BUFLEN) == -1) {
        LOG_ERROR("Can't get hostname: %s\n", strerror(errno));
        return 1;
    }
    if (getdomainname(domain, BUFLEN) == -1) {
        LOG_ERROR("Can't get domain name: %s\n", strerror(errno));
        return 1;
    }

    if (strncmp(domain, "(none)", 6) == 0) {
        sp->qname = strdup(name);
    } else {
        size = strlen(name) + strlen(domain) + 2;
        sp->qname = (char*)malloc(size);
        snprintf(sp->qname, size, "%s.%s", name, domain);
    }
    return 0;
}

void print_stats(int signo)
{
    static unsigned old_partial = 0;
    unsigned rate = partial - old_partial;

    LOG_INFO("%c[2K", 27);
    LOG_INFO("\r%u/%u (%.2f%%) ", partial, tot, (float)partial/(float)tot*100);
    LOG_INFO("%u pkt/s ", rate);
    LOG_INFO("%u B/s ", rate * probesize);

    unsigned left;

    if (rate > 0)
        left = (tot - partial) / rate;
    else
        left = 0;

    LOG_INFO("- ETA: %u secs left", left);
    fflush(stdout);
    old_partial = partial;
    alarm(1);
}

void scanner(scanner_params_t* sp)
{
    int i;
    int j;

    uint32_t ip;
    uint32_t off;
    uint32_t ptr;
    uint32_t diff;

    int sock;

    struct iphdr iphdr;
    struct udphdr udphdr;

    struct timespec t = { sp->timeout, 0 };
    struct timespec rem;

    char* dns;
    unsigned dnslen = 0;

    sock = sock_create();
    if (sock == -1) {
        LOG_ERROR("Can't create socket\n");
        return;
    }

    struct sockaddr_in sin;
    memset(&sin, 0x0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(53);

    iphdr = sock_set_iphdr(sock, sp->saddr);
    udphdr = sock_set_udphdr();

    for (i = 0; i < sp->ranges_count; i++) {
        tot += ntohl(sp->ranges[i].ip_to) - ntohl(sp->ranges[i].ip_from) + 1;
    }

    LOG_INFO("%u address%s to probe\n", tot, tot > 1 ? "es" : "");

    signal(SIGALRM, print_stats);
    alarm(1);

    dns_pack(sp->qname, sp->qtype, sp->qclass, &dns, &dnslen, sp->edns0);

    probesize = sizeof(struct ether_header) + sizeof(struct iphdr) +
        sizeof(struct udphdr) + dnslen;

    LOG_INFO("Probe size: %u\n", probesize);

    for (i = 0; i < sp->ranges_count; i++) {
        diff = ntohl(sp->ranges[i].ip_to) - ntohl(sp->ranges[i].ip_from) + 1;
        ptr = ntohl(sp->ranges[i].ip_from);

        if (sp->randomize == false) {
            off = 1;
        } else {
            off = 1;
            if (diff > 2) {
                do {
                    off = rand() % diff;
                    if (off == 0)
                        off = 1;
                } while(!is_prime_mr(off));
            }
            LOG_DEBUG("Using %u as offset\n", off);
        }

        if (diff % off == 0 && off > 1) {
            printf("%u %u\n", diff, off);
            LOG_ERROR("Collision detected. Specify another offset\n");
            return;
        }

        for (j = 0; j < diff; j++) {
            ptr = (ptr + off) % diff;
            ip = ptr + ntohl(sp->ranges[i].ip_from);

            //uint32_t ipn = htonl(ip);
            //char buf[INET_ADDRSTRLEN];
            //LOG_DEBUG("Probing %s\n", inet_ntop(AF_INET, &ipn, buf, INET_ADDRSTRLEN));

            sin.sin_addr.s_addr = htonl(ip);
            iphdr.daddr = sin.sin_addr.s_addr;

            // add a fingerprint into txid and source port
            fingerprint_gen(&udphdr.source, (uint16_t*)&dns[0]);

            if (sock_send(sock, &sin, iphdr, udphdr, dns, dnslen) == -1) {
                char buf[INET_ADDRSTRLEN];
                uint32_t ipn = htonl(ip);
                LOG_DEBUG("Can't send datagram to %s: %s\n",
                    inet_ntop(AF_INET, &ipn, buf, INET_ADDRSTRLEN),
                    strerror(errno));
            }

            t.tv_sec = sp->delay;
            t.tv_nsec = 0;
            while (nanosleep(&t, &rem) == -1) {
                t = rem;
            }

            partial++;
        }
    }

    t.tv_sec = sp->timeout;
    t.tv_nsec = 0;
    while (nanosleep(&t, &rem) == -1) {
        t = rem;
    }
}
