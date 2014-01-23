
#include <radar.h>
#include <stdio.h>
#include <stdlib.h>
#include <fingerprint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <list.h>
#include <dns.h>

extern unsigned probesize;

static fragnode_t* head = NULL;

void process_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void radar_set_defaults(radar_params_t* rp)
{
    rp->dev = NULL;
    rp->outfile = NULL;
  	rp->level = 0;
}

pcap_t* radar_init(radar_params_t* rp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;

    if (rp->dev == NULL) {
        rp->dev = pcap_lookupdev(errbuf);
        if (rp->dev == NULL) {
            LOG_ERROR("Can't lookup device: %s\n", errbuf);
            return NULL;
        }
    }

    pcap_t* handle;
    handle = pcap_open_live(rp->dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        LOG_ERROR("Can't open live %s: %s\n", rp->dev, errbuf);
        return NULL;
    }

    if (pcap_lookupnet(rp->dev, &net, &mask, errbuf) == -1) {
        LOG_ERROR("Couldn't get netmask for device %s: %s\n", rp->dev, errbuf);
        return NULL;
    }

    LOG_DEBUG("Working on %s\n", rp->dev);

    // udp port 53 or fragment
    if (pcap_compile(handle, &fp, "src port 53 or ((ip[6:2] > 0) and (not ip[6] = 64))", 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        return NULL;
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        exit(2);
    }

    return handle;
}

void* radar(void* p)
{
    radar_params_t* rp = (radar_params_t*)p;
    pcap_t* handle = rp->handle;
    pcap_loop(handle, -1, process_pkt, (u_char*)rp);
    return NULL;
}

void print_server(struct ip* ip, float ratio, FILE* fp)
{
    char buf[INET_ADDRSTRLEN];
    LOG_INFO("%c[2K", 27);
    LOG_INFO("\rResponse from %s, ", inet_ntop(AF_INET, &ip->ip_src, buf, INET_ADDRSTRLEN));
        LOG_INFO("amp ratio: %.2f\n", ratio);
    fflush(stdout);
    if (fp != NULL) {
        fprintf(fp, "%s\n", buf);
        fflush(fp);
    }
}

#define IS_FIRST_FRAGMENT(ip) (((ntohs(ip->ip_off)) & IP_MF)==IP_MF && (((ntohs(ip->ip_off)) & IP_OFFMASK) == 0))
#define IS_INNER_FRAGMENT(ip) (((ntohs(ip->ip_off)) & IP_MF) && ((ntohs(ip->ip_off)) & IP_OFFMASK))
#define IS_LAST_FRAGMENT(ip) ((!((ntohs(ip->ip_off)) & IP_MF)) && ((ntohs(ip->ip_off)) & IP_OFFMASK))
#define IS_NOT_FRAGMENT(ip) ((!((ntohs(ip->ip_off)) & IP_MF)) && (!((ntohs(ip->ip_off)) & IP_OFFMASK)))

void process_pkt(u_char* args, const struct pcap_pkthdr* h, const u_char* packet)
{
    radar_params_t* rp = (radar_params_t*)args;

    struct ip* ip = (struct ip*)(packet + sizeof(struct ether_header));
    struct udphdr* udphdr;
    dns_header_t* dnshdr;

    char buf[INET_ADDRSTRLEN];
    float ratio = 0;

    fragnode_t* fragnode;

    if (IS_FIRST_FRAGMENT(ip)) {
        if (h->len < (sizeof(struct ether_header) + sizeof(struct ip)
                + sizeof(struct udphdr) + sizeof(dns_header_t))) {
            LOG_DEBUG("Short packet. Discarding");
            return;
        }
        udphdr = (struct udphdr*)(packet + sizeof(struct ether_header)
            + sizeof(struct ip));
        dnshdr = (dns_header_t*)(packet + sizeof(struct ether_header) + sizeof(struct ip)
            + sizeof(struct udphdr));
        if (fingerprint_check(udphdr->dest, dnshdr->txid))
            fragnode_add(&head, ip->ip_id, ip->ip_src, ip->ip_dst, h->len);
    }

    if (IS_INNER_FRAGMENT(ip)) {
        fragnode_update(head, ip->ip_id, ip->ip_src, ip->ip_dst, h->len);
    }

    if (IS_LAST_FRAGMENT(ip)) {
        fragnode = fragnode_update(head, ip->ip_id, ip->ip_src, ip->ip_dst, h->len);
        if (fragnode == NULL)
            return;
        fragnode_unlink(&head, fragnode);
        ratio = (float)fragnode->size/(float)probesize;
        if (ratio >= rp->level)
            print_server(ip, ratio, rp->outfile);
        free(fragnode);
    }

    if (IS_NOT_FRAGMENT(ip)) {
        if (h->len < (sizeof(struct ether_header) + sizeof(struct ip)
                + sizeof(struct udphdr) + sizeof(dns_header_t))) {
            LOG_DEBUG("Short packet. Discarding");
            return;
        }
        udphdr = (struct udphdr*)(packet + sizeof(struct ether_header)
            + sizeof(struct ip));
        dnshdr = (dns_header_t*)(packet + sizeof(struct ether_header) + sizeof(struct ip)
            + sizeof(struct udphdr));
        ratio = (float)h->len/(float)probesize;
        if (ratio >= rp->level && fingerprint_check(udphdr->dest, dnshdr->txid)) {
            print_server(ip, ratio, rp->outfile);
        } else {
            LOG_DEBUG("Ignoring packet from %s\n", inet_ntop(AF_INET, &ip->ip_src, buf, INET_ADDRSTRLEN));
        }
    }
}
