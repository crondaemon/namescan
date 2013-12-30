
#include <radar.h>
#include <stdio.h>
#include <stdlib.h>
#include <fingerprint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

void process_pkt(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);

void radar_set_defaults(radar_params_t* rp)
{
    rp->dev = NULL;
    rp->outfile = NULL;
}

pcap_t* radar_init(radar_params_t* rp)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    bpf_u_int32 mask;
	bpf_u_int32 net;

    if (rp->dev == NULL) {
        LOG_INFO("No interface specified. Using first\n");
        rp->dev = pcap_lookupdev(errbuf);
        if (rp->dev == NULL) {
            LOG_ERROR("Can't lookup device: %s\n", errbuf);
            exit(1);
        }
    }

    pcap_t* handle;
    handle = pcap_open_live(rp->dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        LOG_ERROR("Can't open live %s: %s\n", rp->dev, errbuf);
        exit(1);
    }

	if (pcap_lookupnet(rp->dev, &net, &mask, errbuf) == -1) {
		LOG_ERROR("Couldn't get netmask for device %s: %s\n", rp->dev, errbuf);
		exit(1);
	}

    LOG_DEBUG("Working on %s\n", rp->dev);

	if (pcap_compile(handle, &fp, "src port 53", 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
		exit(2);
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

void process_pkt(u_char* args, const struct pcap_pkthdr* h, const u_char* packet)
{
    radar_params_t* rp = (radar_params_t*)args;

    struct iphdr* iphdr = (struct iphdr*)(packet + sizeof(struct ether_header));
    struct udphdr* udphdr = (struct udphdr*)(packet + sizeof(struct ether_header)
        + sizeof(struct iphdr));
    const u_char* dns = packet + sizeof(struct ether_header) + sizeof(struct iphdr)
        + sizeof(struct udphdr);

    char buf[INET_ADDRSTRLEN];

    if (fingerprint_check(udphdr->dest, *(uint16_t*)dns)) {
        LOG_INFO("\rResponse from %s\n", inet_ntop(AF_INET, &iphdr->saddr, buf, INET_ADDRSTRLEN));
        fflush(stdout);
        if (rp->outfile != NULL) {
            fprintf(rp->outfile, "%s\n", buf);
        }
    } else {
        LOG_DEBUG("Ignoring packet from %s\n", inet_ntop(AF_INET, &iphdr->saddr, buf, INET_ADDRSTRLEN));
    }
}
