
#ifndef __SOCK_H__
#define __SOCK_H__

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

int sock_create();

int sock_send(int socket, struct sockaddr_in* sin, struct iphdr iphdr,
    struct udphdr udphdr, char* dns, unsigned dnslen);

struct iphdr sock_set_iphdr();

struct udphdr sock_set_udphdr();

#endif
