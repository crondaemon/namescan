
#ifndef __RADAR_H__
#define __RADAR_H__

#include <log.h>
#include <pcap/pcap.h>

typedef struct {
    char* dev;
    pcap_t* handle;
    FILE* outfile;
} radar_params_t;

extern radar_params_t radar_params;

pcap_t* radar_init(radar_params_t* rp);

void* radar(void*);

#endif
