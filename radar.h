
#ifndef __RADAR_H__
#define __RADAR_H__

#include <log.h>
#include <pcap/pcap.h>
#include <stdint.h>

typedef struct {
    char* dev;
    pcap_t* handle;
    FILE* outfile;
	uint8_t level;
} radar_params_t;

extern radar_params_t radar_params;

void radar_set_defaults(radar_params_t* rp);

pcap_t* radar_init(radar_params_t* rp);

void* radar(void*);

#endif
