
#ifndef __SCANNER_H__
#define __SCANNER_H__

#include <log.h>
#include <stdint.h>

typedef struct {
    uint32_t ip_from;
    uint32_t ip_to;
} ip_range_t;

typedef struct {
    ip_range_t* ranges;
    unsigned ranges_count;

    uint32_t saddr;

    // delay between probes
    unsigned delay;

    // timeout to wait after the last probe
    unsigned timeout;

    // dns params
    char* qname;
    uint16_t qtype;
    uint16_t qclass;

} scanner_params_t;

extern scanner_params_t scanner_params;

void scanner(scanner_params_t*);

#endif
