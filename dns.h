
#ifndef __DNS_H__
#define __DNS_H__

#include <stdint.h>
#include <stdbool.h>

#pragma pack(1)
typedef struct {
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint8_t qr: 1,
            opcode: 4,
            aa: 1,
            tc: 1,
            rd: 1;
    uint8_t ra: 1,
            z: 1,
            auth: 1,
            cd: 1,
            rcode: 4;
#else
    uint8_t rd: 1,
            tc: 1,
            aa: 1,
            opcode: 4,
            qr: 1;
    uint8_t rcode: 4,
            cd: 1,
            auth: 1,
            z: 1,
            ra: 1;
#endif
} dns_header_flags_t;

typedef struct {
    uint16_t txid;
    dns_header_flags_t flags;
    uint16_t n_record[4];
} dns_header_t;

void dns_pack(char* qname, uint16_t qtype, uint16_t qclass, char** dns, unsigned* dnslen, bool edns0);

int string_to_qtype(char* qtype_s);

int string_to_qclass(char* qclass_s);

#endif
