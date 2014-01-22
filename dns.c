
#include <dns.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>

void domainname_encode(char* qname, char* qname_enc)
{
    unsigned i;
    unsigned len_cur = 0;
    unsigned cur = 1;
    memset(qname_enc, 0x0, strlen(qname) + 2);
    for (i = 0; i < strlen(qname); i++) {
        if (qname[i] == '.') {
            len_cur = i + 1;
            cur++;
        } else {
            qname_enc[cur] = qname[i];
            qname_enc[len_cur] += 1;
            cur++;
        }
    }
    qname_enc[i + 1] = 0;
}

void dns_pack(char* qname, uint16_t qtype, uint16_t qclass, char** dns, unsigned* dnslen, bool edns0)
{
    dns_header_t hdr;
    char* qname_enc = malloc(strlen(qname) + 2);
    uint16_t temp;
    char edns0_record[] = { 0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    memset(&hdr, 0x0, sizeof(hdr));

    // txid will be set by the fingerprint system
    hdr.txid = 0;
    // Force recursion
    hdr.flags.rd = 1;
    // we have nquestion = 1, nadditional = 1
    hdr.n_record[0] = htons(1);
    if (edns0 == true) {
        hdr.n_record[3] = htons(1);
    }

    domainname_encode(qname, qname_enc);

    // compute the len of the dns packet
    *dnslen = sizeof(hdr) // header
        + strlen(qname) + 2 // qname encoded
        + 2 // qtype
        + 2; // qclass
    if (edns0 == true) {
        *dnslen += sizeof(edns0_record);
    }

    (*dns) = (char*)malloc(*dnslen);

    // Add the header
    memcpy(*dns, &hdr, sizeof(hdr));

    // Add the question
    memcpy(*dns + sizeof(hdr), qname_enc, strlen(qname) + 2);

    temp = htons(qtype);
    memcpy(*dns + sizeof(hdr) + strlen(qname) + 2, &temp, 2);

    temp = htons(qclass);
    memcpy(*dns + sizeof(hdr) + strlen(qname) + 2 + 2, &temp, 2);

    printf("AAAAAAAAAAAAAAAAAAAAAA %d\n", edns0);
    if (edns0 == true) {
        memcpy(*dns + sizeof(hdr) + strlen(qname) + 2 + 2 + 2, edns0_record, sizeof(edns0_record));
    }
}
