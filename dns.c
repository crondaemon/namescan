
#include <dns.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

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

void dns_pack(char* qname, uint16_t qtype, uint16_t qclass, char* dns, unsigned* dnslen)
{
    dns_header_t hdr;
    char* qname_enc = malloc(strlen(qname) + 2);
    uint16_t temp;

    memset(&hdr, 0x0, sizeof(hdr));
    *dnslen = 0;

    hdr.txid = 0;
	// Force recursion
    hdr.flags.rd = 1;
    hdr.n_record[0] = htons(1);

    memcpy(dns, &hdr, sizeof(hdr));
    *dnslen += sizeof(hdr);

    domainname_encode(qname, qname_enc);
    memcpy(dns + *dnslen, qname_enc, strlen(qname) + 2);
    *dnslen += strlen(qname) + 2;

    temp = htons(qtype);
    memcpy(dns + *dnslen, &temp, 2);
    *dnslen += 2;

    temp = htons(qclass);
    memcpy(dns + *dnslen, &temp, 2);
    *dnslen += 2;
}
