
#include <dns.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <ctype.h>
#include <log.h>

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

    LOG_INFO("Using record: %s\n", qname);
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

static char* tolower_s(char* s)
{
    char* temp = strdup(s);
    unsigned i;
    for (i = 0; i < strlen(temp); i++)
        temp[i] = tolower(s[i]);
    return temp;
}

#define CONVERT_DNS_TYPE(str,val_s,val_i) \
{ \
    char* temp_str; \
    char* temp_val_s; \
    unsigned len; \
    int i = 0; \
    temp_str = tolower_s(str); \
    temp_val_s = tolower_s(val_s); \
    len = (strlen(temp_str) >= strlen(temp_val_s) ? strlen(temp_str) : strlen(temp_val_s)); \
    if (strncmp(temp_str,temp_val_s,len) == 0) \
        i = val_i; \
    free(temp_str); \
    free(temp_val_s); \
    if (i > 0) \
        return i; \
}

int string_to_qtype(char* qtype_s)
{
    /* http://en.wikipedia.org/wiki/List_of_DNS_record_types */
    CONVERT_DNS_TYPE(qtype_s, "A", 1);
    CONVERT_DNS_TYPE(qtype_s, "NS", 2);
    CONVERT_DNS_TYPE(qtype_s, "CNAME", 5);
    CONVERT_DNS_TYPE(qtype_s, "SOA", 6);
    CONVERT_DNS_TYPE(qtype_s, "PTR", 12);
    CONVERT_DNS_TYPE(qtype_s, "MX", 15);
    CONVERT_DNS_TYPE(qtype_s, "TXT", 16);
    CONVERT_DNS_TYPE(qtype_s, "RP", 17);
    CONVERT_DNS_TYPE(qtype_s, "AFSDB", 18);
    CONVERT_DNS_TYPE(qtype_s, "SIG", 24);
    CONVERT_DNS_TYPE(qtype_s, "KEY", 25);
    CONVERT_DNS_TYPE(qtype_s, "AAAA", 28);
    CONVERT_DNS_TYPE(qtype_s, "LOC", 29);
    CONVERT_DNS_TYPE(qtype_s, "SRV", 33);
    CONVERT_DNS_TYPE(qtype_s, "NAPTR", 35);
    CONVERT_DNS_TYPE(qtype_s, "KX", 36);
    CONVERT_DNS_TYPE(qtype_s, "CERT", 37);
    CONVERT_DNS_TYPE(qtype_s, "DNAME", 39);
    CONVERT_DNS_TYPE(qtype_s, "APL", 42);
    CONVERT_DNS_TYPE(qtype_s, "DS", 43);
    CONVERT_DNS_TYPE(qtype_s, "SSHFP", 44);
    CONVERT_DNS_TYPE(qtype_s, "IPSECKEY", 45);
    CONVERT_DNS_TYPE(qtype_s, "RRSIG", 46);
    CONVERT_DNS_TYPE(qtype_s, "NSEC", 47);
    CONVERT_DNS_TYPE(qtype_s, "DNSKEY", 48);
    CONVERT_DNS_TYPE(qtype_s, "DHCID", 49);
    CONVERT_DNS_TYPE(qtype_s, "NSEC3", 50);
    CONVERT_DNS_TYPE(qtype_s, "NSEC3PARAM", 51);
    CONVERT_DNS_TYPE(qtype_s, "TLSA", 52);
    CONVERT_DNS_TYPE(qtype_s, "HIP", 55);
    CONVERT_DNS_TYPE(qtype_s, "SPF", 99);
    CONVERT_DNS_TYPE(qtype_s, "TKEY", 249);
    CONVERT_DNS_TYPE(qtype_s, "TSIG", 250);
    CONVERT_DNS_TYPE(qtype_s, "CAA", 257);
    CONVERT_DNS_TYPE(qtype_s, "TA", 32768);
    CONVERT_DNS_TYPE(qtype_s, "DLV", 32769);
    return 0;
}

int string_to_qclass(char* qclass_s)
{
    /* http://tools.ietf.org/html/rfc2929 */
    CONVERT_DNS_TYPE(qclass_s, "IN", 1);
    CONVERT_DNS_TYPE(qclass_s, "CH", 3);
    CONVERT_DNS_TYPE(qclass_s, "CHAOS", 3);
    CONVERT_DNS_TYPE(qclass_s, "HS", 4);
    CONVERT_DNS_TYPE(qclass_s, "NONE", 254);
    CONVERT_DNS_TYPE(qclass_s, "ANY", 255);
    return 0;
}

static char* rcode_to_string(uint8_t rcode, char* s, unsigned s_len)
{
    memset(s, 0x0, s_len);

    switch(rcode) {
        case 0:
            strncat(s, "No error", s_len);
            break;
        case 1:
            strncat(s, "Format error", s_len);
            break;
        case 2:
            strncat(s, "Server error", s_len);
            break;
        case 3:
            strncat(s, "Non existent domain", s_len);
            break;
        case 4:
            strncat(s, "Not implemented", s_len);
            break;
        case 5:
            strncat(s, "Refused", s_len);
            break;
        case 6:
            strncat(s, "Name Exists when it should not", s_len);
            break;
        case 7:
            strncat(s, "RR Set Exists when it should not", s_len);
            break;
        case 8:
            strncat(s, "RR Set that should exist does not", s_len);
            break;
        case 9:
            strncat(s, "Not Authorized", s_len);
            break;
        case 10:
            strncat(s, "Name not contained in zone", s_len);
            break;
        case 16:
            strncat(s, "Bad OPT Version", s_len);
            break;
        case 17:
            strncat(s, "Key not recognized", s_len);
            break;
        case 18:
            strncat(s, "Signature out of time window", s_len);
            break;
        case 19:
            strncat(s, "Bad TKEY Mode", s_len);
            break;
        case 20:
            strncat(s, "Duplicate key name", s_len);
            break;
        case 21:
            strncat(s, "Algorithm not supported", s_len);
            break;
        case 22:
            strncat(s, "Bad Truncation", s_len);
            break;
        default:
            LOG_ERROR("Unassigned RCODE");
    }
    return s;
}

int rcode_check(struct ip* ip, dns_header_t* dnshdr)
{
    char msgbuf[100];
    char buf[INET_ADDRSTRLEN];

    switch(dnshdr->flags.rcode) {
        case 0:
            return 0;
        case 5:
        case 9:
            LOG_DEBUG("Not allowed from %s\n", inet_ntop(AF_INET, &ip->ip_src, buf, INET_ADDRSTRLEN));
            return 1;
        default:
            LOG_ERROR("Error from %s: %s\n", inet_ntop(AF_INET, &ip->ip_src, buf, INET_ADDRSTRLEN),
                rcode_to_string(dnshdr->flags.rcode, msgbuf, 100));
            return 1;
    }

    return 0;
}
