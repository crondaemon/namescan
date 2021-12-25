
#include <cmdline.h>

#include <dns.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

static void activate_debug(int argc, char* argv[])
{
    unsigned i;
    set_debug(false);
    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "-v", 2) == 0) {
            set_debug(true);
            LOG_DEBUG("Verbose mode on\n");
        }
    }
}

static void usage(char* name)
{
    printf("Usage: %s [-i <iface>] [-v] [-s <source>] [-d <delay>] ", name);
    printf("[-t <timeout>] [-o <outfile>] [-n <domain name>] [-q <type>] ");
    printf("[-c <class>] [-r] [-l <level>] [-p <name>] [-e] <addresses to scan>");
    printf("\n\n");
}

static void parse_addresses(char* optarg, scanner_params_t* sp)
{
    char* cidr;
    char* addr;
    char* mask;
    uint32_t addr32;
    uint32_t mask32;
    char* saveptr1;
    char* saveptr2;
    uint32_t ip_start;
    uint32_t ip_end;

    char buf1[INET_ADDRSTRLEN];
    char buf2[INET_ADDRSTRLEN];

    cidr = strtok_r(optarg, ",", &saveptr1);

    while (cidr != NULL) {
        addr = strtok_r(cidr, "/", &saveptr2);
        mask = strtok_r(saveptr2, "/", &saveptr2);

        addr32 = ntohl(inet_addr(addr));
        if (mask)
            mask32 = atoi(mask);
        else
            mask32 = 32;

        ip_start = htonl(addr32 & (0xFFFFFFFF << (32 - mask32)));
        ip_end = htonl(addr32 | ~(0xFFFFFFFF << (32 - mask32)));

        LOG_DEBUG("Loading range: %s - %s\n", inet_ntop(AF_INET, &ip_start, buf1,
            INET_ADDRSTRLEN),
            inet_ntop(AF_INET, &ip_end, buf2, INET_ADDRSTRLEN));

        sp->ranges_count++;

        if (sp->ranges == NULL || sizeof(sp->ranges) < sizeof(ip_range_t) * sp->ranges_count) {
            sp->ranges = realloc(sp->ranges, sizeof(ip_range_t) * sp->ranges_count);
        }

        sp->ranges[sp->ranges_count - 1].ip_from = ip_start;
        sp->ranges[sp->ranges_count - 1].ip_to = ip_end;

        cidr = strtok_r(saveptr1, ",", &saveptr1);
    }
}

int parse_cmdline(int argc, char* argv[], radar_params_t* rp, scanner_params_t* sp)
{
    int opt;
    int val;

    if (argc == 1) {
        usage(argv[0]);
        return 1;
    }

    activate_debug(argc, argv);

    while ((opt = getopt(argc, argv, "i:vs:d:t:o:n:p:q:c:hrl:e")) != -1) {
        switch (opt) {
            case 'i':
                rp->dev = strdup(optarg);
                LOG_INFO("Running on %s\n", rp->dev);
                break;
            case 'v':
                break;
            case 's':
                LOG_INFO("Source: %s\n", optarg);
                sp->saddr = inet_addr(optarg);
                break;
            case 'd':
                val = strtol(optarg, (char**)NULL, 10);
                if (val == LONG_MIN || val == LONG_MAX || val <= 0) {
                    LOG_ERROR("Can't convert %s to a valid int\n", optarg);
                    return 1;
                }
                sp->delay = val;
                LOG_INFO("Delay: %u\n", sp->delay);
                break;
            case 't':
                val = strtol(optarg, (char**)NULL, 10);
                if (val == LONG_MIN || val == LONG_MAX || val <= 0) {
                    LOG_ERROR("Can't convert %s to a valid int\n", optarg);
                    return 1;
                }
                sp->timeout = val;
                LOG_INFO("Timeout: %u\n", sp->timeout);
                break;
            case 'o':
                rp->outfile = fopen(optarg, "w");
                if (rp->outfile == NULL) {
                    LOG_ERROR("Can't open outfile: %s\n", optarg);
                    return 1;
                }
                LOG_INFO("Writing output to %s\n", optarg);
                break;
            case 'n':
                free(sp->qname);
                sp->qname = strdup(optarg);
                break;
            case 'p':
                rp->pcap_dumper_name = strdup(optarg);
                break;
            case 'q':
                val = strtol(optarg, (char**)NULL, 10);
                if (val == LONG_MIN || val == LONG_MAX || val <= 0) {
                    val = 0;
                    val = string_to_qtype(optarg);
                    if (val == 0) {
                        LOG_ERROR("Can't convert %s to a valid qtype\n", optarg);
                        return 1;
                    }
                }
                sp->qtype = val;
                LOG_INFO("Qtype: %s (%u)\n", optarg, sp->qtype);
                break;
            case 'c':
                val = strtol(optarg, (char**)NULL, 10);
                if (val == LONG_MIN || val == LONG_MAX || val <= 0) {
                    val = 0;
                    val = string_to_qclass(optarg);
                    if (val == 0) {
                        LOG_ERROR("Can't convert %s to a valid int\n", optarg);
                        return 1;
                    }
                }
                sp->qclass = val;
                LOG_INFO("Qclass: %s (%u)\n", optarg, sp->qclass);
                break;
            case 'h':
                usage(argv[0]);
                return 1;
                break;
            case 'r':
                sp->randomize = false;
                break;
			case 'l':
				val = strtol(optarg, (char**)NULL, 10);
				if (val == LONG_MIN || val == LONG_MAX || val <= 0) {
					LOG_ERROR("Can't convert %s to a valid int\n", optarg);
					return 1;
				}
				rp->level = val;
				LOG_INFO("Minimum amplification ratio: %u\n", rp->level);
				break;
			case 'e':
			    sp->edns0 = false;
			    LOG_INFO("EDNS0 record disabled\n");
			    break;
            default:
                LOG_ERROR("Error parsing command line\n");
                return 1;
        }
    }

    // The rest of the cmdline contains the addresses to scan
    if (argc == optind) {
        usage(argv[0]);
        return 1;
    }

    parse_addresses(argv[optind], sp);

    return 0;
}
