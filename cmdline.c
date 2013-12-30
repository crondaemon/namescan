
#include <cmdline.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

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
    printf("\nUsage: %s [-i <iface>] [-v] [-s <source>] [-d <delay>]", name);
    printf("\t[-t <timeout>] [-o <outfile>] [-n <domain name>] [-q <type>]");
    printf("\t[-c <class>] -a <addresses to scan>");
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
        mask32 = atoi(mask);

        ip_start = htonl(addr32 & (0xFFFFFFFF << (32 - mask32)));
        ip_end = htonl(addr32 | ~(0xFFFFFFFF << (32 - mask32)));

        LOG_DEBUG("Loading range: %s - %s\n", inet_ntop(AF_INET, &ip_start, buf1,
            INET_ADDRSTRLEN),
            inet_ntop(AF_INET, &ip_end, buf2, INET_ADDRSTRLEN));

        sp->ranges_count++;

        if (sp->ranges == NULL || sizeof(sp->ranges) < sizeof(ip_range_t) * sp->ranges_count) {
/*            printf("REALLOC %u\n", sp->ranges_count);*/
            sp->ranges = realloc(sp->ranges, sizeof(ip_range_t) * sp->ranges_count);
        } else {
/*            printf("JUMP %u\n", sizeof(sp->ranges));*/
        }

        sp->ranges[sp->ranges_count - 1].ip_from = ip_start;
        sp->ranges[sp->ranges_count - 1].ip_to = ip_end;

        cidr = strtok_r(saveptr1, ",", &saveptr1);
    }
}

int parse_cmdline(int argc, char* argv[], radar_params_t* rp, scanner_params_t* sp)
{
    int opt;

    if (argc == 1)
        usage(argv[0]);

    activate_debug(argc, argv);

    while ((opt = getopt(argc, argv, "i:vs:d:t:a:o:n:q:c:")) != -1) {
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
                sp->delay = strtol(optarg, NULL, 10);
                LOG_INFO("Delay: %u\n", sp->delay);
                break;
            case 't':
                sp->timeout = strtol(optarg, NULL, 10);
                LOG_INFO("Timeout: %u\n", sp->timeout);
                break;
            case 'a':
                parse_addresses(optarg, sp);
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
                sp->qname = strdup(optarg);
                break;
            case 'q':
                sp->qtype = atoi(optarg);
                break;
            case 'c':
                sp->qclass = atoi(optarg);
                break;
            default:
                LOG_ERROR("Error parsing command line\n");
                return 1;
        }
    }
    return 0;
}
