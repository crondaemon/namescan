
#include <radar.h>
#include <scanner.h>
#include <cmdline.h>

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <config.h>

int main(int argc, char* argv[])
{
    pthread_t t;
    radar_params_t radar_params;
    scanner_params_t scanner_params;

    printf("\n%s - massive DNS scanner\n\n", PACKAGE_STRING);

    // Set the default params for the radar
    radar_params.dev = NULL;
    radar_params.outfile = NULL;

    // Set the params for the scanner
    scanner_params.ranges_count = 0;
    scanner_params.ranges = NULL;
    scanner_params.delay = 0;
    scanner_params.timeout = 3 * 1000000;
    scanner_params.saddr = 0;
    scanner_params.qname = "www.test.com";
    scanner_params.qtype = 1;
    scanner_params.qclass = 1;

    if (parse_cmdline(argc, argv, &radar_params, &scanner_params))
        return 1;

    // Start a separate thread for the radar
    radar_params.handle = radar_init(&radar_params);
    if (pthread_create(&t, NULL, radar, &radar_params)) {
        LOG_ERROR("Can't create thread");
        return -1;
    }

    // Run the scanner
    scanner(&scanner_params);

    // Scanning finished. Cleaning up stuff
    fclose(radar_params.outfile);
    return 1;
}
