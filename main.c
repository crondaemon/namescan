
#include <radar.h>
#include <scanner.h>
#include <cmdline.h>
#include <fingerprint.h>

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
    radar_set_defaults(&radar_params);

    // Set the params for the scanner
    scanner_set_defaults(&scanner_params);

    if (parse_cmdline(argc, argv, &radar_params, &scanner_params))
        return 1;

    // Init the fingerprint subsystem
    if (fingerprint_init())
        return 1;

    // Start a separate thread for the radar
    radar_params.handle = radar_init(&radar_params);
    if (radar_params.handle == NULL) {
        LOG_ERROR("Error in libpcap");
        return 1;
    }
    if (pthread_create(&t, NULL, radar, &radar_params)) {
        LOG_ERROR("Can't create thread");
        return 1;
    }

    // Run the scanner
    scanner(&scanner_params);

    // Scanning finished. Cleaning up stuff
    if (radar_params.outfile)
        fclose(radar_params.outfile);

    printf("\n");
    return 0;
}
