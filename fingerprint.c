
#include <fingerprint.h>
#include <stdio.h>
#include <log.h>
#include <stdlib.h>
#include <string.h>

static uint16_t secret[2];

int fingerprint_init()
{
    unsigned int seed;
    unsigned int r;
    FILE* fp;
    int ret;

    fp = fopen("/dev/urandom", "r");
    if (fp == NULL) {
        LOG_ERROR("Can't open /dev/urandom");
        return 1;
    }
    ret = fread(&seed, sizeof(uint16_t), 2, fp);
    if (ret != 2) {
        LOG_ERROR("Error in fread(). %d bytes read\n", ret);
        return 1;
    }
    srand(seed);
    fclose(fp);

    r = rand();
    memcpy(secret, &r, sizeof(uint16_t) * 2);

    LOG_DEBUG("Secret: %.2X%.2X\n", secret[0], secret[1]);

    return 0;
}

void fingerprint_gen(uint16_t* sport, uint16_t* txid)
{
    *sport = secret[0];
    *txid = secret[1];
}

int fingerprint_check(uint16_t sport, uint16_t txid)
{
    if (sport == secret[0] && txid == secret[1])
        return 1;
    else
        return 0;
}
