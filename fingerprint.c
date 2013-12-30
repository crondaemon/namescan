
#include <fingerprint.h>

void fingerprint_gen(uint16_t* sport, uint16_t* txid)
{
    *sport = 0x1234;
    *txid = 0x1234;
}

int fingerprint_check(uint16_t sport, uint16_t txid)
{
    if (sport == 0x1234 && txid == 0x1234)
        return 1;
    else
        return 0;
}
