
#ifndef __FINGERPRINT_H__
#define __FINGERPRINT_H__

#include <stdint.h>
#include <stdbool.h>

int fingerprint_init();

void fingerprint_gen(uint16_t* sport, uint16_t* txid);

int fingerprint_check(uint16_t sport, uint16_t txid);

#endif
