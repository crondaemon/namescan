
#ifndef __MILLERRABIN_H__
#define __MILLERRABIN_H__

#include <stdbool.h>
#include <unistd.h>

/* Returns true is n is prime, using the Miller-Rabin algorhytm */
bool is_prime_mr(size_t n);

#endif
