
#ifndef __LOG_H__
#define __LOG_H__

#include <stdio.h>
#include <stdbool.h>

extern bool debug;

void set_debug(bool d);

#define LOG_ERROR(m...) printf(m)

#define LOG_INFO(m...) LOG_ERROR(m)

#define LOG_DEBUG(m...) { if (debug) LOG_ERROR(m); }

#endif
