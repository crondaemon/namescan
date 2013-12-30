
#ifndef __CMDLINE_H__
#define __CMDLINE_H__

#include <radar.h>
#include <scanner.h>

int parse_cmdline(int argc, char* argv[], radar_params_t* rp, scanner_params_t* sp);

#endif
