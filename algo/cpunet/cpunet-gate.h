#ifndef __CPUNET_GATE_H__
#define __CPUNET_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

bool register_cpunet_algo( algo_gate_t* gate );

int cpunet_hash( void *hash, const void *data, int len );

#endif
