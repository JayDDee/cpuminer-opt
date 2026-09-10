#ifndef __SHA256DV_H__
#define __SHA256DV_H__ 1

#include <stdint.h>
#include <stdbool.h>

#include "algo-gate-api.h"
#include "miner.h"

bool register_sha256dv_algo( algo_gate_t *gate );

int scanhash_sha256dv( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr );

#endif /* __SHA256DV_H__ */
