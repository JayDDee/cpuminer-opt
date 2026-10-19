#ifndef BC3HASH_GATE_H__
#define BC3HASH_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include <stdbool.h>

/* bc3hash -- Bitcoin III (BC3) from block 64360. Standard Bitcoin header and
 * merkle; only the PoW differs (see docs/algorithms/bc3hash.md).
 *
 * `input` is the 80-byte LE wire header, as for curvehash. Returns false on an
 * internal failure; the caller must skip the nonce, not submit. */
bool bc3hash_hash( void *output, const void *input );

const char *bc3hash_self_test( void );

int scanhash_bc3hash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

bool register_bc3hash_algo( algo_gate_t *gate );

#endif
