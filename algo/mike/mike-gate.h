#ifndef MIKE_GATE_H__
#define MIKE_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// Consensus Mike hash (VKAX, FortuneBlock). GhostRider with the core pool
// reduced from 15 algorithms to 11, which shortens the third core group from
// five rounds to one: 5 core, CN, 5 core, CN, 1 core, CN. `output` receives
// 32 bytes. See algo/gr/gr-gate.h for the shared tables.
void mike_hash( void *output, const void *input );

// Known-answer self-test; returns true on success. Run once per process.
bool mike_self_test( void );

int scanhash_mike( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                   struct thr_info *mythr );

bool register_mike_algo( algo_gate_t *gate );

#endif /* MIKE_GATE_H__ */
