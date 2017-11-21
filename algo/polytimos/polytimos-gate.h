#ifndef __POLYTIMOS_GATE_H__
#define __POLYTIMOS_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

void polytimos_hash( void *state, const void *input );
int scanhash_polytimos( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );
void init_polytimos_context();

#endif
