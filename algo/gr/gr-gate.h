#ifndef GR_GATE_H__
#define GE_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

void gr_hash( void *state, const void *input );
int scanhash_gr(struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr);

#endif
