#ifndef ODO_GATE_H__
#define ODO_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// DigiByte shapechange epoch: the Odo cipher tables are regenerated every
// 10 days (mainnet). Key = nTime - (nTime % ODO_SHAPECHANGE_INTERVAL).
#define ODO_SHAPECHANGE_INTERVAL  864000u

void odo_hash( void *output, const void *input );   // uses the cached epoch key
bool odo_self_test( void );

int scanhash_odo( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                  struct thr_info *mythr );

bool register_odo_algo( algo_gate_t *gate );

#endif /* ODO_GATE_H__ */
