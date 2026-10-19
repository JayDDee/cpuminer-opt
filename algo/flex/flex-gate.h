#ifndef FLEX_GATE_H__
#define FLEX_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

// Flex (Kylacoin / Lyncoin family) hash.
//
// A GhostRider-class chain: 14 "core" rounds (the x16 set without JH and SHA)
// interleaved with 3 of 6 CryptoNight-v1 variants. Both the core order and the
// CN triple are derived from keccak512() of the 80-byte header (note: unlike
// GhostRider, this selection depends on the nonce). The chain is three groups
// of five core rounds, each followed by one CN round, finished by a keccak256.
//
// Flex uses SHA3-style keccak padding (hard_coded_eb = 6) and a keccak-based
// (sha3d) merkle root. `output` receives 32 bytes.
void flex_hash( void *output, const void *input );

// Known-answer self-test; returns true on success. Run once per process.
bool flex_self_test( void );

int scanhash_flex( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                   struct thr_info *mythr );

bool register_flex_algo( algo_gate_t *gate );

#endif /* FLEX_GATE_H__ */
