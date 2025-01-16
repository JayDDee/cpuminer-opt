#ifndef ARGON2D_GATE_H__
#define ARGON2D_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

// Credits: version = 0x10, m_cost = 250.
bool register_argon2d250_algo( algo_gate_t* gate );

void argon2d250_hash( void *state, const void *input );

int scanhash_argon2d250( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

// Dynamic: version = 0x10, m_cost = 500.
bool register_argon2d500_algo( algo_gate_t* gate );

void argon2d500_hash( void *state, const void *input );

int scanhash_argon2d500( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );


// Unitus: version = 0x13, m_cost = 4096.
bool register_argon2d4096_algo( algo_gate_t* gate );

int scanhash_argon2d4096( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr );

#endif

