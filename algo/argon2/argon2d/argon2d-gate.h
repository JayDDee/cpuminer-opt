#ifndef ARGON2D_GATE_H__
#define ARGON2D_GATE_H__

#include "algo-gate-api.h"
#include <stdint.h>

// Credits: version = 0x10, m_cost = 250.
bool register_argon2d_crds_algo( algo_gate_t* gate );

void argon2d_crds_hash( void *state, const void *input );

int scanhash_argon2d_crds( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

// Dynamic: version = 0x10, m_cost = 500.
bool register_argon2d_dyn_algo( algo_gate_t* gate );

void argon2d_dyn_hash( void *state, const void *input );

int scanhash_argon2d_dyn( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );


// Unitus: version = 0x13, m_cost = 4096.
bool register_argon2d4096_algo( algo_gate_t* gate );

int scanhash_argon2d4096( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

#endif

