#ifndef X16R_GATE_H__
#define X16R_GATE_H__ 1

#include "algo-gate-api.h"
#include "avxdefs.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X16R_4WAY
#endif

enum x16r_Algo {
        BLAKE = 0,
        BMW,
        GROESTL,
        JH,
        KECCAK,
        SKEIN,
        LUFFA,
        CUBEHASH,
        SHAVITE,
        SIMD,
        ECHO,
        HAMSI,
        FUGUE,
        SHABAL,
        WHIRLPOOL,
        SHA_512,
        X16R_HASH_FUNC_COUNT
};

bool register_x16r_algo( algo_gate_t* gate );
void x16r_getAlgoString( const uint8_t* prevblock, char *output );

#if defined(X16R_4WAY)

void x16r_4way_hash( void *state, const void *input );

int scanhash_x16r_4way( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done );

void init_x16r_4way_ctx();

#endif

void x16r_hash( void *state, const void *input );

int scanhash_x16r( int thr_id, struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done );

void init_x16r_ctx();

#endif

