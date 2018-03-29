#ifndef X16S_GATE_H__
#define X16S_GATE_H__ 1

#include "algo-gate-api.h"
#include "avxdefs.h"
#include <stdint.h>

#if defined(__AVX2__) && defined(__AES__)
  #define X16S_4WAY
#endif

enum x16s_Algo {
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
        X16S_HASH_FUNC_COUNT
};

bool register_x16s_algo( algo_gate_t* gate );
void x16s_getAlgoString( const uint8_t* prevblock, char *output );

#if defined(X16S_4WAY)

void x16s_4way_hash( void *state, const void *input );

int scanhash_x16s_4way( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done );

void init_x16s_4way_ctx();

#endif

void x16s_hash( void *state, const void *input );

int scanhash_x16s( int thr_id, struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done );

void init_x16s_ctx();

#endif

