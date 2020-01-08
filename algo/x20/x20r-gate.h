#ifndef X20R_GATE_H__
#define X20R_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>

/*
#if defined(__AVX2__) && defined(__AES__)
  #define X20R_4WAY
#endif
*/

enum x20r_Algo {
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
        HAVAL,      // 256-bits output
        GOST,
        RADIOGATUN, // 256-bits output
        PANAMA,     // 256-bits output
        X20R_HASH_FUNC_COUNT
};

void (*x20_r_s_getAlgoString) ( const uint8_t*, char* );

void x20r_getAlgoString( const uint8_t* prevblock, char *output );

bool register_xi20r_algo( algo_gate_t* gate );

#if defined(X20R_4WAY)

void x20r_4way_hash( void *state, const void *input );

int scanhash_x20r_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#endif

void x20rhash( void *state, const void *input );

int scanhash_x20r( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

