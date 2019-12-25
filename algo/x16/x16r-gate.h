#ifndef X16R_GATE_H__
#define X16R_GATE_H__ 1

#include "algo-gate-api.h"
#include "simd-utils.h"
#include <stdint.h>
#include <unistd.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X16R_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X16R_4WAY 1
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X16RV2_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X16RV2_4WAY 1
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X16RT_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X16RT_4WAY 1
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #define X21S_8WAY 1
#elif defined(__AVX2__) && defined(__AES__)
  #define X21S_4WAY 1
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

void (*x16_r_s_getAlgoString) ( const uint8_t*, char* );
void x16r_getAlgoString( const uint8_t *prevblock, char *output );
void x16s_getAlgoString( const uint8_t *prevblock, char *output );
void x16rt_getAlgoString( const uint32_t *timeHash, char *output );

void x16rt_getTimeHash( const uint32_t timeStamp, void* timeHash );

bool register_x16r_algo( algo_gate_t* gate );
bool register_x16rv2_algo( algo_gate_t* gate );
bool register_x16s_algo( algo_gate_t* gate );
bool register_x16rt_algo( algo_gate_t* gate );
bool register_hex__algo( algo_gate_t* gate );
bool register_x21s__algo( algo_gate_t* gate );

// x16r, x16s
#if defined(X16R_8WAY)

void x16r_8way_hash( void *state, const void *input );
int scanhash_x16r_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );


#elif defined(X16R_4WAY)

void x16r_4way_hash( void *state, const void *input );
int scanhash_x16r_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

void x16r_hash( void *state, const void *input );
int scanhash_x16r( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

// x16Rv2
#if defined(X16RV2_8WAY)

void x16rv2_8way_hash( void *state, const void *input );
int scanhash_x16rv2_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X16RV2_4WAY)

void x16rv2_4way_hash( void *state, const void *input );
int scanhash_x16rv2_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

void x16rv2_hash( void *state, const void *input );
int scanhash_x16rv2( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

// x16rt, veil
#if defined(X16RT_8WAY)

void x16rt_8way_hash( void *state, const void *input );
int scanhash_x16rt_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X16RT_4WAY)

void x16rt_4way_hash( void *state, const void *input );
int scanhash_x16rt_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

void x16rt_hash( void *state, const void *input );
int scanhash_x16rt( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

// x21s
#if defined(X21S_8WAY)

void x21s_8way_hash( void *state, const void *input );
int scanhash_x21s_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_8way_thread_init();

#elif defined(X21S_4WAY)

void x21s_4way_hash( void *state, const void *input );
int scanhash_x21s_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_4way_thread_init();

#else

void x21s_hash( void *state, const void *input );
int scanhash_x21s( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_thread_init();

#endif

void hex_hash( void *state, const void *input );
int scanhash_hex( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

#endif

