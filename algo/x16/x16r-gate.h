#ifndef X16R_GATE_H__
#define X16R_GATE_H__ 1

#include "algo-gate-api.h"
#include "simd-utils.h"
#include <stdint.h>
#include <unistd.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/echo/sph_echo.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"

#if defined(__AES__)
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/fugue/fugue-aesni.h"
#endif

#if defined (__AVX2__)

#include "algo/blake/blake-hash-4way.h"
#include "algo/bmw/bmw-hash-4way.h"
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/keccak/keccak-hash-4way.h"
#include "algo/luffa/luffa-hash-2way.h"
#include "algo/cubehash/cube-hash-2way.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/echo/aes_ni/hash_api.h"
#include "algo/hamsi/hamsi-hash-4way.h"
#include "algo/shabal/shabal-hash-4way.h"
#include "algo/sha/sha-hash-4way.h"

#if defined(__VAES__)
#include "algo/groestl/groestl512-hash-4way.h"
#include "algo/shavite/shavite-hash-2way.h"
#include "algo/shavite/shavite-hash-4way.h"
#include "algo/echo/echo-hash-4way.h"
#endif

#endif // AVX2

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

  #define X16R_8WAY   1
  #define X16RV2_8WAY 1
  #define X16RT_8WAY  1
  #define X21S_8WAY   1

#elif defined(__AVX2__) && defined(__AES__)

  #define X16RV2_4WAY 1
  #define X16RT_4WAY  1
  #define X21S_4WAY   1
  #define X16R_4WAY   1

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

extern __thread char x16r_hash_order[ X16R_HASH_FUNC_COUNT + 1 ];

extern void (*x16_r_s_getAlgoString) ( const uint8_t*, char* );
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

union _x16r_8way_context_overlay
{
    blake512_8way_context   blake;
    bmw512_8way_context     bmw;
    skein512_8way_context   skein;
    jh512_8way_context      jh;
    keccak512_8way_context  keccak;
    luffa_4way_context      luffa;
    cube_4way_context       cube;
    simd_4way_context       simd;
    hamsi512_8way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_8way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_8way_context     sha512;
#if defined(__VAES__)
    groestl512_4way_context groestl;
    shavite512_4way_context shavite;
    echo_4way_context       echo;
#else
    hashState_groestl       groestl;
    shavite512_context      shavite;
    hashState_echo          echo;
#endif
} __attribute__ ((aligned (64)));

typedef union _x16r_8way_context_overlay x16r_8way_context_overlay;

extern __thread x16r_8way_context_overlay x16r_ctx;

void x16r_8way_prehash( void *, void * );
int x16r_8way_hash_generic( void *, const void *, int );
int x16r_8way_hash( void *, const void *, int );
int scanhash_x16r_8way( struct work *, uint32_t ,
                        uint64_t *, struct thr_info * );
extern __thread x16r_8way_context_overlay x16r_ctx;


#elif defined(X16R_4WAY)

union _x16r_4way_context_overlay
{
    blake512_4way_context   blake;
    bmw512_4way_context     bmw;
#if defined(__VAES__)
    groestl512_2way_context groestl;
    shavite512_2way_context shavite;
    echo_2way_context       echo;
#else
    hashState_groestl       groestl;
    shavite512_context      shavite;
    hashState_echo          echo;
#endif
    skein512_4way_context   skein;
    jh512_4way_context      jh;
    keccak512_4way_context  keccak;
    luffa_2way_context      luffa;
    cube_2way_context       cube;
    hashState_luffa         luffa1;
    simd_2way_context       simd;
    hamsi512_4way_context   hamsi;
    hashState_fugue         fugue;
    shabal512_4way_context  shabal;
    sph_whirlpool_context   whirlpool;
    sha512_4way_context     sha512;
} __attribute__ ((aligned (64)));

typedef union _x16r_4way_context_overlay x16r_4way_context_overlay;

extern __thread x16r_4way_context_overlay x16r_ctx;

void x16r_4way_prehash( void *, void * );
int x16r_4way_hash_generic( void *, const void *, int );
int x16r_4way_hash( void *, const void *, int );
int scanhash_x16r_4way( struct work *, uint32_t,
                        uint64_t *, struct thr_info * );
extern __thread x16r_4way_context_overlay x16r_ctx;

#endif

// needed for hex
union _x16r_context_overlay
{
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
        hashState_fugue         fugue;
#else
        sph_groestl512_context   groestl;
        sph_echo512_context      echo;
        sph_fugue512_context    fugue;
#endif
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cube;
        shavite512_context      shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;
} __attribute__ ((aligned (64)));

typedef union _x16r_context_overlay x16r_context_overlay;

extern __thread x16r_context_overlay x16_ctx;

void x16r_prehash( void *, void * );
int x16r_hash_generic( void *, const void *, int );
int x16r_hash( void *, const void *, int );
int scanhash_x16r( struct work *, uint32_t, uint64_t *, struct thr_info * );

// x16Rv2
#if defined(X16RV2_8WAY)

int x16rv2_8way_hash( void *state, const void *input, int thrid );
int scanhash_x16rv2_8way( struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X16RV2_4WAY)

int x16rv2_4way_hash( void *state, const void *input, int thrid );
int scanhash_x16rv2_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

int x16rv2_hash( void *state, const void *input, int thr_id );
int scanhash_x16rv2( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

// x16rt, veil
#if defined(X16R_8WAY)

//void x16rt_8way_hash( void *state, const void *input );
int scanhash_x16rt_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#elif defined(X16R_4WAY)

//void x16rt_4way_hash( void *state, const void *input );
int scanhash_x16rt_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );

#else

//void x16rt_hash( void *state, const void *input );
int scanhash_x16rt( struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

#endif

// x21s
#if defined(X16R_8WAY)

int x21s_8way_hash( void *state, const void *input, int thrid );
int scanhash_x21s_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_8way_thread_init();

#elif defined(X16R_4WAY)

int x21s_4way_hash( void *state, const void *input, int thrid );
int scanhash_x21s_4way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_4way_thread_init();

#else

int x21s_hash( void *state, const void *input, int thr_id );
int scanhash_x21s( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );
bool x21s_thread_init();

#endif

//void hex_hash( void *state, const void *input );
int scanhash_hex( struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done, struct thr_info *mythr );

#endif

