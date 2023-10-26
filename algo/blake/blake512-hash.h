#ifndef BLAKE512_HASH__
#define BLAKE512_HASH__ 1

#include <stddef.h>
#include "simd-utils.h"

#if defined(__SSE2__) || defined(__ARM_NEON)

/////////////////////////
//
//  Blake-512 1 way SSE2, AVX2, NEON

typedef struct
{
   unsigned char buf[128];    /* first field, for alignment */
   uint64_t H[8];
   uint64_t T0, T1;
   size_t ptr;
} blake512_context __attribute__ ((aligned (32)));

void  blake512_transform( uint64_t *H, const uint64_t *buf,
                          const uint64_t T0, const uint64_t T1 );
void blake512_init( blake512_context *sc );
void blake512_update( blake512_context *sc, const void *data, size_t len );
void blake512_close( blake512_context *sc, void *dst );
void blake512_full( blake512_context *sc, void *dst, const void *data,
                    size_t len );

/////////////////////////
//
//  Blake-512 2 way SSE2 & NEON

typedef struct
{
   v128u64_t buf[16];
   v128u64_t H[8];
   v128u64_t S[4];
   size_t ptr;
   uint64_t T0, T1;
} blake_2x64_big_context __attribute__ ((aligned (32)));

typedef blake_2x64_big_context blake512_2x64_context;

void blake512_2x64_init( blake_2x64_big_context *sc );
void blake512_2x64_update( void *cc, const void *data, size_t len );
void blake512_2x64_close( void *cc, void *dst );
void blake512_2x64_full( blake_2x64_big_context *sc, void * dst,
                         const void *data, size_t len );
void blake512_2x64_full_le( blake_2x64_big_context *sc, void * dst,
                            const void *data, size_t len );
void blake512_2x64_prehash_part1_le( blake_2x64_big_context *sc,
                                     v128u64_t *midstate, const void *data );
void blake512_2x64_prehash_part2_le( blake_2x64_big_context *sc,
              void *hash, const v128u64_t nonce, const v128u64_t *midstate );

#ifdef __AVX2__

/////////////////////////
//
// Blake-512 4 way AVX2

typedef struct
{
   __m256i buf[16];
   __m256i H[8];
   __m256i S[4];   
   size_t ptr;
   uint64_t T0, T1;
} blake_4x64_big_context __attribute__ ((aligned (64)));

typedef blake_4x64_big_context blake512_4x64_context;

void blake512_4x64_init( blake_4x64_big_context *sc );
void blake512_4x64_update( void *cc, const void *data, size_t len );
void blake512_4x64_close( void *cc, void *dst );
void blake512_4x64_full( blake_4x64_big_context *sc, void * dst,
                         const void *data, size_t len );
void blake512_4x64_full_le( blake_4x64_big_context *sc, void * dst,
                            const void *data, size_t len );
void blake512_4x64_prehash_le( blake_4x64_big_context *sc, __m256i *midstate,
                               const void *data );
void blake512_4x64_final_le( blake_4x64_big_context *sc, void *hash,
                             const __m256i nonce, const __m256i *midstate );

#define blake_4way_big_context    blake_4x64_big_context
#define blake512_4way_context     blake512_4x64_context
#define blake512_4way_init        blake512_4x64_init
#define blake512_4way_update      blake512_4x64_update
#define blake512_4way_close       blake512_4x64_close 
#define blake512_4way_full        blake512_4x64_full
#define blake512_4way_full_le     blake512_4x64_full_le
#define blake512_4way_prehash_le  blake512_4x64_prehash_le
#define blake512_4way_final_le    blake512_4x64_final_le

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

////////////////////////////
//
//   Blake-512 8 way AVX512

typedef struct
{
   __m512i buf[16];
   __m512i H[8];
   __m512i S[4];
   size_t ptr;
   uint64_t T0, T1;
} blake_8x64_big_context __attribute__ ((aligned (128)));

typedef blake_8x64_big_context blake512_8x64_context;

void blake512_8x64_init( blake_8x64_big_context *sc );
void blake512_8x64_update( void *cc, const void *data, size_t len );
void blake512_8x64_close( void *cc, void *dst );
void blake512_8x64_full( blake_8x64_big_context *sc, void * dst,
                        const void *data, size_t len );
void blake512_8x64_full_le( blake_8x64_big_context *sc, void * dst,
                            const void *data, size_t len );
void blake512_8x64_prehash_le( blake_8x64_big_context *sc, __m512i *midstate,
                               const void *data );
void blake512_8x64_final_le( blake_8x64_big_context *sc, void *hash,
                             const __m512i nonce, const __m512i *midstate );

#define blake_8way_big_context      blake_8x64_big_context
#define blake512_8way_context       blake512_8x64_context
#define blake512_8way_init          blake512_8x64_init
#define blake512_8way_update        blake512_8x64_update
#define blake512_8way_close         blake512_8x64_close
#define blake512_8way_full          blake512_8x64_full  
#define blake512_8way_full_le       blake512_8x64_full_le
#define blake512_8way_prehash_le    blake512_8x64_prehash_le
#define blake512_8way_final_le      blake512_8x64_final_le

#endif  // AVX512
#endif  // AVX2
#endif  // SSE2 or NEON

#endif  // BLAKE512_HASH_H__
