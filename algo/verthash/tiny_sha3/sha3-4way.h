// sha3.h
// 19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>
// 2021-03-27 JayDDee
//
#ifndef SHA3_4WAY_H
#define SHA3_4WAY_H

#include <stddef.h>
#include <stdint.h>
#include "simd-utils.h"

#if defined(__cplusplus)
extern "C" {
#endif

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#if defined(__AVX2__)

typedef struct
{
   __m256i st[25];                     // 64-bit words * 4 lanes
    int pt, rsiz, mdlen;                    // these don't overflow
} sha3_4way_ctx_t __attribute__ ((aligned (64)));;

// Compression function.
void sha3_4way_keccakf( __m256i st[25] );

// OpenSSL - like interfece
int sha3_4way_init( sha3_4way_ctx_t *c, int mdlen );    // mdlen = hash output in bytes
int sha3_4way_update( sha3_4way_ctx_t *c, const void *data, size_t len );
int sha3_4way_final( void *md, sha3_4way_ctx_t *c );    // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
void *sha3_4way( const void *in, size_t inlen, void *md, int mdlen );


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// state context
typedef struct
{
   __m512i st[25];                     // 64-bit words * 8 lanes
    int pt, rsiz, mdlen;                    // these don't overflow
} sha3_8way_ctx_t __attribute__ ((aligned (64)));;

// Compression function.
void sha3_8way_keccakf( __m512i st[25] );

// OpenSSL - like interfece
int sha3_8way_init( sha3_8way_ctx_t *c, int mdlen );    // mdlen = hash output in bytes
int sha3_8way_update( sha3_8way_ctx_t *c, const void *data, size_t len );
int sha3_8way_final( void *md, sha3_8way_ctx_t *c );    // digest goes to md

// compute a sha3 hash (md) of given byte length from "in"
void *sha3_8way( const void *in, size_t inlen, void *md, int mdlen );

#endif // AVX512
#endif // AVX2

#if defined(__cplusplus)
}
#endif

#endif
