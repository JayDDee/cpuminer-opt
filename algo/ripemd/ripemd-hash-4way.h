#ifndef RIPEMD_HASH_4WAY_H__
#define RIPEMD_HASH_4WAY_H__

#include <stddef.h>
#include "algo/sha/sph_types.h"

#if defined(__SSE4_2__)

#include "avxdefs.h"

typedef struct
{
   __m128i buf[64>>2];
   __m128i val[5];
   uint32_t count_high, count_low;
} __attribute__ ((aligned (64))) ripemd160_4way_context;

void ripemd160_4way_init( ripemd160_4way_context *sc );
void ripemd160_4way( ripemd160_4way_context *sc, const void *data, size_t len );
void ripemd160_4way_close( ripemd160_4way_context *sc, void *dst );

#if defined (__AVX2__)

typedef struct
{
   __m256i buf[64>>2];
   __m256i val[5];
   uint32_t count_high, count_low;
} __attribute__ ((aligned (64))) ripemd160_8way_context;

void ripemd160_8way_init( ripemd160_8way_context *sc );
void ripemd160_8way( ripemd160_8way_context *sc, const void *data, size_t len );
void ripemd160_8way_close( ripemd160_8way_context *sc, void *dst );


#endif // __AVX2__
#endif // __SSE4_2__
#endif // RIPEMD_HASH_4WAY_H__
