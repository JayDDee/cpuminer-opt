#ifndef SHA512_HASH_H__
#define SHA512_HASH_H__ 1

#include <stddef.h>
#include "simd-utils.h"
#include "sph_sha2.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// SHA-512 8 way

typedef struct {
   __m512i buf[128>>3];
   __m512i val[8];
   uint64_t count;
   bool initialized;
} sha512_8way_context __attribute__ ((aligned (128)));

void sha512_8way_init( sha512_8way_context *sc);
void sha512_8way_update( sha512_8way_context *sc, const void *data, 
                         size_t len );
void sha512_8way_close( sha512_8way_context *sc, void *dst );
void sha512_8way_full( void *dst, const void *data, size_t len );

#endif  // AVX512

#if defined (__AVX2__)

// SHA-512 4 way

typedef struct {
   __m256i buf[128>>3];
   __m256i val[8];
   uint64_t count;
   bool initialized;
} sha512_4way_context __attribute__ ((aligned (64)));

void sha512_4way_init( sha512_4way_context *sc);
void sha512_4way_update( sha512_4way_context *sc, const void *data,
                         size_t len );
void sha512_4way_close( sha512_4way_context *sc, void *dst );
void sha512_4way_full( void *dst, const void *data, size_t len );

#endif  // AVX2

#endif
