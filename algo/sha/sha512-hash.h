#ifndef SHA512_HASH_H__
#define SHA512_HASH_H__ 1

#include <stddef.h>
#include "simd-utils.h"
#include "sph_sha2.h"

#if defined(__SHA512__) && defined(__AVX__)

// Experimental, untested
// Need to substitute for sph_sha512

typedef struct
{
   uint64_t buf[128>>3];
   uint64_t val[8];
   uint64_t count;
} sha512_context __attribute__ ((aligned (64)));

void sha512_opt_transform_be( uint64_t *state_out, const void *input,
                              const uint64_t *state_in );

void sha512_opt_transform_le( uint64_t *state_out, const void *input,
                              const uint64_t *state_in );

#endif

#if defined(SIMD512)

// SHA-512 8 way

typedef struct
{
   __m512i buf[128>>3];
   __m512i val[8];
   uint64_t count;
   bool initialized;
} sha512_8x64_context __attribute__ ((aligned (128)));

void sha512_8x64_init( sha512_8x64_context *sc);
void sha512_8x64_update( sha512_8x64_context *sc, const void *data, 
                         size_t len );
void sha512_8x64_close( sha512_8x64_context *sc, void *dst );
void sha512_8x64_ctx( sha512_8x64_context *sc, void *dst, const void *data,
                      size_t len );

#endif  // AVX512

#if defined (__AVX2__)

// SHA-512 4 way

typedef struct
{
   __m256i buf[128>>3];
   __m256i val[8];
   uint64_t count;
   bool initialized;
} sha512_4x64_context __attribute__ ((aligned (64)));

void sha512_4x64_init( sha512_4x64_context *sc);
void sha512_4x64_update( sha512_4x64_context *sc, const void *data,
                         size_t len );
void sha512_4x64_close( sha512_4x64_context *sc, void *dst );
void sha512_4x64_ctx( sha512_4x64_context *sc, void *dst, const void *data,
                       size_t len );

#endif  // AVX2

typedef struct
{
   v128u64_t buf[128>>3];
   v128u64_t val[8];
   uint64_t count;
   bool initialized;
} sha512_2x64_context __attribute__ ((aligned (64)));

void sha512_2x64_init( sha512_2x64_context *sc);
void sha512_2x64_update( sha512_2x64_context *sc, const void *data,
                         size_t len );
void sha512_2x64_close( sha512_2x64_context *sc, void *dst );
void sha512_2x64( void *dst, const void *data, size_t len );
void sha512_2x64_ctx( sha512_2x64_context *sc, void *dst, const void *data, 
                      size_t len );

#endif
