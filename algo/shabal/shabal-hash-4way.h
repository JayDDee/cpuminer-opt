#ifndef SHABAL_HASH_4WAY_H__
#define SHABAL_HASH_4WAY_H__ 1

#include <stddef.h>
#include "simd-utils.h"

#define SPH_SIZE_shabal256   256

#define SPH_SIZE_shabal512   512

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
   __m512i buf[16];
   __m512i A[12], B[16], C[16];
   uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_16way_context __attribute__ ((aligned (64)));

typedef shabal_16way_context shabal256_16way_context;
typedef shabal_16way_context shabal512_16way_context;

void shabal256_16way_init( void *cc );
void shabal256_16way_update( void *cc, const void *data, size_t len );
void shabal256_16way_close( void *cc, void *dst );
void shabal256_16way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_16way_init( void *cc );
void shabal512_16way_update( void *cc, const void *data, size_t len );
void shabal512_16way_close( void *cc, void *dst );
void shabal512_16way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

#endif

#if defined(__AVX2__)

typedef struct {
   __m256i buf[16];
   __m256i A[12], B[16], C[16];
   uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_8way_context __attribute__ ((aligned (64)));

typedef shabal_8way_context shabal256_8way_context;
typedef shabal_8way_context shabal512_8way_context;

void shabal256_8way_init( void *cc );
void shabal256_8way_update( void *cc, const void *data, size_t len );
void shabal256_8way_close( void *cc, void *dst );
void shabal256_8way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_8way_init( void *cc );
void shabal512_8way_update( void *cc, const void *data, size_t len );
void shabal512_8way_close( void *cc, void *dst );
void shabal512_8way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

#endif

#if defined(__SSE2__) || defined(__ARM_NEON)

typedef struct {
	v128_t buf[16] __attribute__ ((aligned (64)));
	v128_t A[12], B[16], C[16];
	uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_4way_context;

typedef shabal_4way_context shabal256_4way_context;
typedef shabal_4way_context shabal512_4way_context;

void shabal256_4way_init( void *cc );
void shabal256_4way_update( void *cc, const void *data, size_t len );
void shabal256_4way_close( void *cc, void *dst );
void shabal256_4way_addbits_and_close(	void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_4way_init( void *cc );
void shabal512_4way_update( void *cc, const void *data, size_t len );
void shabal512_4way_close( void *cc, void *dst );
void shabal512_4way_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

#endif

// SSE or NEON

/* No __mullo_pi32

typedef struct
{
   v64_t buf[16] __attribute__ ((aligned (64)));
   v64_t A[12], B[16], C[16];
   uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_2x32_context;

typedef shabal_2x32_context shabal256_2x32_context;
typedef shabal_2x32_context shabal512_2x32_context;

void shabal256_2x32_init( void *cc );
void shabal256_2x32_update( void *cc, const void *data, size_t len );
void shabal256_2x32_close( void *cc, void *dst );
void shabal256_2x32_addbits_and_close( void *cc, unsigned ub, unsigned n,
                                       void *dst );

void shabal512_2x32_init( shabal512_2x32_context *cc );
void shabal512_2x32_update( shabal512_2x32_context *cc, const void *data,
                            size_t len );
void shabal512_2x32_close( shabal512_2x32_context *cc, void *dst );
void shabal512_2x32_addbits_and_close( shabal512_2x32_context *cc,
                                       unsigned ub, unsigned n, void *dst );
void shabal512_2x32_ctx( shabal512_2x32_context *cc, void *dst,
                         const void *data, size_t len );
void shabal512_2x32( shabal512_2x32_context *dst, const void *data,
                     size_t len );

*/

#endif

