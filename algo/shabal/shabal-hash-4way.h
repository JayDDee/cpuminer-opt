#ifndef SHABAL_HASH_4WAY_H__
#define SHABAL_HASH_4WAY_H__ 1

#include <stddef.h>
#include "simd-utils.h"

#if defined(SIMD512)

typedef struct {
   __m512i buf[16];
   __m512i A[12], B[16], C[16];
   uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_16x32_context __attribute__ ((aligned (64)));

typedef shabal_16x32_context shabal256_16x32_context;
typedef shabal_16x32_context shabal512_16x32_context;

void shabal256_16x32_init( void *cc );
void shabal256_16x32_update( void *cc, const void *data, size_t len );
void shabal256_16x32_close( void *cc, void *dst );

void shabal512_16x32_init( void *cc );
void shabal512_16x32_update( void *cc, const void *data, size_t len );
void shabal512_16x32_close( void *cc, void *dst );

#define shabal256_16way_context    shabal256_16x32_context
#define shabal256_16way_init       shabal256_16x32_init
#define shabal256_16way_update     shabal256_16x32_update
#define shabal256_16way_close      shabal256_16x32_close
#define shabal512_16way_context    shabal512_16x32_context
#define shabal512_16way_init       shabal512_16x32_init
#define shabal512_16way_update     shabal512_16x32_update
#define shabal512_16way_close      shabal512_16x32_close

#endif

#if defined(__AVX2__)

typedef struct {
   __m256i buf[16];
   __m256i A[12], B[16], C[16];
   uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_8x32_context __attribute__ ((aligned (64)));

typedef shabal_8x32_context shabal256_8x32_context;
typedef shabal_8x32_context shabal512_8x32_context;

void shabal256_8x32_init( void *cc );
void shabal256_8x32_update( void *cc, const void *data, size_t len );
void shabal256_8x32_close( void *cc, void *dst );

void shabal512_8x32_init( void *cc );
void shabal512_8x32_update( void *cc, const void *data, size_t len );
void shabal512_8x32_close( void *cc, void *dst );

#define shabal256_8way_context     shabal256_8x32_context
#define shabal256_8way_init        shabal256_8x32_init
#define shabal256_8way_update      shabal256_8x32_update
#define shabal256_8way_close       shabal256_8x32_close
#define shabal512_8way_context     shabal512_8x32_context
#define shabal512_8way_init        shabal512_8x32_init
#define shabal512_8way_update      shabal512_8x32_update
#define shabal512_8way_close       shabal512_8x32_close

#endif

#if defined(__SSE2__) || defined(__ARM_NEON)

typedef struct {
	v128_t buf[16] __attribute__ ((aligned (64)));
	v128_t A[12], B[16], C[16];
	uint32_t Whigh, Wlow;
   size_t ptr;
   bool state_loaded;
} shabal_4x32_context;

typedef shabal_4x32_context shabal256_4x32_context;
typedef shabal_4x32_context shabal512_4x32_context;

void shabal256_4x32_init( void *cc );
void shabal256_4x32_update( void *cc, const void *data, size_t len );
void shabal256_4x32_close( void *cc, void *dst );

void shabal512_4x32_init( void *cc );
void shabal512_4x32_update( void *cc, const void *data, size_t len );
void shabal512_4x32_close( void *cc, void *dst );

#define shabal256_4way_context     shabal256_4x32_context
#define shabal256_4way_init        shabal256_4x32_init
#define shabal256_4way_update      shabal256_4x32_update
#define shabal256_4way_close       shabal256_4x32_close
#define shabal512_4way_context     shabal512_4x32_context
#define shabal512_4way_init        shabal512_4x32_init
#define shabal512_4way_update      shabal512_4x32_update
#define shabal512_4way_close       shabal512_4x32_close

#endif

#endif

