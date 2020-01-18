#ifndef SHAVITE_HASH_4WAY_H__
#define SHAVITE_HASH_4WAY_H__ 1

#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  
#include "simd-utils.h"

typedef struct {
        unsigned char buf[128<<2];
        uint32_t h[16<<2];
        size_t ptr;
        uint32_t count0, count1, count2, count3;
} shavite512_4way_context __attribute__ ((aligned (64)));

void shavite512_4way_init( shavite512_4way_context *ctx );
void shavite512_4way_update( shavite512_4way_context *ctx, const void *data,
	                     size_t len );
void shavite512_4way_close( shavite512_4way_context *ctx, void *dst );
void shavite512_4way_update_close( shavite512_4way_context *ctx, void *dst,
		                   const void *data, size_t len );
void shavite512_4way_full( shavite512_4way_context *ctx, void *dst,
                           const void *data, size_t len );

#endif // VAES

#endif // SHAVITE_HASH_4WAY_H__

