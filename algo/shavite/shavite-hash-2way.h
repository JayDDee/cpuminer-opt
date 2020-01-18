#ifndef SHAVITE_HASH_2WAY_H__
#define SHAVITE_HASH_2WAY_H__

#if defined(__AVX2__)
  
#include "simd-utils.h"

typedef struct {
        unsigned char buf[128<<1];
        uint32_t h[16<<1];
        size_t ptr;
        uint32_t count0, count1, count2, count3;
} shavite512_2way_context __attribute__ ((aligned (64)));

void shavite512_2way_init( shavite512_2way_context *ctx );
void shavite512_2way_update( shavite512_2way_context *ctx, const void *data,
	                     size_t len );
void shavite512_2way_close( shavite512_2way_context *ctx, void *dst );
void shavite512_2way_update_close( shavite512_2way_context *ctx, void *dst,
		                   const void *data, size_t len );
void shavite512_2way_full( shavite512_2way_context *ctx, void *dst,
                           const void *data, size_t len );

#endif // AVX2

#endif // SHAVITE_HASH_2WAY_H__

