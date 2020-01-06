#ifndef PANAMA_HASH_4WAY_H__
#define PANAMA_HASH_4WAY_H__ 1

#include <stddef.h>
#include "simd-utils.h"

/**
 * Output size (in bits) for PANAMA.
 */
#define SPH_SIZE_panama   256

typedef struct {
   unsigned char data[32<<2];
   __m128i buffer[32][8];
   __m128i state[17];
   unsigned data_ptr;
   unsigned buffer_ptr;
} panama_4way_context __attribute__ ((aligned (64)));

void panama_4way_init( void *cc );

void panama_4way_update( void *cc, const void *data, size_t len );

void panama_4way_close( void *cc, void *dst );

#if defined(__AVX2__)

typedef struct {
   unsigned char data[32<<3];
   __m256i buffer[32][8];
   __m256i state[17];
   unsigned data_ptr;
   unsigned buffer_ptr;
} panama_8way_context __attribute__ ((aligned (128)));

void panama_8way_init( void *cc );

void panama_8way_update( void *cc, const void *data, size_t len );

void panama_8way_close( void *cc, void *dst );

#endif
#endif
