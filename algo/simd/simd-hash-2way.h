#ifndef SIMD_HASH_2WAY_H__
#define SIMD_HASH_2WAY_H__ 1

#include "simd-compat.h"

#if defined(__AVX2__)

#include "avxdefs.h"

typedef struct {
  uint32_t A[ 32*2 ] __attribute__((aligned(64)));
  uint8_t buffer[ 128*2 ] __attribute__((aligned(64)));
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;
  
} simd_2way_context;

int simd_2way_init( simd_2way_context *state, int hashbitlen );
int simd_2way_update( simd_2way_context *state, const void *data,
                      int databitlen );
int simd_2way_close( simd_2way_context *state, void *hashval );
int simd_2way_update_close( simd_2way_context *state, void *hashval,
                            const void *data, int databitlen );
#endif
#endif
