#ifndef SIMD_HASH_2WAY_H__
#define SIMD_HASH_2WAY_H__ 1

#include "simd-compat.h"

#if defined(__AVX2__)

#include "simd-utils.h"


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
  uint32_t A[ 32*4 ];
  uint8_t buffer[ 128*4 ];
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;

} simd_4way_context __attribute__((aligned(128)));

int simd_4way_init( simd_4way_context *state, int hashbitlen );
int simd_4way_update( simd_4way_context *state, const void *data,
                      int databitlen );
int simd_4way_close( simd_4way_context *state, void *hashval );
int simd_4way_update_close( simd_4way_context *state, void *hashval,
                            const void *data, int databitlen );
int simd512_4way_full( simd_4way_context *state, void *hashval,
                    const void *data, int datalen );

#endif

typedef struct {
  uint32_t A[ 32*2 ];
  uint8_t buffer[ 128*2 ];
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;
  
} simd_2way_context __attribute__((aligned(128)));

int simd_2way_init( simd_2way_context *state, int hashbitlen );
int simd_2way_update( simd_2way_context *state, const void *data,
                      int databitlen );
int simd_2way_close( simd_2way_context *state, void *hashval );
int simd_2way_update_close( simd_2way_context *state, void *hashval,
                            const void *data, int databitlen );
int simd512_2way_full( simd_2way_context *state, void *hashval,
                    const void *data, int datalen );

#endif
#endif
