#ifndef SIMD_HASH_2WAY_H__
#define SIMD_HASH_2WAY_H__ 1

#include "simd-utils.h"

#if defined(__SSE2__) || defined (__ARM_NEON)

typedef struct
{
  uint32_t A[32];
  uint8_t buffer[128];
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;
} simd512_context __attribute__((aligned(64)));

// datalen is bytes
int simd512_ctx( simd512_context *ctx, void *hashval, const void *data,
                  int datalen );

int simd512( void *hashval, const void *data, int datalen );

#endif

#if defined(__AVX2__)

typedef struct
{
  uint32_t A[ 32*2 ];
  uint8_t buffer[ 128*2 ];
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;
} simd512_2way_context __attribute__((aligned(64)));
#define simd_2way_context simd512_2way_context

// databitlen is bits
int simd_2way_init( simd_2way_context *state, int hashbitlen );
int simd_2way_update( simd_2way_context *state, const void *data,
                      int databitlen );
int simd_2way_close( simd_2way_context *state, void *hashval );
int simd_2way_update_close( simd_2way_context *state, void *hashval,
                            const void *data, int databitlen );
int simd512_2way_ctx( simd512_2way_context *state, void *hashval,
                    const void *data, int datalen );
#define simd512_2way_full simd512_2way_ctx

int simd512_2way( void *hashval, const void *data, int datalen );

#endif

#if defined(SIMD512)

typedef struct
{
  uint32_t A[ 32*4 ];
  uint8_t buffer[ 128*4 ];
  uint64_t count;
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;
} simd512_4way_context __attribute__((aligned(128)));
#define simd_4way_context simd512_4way_context

int simd_4way_init( simd_4way_context *state, int hashbitlen );
int simd_4way_update( simd_4way_context *state, const void *data,
                      int databitlen );
int simd_4way_close( simd_4way_context *state, void *hashval );
int simd_4way_update_close( simd_4way_context *state, void *hashval,
                            const void *data, int databitlen );
int simd512_4way_ctx( simd_4way_context *state, void *hashval,
                    const void *data, int datalen );
#define simd512_4way_full simd512_4way_ctx

int simd512_4way( void *hashval, const void *data, int datalen );

#endif

#endif
