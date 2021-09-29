#ifndef SHA256_HASH_H__
#define SHA256_HASH_H__ 1

#include <stddef.h>
#include "simd-utils.h"
#include "cpuminer-config.h"
#include "sph_sha2.h"


// generic interface 

typedef struct {
   unsigned char buf[64];    /* first field, for alignment */
   uint32_t state[8];
   uint64_t count;
} sha256_context __attribute__((aligned(64)));

void sha256_full( void *hash, const void *data, size_t len );
void sha256_update( sha256_context *ctx, const void *data, size_t len );
void sha256_final( sha256_context *ctx, void *hash );
void sha256_ctx_init( sha256_context *ctx );
void sha256_transform_le( uint32_t *state_out, const uint32_t *data,
                          const uint32_t *state_in );
void sha256_transform_be( uint32_t *state_out, const uint32_t *data,
                          const uint32_t *state_in );

#if defined(__SHA__)

void sha256_opt_transform_le( uint32_t *state_out, const void *input,
                           const uint32_t *state_in );

void sha256_opt_transform_be( uint32_t *state_out, const void *input,
                           const uint32_t *state_in );

// 2 way with interleaved instructions
void sha256_ni2way_transform_le( uint32_t *out_X, uint32_t*out_Y,
                              const void *msg_X, const void *msg_Y,
                              const uint32_t *in_X, const uint32_t *in_Y );

void sha256_ni2way_transform_be( uint32_t *out_X, uint32_t*out_Y,
                              const void *msg_X, const void *msg_Y,
                              const uint32_t *in_X, const uint32_t *in_Y );

// Select target
// with SHA...
#define sha256_transform_le sha256_opt_transform_le
#define sha256_transform_be sha256_opt_transform_be

#else

// without SHA...
#define sha256_transform_le sph_sha256_transform_le
#define sha256_transform_be sph_sha256_transform_be

#endif
#endif
