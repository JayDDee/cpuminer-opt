#ifndef SHA2_HASH_OPT_H__
#define SHA2_HASH_OPT_H__ 1

#include <stddef.h>
#include "simd-utils.h"

#if defined(__SHA__)

void sha256_opt_transform( uint32_t *state_out, const void *input,
                           const uint32_t *state_in );

// 2 way with interleaved instructions
void sha256_ni2way_transform( uint32_t *out_X, uint32_t*out_Y,
                              const void *msg_X, const void *msg_Y,
                              const uint32_t *in_X, const uint32_t *in_Y );

#endif
#endif
