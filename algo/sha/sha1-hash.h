#ifndef SHA1_HASH_H__
#define SHA1_HASH_H__ 1

#include <stddef.h>
#include "simd-utils.h"
#include "cpuminer-config.h"
#include "sph_sha1.h"

// SHA hooks for sha1, automaticaaly substituded in SPH
#if defined(__x86_64__) && defined(__SHA__)

void sha1_x86_sha_transform_le( uint32_t *state_out, const void *input,
                                const uint32_t *state_in );

void sha1_x86_sha_transform_be( uint32_t *state_out, const void *input,
                                const uint32_t *state_in );

#define sha1_transform_le        sha1_x86_sha_transform_le
#define sha1_transform_be        sha1_x86_sha_transform_be

#elif defined(__ARM_NEON) && defined(__ARM_FEATURE_SHA2)

void sha1_neon_sha_transform_be( uint32_t *state_out, const void *input,
                                 const uint32_t *state_in );
void sha1_neon_sha_transform_le( uint32_t *state_out, const void *input,
                                 const uint32_t *state_in );

#define sha1_transform_le        sha1_neon_sha_transform_le
#define sha1_transform_be        sha1_neon_sha_transform_be

#else

#define sha1_transform_le        sph_sha1_transform_le
#define sha1_transform_be        sph_sha1_transform_be

#endif

#define sha1_full                sph_sha1_full

#endif
