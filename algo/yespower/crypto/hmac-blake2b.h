#pragma once
#ifndef __HMAC_BLAKE2B_H__
#define __HMAC_BLAKE2B_H__

#include <stddef.h>
#include <stdint.h>
#include "algo/blake/sph_blake2b.h"

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

typedef struct
{
    sph_blake2b_ctx inner;
    sph_blake2b_ctx outer;
} hmac_blake2b_ctx;

#if defined(__cplusplus)
extern "C" {
#endif

void hmac_blake2b_hash( void *out, const void *key, size_t keylen,
                        const void *in, size_t inlen );

void pbkdf2_blake2b( const uint8_t * passwd, size_t passwdlen,
                     const uint8_t * salt, size_t saltlen, uint64_t c,
                     uint8_t * buf, size_t dkLen );

#if defined(__cplusplus)
}
#endif

#endif
