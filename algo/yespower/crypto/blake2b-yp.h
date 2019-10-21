#pragma once
#ifndef __BLAKE2B_H__
#define __BLAKE2B_H__

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER) || defined(__x86_64__) || defined(__x86__)
#define NATIVE_LITTLE_ENDIAN
#endif

// state context
typedef struct {
    uint8_t b[128]; // input buffer
    uint64_t h[8];  // chained state
    uint64_t t[2];  // total number of bytes
    size_t c;       // pointer for b[]
    size_t outlen;  // digest size
} blake2b_yp_ctx;

typedef struct {
    blake2b_yp_ctx inner;
    blake2b_yp_ctx outer;
} hmac_yp_ctx;

#if defined(__cplusplus)
extern "C" {
#endif

int blake2b_yp_init(blake2b_yp_ctx *ctx, size_t outlen, const void *key, size_t keylen);
void blake2b_yp_update(blake2b_yp_ctx *ctx, const void *in, size_t inlen);
void blake2b_yp_final(blake2b_yp_ctx *ctx, void *out);
void blake2b_yp_hash(void *out, const void *in, size_t inlen);
void hmac_blake2b_yp_hash(void *out, const void *key, size_t keylen, const void *in, size_t inlen);
void pbkdf2_blake2b_yp(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#if defined(__cplusplus)
}
#endif

#endif
