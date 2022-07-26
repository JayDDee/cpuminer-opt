/*
 * Copyright 2009 Colin Percival, 2014 savale
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *  notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *  notice, this list of conditions and the following disclaimer in the
 *  documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "simd-utils.h"
#include "hmac-blake2b.h"

// keylen = number of bytes
void hmac_blake2b_init( hmac_blake2b_ctx *hctx, const void *_key,
                        size_t keylen )
{
    const uint8_t *key = _key;
    uint8_t keyhash[32];
    uint8_t pad[64];
    uint64_t i;

    if (keylen > 64)
    {
       sph_blake2b_ctx ctx;
       sph_blake2b_init( &ctx, 32, NULL, 0 );
       sph_blake2b_update( &ctx, key, keylen );
       sph_blake2b_final( &ctx, keyhash );
       key = keyhash;
       keylen = 32;
    }

    sph_blake2b_init( &hctx->inner, 32, NULL, 0 );
    memset( pad, 0x36, 64 );
    for ( i = 0; i < keylen; ++i )
        pad[i] ^= key[i];

    sph_blake2b_update( &hctx->inner, pad, 64 );
    sph_blake2b_init( &hctx->outer, 32, NULL, 0 );
    memset( pad, 0x5c, 64 );
    for ( i = 0; i < keylen; ++i )
        pad[i] ^= key[i];

    sph_blake2b_update( &hctx->outer, pad, 64 );
    memset( keyhash, 0, 32 );
}

// datalen = number of bits
void hmac_blake2b_update( hmac_blake2b_ctx *hctx, const void *data,
                          size_t datalen )
{
    // update the inner state
    sph_blake2b_update( &hctx->inner, data, datalen );
}

void hmac_blake2b_final( hmac_blake2b_ctx *hctx, uint8_t *digest )
{
    uint8_t ihash[32];
    sph_blake2b_final( &hctx->inner, ihash );
    sph_blake2b_update( &hctx->outer, ihash, 32 );
    sph_blake2b_final( &hctx->outer, digest );
    memset( ihash, 0, 32 );
}

// // keylen = number of bytes; inlen = number of bytes
void hmac_blake2b_hash( void *out, const void *key, size_t keylen,
                        const void *in, size_t inlen )
{
    hmac_blake2b_ctx hctx;
    hmac_blake2b_init( &hctx, key, keylen );
    hmac_blake2b_update( &hctx, in, inlen );
    hmac_blake2b_final( &hctx, out );
}

void pbkdf2_blake2b( const uint8_t *passwd, size_t passwdlen,
                     const uint8_t *salt, size_t saltlen, uint64_t c,
                     uint8_t *buf, size_t dkLen )
{
    hmac_blake2b_ctx PShctx, hctx;
    size_t i;
    uint32_t ivec;
    uint8_t U[32];
    uint8_t T[32];
    uint64_t j;
    int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    hmac_blake2b_init( &PShctx, passwd, passwdlen );
    hmac_blake2b_update( &PShctx, salt, saltlen );

    /* Iterate through the blocks. */
    for ( i = 0; i * 32 < dkLen; i++ )
    {
        /* Generate INT(i + 1). */
        ivec = bswap_32( i+1 );

        /* Compute U_1 = PRF(P, S || INT(i)). */
        memcpy( &hctx, &PShctx, sizeof(hmac_blake2b_ctx) );
        hmac_blake2b_update( &hctx, &ivec, 4 );
        hmac_blake2b_final( &hctx, U );

        /* T_i = U_1 ... */
        memcpy( T, U, 32 );

        for ( j = 2; j <= c; j++ )
        {
            /* Compute U_j. */
            hmac_blake2b_init( &hctx, passwd, passwdlen );
            hmac_blake2b_update( &hctx, U, 32 );
            hmac_blake2b_final( &hctx, U );

            /* ... xor U_j ... */
            for ( k = 0; k < 32; k++ )
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * 32;
        if (clen > 32)
            clen = 32;

        memcpy( &buf[i * 32], T, clen );
    }

    /* Clean PShctx, since we never called _Final on it. */
    memset( &PShctx, 0, sizeof(hmac_blake2b_ctx) );
}
