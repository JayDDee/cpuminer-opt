/*-
 * Copyright 2005,2007,2009 Colin Percival
 * Copyright 2020 JayDDee@gmailcom
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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
 * $FreeBSD: src/lib/libmd/sha256_Y.h,v 1.2 2006/01/17 15:35:56 phk Exp $
 */

#ifndef HMAC_SHA256_4WAY_H__
#define HMAC_SHA256_4WAY_H__


// Tested only 8-way with null pers

#include <sys/types.h>
#include <stdint.h>
#include "simd-utils.h"
#include "sha-hash-4way.h"

typedef struct _hmac_sha256_4way_context
{
   sha256_4way_context ictx;
   sha256_4way_context octx;
} hmac_sha256_4way_context;

//void SHA256_Buf( const void *, size_t len, uint8_t digest[32] );
void hmac_sha256_4way_init( hmac_sha256_4way_context *, const void *, size_t );
void hmac_sha256_4way_update( hmac_sha256_4way_context *, const void *,
                              size_t );
void hmac_sha256_4way_close( hmac_sha256_4way_context *, void* );
void hmac_sha256_4way_full( void*, const void *, size_t Klen, const void *,
                            size_t len );

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void pbkdf2_sha256_4way( uint8_t *, size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t, uint64_t );

#if defined(__AVX2__)

typedef struct _hmac_sha256_8way_context
{
   sha256_8way_context ictx;
   sha256_8way_context octx;
} hmac_sha256_8way_context;

//void SHA256_Buf( const void *, size_t len, uint8_t digest[32] );
void hmac_sha256_8way_init( hmac_sha256_8way_context *, const void *, size_t );
void hmac_sha256_8way_update( hmac_sha256_8way_context *, const void *,
                              size_t );
void hmac_sha256_8way_close( hmac_sha256_8way_context *, void* );
void hmac_sha256_8way_full( void*, const void *, size_t Klen, const void *,
                            size_t len );

void pbkdf2_sha256_8way( uint8_t *, size_t, const uint8_t *, size_t,
                        const uint8_t *, size_t, uint64_t );
      
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct _hmac_sha256_16way_context
{
   sha256_16way_context ictx;
   sha256_16way_context octx;
} hmac_sha256_16way_context;

//void SHA256_Buf( const void *, size_t len, uint8_t digest[32] );
void hmac_sha256_16way_init( hmac_sha256_16way_context *,
                             const void *, size_t );
void hmac_sha256_16way_update( hmac_sha256_16way_context *, const void *,
                              size_t );
void hmac_sha256_16way_close( hmac_sha256_16way_context *, void* );
void hmac_sha256_16way_full( void*, const void *, size_t Klen, const void *,
                             size_t len );

void pbkdf2_sha256_16way( uint8_t *, size_t, const uint8_t *, size_t,
                          const uint8_t *, size_t, uint64_t );



#endif   // AVX512
#endif   // AVX2

#endif // HMAC_SHA256_4WAY_H__
