/*-
 * Copyright 2005,2007,2009 Colin Percival
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

#ifndef HMAC_SHA256_H__
#define HMAC_SHA256_H__

#include <sys/types.h>
#include <stdint.h>
#include "sha256-hash.h"

typedef struct HMAC_SHA256Context
{
   sha256_context ictx;
   sha256_context octx;
} HMAC_SHA256_CTX;

void SHA256_Buf( const void *, size_t len, uint8_t digest[32] );
void HMAC_SHA256_Init( HMAC_SHA256_CTX *, const void *, size_t );
void HMAC_SHA256_Update( HMAC_SHA256_CTX *, const void *, size_t );
void HMAC_SHA256_Final( void*, HMAC_SHA256_CTX * );
void HMAC_SHA256_Buf( const void *, size_t Klen, const void *,
                      size_t len, uint8_t digest[32] );

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void PBKDF2_SHA256( const uint8_t *, size_t, const uint8_t *, size_t,
                    uint64_t, uint8_t *, size_t);

#endif // HMAC_SHA256_H__
