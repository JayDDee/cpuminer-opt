/* $Id: sph_skein.h 253 2011-06-07 18:33:10Z tp $ */
/**
 * Skein interface. The Skein specification defines three main
 * functions, called Skein-256, Skein-512 and Skein-1024, which can be
 * further parameterized with an output length. For the SHA-3
 * competition, Skein-512 is used for output sizes of 224, 256, 384 and
 * 512 bits; this is what this code implements. Thus, we hereafter call
 * Skein-224, Skein-256, Skein-384 and Skein-512 what the Skein
 * specification defines as Skein-512-224, Skein-512-256, Skein-512-384
 * and Skein-512-512, respectively.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_skein.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef __SKEIN_HASH_4WAY_H__
#define __SKEIN_HASH_4WAY_H__ 1

#include <stddef.h>
#include "simd-utils.h"

#if defined(SIMD512)

typedef struct
{
   __m512i buf[8];
   __m512i h0, h1, h2, h3, h4, h5, h6, h7;
   size_t ptr;
   uint64_t bcount;
} skein_8x64_big_context __attribute__ ((aligned (128)));

typedef skein_8x64_big_context skein512_8x64_context;
typedef skein_8x64_big_context skein256_8x64_context;

void skein512_8x64_full( skein512_8x64_context *sc, void *out,
                         const void *data, size_t len );
void skein512_8x64_init( skein512_8x64_context *sc );
void skein512_8x64_update( void *cc, const void *data, size_t len );
void skein512_8x64_close( void *cc, void *dst );

void skein512_8x64_prehash64( skein512_8x64_context *sc, const void *data );
void skein512_8x64_final16( skein512_8x64_context *sc, void *out,
     const void *data );

void skein256_8x64_init( skein256_8x64_context *sc );
void skein256_8x64_update( void *cc, const void *data, size_t len );
void skein256_8x64_close( void *cc, void *dst );

#define skein512_8way_context       skein512_8x64_context
#define skein512_8way_full          skein512_8x64_full
#define skein512_8way_init          skein512_8x64_init
#define skein512_8way_update        skein512_8x64_update
#define skein512_8way_close         skein512_8x64_close
#define skein512_8way_prehash64     skein512_8x64_prehash64
#define skein512_8way_final16       skein512_8x64_final16
#define skein256_8way_context       skein256_8x64_context
#define skein256_8way_init          skein256_8x64_init
#define skein256_8way_update        skein256_8x64_update
#define skein256_8way_close         skein256_8x64_close

#endif // AVX512

#if defined(__AVX2__)

typedef struct
{
   __m256i buf[8];
   __m256i h0, h1, h2, h3, h4, h5, h6, h7;
   size_t ptr;
	uint64_t bcount;
} skein_4x64_big_context __attribute__ ((aligned (128)));

typedef skein_4x64_big_context skein512_4x64_context;
typedef skein_4x64_big_context skein256_4x64_context;

void skein512_4x64_init( skein512_4x64_context *sc );
void skein512_4x64_full( skein512_4x64_context *sc, void *out,
                         const void *data, size_t len );
void skein512_4x64_update( void *cc, const void *data, size_t len );
void skein512_4x64_close( void *cc, void *dst );
void skein512_4x64_prehash64( skein512_4x64_context *sc, const void *data );
void skein512_4x64_final16( skein512_4x64_context *sc, void *out,
     const void *data );

void skein256_4x64_init( skein256_4x64_context *sc );
void skein256_4x64_update( void *cc, const void *data, size_t len );
void skein256_4x64_close( void *cc, void *dst );

#define skein512_4way_context       skein512_4x64_context
#define skein512_4way_full          skein512_4x64_full
#define skein512_4way_init          skein512_4x64_init
#define skein512_4way_update        skein512_4x64_update
#define skein512_4way_close         skein512_4x64_close
#define skein512_4way_prehash64     skein512_4x64_prehash64
#define skein512_4way_final16       skein512_4x64_final16
#define skein256_4way_context       skein256_4x64_context
#define skein256_4way_init          skein256_4x64_init
#define skein256_4way_update        skein256_4x64_update
#define skein256_4way_close         skein256_4x64_close

#endif

typedef struct
{
   v128u64_t buf[8];
   v128u64_t h0, h1, h2, h3, h4, h5, h6, h7;
   size_t ptr;
   uint64_t bcount;
} skein_2x64_big_context __attribute__ ((aligned (128)));

typedef skein_2x64_big_context skein512_2x64_context;
typedef skein_2x64_big_context skein256_2x64_context;

void skein512_2x64_init( skein512_2x64_context *sc );
void skein512_2x64_full( skein512_2x64_context *sc, void *out,
                         const void *data, size_t len );
void skein512_2x64_update( void *cc, const void *data, size_t len );
void skein512_2x64_close( void *cc, void *dst );
void skein512_2x64_prehash64( skein512_2x64_context *sc, const void *data );
void skein512_2x64_final16( skein512_2x64_context *sc, void *out,
     const void *data );

void skein256_2x64_init( skein256_2x64_context *sc );
void skein256_2x64_update( void *cc, const void *data, size_t len );
void skein256_2x64_close( void *cc, void *dst );

#endif
