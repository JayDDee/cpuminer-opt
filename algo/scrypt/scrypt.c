/*
 * Copyright 2009 Colin Percival, 2011 ArtForz, 2011-2014 pooler
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
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 */

#include "algo-gate-api.h"

#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "algo/sha/sha-hash-4way.h"
#include "algo/sha/sha256-hash.h"
#include <mm_malloc.h>

static const uint32_t keypad[12] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000280
};
static const uint32_t innerpad[11] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x000004a0
};
static const uint32_t outerpad[8] = {
	0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300
};
static const uint32_t finalblk[16] = {
	0x00000001, 0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00000620
};

static const uint32_t sha256_initial_state[8] =
{
  0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
  0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static int scrypt_throughput = 0;

static int scratchbuf_size = 0;

static __thread char *scratchbuf = NULL;

// change this to a constant to be used directly  as input state arg
// vectors still need an init function.
static inline void sha256_init_state( uint32_t *state )
{
   state[ 0 ] = 0x6A09E667;
   state[ 1 ] = 0xBB67AE85;
   state[ 2 ] = 0x3C6EF372;
   state[ 3 ] = 0xA54FF53A;
   state[ 4 ] = 0x510E527F;
   state[ 5 ] = 0x9B05688C;
   state[ 6 ] = 0x1F83D9AB;
   state[ 7 ] = 0x5BE0CD19;
}

static inline void HMAC_SHA256_80_init(const uint32_t *key,
	uint32_t *tstate, uint32_t *ostate)
{
   uint32_t ihash[8];
   uint32_t pad[16];
   int i;

   /* tstate is assumed to contain the midstate of key */
   memcpy(pad, key + 16, 16);
   memcpy(pad + 4, keypad, 48);

   sha256_transform_le( tstate, pad, tstate );

   memcpy( ihash, tstate, 32 );

   for ( i = 0; i < 8; i++ )  pad[i] = ihash[i] ^ 0x5c5c5c5c;
   for ( ; i < 16; i++ )      pad[i] = 0x5c5c5c5c;

   sha256_transform_le( ostate, pad, sha256_initial_state );

   for ( i = 0; i < 8; i++ )  pad[i] = ihash[i] ^ 0x36363636;
   for ( ; i < 16; i++ )      pad[i] = 0x36363636;

   sha256_transform_le( tstate, pad, sha256_initial_state );
}

static inline void PBKDF2_SHA256_80_128(const uint32_t *tstate,
	const uint32_t *ostate, const uint32_t *salt, uint32_t *output)
{
   uint32_t istate[8], ostate2[8];
   uint32_t ibuf[16], obuf[16];
   int i, j;

   sha256_transform_le( istate, salt, tstate );

   memcpy(ibuf, salt + 16, 16);
   memcpy(ibuf + 5, innerpad, 44);
   memcpy(obuf + 8, outerpad, 32);

   for (i = 0; i < 4; i++)
   {
      memcpy(obuf, istate, 32);
      ibuf[4] = i + 1;

      sha256_transform_le( obuf, ibuf, obuf );
      sha256_transform_le( ostate2, obuf, ostate );

      for (j = 0; j < 8; j++)
         output[8 * i + j] = bswap_32( ostate2[j] );
   }
}

static inline void PBKDF2_SHA256_128_32(uint32_t *tstate, uint32_t *ostate,
	const uint32_t *salt, uint32_t *output)
{
   uint32_t buf[16];
   int i;

   sha256_transform_be( tstate, salt, tstate );
   sha256_transform_be( tstate, salt+16, tstate );
   sha256_transform_le( tstate, finalblk, tstate );

   memcpy(buf, tstate, 32);
   memcpy(buf + 8, outerpad, 32);

   sha256_transform_le( ostate, buf, ostate );

   for (i = 0; i < 8; i++)
      output[i] = bswap_32( ostate[i] );
}

#if defined(__SHA__)

static inline void HMAC_SHA256_80_init_SHA_2BUF( const uint32_t *key0, 
                    const uint32_t *key1, uint32_t *tstate0, uint32_t *tstate1,
                    uint32_t *ostate0, uint32_t *ostate1 )
{
   uint32_t ihash0[8], ihash1[8], pad0[16], pad1[16];
   int i;

   memcpy( pad0, key0 + 16, 16 );
   memcpy( pad0 + 4, keypad, 48 );
   memcpy( pad1, key1 + 16, 16 );
   memcpy( pad1 + 4, keypad, 48 );

   sha256_ni2way_transform_le( tstate0, tstate1, pad0, pad1,
		               tstate0, tstate1 );

   memcpy( ihash0, tstate0, 32 );
   memcpy( ihash1, tstate1, 32 );

   for ( i = 0; i < 8; i++ )
   {
      pad0[i] = ihash0[i] ^ 0x5c5c5c5c;
      pad1[i] = ihash1[i] ^ 0x5c5c5c5c;
   }
   for ( ; i < 16; i++ ) pad0[i] = pad1[i] = 0x5c5c5c5c;

   sha256_ni2way_transform_le( ostate0, ostate1, pad0, pad1,
                               sha256_initial_state, sha256_initial_state );

   for ( i = 0; i < 8; i++ )
   {
      pad0[i] = ihash0[i] ^ 0x36363636;
      pad1[i] = ihash1[i] ^ 0x36363636;
   }
   for ( ; i < 16; i++ )      pad0[i] = pad1[i] = 0x36363636;

   sha256_ni2way_transform_le( tstate0, tstate1, pad0, pad1, 
                               sha256_initial_state, sha256_initial_state );
}

static inline void PBKDF2_SHA256_80_128_SHA_2BUF( const uint32_t *tstate0,
            const uint32_t *tstate1, uint32_t *ostate0, uint32_t *ostate1,
            const uint32_t *salt0, const uint32_t *salt1, uint32_t *output0,
            uint32_t *output1 )
{
   uint32_t istate0[8], istate1[8], ostateb0[8], ostateb1[8];
   uint32_t ibuf0[16], obuf0[16], ibuf1[16], obuf1[16];
   int i, j;

   sha256_ni2way_transform_le( istate0, istate1, salt0, salt1,
                               tstate0, tstate1 );

   memcpy( ibuf0, salt0 + 16, 16 );
   memcpy( ibuf0 + 5, innerpad, 44 );
   memcpy( obuf0 + 8, outerpad, 32 );
   memcpy( ibuf1, salt1 + 16, 16 );
   memcpy( ibuf1 + 5, innerpad, 44 );
   memcpy( obuf1 + 8, outerpad, 32 );

   for ( i = 0; i < 4; i++ )
   {
      memcpy( obuf0, istate0, 32 );
      memcpy( obuf1, istate1, 32 );
      ibuf0[4] = ibuf1[4] = i + 1;

      sha256_ni2way_transform_le( obuf0, obuf1, ibuf0, ibuf1,
                                  obuf0, obuf1 );
      sha256_ni2way_transform_le( ostateb0, ostateb1, obuf0, obuf1,
                                  ostate0, ostate1 );
      
      for ( j = 0; j < 8; j++ )
      {
         output0[ 8*i + j ] = bswap_32( ostateb0[j] );
         output1[ 8*i + j ] = bswap_32( ostateb1[j] );
      }
   }
}

static inline void PBKDF2_SHA256_128_32_SHA_2BUF( uint32_t *tstate0,
                    uint32_t *tstate1, uint32_t *ostate0, uint32_t *ostate1,
                    const uint32_t *salt0, const uint32_t *salt1,
                    uint32_t *output0, uint32_t *output1 )
{
   uint32_t buf0[16], buf1[16];
   int i;

   sha256_ni2way_transform_be( tstate0, tstate1, salt0, salt1,
                               tstate0, tstate1 );   
   sha256_ni2way_transform_be( tstate0, tstate1, salt0+16, salt1+16,
                               tstate0, tstate1 );
   sha256_ni2way_transform_le( tstate0, tstate1, finalblk, finalblk,
                               tstate0, tstate1 );

   memcpy( buf0, tstate0, 32 );
   memcpy( buf0 + 8, outerpad, 32 );
   memcpy( buf1, tstate1, 32 );
   memcpy( buf1 + 8, outerpad, 32 );

   sha256_ni2way_transform_le( ostate0, ostate1, buf0, buf1,
                               ostate0, ostate1 );

   for ( i = 0; i < 8; i++ )
   {
      output0[i] = bswap_32( ostate0[i] );
      output1[i] = bswap_32( ostate1[i] );
   }
}



#endif

#ifdef HAVE_SHA256_4WAY

static const uint32_t keypad_4way[4 * 12] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000280, 0x00000280, 0x00000280, 0x00000280
};
static const uint32_t innerpad_4way[4 * 11] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x000004a0, 0x000004a0, 0x000004a0, 0x000004a0
};
static const uint32_t outerpad_4way[4 * 8] = {
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000300, 0x00000300, 0x00000300, 0x00000300
};

/*
static const uint32_t _ALIGN(16) finalblk_4way[4 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620
};
*/

static inline void sha256_4way_init_state( void *state )
{
   casti_m128i( state, 0 ) = _mm_set1_epi32( 0x6A09E667 );
   casti_m128i( state, 1 ) = _mm_set1_epi32( 0xBB67AE85 );
   casti_m128i( state, 2 ) = _mm_set1_epi32( 0x3C6EF372 );
   casti_m128i( state, 3 ) = _mm_set1_epi32( 0xA54FF53A );
   casti_m128i( state, 4 ) = _mm_set1_epi32( 0x510E527F );
   casti_m128i( state, 5 ) = _mm_set1_epi32( 0x9B05688C );
   casti_m128i( state, 6 ) = _mm_set1_epi32( 0x1F83D9AB );
   casti_m128i( state, 7 ) = _mm_set1_epi32( 0x5BE0CD19 );
}

static inline void HMAC_SHA256_80_init_4way( const uint32_t *key,
                                   uint32_t *tstate, uint32_t *ostate )
{
	uint32_t _ALIGN(16) ihash[4 * 8];
	uint32_t _ALIGN(16) pad[4 * 16];
	int i;

	/* tstate is assumed to contain the midstate of key */
	memcpy( pad, key + 4*16, 4*16 );
	memcpy( pad + 4*4, keypad_4way, 4*48 );

   sha256_4way_transform_le( (__m128i*)ihash, (__m128i*)pad,
                             (const __m128i*)tstate );

   sha256_4way_init_state( tstate );

	for ( i = 0; i < 4*8; i++ )  pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for ( ; i < 4*16; i++ )      pad[i] = 0x5c5c5c5c;

   sha256_4way_transform_le( (__m128i*)ostate, (__m128i*)pad,
                             (const __m128i*)tstate );
   
   for ( i = 0; i < 4*8; i++ )  pad[i] = ihash[i] ^ 0x36363636;
	for ( ; i < 4*16; i++ )      pad[i] = 0x36363636;

   sha256_4way_transform_le( (__m128i*)tstate, (__m128i*)pad,
                             (const __m128i*)tstate );
}

static inline void PBKDF2_SHA256_80_128_4way( const uint32_t *tstate,
          const uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
	uint32_t _ALIGN(16) istate[4 * 8];
	uint32_t _ALIGN(16) ostate2[4 * 8];
	uint32_t _ALIGN(16) ibuf[4 * 16];
	uint32_t _ALIGN(16) obuf[4 * 16];
	int i, j;

   sha256_4way_transform_le( (__m128i*)istate, (__m128i*)salt,
                             (const __m128i*)tstate );
	
	memcpy(ibuf, salt + 4 * 16, 4 * 16);
	memcpy(ibuf + 4 * 5, innerpad_4way, 4 * 44);
	memcpy(obuf + 4 * 8, outerpad_4way, 4 * 32);

	for ( i = 0; i < 4; i++ )
   {
		ibuf[4 * 4 + 0] = i + 1;
		ibuf[4 * 4 + 1] = i + 1;
		ibuf[4 * 4 + 2] = i + 1;
		ibuf[4 * 4 + 3] = i + 1;

      sha256_4way_transform_le( (__m128i*)obuf, (__m128i*)ibuf,
                                (const __m128i*)istate );
      
      sha256_4way_transform_le( (__m128i*)ostate2, (__m128i*)obuf,
                                (const __m128i*)ostate );

      for ( j = 0; j < 4 * 8; j++ )
			output[4 * 8 * i + j] = bswap_32( ostate2[j] );
	}
}

static inline void PBKDF2_SHA256_128_32_4way( uint32_t *tstate,
               uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
   __m128i _ALIGN(64) final[ 8*16 ];
	uint32_t _ALIGN(64) buf[4 * 16];
	int i;
	
   sha256_4way_transform_be( (__m128i*)tstate, (__m128i*)salt,
                       (const __m128i*)tstate );
   sha256_4way_transform_be( (__m128i*)tstate, (__m128i*)( salt + 4*16),
                       (const __m128i*)tstate );

   final[ 0] = _mm_set1_epi32( 0x00000001 );
   final[ 1] = _mm_set1_epi32( 0x80000000 );
   final[ 2] = final[ 3] = final[ 4] = final[ 5] = final[ 6]
             = final[ 7] = final[ 8] = final[ 9] = final[10]
             = final[11] = final[12] = final[13] = final[14]
             = _mm_setzero_si128();
   final[15] = _mm_set1_epi32 ( 0x00000620 );

   sha256_4way_transform_le( (__m128i*)tstate, (__m128i*)final,
                       (const __m128i*)tstate );
   
   memcpy(buf, tstate, 4 * 32);
	memcpy(buf + 4 * 8, outerpad_4way, 4 * 32);

   sha256_4way_transform_le( (__m128i*)ostate, (__m128i*)buf,
                             (const __m128i*)ostate );

   for ( i = 0; i < 4 * 8; i++ )
		output[i] = bswap_32( ostate[i] );
}

#endif /* HAVE_SHA256_4WAY */


#ifdef HAVE_SHA256_8WAY

/*
static const uint32_t _ALIGN(32) finalblk_8way[8 * 16] = {
	0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001, 0x00000001,
	0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000, 0x80000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620, 0x00000620
};
*/

static inline void sha256_8way_init_state( void *state )
{
   casti_m256i( state, 0 ) = _mm256_set1_epi32( 0x6A09E667 );
   casti_m256i( state, 1 ) = _mm256_set1_epi32( 0xBB67AE85 );
   casti_m256i( state, 2 ) = _mm256_set1_epi32( 0x3C6EF372 );
   casti_m256i( state, 3 ) = _mm256_set1_epi32( 0xA54FF53A );
   casti_m256i( state, 4 ) = _mm256_set1_epi32( 0x510E527F );
   casti_m256i( state, 5 ) = _mm256_set1_epi32( 0x9B05688C );
   casti_m256i( state, 6 ) = _mm256_set1_epi32( 0x1F83D9AB );
   casti_m256i( state, 7 ) = _mm256_set1_epi32( 0x5BE0CD19 );
}

static inline void HMAC_SHA256_80_init_8way( const uint32_t *key,
                                      uint32_t *tstate, uint32_t *ostate )
{
	uint32_t _ALIGN(32) ihash[8 * 8];
	uint32_t _ALIGN(32)  pad[8 * 16];
	int i;
	
	memcpy( pad, key + 8*16, 8*16 );
	for ( i = 0; i < 8; i++ )    pad[ 8*4 + i ] = 0x80000000;
	memset( pad + 8*5, 0x00, 8*40 );
	for ( i = 0; i < 8; i++ )    pad[ 8*15 + i ] = 0x00000280;

   sha256_8way_transform_le( (__m256i*)ihash, (__m256i*)pad,
                             (const __m256i*)tstate );

   sha256_8way_init_state( tstate );

   for ( i = 0; i < 8*8; i++ )   pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for ( ; i < 8*16; i++ )       pad[i] = 0x5c5c5c5c;

   sha256_8way_transform_le( (__m256i*)ostate, (__m256i*)pad,
                             (const __m256i*)tstate );

   for ( i = 0; i < 8*8; i++ )   pad[i] = ihash[i] ^ 0x36363636;
	for ( ; i < 8*16; i++ )       pad[i] = 0x36363636;

   sha256_8way_transform_le( (__m256i*)tstate, (__m256i*)pad,
                             (const __m256i*)tstate );
}

static inline void PBKDF2_SHA256_80_128_8way( const uint32_t *tstate,
          const uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
	uint32_t _ALIGN(32) istate[8 * 8];
	uint32_t _ALIGN(32) ostate2[8 * 8];
	uint32_t _ALIGN(32) ibuf[8 * 16];
	uint32_t _ALIGN(32) obuf[8 * 16];
	int i, j;
	
   sha256_8way_transform_le( (__m256i*)istate, (__m256i*)salt,
                             (const __m256i*)tstate );

	memcpy( ibuf, salt + 8*16, 8*16 );
	for ( i = 0; i < 8; i++ )     ibuf[ 8*5 + i ] = 0x80000000;
	memset( ibuf + 8*6, 0x00, 8*36 );
	for ( i = 0; i < 8; i++ )     ibuf[ 8*15 + i ] = 0x000004a0;
	
	for ( i = 0; i < 8; i++ )     obuf[ 8*8 + i ] = 0x80000000;
	memset( obuf + 8*9, 0x00, 8*24 );
	for ( i = 0; i < 8; i++ )     obuf[ 8*15 + i ] = 0x00000300;
	
	for ( i = 0; i < 4; i++ )
   {
		ibuf[8 * 4 + 0] = i + 1;
		ibuf[8 * 4 + 1] = i + 1;
		ibuf[8 * 4 + 2] = i + 1;
		ibuf[8 * 4 + 3] = i + 1;
		ibuf[8 * 4 + 4] = i + 1;
		ibuf[8 * 4 + 5] = i + 1;
		ibuf[8 * 4 + 6] = i + 1;
		ibuf[8 * 4 + 7] = i + 1;

      sha256_8way_transform_le( (__m256i*)obuf, (__m256i*)ibuf,
                                (const __m256i*)istate );

      sha256_8way_transform_le( (__m256i*)ostate2, (__m256i*)obuf,
                                (const __m256i*)ostate );

      for ( j = 0; j < 8*8; j++ )
			output[ 8*8*i + j ] = bswap_32( ostate2[j] );
	}
}

static inline void PBKDF2_SHA256_128_32_8way( uint32_t *tstate,
                uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
   __m256i _ALIGN(128) final[ 8*16 ];
   uint32_t _ALIGN(128) buf[ 8*16 ];
	int i;
	
   sha256_8way_transform_be( (__m256i*)tstate, (__m256i*)salt,
                             (const __m256i*)tstate );
   sha256_8way_transform_be( (__m256i*)tstate, (__m256i*)( salt + 8*16),
                             (const __m256i*)tstate );
   
   final[ 0] = _mm256_set1_epi32( 0x00000001 );
   final[ 1] = _mm256_set1_epi32( 0x80000000 ); 
   final[ 2] = final[ 3] = final[ 4] = final[ 5] = final[ 6]
             = final[ 7] = final[ 8] = final[ 9] = final[10]
             = final[11] = final[12] = final[13] = final[14]
             = _mm256_setzero_si256();
   final[15] = _mm256_set1_epi32 ( 0x00000620 );

   sha256_8way_transform_le( (__m256i*)tstate, final,
                             (const __m256i*)tstate );

	memcpy( buf, tstate, 8*32 );
	for ( i = 0; i < 8; i++ )     buf[ 8*8 + i ] = 0x80000000;
	memset( buf + 8*9, 0x00, 8*24 );
	for ( i = 0; i < 8; i++ )     buf[ 8*15 + i ] = 0x00000300;

   sha256_8way_transform_le( (__m256i*)ostate, (__m256i*)buf,
                             (const __m256i*)ostate );

	for (i = 0; i < 8 * 8; i++)
		output[i] = bswap_32(ostate[i]);
}

#endif /* HAVE_SHA256_8WAY */

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static inline void sha256_16way_init_state( void *state )
{
   casti_m512i( state, 0 ) = _mm512_set1_epi32( 0x6A09E667 );
   casti_m512i( state, 1 ) = _mm512_set1_epi32( 0xBB67AE85 );
   casti_m512i( state, 2 ) = _mm512_set1_epi32( 0x3C6EF372 );
   casti_m512i( state, 3 ) = _mm512_set1_epi32( 0xA54FF53A );
   casti_m512i( state, 4 ) = _mm512_set1_epi32( 0x510E527F );
   casti_m512i( state, 5 ) = _mm512_set1_epi32( 0x9B05688C );
   casti_m512i( state, 6 ) = _mm512_set1_epi32( 0x1F83D9AB );
   casti_m512i( state, 7 ) = _mm512_set1_epi32( 0x5BE0CD19 );
}

static inline void HMAC_SHA256_80_init_16way( const uint32_t *key,
                                     uint32_t *tstate, uint32_t *ostate )
{
   uint32_t _ALIGN(128)   pad[16*16];
   uint32_t _ALIGN(128) ihash[16* 8];
   int i;

   memcpy( pad, key + 16*16, 16*16 ); 
   for ( i = 0; i < 16; i++ )       pad[ 16*4 + i ] = 0x80000000;
   memset( pad + 16*5, 0x00, 16*40 );
   for ( i = 0; i < 16; i++ )       pad[ 16*15 + i ] = 0x00000280;

   sha256_16way_transform_le( (__m512i*)ihash, (__m512i*)pad,
                              (const __m512i*)tstate );

   sha256_16way_init_state( tstate );

   for ( i = 0; i < 16*8; i++ )    pad[i] = ihash[i] ^ 0x5c5c5c5c;
   for ( ; i < 16*16; i++ )        pad[i] = 0x5c5c5c5c;

   sha256_16way_transform_le( (__m512i*)ostate, (__m512i*)pad,
                              (const __m512i*)tstate );

   for ( i = 0; i < 16*8; i++ )   pad[i] = ihash[i] ^ 0x36363636;
   for ( ; i < 16*16; i++ )       pad[i] = 0x36363636;
 
   sha256_16way_transform_le( (__m512i*)tstate, (__m512i*)pad,
                              (const __m512i*)tstate );
}


static inline void PBKDF2_SHA256_80_128_16way( const uint32_t *tstate,
          const uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
   uint32_t _ALIGN(128) ibuf[ 16*16 ];
   uint32_t _ALIGN(128) obuf[ 16*16 ];
   uint32_t _ALIGN(128) istate[ 16*8 ];
   uint32_t _ALIGN(128) ostate2[ 16*8 ];
   int i, j;

   sha256_16way_transform_le( (__m512i*)istate, (__m512i*)salt,
                              (const __m512i*)tstate );

   memcpy( ibuf, salt + 16*16, 16*16 );
   for ( i = 0; i < 16; i++ )      ibuf[ 16*5 + i ] = 0x80000000;
   memset( ibuf + 16*6, 0x00, 16*36 );
   for ( i = 0; i < 16; i++ )      ibuf[ 16*15 + i ] = 0x000004a0;

   for ( i = 0; i < 16; i++ )      obuf[ 16*8 + i ] = 0x80000000;
   memset( obuf + 16*9, 0x00, 16*24 );
   for ( i = 0; i < 16; i++ )      obuf[ 16*15 + i ] = 0x00000300;

   for ( i = 0; i < 4; i++ )
   {
      ibuf[ 16*4 +  0 ] = i + 1;
      ibuf[ 16*4 +  1 ] = i + 1;
      ibuf[ 16*4 +  2 ] = i + 1;
      ibuf[ 16*4 +  3 ] = i + 1;
      ibuf[ 16*4 +  4 ] = i + 1;
      ibuf[ 16*4 +  5 ] = i + 1;
      ibuf[ 16*4 +  6 ] = i + 1;
      ibuf[ 16*4 +  7 ] = i + 1;
      ibuf[ 16*4 +  8 ] = i + 1;
      ibuf[ 16*4 +  9 ] = i + 1;
      ibuf[ 16*4 + 10 ] = i + 1;
      ibuf[ 16*4 + 11 ] = i + 1;
      ibuf[ 16*4 + 12 ] = i + 1;
      ibuf[ 16*4 + 13 ] = i + 1;
      ibuf[ 16*4 + 14 ] = i + 1;
      ibuf[ 16*4 + 15 ] = i + 1;

      sha256_16way_transform_le( (__m512i*)obuf, (__m512i*)ibuf,
                                 (const __m512i*)istate );

      sha256_16way_transform_le( (__m512i*)ostate2, (__m512i*)obuf,
                                 (const __m512i*)ostate );

      for ( j = 0; j < 16*8; j++ )
         output[ 16*8*i + j ] = bswap_32( ostate2[j] );
   }
}

static inline void PBKDF2_SHA256_128_32_16way( uint32_t *tstate,
                 uint32_t *ostate, const uint32_t *salt, uint32_t *output )
{
   __m512i _ALIGN(128) final[ 16*16 ];
   uint32_t _ALIGN(128) buf[ 16*16 ];
   int i;

   sha256_16way_transform_be( (__m512i*)tstate, (__m512i*)salt,
                             (const __m512i*)tstate );
   sha256_16way_transform_be( (__m512i*)tstate, (__m512i*)( salt + 16*16),
                             (const __m512i*)tstate );

   final[ 0] = _mm512_set1_epi32( 0x00000001 );
   final[ 1] = _mm512_set1_epi32( 0x80000000 );
   final[ 2] = final[ 3] = final[ 4] = final[ 5] = final[ 6]
             = final[ 7] = final[ 8] = final[ 9] = final[10]
             = final[11] = final[12] = final[13] = final[14]
             = _mm512_setzero_si512();
   final[15] = _mm512_set1_epi32 ( 0x00000620 );

   sha256_16way_transform_le( (__m512i*)tstate, final,
                             (const __m512i*)tstate );

   memcpy( buf, tstate, 16*32 );
   for ( i = 0; i < 16; i++ )      buf[ 16*8 + i ] = 0x80000000;
   memset( buf + 16*9, 0x00, 16*24 );
   for ( i = 0; i < 16; i++ )      buf[ 16*15 + i ] = 0x00000300;

   sha256_16way_transform_le( (__m512i*)ostate, (__m512i*)buf,
                             (const __m512i*)ostate );

   for ( i = 0; i < 16*8; i++ )
      output[i] = bswap_32( ostate[i] );
}

#endif // AVX512

//#if defined(USE_ASM) && defined(__x86_64__)

#define SCRYPT_MAX_WAYS 12
#define HAVE_SCRYPT_3WAY 1
//int scrypt_best_throughput();
void scrypt_core(uint32_t *X, uint32_t *V, int N);
void scrypt_core_3way(uint32_t *X, uint32_t *V, int N);

//#if defined(USE_AVX2)
#if defined(__AVX2__)
#undef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 24
#define HAVE_SCRYPT_6WAY 1
void scrypt_core_6way(uint32_t *X, uint32_t *V, int N);
#endif

#ifndef SCRYPT_MAX_WAYS
#define SCRYPT_MAX_WAYS 1
//#define scrypt_best_throughput() 1
#endif

#include "scrypt-core-4way.h"

static bool scrypt_N_1_1_256(const uint32_t *input, uint32_t *output,
	uint32_t *midstate, unsigned char *scratchpad, int N, int thr_id )
{
	uint32_t tstate[8], ostate[8];
	uint32_t X[32];
	uint32_t *V = (uint32_t*)scratchpad;
	
	memcpy(tstate, midstate, 32);
	HMAC_SHA256_80_init(input, tstate, ostate);
	PBKDF2_SHA256_80_128(tstate, ostate, input, X);

   scrypt_core_simd128( X, V, N );  // woring
//   scrypt_core_1way( X, V, N );  // working
//   scrypt_core(X, V, N);

	PBKDF2_SHA256_128_32(tstate, ostate, X, output);
   return true;
}

#if defined(__AVX2__)

static int scrypt_N_1_1_256_8way( const uint32_t *input, uint32_t *output,
           uint32_t *midstate, unsigned char *scratchpad, int N, int thrid )
{
   uint32_t _ALIGN(128) tstate[ 8*8 ];
   uint32_t _ALIGN(128) ostate[ 8*8 ];
   uint32_t _ALIGN(128) W[ 8*32 ];
   uint32_t _ALIGN(128) X[ 8*32 ];
   uint32_t *V = (uint32_t*)scratchpad;

   intrlv_8x32( W, input,    input+ 20, input+ 40, input+ 60,
                   input+80, input+100, input+120, input+140, 640 );
   for ( int i = 0; i < 8; i++ )
      casti_m256i( tstate, i ) = _mm256_set1_epi32( midstate[i] );

   HMAC_SHA256_80_init_8way( W, tstate, ostate );
   PBKDF2_SHA256_80_128_8way( tstate, ostate, W, W );

   dintrlv_8x32( X, X+32, X+64, X+96, X+128, X+160, X+192, X+224, W, 1024 );
   
   if ( opt_param_n > 0x4000 )
   {
      scrypt_core_simd128_3buf( X,     V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_3buf( X+ 96, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_2buf( X+192, V, N );
   }
   else
   {
      intrlv_2x128( W,     X,     X+ 32, 1024 );
      intrlv_2x128( W+ 64, X+ 64, X+ 96, 1024 );
      intrlv_2x128( W+128, X+128, X+160, 1024 );
      intrlv_2x128( W+192, X+192, X+224, 1024 );
      scrypt_core_2way_simd128( (__m256i*) W,      (__m256i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_2way_simd128( (__m256i*)(W+ 64), (__m256i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_2way_simd128( (__m256i*)(W+128), (__m256i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_2way_simd128( (__m256i*)(W+192), (__m256i*)V, N );
      dintrlv_2x128( X,     X+ 32, W,     1024 );
      dintrlv_2x128( X+ 64, X+ 96, W+ 64, 1024 );
      dintrlv_2x128( X+128, X+160, W+128, 1024 );
      dintrlv_2x128( X+192, X+224, W+192, 1024 );
   }

      

   // SCRYPT CORE

  // AVX2


   // AVX2   
   // disable de/interleave for testing.
//   scrypt_core_8way( (__m256i*)W , (__m256i*)V, N );


/*
   // AVX2 working
   intrlv_2x128( W,     X,     X+ 32, 1024 );
   intrlv_2x128( W+ 64, X+ 64, X+ 96, 1024 );
   intrlv_2x128( W+128, X+128, X+160, 1024 );
   intrlv_2x128( W+192, X+192, X+224, 1024 );

   // working
//   scrypt_core_2way_simd128_2buf( (__m256i*) W,      (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128_2buf( (__m256i*)(W+128), (__m256i*)V, N );

   // working
   scrypt_core_2way_simd128( (__m256i*) W,      (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128( (__m256i*)(W+ 64), (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128( (__m256i*)(W+128), (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128( (__m256i*)(W+192), (__m256i*)V, N );

   dintrlv_2x128( X,     X+ 32, W,     1024 );
   dintrlv_2x128( X+ 64, X+ 96, W+ 64, 1024 );
   dintrlv_2x128( X+128, X+160, W+128, 1024 );
   dintrlv_2x128( X+192, X+224, W+192, 1024 );
*/

/* 
   // AVX2
   intrlv_2x32( W,     X    , X+ 32, 1024 );
   intrlv_2x32( W+64,  X+ 64, X+ 96, 1024 );
   intrlv_2x32( W+128, X+128, X+160, 1024 );
   intrlv_2x32( W+192, X+192, X+224, 1024 );

   // working
   scrypt_core_simd128_2way_2buf( (uint64_t*)  W,       (uint64_t*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2way_2buf( (uint64_t*)( W+128 ), (uint64_t*)V, N );

//   scrypt_core_simd128_2way( (uint64_t*)  W,       (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+ 64 ), (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+128 ), (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+192 ), (uint64_t*)V, N );
   
   dintrlv_2x32( X,     X+ 32, W,     1024 );
   dintrlv_2x32( X+ 64, X+ 96, W+ 64, 1024 );
   dintrlv_2x32( X+128, X+160, W+128, 1024 );
   dintrlv_2x32( X+192, X+224, W+192, 1024 );
*/   

   // SSE2

/*   
   // SSE2 working
   intrlv_4x32( W,     X,      X+ 32,  X+ 64, X+ 96, 1024 );
   intrlv_4x32( W+128, X+128 , X+160,  X+192, X+224, 1024 );
   scrypt_core_4way( (__m128i*) W,      (__m128i*)V, N ); 
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_4way( (__m128i*)(W+128), (__m128i*)V, N ); 
   dintrlv_4x32( X,     X+ 32,  X+ 64, X+ 96, W,     1024 );
   dintrlv_4x32( X+128, X+160,  X+192, X+224, W+128, 1024 );
*/

/*
   // SSE2
   scrypt_core_simd128( X,     V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 32, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 96, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+128, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+160, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+192, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+224, V, N );
*/
/*
   // SSE2 working
   scrypt_core_simd128_2buf( X, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+128, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+192, V, N );
*/
/**************
   scrypt_core_simd128_3buf( X,     V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_3buf( X+ 96, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+192, V, N );
*************/


   if ( work_restart[thrid].restart ) return 0;

   intrlv_8x32( W, X, X+32, X+64, X+96, X+128, X+160, X+192, X+224, 1024 );

   PBKDF2_SHA256_128_32_8way( tstate, ostate, W, W );

   dintrlv_8x32( output,    output+ 8, output+16, output+24,
                 output+32, output+40, output+48, output+56, W, 256 );

   return 1;
}

#endif  // AVX2

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static int scrypt_N_1_1_256_16way( const uint32_t *input, uint32_t *output,
           uint32_t *midstate, unsigned char *scratchpad, int N, int thrid )
{
   uint32_t _ALIGN(128) tstate[ 16*8 ];
   uint32_t _ALIGN(128) ostate[ 16*8 ];
   uint32_t _ALIGN(128) W[ 16*32 ]; 
   uint32_t _ALIGN(128) X[ 16*32 ];
   uint32_t *V = (uint32_t*)scratchpad;

   intrlv_16x32( W, input,     input+ 20, input+ 40, input+ 60,
                    input+ 80, input+100, input+120, input+140,
                    input+160, input+180, input+200, input+220,
                    input+240, input+260, input+280, input+300, 640 );
   for ( int i = 0; i < 8; i++ )
      casti_m512i( tstate, i ) = _mm512_set1_epi32( midstate[i] );

   HMAC_SHA256_80_init_16way( W, tstate, ostate );
   PBKDF2_SHA256_80_128_16way( tstate, ostate, W, W );

   dintrlv_16x32( X,     X+ 32, X+ 64, X+ 96, X+128, X+160, X+192, X+224,
                  X+256, X+288, X+320, X+352, X+384, X+416, X+448, X+480,
                  W, 1024 );


   if ( opt_param_n > 0x4000 )
   {
      scrypt_core_simd128_3buf( X,     V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_3buf( X+ 96, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_2buf( X+192, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_3buf( X+256, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_3buf( X+352, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_2buf( X+448, V, N );
   }
   else
   {
      intrlv_4x128( W,     X,     X+ 32, X+ 64, X+ 96, 1024 );
      intrlv_4x128( W+128, X+128, X+160, X+192, X+224, 1024 );
      intrlv_4x128( W+256, X+256, X+288, X+320, X+352, 1024 );
      intrlv_4x128( W+384, X+384, X+416, X+448, X+480, 1024 );
      scrypt_core_4way_simd128( (__m512i*) W,      (__m512i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_4way_simd128( (__m512i*)(W+128), (__m512i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_4way_simd128( (__m512i*)(W+256), (__m512i*)V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_4way_simd128( (__m512i*)(W+384), (__m512i*)V, N );
      dintrlv_4x128( X,     X+ 32, X+ 64, X+ 96, W,     1024 );
      dintrlv_4x128( X+128, X+160, X+192, X+224, W+128, 1024 );
      dintrlv_4x128( X+256, X+288, X+320, X+352, W+256, 1024 );
      dintrlv_4x128( X+384, X+416, X+448, X+480, W+384, 1024 );
   }

   // SCRYPT CORE


   // AVX512
/*
   // AVX512 16 way working
   intrlv_16x32( W, X, X+32, X+64, X+96, X+128, X+160, X+192, X+224,
                    X+256, X+256+32, X+256+64, X+256+96, X+256+128,
                    X+256+160, X+256+192, X+256+224, 1024 );

   scrypt_core_16way( (__m512i*)W , (__m512i*)V, N );

   dintrlv_16x32( X, X+32, X+64, X+96, X+128, X+160, X+192, X+224,
                  X+256, X+256+32, X+256+64, X+256+96, X+256+128,
                  X+256+160, X+256+192, X+256+224, W, 1024 );
*/
/*
   // AVX512 working
   intrlv_4x32( W,     X,     X+ 32, X+ 64, X+ 96, 1024 );
   intrlv_4x32( W+128, X+128, X+160, X+192, X+224, 1024 );
   intrlv_4x32( W+256,     X+256,     X+256+ 32, X+256+ 64, X+256+ 96, 1024 );
   intrlv_4x32( W+256+128, X+256+128, X+256+160, X+256+192, X+256+224, 1024 );
   scrypt_core_simd128_4way( (__m128i*)W, (__m128i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_4way( (__m128i*)(W+128), (__m128i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_4way( (__m128i*)(W+256), (__m128i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_4way( (__m128i*)(W+256+128), (__m128i*)V, N );
   dintrlv_4x32( X,     X+ 32, X+ 64, X+ 96, W,     1024 );
   dintrlv_4x32( X+128, X+160, X+192, X+224, W+128, 1024 );
   dintrlv_4x32( X+256,     X+256+ 32, X+256+ 64, X+256+ 96, W+256,     1024 );
   dintrlv_4x32( X+256+128, X+256+160, X+256+192, X+256+224, W+256+128, 1024 );
*/
/*
   // AVX512, working
   intrlv_4x128( W,     X,     X+ 32, X+ 64, X+ 96, 1024 );
   intrlv_4x128( W+128, X+128, X+160, X+192, X+224, 1024 );
   intrlv_4x128( W+256,     X+256,     X+256+ 32, X+256+ 64, X+256+ 96, 1024 );
   intrlv_4x128( W+256+128, X+256+128, X+256+160, X+256+192, X+256+224, 1024 );
   scrypt_core_4way_simd128( (__m512i*)W,      (__m512i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_4way_simd128( (__m512i*)(W+128), (__m512i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_4way_simd128( (__m512i*)(W+256),   (__m512i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_4way_simd128( (__m512i*)(W+256+128), (__m512i*)V, N );
   dintrlv_4x128( X,     X+ 32, X+ 64, X+ 96, W,     1024 );
   dintrlv_4x128( X+128, X+160, X+192, X+224, W+128, 1024 );
   dintrlv_4x128( X+256,     X+256+ 32, X+256+ 64, X+256+ 96, W+256,     1024 );
   dintrlv_4x128( X+256+128, X+256+160, X+256+192, X+256+224, W+256+128, 1024 );
*/


  // AVX2

/*
   // AVX2
   // disable de/interleave for testing.
   scrypt_core_8way( (__m256i*)W , (__m256i*)V, N );
*/

/*
   // AVX2 working
   intrlv_2x128( W,     X,     X+ 32, 1024 );
   intrlv_2x128( W+ 64, X+ 64, X+ 96, 1024 );
   intrlv_2x128( W+128, X+128, X+160, 1024 );
   intrlv_2x128( W+192, X+192, X+224, 1024 );
   intrlv_2x128( W+256,     X+256,     X+256+ 32, 1024 );
   intrlv_2x128( W+256+ 64, X+256+ 64, X+256+ 96, 1024 );
   intrlv_2x128( W+256+128, X+256+128, X+256+160, 1024 );
   intrlv_2x128( W+256+192, X+256+192, X+256+224, 1024 );

   // working
   scrypt_core_2way_simd128_2buf( (__m256i*) W,      (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128_2buf( (__m256i*)(W+128), (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128_2buf( (__m256i*)(W+256),      (__m256i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_2way_simd128_2buf( (__m256i*)(W+256+128), (__m256i*)V, N );

   // working
//   scrypt_core_2way_simd128( (__m256i*) W,      (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+ 64), (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+128), (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+192), (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+256),      (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+256+ 64), (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+256+128), (__m256i*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_2way_simd128( (__m256i*)(W+256+192), (__m256i*)V, N );

   dintrlv_2x128( X,     X+ 32, W,     1024 );
   dintrlv_2x128( X+ 64, X+ 96, W+ 64, 1024 );
   dintrlv_2x128( X+128, X+160, W+128, 1024 );
   dintrlv_2x128( X+192, X+224, W+192, 1024 );
   dintrlv_2x128( X+256,     X+256+ 32, W+256,     1024 );
   dintrlv_2x128( X+256+ 64, X+256+ 96, W+256+ 64, 1024 );
   dintrlv_2x128( X+256+128, X+256+160, W+256+128, 1024 );
   dintrlv_2x128( X+256+192, X+256+224, W+256+192, 1024 );
*/

/*
   // AVX2
   intrlv_2x32( W,     X    , X+ 32, 1024 );
   intrlv_2x32( W+64,  X+ 64, X+ 96, 1024 );
   intrlv_2x32( W+128, X+128, X+160, 1024 );
   intrlv_2x32( W+192, X+192, X+224, 1024 );

   // working
//   scrypt_core_simd128_2way_2buf( (uint64_t*)  W,       (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way_2buf( (uint64_t*)( W+128 ), (uint64_t*)V, N );
//   scrypt_core_simd128_2way_2buf( (uint64_t*)  W,       (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way_2buf( (uint64_t*)( W+128 ), (uint64_t*)V, N );

//   scrypt_core_simd128_2way( (uint64_t*)  W,       (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+ 64 ), (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+128 ), (uint64_t*)V, N );
//   if ( work_restart[thrid].restart ) return 0;
//   scrypt_core_simd128_2way( (uint64_t*)( W+192 ), (uint64_t*)V, N );

   dintrlv_2x32( X,     X+ 32, W,     1024 );
   dintrlv_2x32( X+ 64, X+ 96, W+ 64, 1024 );
   dintrlv_2x32( X+128, X+160, W+128, 1024 );
   dintrlv_2x32( X+192, X+224, W+192, 1024 );
*/

   // SSE2

/*
   // SSE2 working
   intrlv_4x32( W,     X,      X+ 32,  X+ 64, X+ 96, 1024 );
   intrlv_4x32( W+128, X+128 , X+160,  X+192, X+224, 1024 );
   scrypt_core_4way( (__m128i*) W,      (__m128i*)V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_4way( (__m128i*)(W+128), (__m128i*)V, N );
   dintrlv_4x32( X,     X+ 32,  X+ 64, X+ 96, W,     1024 );
   dintrlv_4x32( X+128, X+160,  X+192, X+224, W+128, 1024 );
*/
/*
   // SSE2
   scrypt_core_simd128( X,     V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 32, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+ 96, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+128, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+160, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+192, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+224, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+256, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+288, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+320, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+352, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+384, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+416, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+448, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+480, V, N );
*/
/*
   // SSE2 working
   scrypt_core_simd128_2buf( X, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+128, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+192, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+256, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+320, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+384, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+448, V, N );
*/
/***************
   scrypt_core_simd128_3buf( X,     V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_3buf( X+ 96, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+192, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_3buf( X+256, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_3buf( X+352, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+448, V, N );
********************/
/*
   scrypt_core_3way( X,     V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_3way( X+ 96, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+192, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_3way( X+256, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_3way( X+352, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+448, V, N );
*/


   if ( work_restart[thrid].restart ) return 0;

   intrlv_16x32( W, X,     X+ 32, X+ 64, X+ 96, X+128, X+160, X+192, X+224,
                    X+256, X+288, X+320, X+352, X+384, X+416, X+448, X+480,
                    1024 );

   PBKDF2_SHA256_128_32_16way( tstate, ostate, W, W );

   dintrlv_16x32( output,     output+  8, output+ 16, output+ 24,
                  output+ 32, output+ 40, output+ 48, output+ 56,
                  output+ 64, output+ 72, output+ 80, output+ 88,
                  output+ 96, output+104, output+112, output+120, W, 256 );

   return 1;
}


#endif // AVX512

#if defined(__SHA__)

static int scrypt_N_1_1_256_sha_2buf( const uint32_t *input, uint32_t *output,
           uint32_t *midstate, unsigned char *scratchpad, int N, int thrid )
{
    uint32_t _ALIGN(128) tstate[ 2*8 ];
    uint32_t _ALIGN(128) ostate[ 2*8 ];
    uint32_t _ALIGN(128) W[ 2*32 ];
    uint32_t *V = (uint32_t*)scratchpad;

    memcpy( tstate,    midstate, 32 );
    memcpy( tstate+ 8, midstate, 32 );

    HMAC_SHA256_80_init_SHA_2BUF( input, input+20, tstate, tstate+8,
                                  ostate, ostate+8 );
    PBKDF2_SHA256_80_128_SHA_2BUF( tstate, tstate+8, ostate, ostate+8,
                                   input, input+20,  W, W+32 );

    scrypt_core_simd128_2buf( W, V, N );
    if ( work_restart[thrid].restart ) return 0;

    PBKDF2_SHA256_128_32_SHA_2BUF( tstate, tstate+8, ostate, ostate+8, W, W+32,
                                   output, output+8 );

   return 1;
}

static int scrypt_N_1_1_256_4way_sha( const uint32_t *input, uint32_t *output,
           uint32_t *midstate, unsigned char *scratchpad, int N, int thrid )
{
    uint32_t _ALIGN(128) tstate[4 * 8];
    uint32_t _ALIGN(128) ostate[4 * 8];
    uint32_t _ALIGN(128) W[4 * 32];
    uint32_t *V = (uint32_t*)scratchpad;

    memcpy( tstate,    midstate, 32 );
    memcpy( tstate+ 8, midstate, 32 );
    memcpy( tstate+16, midstate, 32 );
    memcpy( tstate+24, midstate, 32 );
    
    HMAC_SHA256_80_init(  input,     tstate,    ostate    );
    PBKDF2_SHA256_80_128( tstate,    ostate,    input,     W );

    HMAC_SHA256_80_init(  input +20, tstate+ 8, ostate+ 8 );
    PBKDF2_SHA256_80_128( tstate+ 8, ostate+ 8, input +20, W+32 );

    HMAC_SHA256_80_init(  input +40, tstate+16, ostate+16 );
    PBKDF2_SHA256_80_128( tstate+16, ostate+16, input +40, W+64 );

    HMAC_SHA256_80_init(  input +60, tstate+24, ostate+24 );
    PBKDF2_SHA256_80_128( tstate+24, ostate+24, input +60, W+96 );

/*    
   // Working Linear single threaded SIMD
   scrypt_core_simd128( W,    V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( W+32, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( W+64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( W+96, V, N );
*/

   // working, double buffered linear simd
   scrypt_core_simd128_2buf( W, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( W+64, V, N );

/*
   scrypt_core_simd128_3buf( W, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( W+96, V, N );
*/


   if ( work_restart[thrid].restart ) return 0;

   PBKDF2_SHA256_128_32( tstate,    ostate,    W,    output    );

   PBKDF2_SHA256_128_32( tstate+ 8, ostate+ 8, W+32, output+ 8 );

   PBKDF2_SHA256_128_32( tstate+16, ostate+16, W+64, output+16 );

   PBKDF2_SHA256_128_32( tstate+24, ostate+24, W+96, output+24 );

   return 1;
}

#else

#ifdef HAVE_SHA256_4WAY
static int scrypt_N_1_1_256_4way( const uint32_t *input,	uint32_t *output,
           uint32_t *midstate, unsigned char *scratchpad, int N, int thrid )
{
   uint32_t _ALIGN(128) tstate[ 4*8 ];
   uint32_t _ALIGN(128) ostate[ 4*8 ];
   uint32_t _ALIGN(128) W[ 4*32 ];
   uint32_t *V = (uint32_t*)scratchpad;

   intrlv_4x32( W, input, input+20, input+40, input+60, 640 );
   for ( int i = 0; i < 8; i++ )
      casti_m128i( tstate, i ) = _mm_set1_epi32( midstate[i] );

   HMAC_SHA256_80_init_4way(W, tstate, ostate);
   PBKDF2_SHA256_80_128_4way(tstate, ostate, W, W);

   if ( opt_param_n > 0x4000 )
   {
      uint32_t _ALIGN(128) X[ 4*32 ];
      dintrlv_4x32( X, X+32, X+64, X+96, W, 1024 );
      scrypt_core_simd128_2buf( X, V, N );
      if ( work_restart[thrid].restart ) return 0;
      scrypt_core_simd128_2buf( X+64, V, N );
      intrlv_4x32( W, X, X+32, X+64, X+96, 1024 );
   }
   else
      scrypt_core_4way( (__m128i*)W, (__m128i*)V, N );



//   dintrlv_4x32( X, X+32, X+64, X+96, W, 1024 );

////// SCRYPT_CORE   

   
   // working, simple 4 way parallel, best for scrypt
//   scrypt_core_4way( (__m128i*)W, (__m128i*)V, N );

/*   
   // Working Linear single threaded SIMD
   scrypt_core_simd128( X,    V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+32, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+64, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+96, V, N );
*/
/*   
   // working, double buffered linear simd, best for n2
   scrypt_core_simd128_2buf( X, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128_2buf( X+64, V, N );
*/  
/*
   scrypt_core_simd128_3buf( X, V, N );
   if ( work_restart[thrid].restart ) return 0;
   scrypt_core_simd128( X+96, V, N );
*/
   
////////////////////////////////

   if ( work_restart[thrid].restart ) return 0;

//   intrlv_4x32( W, X, X+32, X+64, X+96, 1024 );

   PBKDF2_SHA256_128_32_4way(tstate, ostate, W, W);

   dintrlv_4x32( output, output+8, output+16, output+24, W, 256 );

   return 1;
}
#endif /* HAVE_SHA256_4WAY */

#endif // SHA

extern int scanhash_scrypt( struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t data[SCRYPT_MAX_WAYS * 20], hash[SCRYPT_MAX_WAYS * 8];
   uint32_t midstate[8];
   uint32_t n = pdata[19] - 1;
   int thr_id = mythr->id;  
   int throughput = scrypt_throughput;
   int i;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
	
   for ( i = 0; i < throughput; i++ )
      memcpy( data + i * 20, pdata, 80 );

   sha256_transform_le( midstate, data, sha256_initial_state );

   do {
      bool rc = true;
      for ( i = 0; i < throughput; i++ ) data[ i*20 + 19 ] = ++n;

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
      if ( throughput == 16 )
         rc = scrypt_N_1_1_256_16way( data, hash, midstate, scratchbuf,
                                      opt_param_n, thr_id );
      else
#endif
#if defined(__AVX2__)      
      if ( throughput == 8 )      
         rc = scrypt_N_1_1_256_8way( data, hash, midstate, scratchbuf,
                                     opt_param_n, thr_id );
      else
#endif
      if ( throughput == 4 ) // slower on Ryzen than 8way
#if defined(__SHA__)
         rc = scrypt_N_1_1_256_4way_sha( data, hash, midstate, scratchbuf,
                                         opt_param_n, thr_id );
#else
         rc = scrypt_N_1_1_256_4way( data, hash, midstate, scratchbuf,
                                     opt_param_n, thr_id );
#endif
#if defined(__SHA__)
      else
      if (throughput == 2 )  // slower on Ryzen than 4way_sha & 8way
         rc = scrypt_N_1_1_256_sha_2buf( data, hash, midstate, scratchbuf,
                                         opt_param_n, thr_id );
#endif         
      else  // should never get here
         rc = scrypt_N_1_1_256( data, hash, midstate, scratchbuf,
                                opt_param_n, thr_id );

      // test the hash
      if ( rc )
      for ( i = 0; i < throughput; i++ )
      {
         if ( unlikely( valid_hash( hash + i*8, ptarget ) && !opt_benchmark ) )
         {
//            applog( LOG_INFO, "Thread %d, Lane %d", thr_id,i );
            pdata[19] = data[i * 20 + 19];
            submit_solution( work, hash + i * 8, mythr );
         }

      }


   } while ( likely( ( n < ( max_nonce - throughput ) ) && !(*restart) ) );
	
	*hashes_done = n - pdata[19];
	pdata[19] = n;
	return 0;
}

bool scrypt_miner_thread_init( int thr_id )
{
   scratchbuf = _mm_malloc( scratchbuf_size, 128 );
   if ( scratchbuf )
      return true;
   applog( LOG_ERR, "Thread %u: Scrypt buffer allocation failed", thr_id );
   return false; 
}

bool register_scrypt_algo( algo_gate_t* gate )
{
//#if defined(__SHA__)
//   gate->optimizations = SSE2_OPT | SHA_OPT;
//#else
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
//#endif
   gate->miner_thread_init =(void*)&scrypt_miner_thread_init;
   gate->scanhash         = (void*)&scanhash_scrypt;
   opt_target_factor = 65536.0;
   opt_param_n = opt_param_n ? opt_param_n : 1024;
   applog( LOG_INFO,"Scrypt paramaters: N= %d, R= 1", opt_param_n );

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
   scrypt_throughput = 16;
   if ( opt_param_n > 0x4000 )
      scratchbuf_size = opt_param_n * 3 * 128;  // 3 buf
   else      
      scratchbuf_size = opt_param_n * 4 * 128;  // 4 way

/* SHA is slower than AVX2 on Ryzen
#elif defined(__SHA__)
   scrypt_throughput = 4;
   scratchbuf_size = opt_param_n * 2 * 128;  // 2 buf
*/

#elif defined(__AVX2__)
   scrypt_throughput = 8;   
   if ( opt_param_n > 0x4000 )
      scratchbuf_size = opt_param_n * 3 * 128;  // 3 buf
   else
      scratchbuf_size = opt_param_n * 2 * 128;  // 2 way
#else
   scrypt_throughput = 4;
   if ( opt_param_n > 0x4000 )
   scratchbuf_size = opt_param_n * 2 * 128;  // 2 buf
   else
   scratchbuf_size = opt_param_n * 4 * 128;  // 4 way
#endif

   char t_units[4] = {0};
   char d_units[4] = {0};
   double t_size = (double)scratchbuf_size;
   double d_size = (double)scratchbuf_size * opt_n_threads;

   format_number_si( &t_size, t_units );
   format_number_si( &d_size, d_units );
   
   applog( LOG_INFO,"Throughput %d/thr, Buffer %.0f %siB/thr, Total %.0f %siB\n",
          scrypt_throughput, t_size, t_units, d_size, d_units );

   return true;
};

