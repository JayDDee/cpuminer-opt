/*
 * file        : fugue_vperm.c
 * version     : 1.0.208
 * date        : 14.12.2010
 * 
 * - vperm and aes_ni implementations of hash function Fugue
 * - implements NIST hash api
 * - assumes that message lenght is multiple of 8-bits
 * - _FUGUE_VPERM_ must be defined if compiling with ../main.c
 * - default version is vperm, define AES_NI for aes_ni version
 * 
 * Cagdas Calik
 * ccalik@metu.edu.tr
 * Institute of Applied Mathematics, Middle East Technical University, Turkey.
 *
 */

#if defined(__AES__)

#include <x86intrin.h>

#include <memory.h>
#include "fugue-aesni.h"


MYALIGN const unsigned long long _supermix1a[]	= {0x0202010807020100, 0x0a05000f06010c0b};
MYALIGN const unsigned long long _supermix1b[]	= {0x0b0d080703060504, 0x0e0a090c050e0f0a};
MYALIGN const unsigned long long _supermix1c[]	= {0x0402060c070d0003, 0x090a060580808080};
MYALIGN const unsigned long long _supermix1d[]	= {0x808080800f0e0d0c, 0x0f0e0d0c80808080};
MYALIGN const unsigned long long _supermix2a[]	= {0x07020d0880808080, 0x0b06010c050e0f0a};
MYALIGN const unsigned long long _supermix4a[]	= {0x000f0a050c0b0601, 0x0302020404030e09};
MYALIGN const unsigned long long _supermix4b[]	= {0x07020d08080e0d0d, 0x07070908050e0f0a};
MYALIGN const unsigned long long _supermix4c[]	= {0x0706050403020000, 0x0302000007060504};
MYALIGN const unsigned long long _supermix7a[]	= {0x010c0b060d080702, 0x0904030e03000104};
MYALIGN const unsigned long long _supermix7b[]	= {0x8080808080808080, 0x0504070605040f06};
MYALIGN const unsigned long long _k_n[] = {0x4E4E4E4E4E4E4E4E, 0x1B1B1B1B0E0E0E0E};
MYALIGN const unsigned char _shift_one_mask[]   = {7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14, 3, 0, 1, 2};
MYALIGN const unsigned char _shift_four_mask[]  = {13, 14, 15, 12, 1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8};
MYALIGN const unsigned char _shift_seven_mask[] = {10, 11, 8, 9, 14, 15, 12, 13, 2, 3, 0, 1, 6, 7, 4, 5};
MYALIGN const unsigned char _aes_shift_rows[]   = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};
MYALIGN const unsigned int _inv_shift_rows[] = {0x070a0d00, 0x0b0e0104, 0x0f020508, 0x0306090c};
MYALIGN const unsigned int _mul2mask[] = {0x1b1b0000, 0x00000000, 0x00000000, 0x00000000};
MYALIGN const unsigned int _mul4mask[] = {0x2d361b00, 0x00000000, 0x00000000, 0x00000000};
MYALIGN const unsigned int _lsbmask2[] = {0x03030303, 0x03030303, 0x03030303, 0x03030303};


MYALIGN const unsigned int _IV512[] = {		
	0x00000000, 0x00000000,	0x7ea50788, 0x00000000,
	0x75af16e6, 0xdbe4d3c5, 0x27b09aac, 0x00000000,
	0x17f115d9, 0x54cceeb6, 0x0b02e806, 0x00000000,
	0xd1ef924a, 0xc9e2c6aa, 0x9813b2dd, 0x00000000,
	0x3858e6ca, 0x3f207f43, 0xe778ea25, 0x00000000,
	0xd6dd1f95, 0x1dd16eda, 0x67353ee1, 0x00000000};

#if defined(__SSE4_1__)

#define PACK_S0(s0, s1, t1)\
   s0 = _mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(s0), _mm_castsi128_ps(s1), 0x30))

#define UNPACK_S0(s0, s1, t1)\
   s1 = _mm_castps_si128(_mm_insert_ps(_mm_castsi128_ps(s1), _mm_castsi128_ps(s0), 0xc0));\
   s0 = mm128_mask_32( s0, 8 )

#define CMIX(s1, s2, r1, r2, t1, t2)\
   t1 = s1;\
   t1 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(t1), _mm_castsi128_ps(s2), _MM_SHUFFLE(3, 0, 2, 1)));\
   r1 = _mm_xor_si128(r1, t1);\
   r2 = _mm_xor_si128(r2, t1);

#else   // SSE2

#define PACK_S0(s0, s1, t1)\
   t1 = _mm_shuffle_epi32(s1, _MM_SHUFFLE(0, 3, 3, 3));\
   s0 = _mm_xor_si128(s0, t1);

#define UNPACK_S0(s0, s1, t1)\
   t1 = _mm_shuffle_epi32(s0, _MM_SHUFFLE(3, 3, 3, 3));\
   s1 = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(s1), _mm_castsi128_ps(t1)));\
   s0 = mm128_mask_32( s0, 8 )

#define CMIX(s1, s2, r1, r2, t1, t2)\
   t1 = _mm_shuffle_epi32(s1, 0xf9);\
   t2 = _mm_shuffle_epi32(s2, 0xcf);\
   t1 = _mm_xor_si128(t1, t2);\
   r1 = _mm_xor_si128(r1, t1);\
   r2 = _mm_xor_si128(r2, t1)

#endif

#define TIX256(msg, s10, s8, s24, s0, t1, t2, t3)\
	t1 = _mm_shuffle_epi32(s0, _MM_SHUFFLE(3, 3, 0, 3));\
	s10 = _mm_xor_si128(s10, t1);\
	t1 = _mm_castps_si128(_mm_load_ss((float*)msg));\
	s0 = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(s0), _mm_castsi128_ps(t1)));\
	t1 = _mm_slli_si128(t1, 8);\
	s8 = _mm_xor_si128(s8, t1);\
	t1 = _mm_shuffle_epi32(s24, _MM_SHUFFLE(3, 3, 0, 3));\
	s0 = _mm_xor_si128(s0, t1)


#define TIX384(msg, s16, s8, s27, s30, s0, s4, t1, t2, t3)\
	t1 = _mm_shuffle_epi32(s0, _MM_SHUFFLE(3, 3, 0, 3));\
	s16 = _mm_xor_si128(s16, t1);\
	t1 = _mm_castps_si128(_mm_load_ss((float*)msg));\
	s0 = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(s0), _mm_castsi128_ps(t1)));\
	t1 = _mm_slli_si128(t1, 8);\
	s8 = _mm_xor_si128(s8, t1);\
	t1 = _mm_shuffle_epi32(s27, _MM_SHUFFLE(3, 3, 0, 3));\
	s0 = _mm_xor_si128(s0, t1);\
	t1 = _mm_shuffle_epi32(s30, _MM_SHUFFLE(3, 3, 0, 3));\
	s4 = _mm_xor_si128(s4, t1)

#define TIX512(msg, s22, s8, s24, s27, s30, s0, s4, s7, t1, t2, t3)\
	t1 = _mm_shuffle_epi32(s0, _MM_SHUFFLE(3, 3, 0, 3));\
	s22 = _mm_xor_si128(s22, t1);\
	t1 = _mm_castps_si128(_mm_load_ss((float*)msg));\
	s0 = _mm_castps_si128(_mm_move_ss(_mm_castsi128_ps(s0), _mm_castsi128_ps(t1)));\
	t1 = _mm_slli_si128(t1, 8);\
	s8 = _mm_xor_si128(s8, t1);\
	t1 = _mm_shuffle_epi32(s24, _MM_SHUFFLE(3, 3, 0, 3));\
	s0 = _mm_xor_si128(s0, t1);\
	t1 = _mm_shuffle_epi32(s27, _MM_SHUFFLE(3, 3, 0, 3));\
	s4 = _mm_xor_si128(s4, t1);\
	t1 = _mm_shuffle_epi32(s30, _MM_SHUFFLE(3, 3, 0, 3));\
	s7 = _mm_xor_si128(s7, t1)

#define PRESUPERMIX(t0, t1, t2, t3, t4)\
   t2 = t0;\
   t3 = _mm_add_epi8(t0, t0);\
   t4 = _mm_add_epi8(t3, t3);\
   t1 = _mm_srli_epi16(t0, 6);\
   t1 = _mm_and_si128(t1, M128(_lsbmask2));\
   t3 = _mm_xor_si128(t3, _mm_shuffle_epi8(M128(_mul2mask), t1));\
   t0  = _mm_xor_si128(t4, _mm_shuffle_epi8(M128(_mul4mask), t1))

/*
#define PRESUPERMIX(x, t1, s1, s2, t2)\
	s1 = x;\
	s2 = _mm_add_epi8(x, x);\
	t2 = _mm_add_epi8(s2, s2);\
	t1 = _mm_srli_epi16(x, 6);\
	t1 = _mm_and_si128(t1, M128(_lsbmask2));\
	s2 = _mm_xor_si128(s2, _mm_shuffle_epi8(M128(_mul2mask), t1));\
	x  = _mm_xor_si128(t2, _mm_shuffle_epi8(M128(_mul4mask), t1))
*/

#define SUBSTITUTE(r0, _t2 )\
	_t2 = _mm_shuffle_epi8(r0, M128(_inv_shift_rows));\
	_t2 = _mm_aesenclast_si128( _t2, m128_zero )

#define SUPERMIX(t0, t1, t2, t3, t4)\
   t2 = t0;\
   t3 = _mm_add_epi8(t0, t0);\
   t4 = _mm_add_epi8(t3, t3);\
   t1 = _mm_srli_epi16(t0, 6);\
   t1 = _mm_and_si128(t1, M128(_lsbmask2));\
   t0 = _mm_xor_si128(t4, _mm_shuffle_epi8(M128(_mul4mask), t1)); \
   t4 = _mm_shuffle_epi8(t2, M128(_supermix1b));\
   t3 = _mm_xor_si128(t3, _mm_shuffle_epi8(M128(_mul2mask), t1));\
   t1 = _mm_shuffle_epi8(t4, M128(_supermix1c));\
   t4 = _mm_xor_si128(t4, t1);\
   t1 = _mm_shuffle_epi8(t4, M128(_supermix1d));\
   t4 = _mm_xor_si128(t4, t1);\
   t1 = _mm_shuffle_epi8(t2, M128(_supermix1a));\
   t2 = mm128_xor3(t2, t3, t0 );\
   t2 = _mm_shuffle_epi8(t2, M128(_supermix7a));\
   t4 = mm128_xor3( t4, t1, t2 ); \
   t2 = _mm_shuffle_epi8(t2, M128(_supermix7b));\
   t3 = _mm_shuffle_epi8(t3, M128(_supermix2a));\
   t1 = _mm_shuffle_epi8(t0, M128(_supermix4a));\
   t0 = _mm_shuffle_epi8(t0, M128(_supermix4b));\
   t4 = mm128_xor3( t4, t2, t1 ); \
   t0 = _mm_xor_si128(t0, t3);\
   t4 = mm128_xor3(t4, t0, _mm_shuffle_epi8(t0, M128(_supermix4c)));

/*
#define SUPERMIX(t0, t1, t2, t3, t4)\
	PRESUPERMIX(t0, t1, t2, t3, t4);\
	POSTSUPERMIX(t0, t1, t2, t3, t4)
*/

#define POSTSUPERMIX(t0, t1, t2, t3, t4)\
	t1 = _mm_shuffle_epi8(t2, M128(_supermix1b));\
	t4 = t1;\
	t1 = _mm_shuffle_epi8(t1, M128(_supermix1c));\
	t4 = _mm_xor_si128(t4, t1);\
	t1 = _mm_shuffle_epi8(t4, M128(_supermix1d));\
	t4 = _mm_xor_si128(t4, t1);\
	t1 = _mm_shuffle_epi8(t2, M128(_supermix1a));\
	t4 = _mm_xor_si128(t4, t1);\
	t2 = mm128_xor3(t2, t3, t0 );\
	t2 = _mm_shuffle_epi8(t2, M128(_supermix7a));\
	t4 = _mm_xor_si128(t4, t2);\
	t2 = _mm_shuffle_epi8(t2, M128(_supermix7b));\
	t4 = _mm_xor_si128(t4, t2);\
	t3 = _mm_shuffle_epi8(t3, M128(_supermix2a));\
	t1 = _mm_shuffle_epi8(t0, M128(_supermix4a));\
	t4 = _mm_xor_si128(t4, t1);\
	t0 = _mm_shuffle_epi8(t0, M128(_supermix4b));\
	t0 = _mm_xor_si128(t0, t3);\
	t4 = _mm_xor_si128(t4, t0);\
	t0 = _mm_shuffle_epi8(t0, M128(_supermix4c));\
	t4 = _mm_xor_si128(t4, t0)

#define SUBROUND512_3(r1a, r1b, r1c, r1d, r2a, r2b, r2c, r2d, r3a, r3b, r3c, r3d)\
	CMIX(r1a, r1b, r1c, r1d, _t0, _t1);\
	PACK_S0(r1c, r1a, _t0);\
	SUBSTITUTE(r1c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r1c);\
	_t0 = _mm_shuffle_epi32(r1c, 0x39);\
	r2c = _mm_xor_si128(r2c, _t0);\
   _t0 = mm128_mask_32( _t0, 8 ); \
	r2d = _mm_xor_si128(r2d, _t0);\
	UNPACK_S0(r1c, r1a, _t3);\
	SUBSTITUTE(r2c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r2c);\
	_t0 = _mm_shuffle_epi32(r2c, 0x39);\
	r3c = _mm_xor_si128(r3c, _t0);\
   _t0 = mm128_mask_32( _t0, 8 ); \
	r3d = _mm_xor_si128(r3d, _t0);\
	UNPACK_S0(r2c, r2a, _t3);\
	SUBSTITUTE(r3c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r3c);\
	UNPACK_S0(r3c, r3a, _t3)

#define SUBROUND512_4(r1a, r1b, r1c, r1d, r2a, r2b, r2c, r2d, r3a, r3b, r3c, r3d, r4a, r4b, r4c, r4d)\
	CMIX(r1a, r1b, r1c, r1d, _t0, _t1);\
	PACK_S0(r1c, r1a, _t0);\
	SUBSTITUTE( r1c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r1c);\
	_t0 = _mm_shuffle_epi32(r1c, 0x39);\
	r2c = _mm_xor_si128(r2c, _t0);\
   _t0 = mm128_mask_32( _t0, 8 ); \
	r2d = _mm_xor_si128(r2d, _t0);\
	UNPACK_S0(r1c, r1a, _t3);\
	SUBSTITUTE(r2c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r2c);\
	_t0 = _mm_shuffle_epi32(r2c, 0x39);\
	r3c = _mm_xor_si128(r3c, _t0);\
   _t0 = mm128_mask_32( _t0, 8 ); \
	r3d = _mm_xor_si128(r3d, _t0);\
	UNPACK_S0(r2c, r2a, _t3);\
	SUBSTITUTE( r3c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r3c);\
	_t0 = _mm_shuffle_epi32(r3c, 0x39);\
	r4c = _mm_xor_si128(r4c, _t0);\
   _t0 = mm128_mask_32( _t0, 8 ); \
	r4d = _mm_xor_si128(r4d, _t0);\
	UNPACK_S0(r3c, r3a, _t3);\
	SUBSTITUTE( r4c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r4c);\
	UNPACK_S0(r4c, r4a, _t3)

#define LOADCOLUMN(x, s, a)\
	block[0] = col[(base + a + 0) % s];\
	block[1] = col[(base + a + 1) % s];\
	block[2] = col[(base + a + 2) % s];\
	block[3] = col[(base + a + 3) % s];\
	x = _mm_load_si128((__m128i*)block)

#define STORECOLUMN(x, s)\
	_mm_store_si128((__m128i*)block, x);\
	col[(base + 0) % s] = block[0];\
	col[(base + 1) % s] = block[1];\
	col[(base + 2) % s] = block[2];\
	col[(base + 3) % s] = block[3]

void Compress512(hashState_fugue *ctx, const unsigned char *pmsg, unsigned int uBlockCount)
{
   __m128i _t0, _t1, _t2, _t3;

   switch(ctx->base)
   {
      case 1:
         TIX512( pmsg, ctx->state[3], ctx->state[10], ctx->state[4],
                       ctx->state[5], ctx->state[ 6], ctx->state[8],
                       ctx->state[9], ctx->state[10], _t0, _t1, _t2 );

	      SUBROUND512_4( ctx->state[8], ctx->state[9], ctx->state[7],
                        ctx->state[1], ctx->state[7], ctx->state[8],
		                  ctx->state[6], ctx->state[0], ctx->state[6],
		                  ctx->state[7], ctx->state[5], ctx->state[11],
		                  ctx->state[5], ctx->state[6], ctx->state[4],
		       	         ctx->state[10] );
         ctx->base++;
         pmsg += 4;
         uBlockCount--;
      if( uBlockCount == 0 ) break;

      case 2:
         TIX512( pmsg, ctx->state[11], ctx->state[6], ctx->state[0],
                       ctx->state[ 1], ctx->state[2], ctx->state[4],
                       ctx->state[ 5], ctx->state[6], _t0, _t1, _t2);

         SUBROUND512_4( ctx->state[4], ctx->state[5], ctx->state[3],
                        ctx->state[9], ctx->state[3], ctx->state[4],
                        ctx->state[2], ctx->state[8], ctx->state[2],
                        ctx->state[3], ctx->state[1], ctx->state[7],
                        ctx->state[1], ctx->state[2], ctx->state[0],
                        ctx->state[6]);

         ctx->base = 0;
         pmsg += 4;
         uBlockCount--;
      break;
   }

   while( uBlockCount > 0 )
   {
      TIX512( pmsg, ctx->state[ 7],ctx->state[2],ctx->state[8],ctx->state[9],
                    ctx->state[10],ctx->state[0],ctx->state[1],ctx->state[2],
                    _t0, _t1, _t2 );
      SUBROUND512_4( ctx->state[0], ctx->state[1],ctx->state[11],ctx->state[5],
                     ctx->state[11],ctx->state[0],ctx->state[10],ctx->state[4],
                     ctx->state[10],ctx->state[11],ctx->state[9],ctx->state[3],
		               ctx->state[9],ctx->state[10],ctx->state[8],ctx->state[2] );

      ctx->base++;
      pmsg += 4;
      uBlockCount--;
      if( uBlockCount == 0 ) break;

      TIX512( pmsg, ctx->state[3],ctx->state[10],ctx->state[4],ctx->state[5],
                    ctx->state[6],ctx->state[8], ctx->state[9],ctx->state[10],
                    _t0, _t1, _t2 );

      SUBROUND512_4( ctx->state[8],ctx->state[9],ctx->state[7],ctx->state[1],
                     ctx->state[7],ctx->state[8],ctx->state[6],ctx->state[0],
		               ctx->state[6],ctx->state[7],ctx->state[5],ctx->state[11],
		               ctx->state[5],ctx->state[6],ctx->state[4],ctx->state[10] );

      ctx->base++;
      pmsg += 4;
      uBlockCount--;
      if( uBlockCount == 0 ) break;

      TIX512( pmsg, ctx->state[11],ctx->state[6],ctx->state[0],ctx->state[1],
                    ctx->state[2], ctx->state[4],ctx->state[5],ctx->state[6],
                    _t0, _t1, _t2);
      SUBROUND512_4( ctx->state[4],ctx->state[5],ctx->state[3],ctx->state[9],
                     ctx->state[3],ctx->state[4],ctx->state[2],ctx->state[8],
                     ctx->state[2],ctx->state[3],ctx->state[1],ctx->state[7],
		               ctx->state[1],ctx->state[2],ctx->state[0],ctx->state[6]);

      ctx->base = 0;
      pmsg += 4;
      uBlockCount--;
   }

}

void Final512(hashState_fugue *ctx, BitSequence *hashval)
{
   unsigned int block[4] __attribute__ ((aligned (32)));
   unsigned int col[36] __attribute__ ((aligned (16)));
	unsigned int i, base;
	__m128i r0, _t0, _t1, _t2, _t3;

	for(i = 0; i < 12; i++)
	{
		_mm_store_si128((__m128i*)block, ctx->state[i]);

		col[3 * i + 0] = block[0];
		col[3 * i + 1] = block[1];
		col[3 * i + 2] = block[2];
	}

	base = (36 - (12 * ctx->base)) % 36;

	for(i = 0; i < 32; i++)
	{
		// ROR3
		base = (base + 33) % 36;

		// CMIX
		col[(base +  0) % 36] ^= col[(base + 4) % 36];
		col[(base +  1) % 36] ^= col[(base + 5) % 36];
		col[(base +  2) % 36] ^= col[(base + 6) % 36];
		col[(base +  18) % 36] ^= col[(base + 4) % 36];
		col[(base +  19) % 36] ^= col[(base + 5) % 36];
		col[(base +  20) % 36] ^= col[(base + 6) % 36];

		// SMIX
		LOADCOLUMN(r0, 36, 0);
		SUBSTITUTE(r0, _t2);
		SUPERMIX(_t2, _t3, _t0, _t1, r0);
		STORECOLUMN(r0, 36);
	}

	for(i = 0; i < 13; i++)
	{
		// S4 += S0; S9 += S0; S18 += S0; S27 += S0;
		col[(base +  4) % 36] ^= col[(base + 0) % 36];
		col[(base +  9) % 36] ^= col[(base + 0) % 36];
		col[(base + 18) % 36] ^= col[(base + 0) % 36];
		col[(base + 27) % 36] ^= col[(base + 0) % 36];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN(r0, 36, 0);
		SUBSTITUTE(r0, _t2);
		SUPERMIX(_t2, _t3, _t0, _t1, r0);
		STORECOLUMN(r0, 36);

		// S4 += S0; S10 += S0; S18 += S0; S27 += S0;
		col[(base +  4) % 36] ^= col[(base + 0) % 36];
		col[(base + 10) % 36] ^= col[(base + 0) % 36];
		col[(base + 18) % 36] ^= col[(base + 0) % 36];
		col[(base + 27) % 36] ^= col[(base + 0) % 36];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN(r0, 36, 0);
		SUBSTITUTE(r0, _t2);
		SUPERMIX(_t2, _t3, _t0, _t1, r0);
		STORECOLUMN(r0, 36);

		// S4 += S0; S10 += S0; S19 += S0; S27 += S0;
		col[(base +  4) % 36] ^= col[(base + 0) % 36];
		col[(base + 10) % 36] ^= col[(base + 0) % 36];
		col[(base + 19) % 36] ^= col[(base + 0) % 36];
		col[(base + 27) % 36] ^= col[(base + 0) % 36];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN(r0, 36, 0);
		SUBSTITUTE(r0, _t2);
		SUPERMIX(_t2, _t3, _t0, _t1, r0);
		STORECOLUMN(r0, 36);

		// S4 += S0; S10 += S0; S19 += S0; S28 += S0;
		col[(base +  4) % 36] ^= col[(base + 0) % 36];
		col[(base + 10) % 36] ^= col[(base + 0) % 36];
		col[(base + 19) % 36] ^= col[(base + 0) % 36];
		col[(base + 28) % 36] ^= col[(base + 0) % 36];

		// ROR8
		base = (base + 28) % 36;

		// SMIX
		LOADCOLUMN(r0, 36, 0);
		SUBSTITUTE(r0, _t2);
		SUPERMIX(_t2, _t3, _t0, _t1, r0);
		STORECOLUMN(r0, 36);
	}

	// S4 += S0; S9 += S0; S18 += S0; S27 += S0;
	col[(base +  4) % 36] ^= col[(base + 0) % 36];
	col[(base +  9) % 36] ^= col[(base + 0) % 36];
	col[(base + 18) % 36] ^= col[(base + 0) % 36];
	col[(base + 27) % 36] ^= col[(base + 0) % 36];

	// Transform to the standard basis and store output; S1 || S2 || S3 || S4
	LOADCOLUMN(r0, 36, 1);
	_mm_store_si128((__m128i*)hashval, r0);

	// Transform to the standard basis and store output; S9 || S10 || S11 || S12
	LOADCOLUMN(r0, 36, 9);
	_mm_store_si128((__m128i*)hashval + 1, r0);

	// Transform to the standard basis and store output; S18 || S19 || S20 || S21
	LOADCOLUMN(r0, 36, 18);
	_mm_store_si128((__m128i*)hashval + 2, r0);

	// Transform to the standard basis and store output; S27 || S28 || S29 || S30
	LOADCOLUMN(r0, 36, 27);
	_mm_store_si128((__m128i*)hashval + 3, r0);
}

HashReturn fugue512_Init(hashState_fugue *ctx, int nHashSize)
{
	int i;
	ctx->processed_bits = 0;
	ctx->uBufferBytes = 0;
	ctx->base = 0;


	ctx->uHashSize = 512;
	ctx->uBlockLength = 4;

	for(i = 0; i < 6; i++)
		ctx->state[i] = m128_zero;

	ctx->state[6]  = _mm_load_si128((__m128i*)_IV512 + 0);
	ctx->state[7]  = _mm_load_si128((__m128i*)_IV512 + 1);
	ctx->state[8]  = _mm_load_si128((__m128i*)_IV512 + 2);
	ctx->state[9]  = _mm_load_si128((__m128i*)_IV512 + 3);
	ctx->state[10] = _mm_load_si128((__m128i*)_IV512 + 4);
	ctx->state[11] = _mm_load_si128((__m128i*)_IV512 + 5);

	return SUCCESS;
}


HashReturn fugue512_Update(hashState_fugue *state, const void *data, DataLength databitlen)
{
	unsigned int uByteLength, uBlockCount, uRemainingBytes;

	uByteLength = (unsigned int)(databitlen / 8);

	if(state->uBufferBytes + uByteLength >= state->uBlockLength)
	{
		if(state->uBufferBytes != 0)
		{
			// Fill the buffer
			memcpy(state->buffer + state->uBufferBytes, (void*)data, state->uBlockLength - state->uBufferBytes);

			// Process the buffer
			Compress512(state, state->buffer, 1);

			state->processed_bits += state->uBlockLength * 8;
			data += state->uBlockLength - state->uBufferBytes;
			uByteLength -= state->uBlockLength - state->uBufferBytes;
		}

		// buffer now does not contain any unprocessed bytes

		uBlockCount = uByteLength / state->uBlockLength;
		uRemainingBytes = uByteLength % state->uBlockLength;

		if(uBlockCount > 0)
		{
			Compress512(state, data, uBlockCount);

			state->processed_bits += uBlockCount * state->uBlockLength * 8;
			data += uBlockCount * state->uBlockLength;
		}

		if(uRemainingBytes > 0)
		{
			memcpy(state->buffer, (void*)data, uRemainingBytes);
		}

		state->uBufferBytes = uRemainingBytes;
	}
	else
	{
		memcpy(state->buffer + state->uBufferBytes, (void*)data, uByteLength);
		state->uBufferBytes += uByteLength;
	}

	return SUCCESS;
}

HashReturn fugue512_Final(hashState_fugue *state, void *hashval)
{
	unsigned int i;
	BitSequence lengthbuf[8] __attribute__((aligned(64)));

	// Update message bit count
	state->processed_bits += state->uBufferBytes * 8;

	// Pad the remaining buffer bytes with zero
	if(state->uBufferBytes != 0)
	{
	   if ( state->uBufferBytes != state->uBlockLength)
		memset(state->buffer + state->uBufferBytes, 0, state->uBlockLength - state->uBufferBytes);

	   Compress512(state, state->buffer, 1);
	}

	// Last two blocks are message length in bits
	for(i = 0; i < 8; i++)
           lengthbuf[i] = ((state->processed_bits) >> (8 * (7 - i))) & 0xff;

	// Process the last two blocks
	Compress512(state, lengthbuf, 2);

	// Finalization
	Final512(state, hashval);

	return SUCCESS;
}


HashReturn fugue512_full(hashState_fugue *hs, void *hashval, const void *data, DataLength databitlen)
{
	fugue512_Init(hs, 512);
	fugue512_Update(hs, data, databitlen*8);
	fugue512_Final(hs, hashval);
	return SUCCESS;
}

#endif  // AES
