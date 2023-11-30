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

#if ( defined(__SSE4_1__) && defined(__AES__) ) || ( defined(__ARM_NEON) && defined(__ARM_FEATURE_AES) )

#include <memory.h>
#include "fugue-aesni.h"

static const v128u64_t _supermix1a	__attribute__ ((aligned (16))) =
   { 0x0202010807020100, 0x0a05000f06010c0b };

static const v128u64_t _supermix1b	__attribute__ ((aligned (16))) =
   { 0x0b0d080703060504, 0x0e0a090c050e0f0a };

static const v128u64_t _supermix1c	__attribute__ ((aligned (16))) =
   { 0x0402060c070d0003, 0x090a060580808080 };

static const v128u64_t _supermix1d	__attribute__ ((aligned (16))) =
   { 0x808080800f0e0d0c, 0x0f0e0d0c80808080 };

static const v128u64_t _supermix2a	__attribute__ ((aligned (16))) =
   { 0x07020d0880808080, 0x0b06010c050e0f0a };

static const v128u64_t _supermix4a	__attribute__ ((aligned (16))) =
   { 0x000f0a050c0b0601, 0x0302020404030e09 };

static const v128u64_t _supermix4b	__attribute__ ((aligned (16))) =
   { 0x07020d08080e0d0d, 0x07070908050e0f0a };

static const v128u64_t _supermix4c	__attribute__ ((aligned (16))) =
   { 0x0706050403020000, 0x0302000007060504 };

static const v128u64_t _supermix7a	__attribute__ ((aligned (16))) =
   { 0x010c0b060d080702, 0x0904030e03000104 };

static const v128u64_t _supermix7b	__attribute__ ((aligned (16))) =
   { 0x8080808080808080, 0x0504070605040f06 };

static const v128u64_t _inv_shift_rows __attribute__ ((aligned (16))) =
   { 0x0b0e0104070a0d00, 0x0306090c0f020508 };

static const v128u64_t _mul2mask __attribute__ ((aligned (16))) =
   { 0x000000001b1b0000, 0x0000000000000000 };

static const v128u64_t _mul4mask __attribute__ ((aligned (16))) =
   { 0x000000002d361b00, 0x0000000000000000 };

static const v128u64_t _lsbmask2 __attribute__ ((aligned (16))) =
   { 0x0303030303030303, 0x0303030303030303 };

static const uint32_t _IV512[] __attribute__ ((aligned (32))) =
 {	0x00000000, 0x00000000,	0x7ea50788, 0x00000000,
	0x75af16e6, 0xdbe4d3c5, 0x27b09aac, 0x00000000,
	0x17f115d9, 0x54cceeb6, 0x0b02e806, 0x00000000,
	0xd1ef924a, 0xc9e2c6aa, 0x9813b2dd, 0x00000000,
	0x3858e6ca, 0x3f207f43, 0xe778ea25, 0x00000000,
	0xd6dd1f95, 0x1dd16eda, 0x67353ee1, 0x00000000
 };

#if defined(__ARM_NEON)

#define mask_1000(v)         v128_put32( v, 0, 3 )

static const v128u32_t MASK_3321 __attribute__ ((aligned (16))) =
   { 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x0f0e0d0c };

static const v128u32_t MASK_3033 __attribute__ ((aligned (16))) =
   { 0x0f0e0d0c, 0x0f0e0d0c, 0x03020100, 0x0f0e0d0c };

static const v128u32_t MASK_3303 __attribute__ ((aligned (16))) =
   { 0x0f0e0d0c, 0x03020100, 0x0f0e0d0c, 0x0f0e0d0c };

static const v128u32_t MASK_0321 __attribute__ ((aligned (16))) =
   { 0x07060504, 0x0b0a0908, 0x0f0e0d0c, 0x03020100 };

#define shuffle_3303(v)      vqtbl1q_u8( v, MASK_3303 )
#define shuffle_0321(v)      vqtbl1q_u8( v, MASK_0321 )

#define CMIX( s1, s2, r1, r2, t1, t2 ) \
   t1 = vqtbl1q_u8( s1, MASK_3321 ); \
   t2 = vqtbl1q_u8( s2, MASK_3033 ); \
   t1 = v128_xor( t1, t2 ); \
   r1 = v128_xor( r1, t1 ); \
   r2 = v128_xor( r2, t1 );

#elif defined(__SSE4_1__)

#define mask_1000(v)         v128_mask32( v, 8 )

#define shuffle_3303(v)      _mm_shuffle_epi32( v, 0xf3 )
#define shuffle_0321(v)      _mm_shuffle_epi32( v, 0x39 )

#define CMIX( s1, s2, r1, r2, t1, t2 ) \
   t1 = s1; \
   t1 = v128_shuffle2_32( t1, s2, _MM_SHUFFLE( 3, 0, 2, 1 ) ); \
   r1 = v128_xor( r1, t1 ); \
   r2 = v128_xor( r2, t1 );

#endif

#define PACK_S0( s0, s1, t1 ) \
 s0 = v128_movlane32( s0, 3, s1, 0 )

#define UNPACK_S0( s0, s1, t1 ) \
   s1 = v128_movlane32( s1, 0, s0, 3 ); \
   s0 = mask_1000( s0 )

#define TIX512(msg, s22, s8, s24, s27, s30, s0, s4, s7, t1, t2, t3)\
	t1 = shuffle_3303( s0 ); \
	s22 = v128_xor(s22, t1);\
	t1 = v128_put32( v128_zero, *(uint32_t*)msg, 0 ); \
	s0 = v128_movlane32( s0, 0, t1, 0 ); \
	t1 = v128_alignr64( t1, v128_zero, 1 ); \
	s8 = v128_xor(s8, t1);\
	t1 = shuffle_3303( s24 ); \
	s0 = v128_xor(s0, t1);\
	t1 = shuffle_3303( s27 ); \
	s4 = v128_xor(s4, t1);\
	t1 = shuffle_3303( s30 ); \
	s7 = v128_xor(s7, t1)

#define SUBSTITUTE( r0, _t2 ) \
	_t2 = v128_shuffle8( r0, _inv_shift_rows ); \
	_t2 = v128_aesenclast_nokey( _t2 )

#define SUPERMIX(t0, t1, t2, t3, t4)\
   t2 = t0;\
   t3 = v128_add8( t0, t0 ); \
   t4 = v128_add8( t3, t3 ); \
   t1 = v128_sr16( t0, 6 ); \
   t1 = v128_and( t1, _lsbmask2 ); \
   t0 = v128_xor( t4, v128_shuffle8( _mul4mask, t1 ) ); \
   t4 = v128_shuffle8( t2, _supermix1b ); \
   t3 = v128_xor( t3, v128_shuffle8( _mul2mask, t1 ) ); \
   t1 = v128_shuffle8( t4, _supermix1c ); \
   t4 = v128_xor( t4, t1 ); \
   t1 = v128_shuffle8( t4, _supermix1d ); \
   t4 = v128_xor( t4, t1 ); \
   t1 = v128_shuffle8( t2, _supermix1a ); \
   t2 = v128_xor3( t2, t3, t0 ); \
   t2 = v128_shuffle8( t2, _supermix7a ); \
   t4 = v128_xor3( t4, t1, t2 ); \
   t2 = v128_shuffle8( t2, _supermix7b ); \
   t3 = v128_shuffle8( t3, _supermix2a ); \
   t1 = v128_shuffle8( t0, _supermix4a ); \
   t0 = v128_shuffle8( t0, _supermix4b ); \
   t4 = v128_xor3( t4, t2, t1 ); \
   t0 = v128_xor( t0, t3 ); \
   t4 = v128_xor3( t4, t0, v128_shuffle8( t0, _supermix4c ) );

#define SUBROUND512_4(r1a, r1b, r1c, r1d, r2a, r2b, r2c, r2d, r3a, r3b, r3c, r3d, r4a, r4b, r4c, r4d)\
	CMIX(r1a, r1b, r1c, r1d, _t0, _t1);\
	PACK_S0(r1c, r1a, _t0);\
	SUBSTITUTE( r1c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r1c);\
	_t0 = shuffle_0321( r1c ); \
	r2c = v128_xor(r2c, _t0);\
   _t0 = mask_1000( _t0 ); \
	r2d = v128_xor(r2d, _t0);\
	UNPACK_S0(r1c, r1a, _t3);\
	SUBSTITUTE(r2c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r2c);\
	_t0 = shuffle_0321( r2c ); \
	r3c = v128_xor(r3c, _t0);\
   _t0 = mask_1000( _t0 ); \
	r3d = v128_xor(r3d, _t0);\
	UNPACK_S0(r2c, r2a, _t3);\
	SUBSTITUTE( r3c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r3c);\
	_t0 = shuffle_0321( r3c ); \
	r4c = v128_xor(r4c, _t0);\
   _t0 = mask_1000( _t0 ); \
	r4d = v128_xor(r4d, _t0);\
	UNPACK_S0(r3c, r3a, _t3);\
	SUBSTITUTE( r4c, _t2 );\
	SUPERMIX(_t2, _t3, _t0, _t1, r4c);\
	UNPACK_S0(r4c, r4a, _t3)

#define LOADCOLUMN(x, s, a)\
	block[0] = col[(base + a + 0) % s];\
	block[1] = col[(base + a + 1) % s];\
	block[2] = col[(base + a + 2) % s];\
	block[3] = col[(base + a + 3) % s];\
	x = v128_load( (v128_t*)block )

#define STORECOLUMN(x, s)\
	v128_store((v128_t*)block, x );\
	col[(base + 0) % s] = block[0];\
	col[(base + 1) % s] = block[1];\
	col[(base + 2) % s] = block[2];\
	col[(base + 3) % s] = block[3]

void Compress512( hashState_fugue *ctx, const unsigned char *pmsg,
                  unsigned int uBlockCount )
{
   v128_t _t0, _t1, _t2, _t3;

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

void Final512( hashState_fugue *ctx, uint8_t *hashval )
{
   unsigned int block[4] __attribute__ ((aligned (32)));
   unsigned int col[36] __attribute__ ((aligned (16)));
	unsigned int i, base;
	v128_t r0, _t0, _t1, _t2, _t3;

	for( i = 0; i < 12; i++ )
	{
		v128_store( (v128_t*)block, ctx->state[i] );

		col[3 * i + 0] = block[0];
		col[3 * i + 1] = block[1];
		col[3 * i + 2] = block[2];
	}

	base = ( 36 - (12 * ctx->base) ) % 36;

	for( i = 0; i < 32; i++ )
	{
		// ROR3
		base = (base + 33) % 36;

		// CMIX
		col[ (base +  0) % 36 ] ^= col[ (base + 4) % 36 ];
		col[ (base +  1) % 36 ] ^= col[ (base + 5) % 36 ];
		col[ (base +  2) % 36 ] ^= col[ (base + 6) % 36 ];
		col[ (base + 18) % 36 ] ^= col[ (base + 4) % 36 ];
		col[ (base + 19) % 36 ] ^= col[ (base + 5) % 36 ];
		col[ (base + 20) % 36 ] ^= col[ (base + 6) % 36 ];

		// SMIX
		LOADCOLUMN( r0, 36, 0 );
		SUBSTITUTE( r0, _t2 );
		SUPERMIX( _t2, _t3, _t0, _t1, r0 );
		STORECOLUMN( r0, 36 );
	}

	for( i = 0; i < 13; i++ )
	{
		// S4 += S0; S9 += S0; S18 += S0; S27 += S0;
		col[ (base +  4) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base +  9) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 18) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 27) % 36 ] ^= col[ (base + 0) % 36 ];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN( r0, 36, 0 );
		SUBSTITUTE( r0, _t2 );
		SUPERMIX( _t2, _t3, _t0, _t1, r0 );
		STORECOLUMN( r0, 36 );

		// S4 += S0; S10 += S0; S18 += S0; S27 += S0;
		col[ (base +  4) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 10) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 18) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 27) % 36 ] ^= col[ (base + 0) % 36 ];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN( r0, 36, 0 );
		SUBSTITUTE( r0, _t2 );
		SUPERMIX( _t2, _t3, _t0, _t1, r0 );
		STORECOLUMN( r0, 36 );

		// S4 += S0; S10 += S0; S19 += S0; S27 += S0;
		col[ (base +  4) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 10) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 19) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 27) % 36 ] ^= col[ (base + 0) % 36 ];

		// ROR9
		base = (base + 27) % 36;

		// SMIX
		LOADCOLUMN( r0, 36, 0 );
		SUBSTITUTE( r0, _t2 );
		SUPERMIX( _t2, _t3, _t0, _t1, r0 );
		STORECOLUMN( r0, 36 );

		// S4 += S0; S10 += S0; S19 += S0; S28 += S0;
		col[ (base +  4) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 10) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 19) % 36 ] ^= col[ (base + 0) % 36 ];
		col[ (base + 28) % 36 ] ^= col[ (base + 0) % 36 ];

		// ROR8
		base = (base + 28) % 36;

		// SMIX
		LOADCOLUMN( r0, 36, 0 );
		SUBSTITUTE( r0, _t2 );
		SUPERMIX( _t2, _t3, _t0, _t1, r0 );
		STORECOLUMN( r0, 36 );
	}

	// S4 += S0; S9 += S0; S18 += S0; S27 += S0;
	col[ (base +  4) % 36 ] ^= col[ (base + 0) % 36 ];
	col[ (base +  9) % 36 ] ^= col[ (base + 0) % 36 ];
	col[ (base + 18) % 36 ] ^= col[ (base + 0) % 36 ];
	col[ (base + 27) % 36 ] ^= col[ (base + 0) % 36 ];

	// Transform to the standard basis and store output; S1 || S2 || S3 || S4
	LOADCOLUMN( r0, 36, 1 );
	v128_store( (v128_t*)hashval, r0 );

	// Transform to the standard basis and store output; S9 || S10 || S11 || S12
	LOADCOLUMN( r0, 36, 9 );
	v128_store( (v128_t*)hashval + 1, r0 );

	// Transform to the standard basis and store output; S18 || S19 || S20 || S21
	LOADCOLUMN( r0, 36, 18 );
	v128_store( (v128_t*)hashval + 2, r0 );

	// Transform to the standard basis and store output; S27 || S28 || S29 || S30
	LOADCOLUMN( r0, 36, 27 );
	v128_store( (v128_t*)hashval + 3, r0 );
}

int fugue512_Init( hashState_fugue *ctx, int nHashSize )
{
	int i;
	ctx->processed_bits = 0;
	ctx->uBufferBytes = 0;
	ctx->base = 0;


	ctx->uHashSize = 512;
	ctx->uBlockLength = 4;

	for(i = 0; i < 6; i++)
		ctx->state[i] = v128_zero;

	ctx->state[6]  = casti_v128( _IV512, 0 );
	ctx->state[7]  = casti_v128( _IV512, 1 );
	ctx->state[8]  = casti_v128( _IV512, 2 );
	ctx->state[9]  = casti_v128( _IV512, 3 );
	ctx->state[10] = casti_v128( _IV512, 4 );
	ctx->state[11] = casti_v128( _IV512, 5 );

	return 0;
}

int fugue512_Update( hashState_fugue *state, const void *data,
                            uint64_t databitlen )
{
	unsigned int uByteLength, uBlockCount, uRemainingBytes;

	uByteLength = (unsigned int)(databitlen / 8);

	if(state->uBufferBytes + uByteLength >= state->uBlockLength)
	{
		if(state->uBufferBytes != 0)
		{
			// Fill the buffer
			memcpy( state->buffer + state->uBufferBytes, (void*)data,
                 state->uBlockLength - state->uBufferBytes );

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

	return 0;
}

int fugue512_Final( hashState_fugue *state, void *hashval )
{
	unsigned int i;
	uint8_t lengthbuf[8] __attribute__((aligned(64)));

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

	return 0;
}


int fugue512_full( hashState_fugue *hs, void *hashval, const void *data,
                   uint64_t databitlen )
{
	fugue512_Init( hs, 512 );
	fugue512_Update( hs, data, databitlen*8 );
	fugue512_Final( hs, hashval );
	return 0;
}

#endif  // AES
