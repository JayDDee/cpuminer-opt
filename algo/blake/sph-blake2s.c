/**
 * BLAKE2 reference source code package - reference C implementations
 *
 * Written in 2012 by Samuel Neves <sneves@dei.uc.pt>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "simd-utils.h"
#include "compat/sph_types.h"
#include "compat.h"
#include "sph-blake2s.h"

static const uint32_t blake2s_IV[8] =
{
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const uint8_t blake2s_sigma[10][16] =
{
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 } ,
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 } ,
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 } ,
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 } ,
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 } ,
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 } ,
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 } ,
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 } ,
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 } ,
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0 } ,
};

static inline int blake2s_set_lastnode( blake2s_state *S )
{
	S->f[1] = ~0U;
	return 0;
}

static inline int blake2s_clear_lastnode( blake2s_state *S )
{
	S->f[1] = 0U;
	return 0;
}

/* Some helper functions, not necessarily useful */
static inline int blake2s_set_lastblock( blake2s_state *S )
{
	if( S->last_node ) blake2s_set_lastnode( S );

	S->f[0] = ~0U;
	return 0;
}

static inline int blake2s_clear_lastblock( blake2s_state *S )
{
	if( S->last_node ) blake2s_clear_lastnode( S );

	S->f[0] = 0U;
	return 0;
}

static inline int blake2s_increment_counter( blake2s_state *S, const uint32_t inc )
{
	S->t[0] += inc;
	S->t[1] += ( S->t[0] < inc );
	return 0;
}

// Parameter-related functions
static inline int blake2s_param_set_digest_length( blake2s_param *P, const uint8_t digest_length )
{
	P->digest_length = digest_length;
	return 0;
}

static inline int blake2s_param_set_fanout( blake2s_param *P, const uint8_t fanout )
{
	P->fanout = fanout;
	return 0;
}

static inline int blake2s_param_set_max_depth( blake2s_param *P, const uint8_t depth )
{
	P->depth = depth;
	return 0;
}

static inline int blake2s_param_set_leaf_length( blake2s_param *P, const uint32_t leaf_length )
{
	store32( &P->leaf_length, leaf_length );
	return 0;
}

static inline int blake2s_param_set_node_offset( blake2s_param *P, const uint64_t node_offset )
{
	store48( P->node_offset, node_offset );
	return 0;
}

static inline int blake2s_param_set_node_depth( blake2s_param *P, const uint8_t node_depth )
{
	P->node_depth = node_depth;
	return 0;
}

static inline int blake2s_param_set_inner_length( blake2s_param *P, const uint8_t inner_length )
{
	P->inner_length = inner_length;
	return 0;
}

static inline int blake2s_param_set_salt( blake2s_param *P, const uint8_t salt[8] )
{
	memcpy( P->salt, salt, 8 );
	return 0;
}

static inline int blake2s_param_set_personal( blake2s_param *P, const uint8_t personal[8] )
{
	memcpy( P->personal, personal, 8 );
	return 0;
}

static inline int blake2s_init0( blake2s_state *S )
{
	memset( S, 0, sizeof( blake2s_state ) );

	for( int i = 0; i < 8; ++i ) S->h[i] = blake2s_IV[i];

	return 0;
}

/* init2 xors IV with input parameter block */
int blake2s_init_param( blake2s_state *S, const blake2s_param *P )
{
	blake2s_init0( S );
	uint32_t *p = ( uint32_t * )( P );

	/* IV XOR ParamBlock */
	for( size_t i = 0; i < 8; ++i )
		S->h[i] ^= load32( &p[i] );

	return 0;
}


// Sequential blake2s initialization
int blake2s_init( blake2s_state *S, const uint8_t outlen )
{
	blake2s_param P[1];

	/* Move interval verification here? */
	if ( ( !outlen ) || ( outlen > 32 ) ) return -1;

	P->digest_length = outlen;
	P->key_length    = 0;
	P->fanout        = 1;
	P->depth         = 1;
	store32( &P->leaf_length, 0 );
	store48( &P->node_offset, 0 );
	P->node_depth    = 0;
	P->inner_length  = 0;
	// memset(P->reserved, 0, sizeof(P->reserved) );
	memset( P->salt,     0, sizeof( P->salt ) );
	memset( P->personal, 0, sizeof( P->personal ) );
	return blake2s_init_param( S, P );
}

int blake2s_init_key( blake2s_state *S, const uint8_t outlen, const void *key, const uint8_t keylen )
{
	blake2s_param P[1];

	if ( ( !outlen ) || ( outlen > 32 ) ) return -1;

	if ( !key || !keylen || keylen > 8 ) return -1;

	P->digest_length = outlen;
	P->key_length    = keylen;
	P->fanout        = 1;
	P->depth         = 1;
	store32( &P->leaf_length, 0 );
	store48( &P->node_offset, 0 );
	P->node_depth    = 0;
	P->inner_length  = 0;
	// memset(P->reserved, 0, sizeof(P->reserved) );
	memset( P->salt,     0, sizeof( P->salt ) );
	memset( P->personal, 0, sizeof( P->personal ) );

	if( blake2s_init_param( S, P ) < 0 ) return -1;

	{
		uint8_t block[64];
		memset( block, 0, 64 );
		memcpy( block, key, keylen );
		blake2s_update( S, block, 64 );
		secure_zero_memory( block, 64 ); /* Burn the key from stack */
	}
	return 0;
}

int blake2s_compress( blake2s_state *S, const uint8_t block[64] )
{
	uint32_t _ALIGN(32) m[16];
	uint32_t _ALIGN(32) v[16];

	for( size_t i = 0; i < 16; ++i )
		m[i] = load32( block + i * sizeof( m[i] ) );

	for( size_t i = 0; i < 8; ++i )
		v[i] = S->h[i];

	v[ 8] = blake2s_IV[0];
	v[ 9] = blake2s_IV[1];
	v[10] = blake2s_IV[2];
	v[11] = blake2s_IV[3];
	v[12] = S->t[0] ^ blake2s_IV[4];
	v[13] = S->t[1] ^ blake2s_IV[5];
	v[14] = S->f[0] ^ blake2s_IV[6];
	v[15] = S->f[1] ^ blake2s_IV[7];

#if defined(__SSE2__)

   v128_t *V = (v128_t*)v;

#define BLAKE2S_ROUND( r ) \
   V[0] = v128_add32( V[0], v128_add32( V[1], v128_set32( \
                  m[blake2s_sigma[r][ 6]], m[blake2s_sigma[r][ 4]], \
                  m[blake2s_sigma[r][ 2]], m[blake2s_sigma[r][ 0]] ) ) ); \
   V[3] = v128_ror32( v128_xor( V[3], V[0] ), 16 ); \
   V[2] = v128_add32( V[2], V[3] ); \
   V[1] = v128_ror32( v128_xor( V[1], V[2] ), 12 ); \
   V[0] = v128_add32( V[0], v128_add32( V[1], v128_set32( \
                   m[blake2s_sigma[r][ 7]], m[blake2s_sigma[r][ 5]], \
                   m[blake2s_sigma[r][ 3]], m[blake2s_sigma[r][ 1]] ) ) ); \
   V[3] = v128_ror32( v128_xor( V[3], V[0] ), 8 ); \
   V[2] = v128_add32( V[2], V[3] ); \
   V[1] = v128_ror32( v128_xor( V[1], V[2] ), 7 ); \
   V[0] = v128_shufll32( V[0] ); \
   V[3] = v128_swap64( V[3] ); \
   V[2] = v128_shuflr32( V[2] ); \
   V[0] = v128_add32( V[0], v128_add32( V[1], v128_set32( \
                    m[blake2s_sigma[r][12]], m[blake2s_sigma[r][10]], \
                    m[blake2s_sigma[r][ 8]], m[blake2s_sigma[r][14]] ) ) ); \
   V[3] = v128_ror32( v128_xor( V[3], V[0] ), 16 ); \
   V[2] = v128_add32( V[2], V[3] ); \
   V[1] = v128_ror32( v128_xor( V[1], V[2] ), 12 ); \
   V[0] = v128_add32( V[0], v128_add32( V[1], v128_set32( \
                    m[blake2s_sigma[r][13]], m[blake2s_sigma[r][11]], \
                    m[blake2s_sigma[r][ 9]], m[blake2s_sigma[r][15]] ) ) ); \
   V[3] = v128_ror32( v128_xor( V[3], V[0] ), 8 ); \
   V[2] = v128_add32( V[2], V[3] ); \
   V[1] = v128_ror32( v128_xor( V[1], V[2] ), 7 ); \
   V[0] = v128_shuflr32( V[0] ); \
   V[3] = v128_swap64( V[3] ); \
   V[2] = v128_shufll32( V[2] )

   BLAKE2S_ROUND(0);
   BLAKE2S_ROUND(1);
   BLAKE2S_ROUND(2);
   BLAKE2S_ROUND(3);
   BLAKE2S_ROUND(4);
   BLAKE2S_ROUND(5);
   BLAKE2S_ROUND(6);
   BLAKE2S_ROUND(7);
   BLAKE2S_ROUND(8);
   BLAKE2S_ROUND(9);
   
#undef BLAKE2S_ROUND

#else

#define G(r,i,a,b,c,d) \
	do { \
		a = a + b + m[blake2s_sigma[r][2*i+0]]; \
		d = SPH_ROTR32(d ^ a, 16); \
		c = c + d; \
		b = SPH_ROTR32(b ^ c, 12); \
		a = a + b + m[blake2s_sigma[r][2*i+1]]; \
		d = SPH_ROTR32(d ^ a, 8); \
		c = c + d; \
		b = SPH_ROTR32(b ^ c, 7); \
	} while(0)

#define ROUND(r)  \
	do { \
		G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
		G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
		G(r,2,v[ 2],v[ 6],v[10],v[14]); \
		G(r,3,v[ 3],v[ 7],v[11],v[15]); \
		G(r,4,v[ 0],v[ 5],v[10],v[15]); \
		G(r,5,v[ 1],v[ 6],v[11],v[12]); \
		G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
		G(r,7,v[ 3],v[ 4],v[ 9],v[14]); \
	} while(0)

   ROUND( 0 );
	ROUND( 1 );
	ROUND( 2 );
	ROUND( 3 );
	ROUND( 4 );
	ROUND( 5 );
	ROUND( 6 );
	ROUND( 7 );
	ROUND( 8 );
	ROUND( 9 );

#endif

	for( size_t i = 0; i < 8; ++i )
		S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
	return 0;
}


int blake2s_update( blake2s_state *S, const uint8_t *in, uint64_t inlen )
{
	while( inlen > 0 )
	{
		size_t left = S->buflen;
		size_t fill = 2 * 64 - left;

		if( inlen > fill )
		{
			memcpy( S->buf + left, in, fill ); // Fill buffer
			S->buflen += fill;
			blake2s_increment_counter( S, 64 );
			blake2s_compress( S, S->buf ); // Compress
			memcpy( S->buf, S->buf + 64, 64 ); // Shift buffer left
			S->buflen -= 64;
			in += fill;
			inlen -= fill;
		}
		else // inlen <= fill
		{
			memcpy(S->buf + left, in, (size_t) inlen);
			S->buflen += (size_t) inlen; // Be lazy, do not compress
			in += inlen;
			inlen -= inlen;
		}
	}

	return 0;
}

int blake2s_final( blake2s_state *S, uint8_t *out, uint8_t outlen )
{
	uint8_t buffer[32];

	if( S->buflen > 64 )
	{
		blake2s_increment_counter( S, 64 );
		blake2s_compress( S, S->buf );
		S->buflen -= 64;
		memcpy( S->buf, S->buf + 64, S->buflen );
	}

	blake2s_increment_counter( S, ( uint32_t )S->buflen );
	blake2s_set_lastblock( S );
	memset( S->buf + S->buflen, 0, 2 * 64 - S->buflen ); /* Padding */
	blake2s_compress( S, S->buf );

	for( int i = 0; i < 8; ++i ) /* Output full hash to temp buffer */
		store32( buffer + sizeof( S->h[i] ) * i, S->h[i] );

	memcpy( out, buffer, outlen );
	return 0;
}

int blake2s( uint8_t *out, const void *in, const void *key, const uint8_t outlen, const uint64_t inlen, uint8_t keylen )
{
	blake2s_state S;

	/* Verify parameters */
	if ( NULL == in ) return -1;

	if ( NULL == out ) return -1;

	if ( NULL == key ) keylen = 0; /* Fail here instead if keylen != 0 and key == NULL? */

	if( keylen > 0 )
	{
		if( blake2s_init_key( &S, outlen, key, keylen ) < 0 ) return -1;
	}
	else
	{
		if( blake2s_init( &S, outlen ) < 0 ) return -1;
	}

	blake2s_update( &S, ( uint8_t * )in, inlen );
	blake2s_final( &S, out, outlen );
	return 0;
}

#if defined(BLAKE2S_SELFTEST)
#include <string.h>
#include "blake2-kat.h" /* test data not included */
int main( int argc, char **argv )
{
	uint8_t key[8];
	uint8_t buf[KAT_LENGTH];

	for( size_t i = 0; i < 8; ++i )
		key[i] = ( uint8_t )i;

	for( size_t i = 0; i < KAT_LENGTH; ++i )
		buf[i] = ( uint8_t )i;

	for( size_t i = 0; i < KAT_LENGTH; ++i )
	{
		uint8_t hash[32];
		blake2s( hash, buf, key, 32, i, );

		if( 0 != memcmp( hash, blake2s_keyed_kat[i], 32 ) )
		{
			puts( "error" );
			return -1;
		}
	}

	puts( "ok" );
	return 0;
}
#endif
