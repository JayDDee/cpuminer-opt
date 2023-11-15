/*
 * luffa_for_sse2.c
 * Version 2.0 (Sep 15th 2009)
 *
 * Copyright (C) 2008-2009 Hitachi, Ltd. All rights reserved.
 *
 * Hitachi, Ltd. is the owner of this software and hereby grant
 * the U.S. Government and any interested party the right to use
 * this software for the purposes of the SHA-3 evaluation process,
 * notwithstanding that this software is copyrighted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include "simd-utils.h"
#include "luffa_for_sse2.h"

#define cns(i)  ( ( (v128_t*)CNS_INIT)[i] )

#define ADD_CONSTANT( a, b, c0 ,c1 ) \
    a = v128_xor( a, c0 ); \
    b = v128_xor( b, c1 ); \

#if defined(__AVX512VL__)
//TODO enable for AVX10_512 AVX10_256

#define MULT2( a0, a1 ) \
{ \
  v128_t b = v128_xor( a0, _mm_maskz_shuffle_epi32( 0xb, a1, 0 ) ); \
  a0 = _mm_alignr_epi8( a1, b, 4 ); \
  a1 = _mm_alignr_epi8( b, a1, 4 ); \
}

#elif defined(__SSE4_1__)

#define MULT2( a0, a1 ) \
{ \
  v128_t b = _mm_shuffle_epi32( a1, 0 ); \
  b =  v128_xor( a0, v128_mask32( b, 0x4 ) ); \
  a0 = _mm_alignr_epi8( a1, b, 4 ); \
  a1 = _mm_alignr_epi8( b, a1, 4 ); \
}

#elif defined(__ARM_NEON)

// { a1_0, 0, a1_0, a1_0 }
#define MULT2( a0, a1 ) \
{ \
  v128_t b = v128_xor( a0, v128_and( vdupq_laneq_u32( a1, 0 ), MASK ) ); \
  a0 = v128_alignr32( a1, b, 1 ); \
  a1 = v128_alignr32( b, a1, 1 ); \
}

#else   // assume SSE2

#define MULT2( a0, a1 ) \
{ \
  v128_t b = v128_xor( a0, v128_and( _mm_shuffle_epi32( a1, 0 ), MASK ) ); \
  a0 = v128_or( _mm_srli_si128(  b, 4 ), _mm_slli_si128( a1, 12 ) ); \
  a1 = v128_or( _mm_srli_si128( a1, 4 ), _mm_slli_si128(  b, 12 ) ); \
} 

#endif

#if defined(__AVX512VL__)
//TODO enable for AVX10_512 AVX10_256

#define SUBCRUMB( a0, a1, a2, a3 ) \
{ \
    v128_t t = a0; \
    a0 = v128_xoror( a3, a0, a1 ); \
    a2 = v128_xor( a2, a3 ); \
    a1 = _mm_ternarylogic_epi64( a1, a3, t, 0x87 ); /* a1 xnor (a3 & t) */ \
    a3 = v128_xorand( a2, a3, t ); \
    a2 = v128_xorand( a1, a2, a0 ); \
    a1 = v128_or( a1, a3 ); \
    a3 = v128_xor( a3, a2 ); \
    t  = v128_xor( t, a1 ); \
    a2 = v128_and( a2, a1 ); \
    a1 = v128_xnor( a1, a0 ); \
    a0 = t; \
}

#else

#define SUBCRUMB( a0, a1, a2, a3 ) \
{ \
    v128_t t = a0; \
    a0 = v128_or( a0, a1 ); \
    a2 = v128_xor( a2, a3 ); \
    a1 = v128_not( a1 ); \
    a0 = v128_xor( a0, a3 ); \
    a3 = v128_and( a3, t ); \
    a1 = v128_xor( a1, a3 ); \
    a3 = v128_xor( a3, a2 ); \
    a2 = v128_and( a2, a0 ); \
    a0 = v128_not( a0 ); \
    a2 = v128_xor( a2, a1 ); \
    a1 = v128_or(  a1, a3 ); \
    t  = v128_xor( t , a1 ); \
    a3 = v128_xor( a3, a2 ); \
    a2 = v128_and( a2, a1 ); \
    a1 = v128_xor( a1, a0 ); \
    a0 = t; \
}

#endif

#define MIXWORD( a, b ) \
    b = v128_xor( a, b ); \
    a = v128_xor( b, v128_rol32( a, 2 ) ); \
    b = v128_xor( a, v128_rol32( b, 14 ) ); \
    a = v128_xor( b, v128_rol32( a, 10 ) ); \
    b = v128_rol32( b, 1 );

#define STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, c0, c1 ) \
    SUBCRUMB( x0, x1, x2, x3 ); \
    SUBCRUMB( x5, x6, x7, x4 ); \
    MIXWORD( x0, x4 ); \
    MIXWORD( x1, x5 ); \
    MIXWORD( x2, x6 ); \
    MIXWORD( x3, x7 ); \
    ADD_CONSTANT( x0, x4, c0, c1 );

#define STEP_PART2( a0, a1, t0, t1, c0, c1 ) \
    t0 = v128_shufll32( a1 ); \
    a1 = v128_unpacklo32( t0, a0 ); \
    t0 = v128_unpackhi32( t0, a0 ); \
    t1 = v128_rev64( t0 ); \
    a0 = v128_rev64( a1 ); \
    SUBCRUMB( t1, t0, a0, a1 ); \
    t0 = v128_unpacklo32( t0, t1 ); \
    a1 = v128_unpacklo32( a1, a0 ); \
    a0 = v128_unpackhi64( a1, t0 ); \
    a1 = v128_unpacklo64( a1, t0 ); \
    a1 = v128_shuflr32( a1 ); \
    MIXWORD( a0, a1 ); \
    ADD_CONSTANT( a0, a1, c0, c1 );

#define NMLTOM1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3)\
    s1 = v128_unpackhi32( r3, r2 ); \
    q1 = v128_unpackhi32( p3, p2 ); \
    s3 = v128_unpacklo32( r3, r2 ); \
    q3 = v128_unpacklo32( p3, p2 ); \
    r3 = v128_unpackhi32( r1, r0 ); \
    r1 = v128_unpacklo32( r1, r0 ); \
    p3 = v128_unpackhi32( p1, p0 ); \
    p1 = v128_unpacklo32( p1, p0 ); \
    s0 = v128_unpackhi64( s1, r3 ); \
    q0 = v128_unpackhi64( q1 ,p3 ); \
    s1 = v128_unpacklo64( s1, r3 ); \
    q1 = v128_unpacklo64( q1, p3 ); \
    s2 = v128_unpackhi64( s3, r1 ); \
    q2 = v128_unpackhi64( q3, p1 ); \
    s3 = v128_unpacklo64( s3, r1 ); \
    q3 = v128_unpacklo64( q3, p1 );

#define MIXTON1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3)\
    NMLTOM1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3);

static void rnd512( hashState_luffa *state, v128_t msg1, v128_t msg0 );

static void finalization512( hashState_luffa *state, uint32_t *b );

/* initial values of chaining variables */
static const uint32_t IV[40] __attribute((aligned(16))) = {
    0xdbf78465,0x4eaa6fb4,0x44b051e0,0x6d251e69,
    0xdef610bb,0xee058139,0x90152df4,0x6e292011,
    0xde099fa3,0x70eee9a0,0xd9d2f256,0xc3b44b95,
    0x746cd581,0xcf1ccf0e,0x8fc944b3,0x5d9b0557,
    0xad659c05,0x04016ce5,0x5dba5781,0xf7efc89d,
    0x8b264ae7,0x24aa230a,0x666d1836,0x0306194f,
    0x204b1f67,0xe571f7d7,0x36d79cce,0x858075d5,
    0x7cde72ce,0x14bcb808,0x57e9e923,0x35870c6a,
    0xaffb4363,0xc825b7c7,0x5ec41e22,0x6c68e9be,
    0x03e86cea,0xb07224cc,0x0fc688f1,0xf5df3999
};

/* Round Constants */
static const uint32_t CNS_INIT[128] __attribute((aligned(16))) = {
    0xb213afa5,0xfc20d9d2,0xb6de10ed,0x303994a6,
    0xe028c9bf,0xe25e72c1,0x01685f3d,0xe0337818,
    0xc84ebe95,0x34552e25,0x70f47aae,0xc0e65299,
    0x44756f91,0xe623bb72,0x05a17cf4,0x441ba90d,
    0x4e608a22,0x7ad8818f,0x0707a3d4,0x6cc33a12,
    0x7e8fce32,0x5c58a4a4,0xbd09caca,0x7f34d442,
    0x56d858fe,0x8438764a,0x1c1e8f51,0xdc56983e,
    0x956548be,0x1e38e2e7,0xf4272b28,0x9389217f,
    0x343b138f,0xbb6de032,0x707a3d45,0x1e00108f,
    0xfe191be2,0x78e38b9d,0x144ae5cc,0xe5a8bce6,
    0xd0ec4e3d,0xedb780c8,0xaeb28562,0x7800423d,
    0x3cb226e5,0x27586719,0xfaa7ae2b,0x5274baf4,
    0x2ceb4882,0xd9847356,0xbaca1589,0x8f5b7882,
    0x5944a28e,0x36eda57f,0x2e48f1c1,0x26889ba7,
    0xb3ad2208,0xa2c78434,0x40a46f3e,0x96e1db12,
    0xa1c4c355,0x703aace7,0xb923c704,0x9a226e9d,
    0x00000000,0x00000000,0x00000000,0xf0d2e9e3,
    0x00000000,0x00000000,0x00000000,0x5090d577,
    0x00000000,0x00000000,0x00000000,0xac11d7fa,
    0x00000000,0x00000000,0x00000000,0x2d1925ab,
    0x00000000,0x00000000,0x00000000,0x1bcb66f2,
    0x00000000,0x00000000,0x00000000,0xb46496ac,
    0x00000000,0x00000000,0x00000000,0x6f2d9bc9,
    0x00000000,0x00000000,0x00000000,0xd1925ab0,
    0x00000000,0x00000000,0x00000000,0x78602649,
    0x00000000,0x00000000,0x00000000,0x29131ab6,
    0x00000000,0x00000000,0x00000000,0x8edae952,
    0x00000000,0x00000000,0x00000000,0x0fc053c3,
    0x00000000,0x00000000,0x00000000,0x3b6ba548,
    0x00000000,0x00000000,0x00000000,0x3f014f0c,
    0x00000000,0x00000000,0x00000000,0xedae9520,
    0x00000000,0x00000000,0x00000000,0xfc053c31
};


static v128_t CNS128[32];

#if !defined(__SSE4_1__)
static v128_t MASK;
#endif

int init_luffa(hashState_luffa *state, int hashbitlen)
{
    int i;
    state->hashbitlen = hashbitlen;
#if !defined(__SSE4_1__)
    /* set the lower 32 bits to '1' */
    MASK = v128_set32( 0xffffffff, 0, 0xffffffff, 0xffffffff );
#endif
    /* set the 32-bit round constant values to the 128-bit data field */
    for ( i=0; i<32; i++ )
        CNS128[i] = v128_load( (v128_t*)&CNS_INIT[i*4] );
    for ( i=0; i<10; i++ ) 
    state->chainv[i] = v128_load( (v128_t*)&IV[i*4] );
    memset(state->buffer, 0, sizeof state->buffer );
    return 0;
}

int update_luffa( hashState_luffa *state, const void *data,
                         size_t len )
{
    int i;
    int blocks = (int)len / 32;
    state-> rembytes = (int)len % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, v128_bswap32( casti_v128( data, 1 ) ),
                      v128_bswap32( casti_v128( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    // store in buffer for transform in final for midstate to work
    if ( state->rembytes  )
    {
      // remaining data bytes
      casti_v128( state->buffer, 0 ) = v128_bswap32( cast_v128( data ) );
      // padding of partial block
      casti_v128( state->buffer, 1 ) = v128_set32( 0, 0, 0, 0x80000000 );
    }

    return 0;
}

int final_luffa(hashState_luffa *state, void *hashval) 
{
    // transform pad block
    if ( state->rembytes )
    {
      // not empty, data is in buffer
      rnd512( state, casti_v128( state->buffer, 1 ),
                     casti_v128( state->buffer, 0 ) );
    }
    else
    {
      // empty pad block, constant data
     rnd512( state, v128_zero, v128_set32( 0, 0, 0, 0x80000000 ) );
    }

    finalization512(state, (uint32_t*) hashval);
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32_t*)( hashval+128 ) );
    return 0;
}

int update_and_final_luffa( hashState_luffa *state, void* output,
              const void* data, size_t inlen )
{
// Optimized for integrals of 16 bytes, good for 64 and 80 byte len
    int i;
    int blocks = (int)( inlen / 32 );
    state->rembytes = inlen % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, v128_bswap32( casti_v128( data, 1 ) ),
                      v128_bswap32( casti_v128( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    if ( state->rembytes  )
       // padding of partial block
       rnd512( state, v128_set64( 0, 0x0000000080000000 ),
                      v128_bswap32( cast_v128( data ) ) );
    else
       // empty pad block
       rnd512( state, v128_zero, v128_64( 0x0000000080000000 ) );

    finalization512( state, (uint32_t*) output );
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32_t*)( output+128 ) );

    return 0;
}

int luffa_full( hashState_luffa *state, void* output, int hashbitlen,
              const void* data, size_t inlen )
{
// Optimized for integrals of 16 bytes, good for 64 and 80 byte len
    int i;
    state->hashbitlen = hashbitlen;
#if !defined(__SSE4_1__)
    /* set the lower 32 bits to '1' */
    MASK= v128_set32( 0xffffffff, 0, 0xffffffff, 0xffffffff );
#endif
    /* set the 32-bit round constant values to the 128-bit data field */
    for ( i=0; i<32; i++ )
        CNS128[i] = casti_v128( CNS_INIT, i );
    for ( i=0; i<10; i++ )
       state->chainv[i] = casti_v128( IV, i );
    memset(state->buffer, 0, sizeof state->buffer );

    // update

    int blocks = (int)( inlen / 32 );
    state->rembytes = inlen % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, v128_bswap32( casti_v128( data, 1 ) ),
                      v128_bswap32( casti_v128( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // final

    // 16 byte partial block exists for 80 byte len
    if ( state->rembytes  )
       // padding of partial block
       rnd512( state, v128_set64( 0, 0x0000000080000000 ),
                      v128_bswap32( cast_v128( data ) ) );
    else
       // empty pad block
       rnd512( state, v128_zero, v128_set64( 0, 0x0000000080000000 ) );

    finalization512( state, (uint32_t*) output );
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32_t*)( output+128 ) );

    return 0;
}

/***************************************************/
/* Round function         */
/* state: hash context    */

static void rnd512( hashState_luffa *state, v128_t msg1, v128_t msg0 )
{
    v128u32_t t0, t1;
    v128u32_t *chainv = state->chainv;
    v128u32_t x0, x1, x2, x3, x4, x5, x6, x7; 

    t0 = v128_xor3( chainv[0], chainv[2], chainv[4] );
    t1 = v128_xor3( chainv[1], chainv[3], chainv[5] );
    t0 = v128_xor3( t0, chainv[6], chainv[8] );
    t1 = v128_xor3( t1, chainv[7], chainv[9] );

    MULT2( t0, t1 );

    msg0 = v128_rev32( msg0 );
    msg1 = v128_rev32( msg1 );

    chainv[0] = v128_xor( chainv[0], t0 );
    chainv[1] = v128_xor( chainv[1], t1 );
    chainv[2] = v128_xor( chainv[2], t0 );
    chainv[3] = v128_xor( chainv[3], t1 );
    chainv[4] = v128_xor( chainv[4], t0 );
    chainv[5] = v128_xor( chainv[5], t1 );
    chainv[6] = v128_xor( chainv[6], t0 );
    chainv[7] = v128_xor( chainv[7], t1 );
    chainv[8] = v128_xor( chainv[8], t0 );
    chainv[9] = v128_xor( chainv[9], t1 );

    t0 = chainv[0];
    t1 = chainv[1];

    MULT2( chainv[0], chainv[1]);
    chainv[0] = v128_xor( chainv[0], chainv[2] );
    chainv[1] = v128_xor( chainv[1], chainv[3] );

    MULT2( chainv[2], chainv[3]);
    chainv[2] = v128_xor(chainv[2], chainv[4]);
    chainv[3] = v128_xor(chainv[3], chainv[5]);

    MULT2( chainv[4], chainv[5]);
    chainv[4] = v128_xor(chainv[4], chainv[6]);
    chainv[5] = v128_xor(chainv[5], chainv[7]);

    MULT2( chainv[6], chainv[7]);
    chainv[6] = v128_xor(chainv[6], chainv[8]);
    chainv[7] = v128_xor(chainv[7], chainv[9]);

    MULT2( chainv[8], chainv[9]);
    t0 = chainv[8] = v128_xor( chainv[8], t0 );
    t1 = chainv[9] = v128_xor( chainv[9], t1 );

    MULT2( chainv[8], chainv[9]);
    chainv[8] = v128_xor( chainv[8], chainv[6] );
    chainv[9] = v128_xor( chainv[9], chainv[7] );

    MULT2( chainv[6], chainv[7]);
    chainv[6] = v128_xor( chainv[6], chainv[4] );
    chainv[7] = v128_xor( chainv[7], chainv[5] );

    MULT2( chainv[4], chainv[5]);
    chainv[4] = v128_xor( chainv[4], chainv[2] );
    chainv[5] = v128_xor( chainv[5], chainv[3] );

    MULT2( chainv[2], chainv[3] );
    chainv[2] = v128_xor( chainv[2], chainv[0] );
    chainv[3] = v128_xor( chainv[3], chainv[1] );

    MULT2( chainv[0], chainv[1] );
    chainv[0] = v128_xor( v128_xor( chainv[0], t0 ), msg0 );
    chainv[1] = v128_xor( v128_xor( chainv[1], t1 ), msg1 );

    MULT2( msg0, msg1);
    chainv[2] = v128_xor( chainv[2], msg0 );
    chainv[3] = v128_xor( chainv[3], msg1 );

    MULT2( msg0, msg1);
    chainv[4] = v128_xor( chainv[4], msg0 );
    chainv[5] = v128_xor( chainv[5], msg1 );

    MULT2( msg0, msg1);
    chainv[6] = v128_xor( chainv[6], msg0 );
    chainv[7] = v128_xor( chainv[7], msg1 );

    MULT2( msg0, msg1);
    chainv[8] = v128_xor( chainv[8], msg0 );
    chainv[9] = v128_xor( chainv[9], msg1 );

    MULT2( msg0, msg1);
    chainv[3] = v128_rol32( chainv[3], 1 );    
    chainv[5] = v128_rol32( chainv[5], 2 );
    chainv[7] = v128_rol32( chainv[7], 3 );
    chainv[9] = v128_rol32( chainv[9], 4 );

    NMLTOM1024( chainv[0], chainv[2], chainv[4], chainv[6], x0, x1, x2, x3,
                chainv[1], chainv[3], chainv[5], chainv[7], x4, x5, x6, x7 );

    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns( 0), cns( 1) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns( 2), cns( 3) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns( 4), cns( 5) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns( 6), cns( 7) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns( 8), cns( 9) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns(10), cns(11) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns(12), cns(13) );
    STEP_PART( x0, x1, x2, x3, x4, x5, x6, x7, cns(14), cns(15) );
    
    MIXTON1024( x0, x1, x2, x3, chainv[0], chainv[2], chainv[4], chainv[6],
                x4, x5, x6, x7, chainv[1], chainv[3], chainv[5], chainv[7]);

    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(16), cns(17) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(18), cns(19) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(20), cns(21) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(22), cns(23) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(24), cns(25) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(26), cns(27) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(28), cns(29) );
    STEP_PART2( chainv[8], chainv[9], t0, t1, cns(30), cns(31) );
}


/***************************************************/
/* Finalization function  */
/* state: hash context    */
/* b[8]: hash values      */

static void finalization512( hashState_luffa *state, uint32_t *b )
{
    uint32_t hash[8] __attribute((aligned(64)));
    v128_t* chainv = state->chainv;
    v128_t t[2];
    const v128_t zero = v128_zero;

    /*---- blank round with m=0 ----*/
    rnd512( state, zero, zero );

    t[0] = chainv[0];
    t[1] = chainv[1];
    t[0] = v128_xor(t[0], chainv[2]);
    t[1] = v128_xor(t[1], chainv[3]);
    t[0] = v128_xor(t[0], chainv[4]);
    t[1] = v128_xor(t[1], chainv[5]);
    t[0] = v128_xor(t[0], chainv[6]);
    t[1] = v128_xor(t[1], chainv[7]);
    t[0] = v128_xor(t[0], chainv[8]);
    t[1] = v128_xor(t[1], chainv[9]);

    t[0] = v128_rev32( t[0] );
    t[1] = v128_rev32( t[1] );

    v128_store((v128_t*)&hash[0], t[0]);
    v128_store((v128_t*)&hash[4], t[1]);

    casti_v128( b, 0 ) = v128_bswap32( casti_v128( hash, 0 ) );
    casti_v128( b, 1 ) = v128_bswap32( casti_v128( hash, 1 ) );

    rnd512( state, zero, zero );

    t[0] = chainv[0];
    t[1] = chainv[1];
    t[0] = v128_xor(t[0], chainv[2]);
    t[1] = v128_xor(t[1], chainv[3]);
    t[0] = v128_xor(t[0], chainv[4]);
    t[1] = v128_xor(t[1], chainv[5]);
    t[0] = v128_xor(t[0], chainv[6]);
    t[1] = v128_xor(t[1], chainv[7]);
    t[0] = v128_xor(t[0], chainv[8]);
    t[1] = v128_xor(t[1], chainv[9]);

    t[0] = v128_rev32( t[0] );
    t[1] = v128_rev32( t[1] );

    casti_v128( hash, 0 ) = t[0];
    casti_v128( hash, 1 ) = t[1];

    casti_v128( b, 2 ) = v128_bswap32( casti_v128( hash, 0 ) );
    casti_v128( b, 3 ) = v128_bswap32( casti_v128( hash, 1 ) );
}

/***************************************************/
