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
#include <emmintrin.h>
#include "simd-utils.h"
#include "luffa_for_sse2.h"

#define MULT2( a0, a1 ) do \
{ \
  __m128i b =  _mm_xor_si128( a0, _mm_shuffle_epi32( _mm_and_si128(a1,MASK), 16 ) ); \
  a0 = _mm_or_si128( _mm_srli_si128(b,4), _mm_slli_si128(a1,12) ); \
  a1 = _mm_or_si128( _mm_srli_si128(a1,4), _mm_slli_si128(b,12) );  \
} while(0)

/*
static inline __m256i mult2_avx2( a )
{ 
   __m128 a0, a0, b;
   a0 = mm128_extractlo_256( a );
   a1 = mm128_extracthi_256( a );
   b =  _mm_xor_si128( a0, _mm_shuffle_epi32( _mm_and_si128(a1,MASK), 16 ) );
   a0 = _mm_or_si128( _mm_srli_si128(b,4), _mm_slli_si128(a1,12) );
   a1 = _mm_or_si128( _mm_srli_si128(a1,4), _mm_slli_si128(b,12) );
   return mm256_concat_128( a1, a0 );
}
*/

#define STEP_PART(x,c,t)\
    SUBCRUMB(*x,*(x+1),*(x+2),*(x+3),*t);\
    SUBCRUMB(*(x+5),*(x+6),*(x+7),*(x+4),*t);\
    MIXWORD(*x,*(x+4),*t,*(t+1));\
    MIXWORD(*(x+1),*(x+5),*t,*(t+1));\
    MIXWORD(*(x+2),*(x+6),*t,*(t+1));\
    MIXWORD(*(x+3),*(x+7),*t,*(t+1));\
    ADD_CONSTANT(*x, *(x+4), *c, *(c+1));

#define STEP_PART2(a0,a1,t0,t1,c0,c1,tmp0,tmp1)\
    a1 = _mm_shuffle_epi32(a1,147);\
    t0 = _mm_load_si128(&a1);\
    a1 = _mm_unpacklo_epi32(a1,a0);\
    t0 = _mm_unpackhi_epi32(t0,a0);\
    t1 = _mm_shuffle_epi32(t0,78);\
    a0 = _mm_shuffle_epi32(a1,78);\
    SUBCRUMB(t1,t0,a0,a1,tmp0);\
    t0 = _mm_unpacklo_epi32(t0,t1);\
    a1 = _mm_unpacklo_epi32(a1,a0);\
    a0 = _mm_load_si128(&a1);\
    a0 = _mm_unpackhi_epi64(a0,t0);\
    a1 = _mm_unpacklo_epi64(a1,t0);\
    a1 = _mm_shuffle_epi32(a1,57);\
    MIXWORD(a0,a1,tmp0,tmp1);\
    ADD_CONSTANT(a0,a1,c0,c1);

#define SUBCRUMB(a0,a1,a2,a3,t)\
    t  = _mm_load_si128(&a0);\
    a0 = _mm_or_si128(a0,a1);\
    a2 = _mm_xor_si128(a2,a3);\
    a1 = _mm_andnot_si128(a1,ALLONE);\
    a0 = _mm_xor_si128(a0,a3);\
    a3 = _mm_and_si128(a3,t);\
    a1 = _mm_xor_si128(a1,a3);\
    a3 = _mm_xor_si128(a3,a2);\
    a2 = _mm_and_si128(a2,a0);\
    a0 = _mm_andnot_si128(a0,ALLONE);\
    a2 = _mm_xor_si128(a2,a1);\
    a1 = _mm_or_si128(a1,a3);\
    t  = _mm_xor_si128(t,a1);\
    a3 = _mm_xor_si128(a3,a2);\
    a2 = _mm_and_si128(a2,a1);\
    a1 = _mm_xor_si128(a1,a0);\
    a0 = _mm_load_si128(&t);\

#define MIXWORD(a,b,t1,t2)\
    b = _mm_xor_si128(a,b);\
    t1 = _mm_slli_epi32(a,2);\
    t2 = _mm_srli_epi32(a,30);\
    a = _mm_or_si128(t1,t2);\
    a = _mm_xor_si128(a,b);\
    t1 = _mm_slli_epi32(b,14);\
    t2 = _mm_srli_epi32(b,18);\
    b = _mm_or_si128(t1,t2);\
    b = _mm_xor_si128(a,b);\
    t1 = _mm_slli_epi32(a,10);\
    t2 = _mm_srli_epi32(a,22);\
    a = _mm_or_si128(t1,t2);\
    a = _mm_xor_si128(a,b);\
    t1 = _mm_slli_epi32(b,1);\
    t2 = _mm_srli_epi32(b,31);\
    b = _mm_or_si128(t1,t2);

#define ADD_CONSTANT(a,b,c0,c1)\
    a = _mm_xor_si128(a,c0);\
    b = _mm_xor_si128(b,c1);\

#define NMLTOM768(r0,r1,r2,s0,s1,s2,s3,p0,p1,p2,q0,q1,q2,q3)\
    s2 = _mm_load_si128(&r1);\
    q2 = _mm_load_si128(&p1);\
    r2 = _mm_shuffle_epi32(r2,216);\
    p2 = _mm_shuffle_epi32(p2,216);\
    r1 = _mm_unpacklo_epi32(r1,r0);\
    p1 = _mm_unpacklo_epi32(p1,p0);\
    s2 = _mm_unpackhi_epi32(s2,r0);\
    q2 = _mm_unpackhi_epi32(q2,p0);\
    s0 = _mm_load_si128(&r2);\
    q0 = _mm_load_si128(&p2);\
    r2 = _mm_unpacklo_epi64(r2,r1);\
    p2 = _mm_unpacklo_epi64(p2,p1);\
    s1 = _mm_load_si128(&s0);\
    q1 = _mm_load_si128(&q0);\
    s0 = _mm_unpackhi_epi64(s0,r1);\
    q0 = _mm_unpackhi_epi64(q0,p1);\
    r2 = _mm_shuffle_epi32(r2,225);\
    p2 = _mm_shuffle_epi32(p2,225);\
    r0 = _mm_load_si128(&s1);\
    p0 = _mm_load_si128(&q1);\
    s0 = _mm_shuffle_epi32(s0,225);\
    q0 = _mm_shuffle_epi32(q0,225);\
    s1 = _mm_unpacklo_epi64(s1,s2);\
    q1 = _mm_unpacklo_epi64(q1,q2);\
    r0 = _mm_unpackhi_epi64(r0,s2);\
    p0 = _mm_unpackhi_epi64(p0,q2);\
    s2 = _mm_load_si128(&r0);\
    q2 = _mm_load_si128(&p0);\
    s3 = _mm_load_si128(&r2);\
    q3 = _mm_load_si128(&p2);\

#define MIXTON768(r0,r1,r2,r3,s0,s1,s2,p0,p1,p2,p3,q0,q1,q2)\
    s0 = _mm_load_si128(&r0);\
    q0 = _mm_load_si128(&p0);\
    s1 = _mm_load_si128(&r2);\
    q1 = _mm_load_si128(&p2);\
    r0 = _mm_unpackhi_epi32(r0,r1);\
    p0 = _mm_unpackhi_epi32(p0,p1);\
    r2 = _mm_unpackhi_epi32(r2,r3);\
    p2 = _mm_unpackhi_epi32(p2,p3);\
    s0 = _mm_unpacklo_epi32(s0,r1);\
    q0 = _mm_unpacklo_epi32(q0,p1);\
    s1 = _mm_unpacklo_epi32(s1,r3);\
    q1 = _mm_unpacklo_epi32(q1,p3);\
    r1 = _mm_load_si128(&r0);\
    p1 = _mm_load_si128(&p0);\
    r0 = _mm_unpackhi_epi64(r0,r2);\
    p0 = _mm_unpackhi_epi64(p0,p2);\
    s0 = _mm_unpackhi_epi64(s0,s1);\
    q0 = _mm_unpackhi_epi64(q0,q1);\
    r1 = _mm_unpacklo_epi64(r1,r2);\
    p1 = _mm_unpacklo_epi64(p1,p2);\
    s2 = _mm_load_si128(&r0);\
    q2 = _mm_load_si128(&p0);\
    s1 = _mm_load_si128(&r1);\
    q1 = _mm_load_si128(&p1);\

#define NMLTOM1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3)\
    s1 = _mm_load_si128(&r3);\
    q1 = _mm_load_si128(&p3);\
    s3 = _mm_load_si128(&r3);\
    q3 = _mm_load_si128(&p3);\
    s1 = _mm_unpackhi_epi32(s1,r2);\
    q1 = _mm_unpackhi_epi32(q1,p2);\
    s3 = _mm_unpacklo_epi32(s3,r2);\
    q3 = _mm_unpacklo_epi32(q3,p2);\
    s0 = _mm_load_si128(&s1);\
    q0 = _mm_load_si128(&q1);\
    s2 = _mm_load_si128(&s3);\
    q2 = _mm_load_si128(&q3);\
    r3 = _mm_load_si128(&r1);\
    p3 = _mm_load_si128(&p1);\
    r1 = _mm_unpacklo_epi32(r1,r0);\
    p1 = _mm_unpacklo_epi32(p1,p0);\
    r3 = _mm_unpackhi_epi32(r3,r0);\
    p3 = _mm_unpackhi_epi32(p3,p0);\
    s0 = _mm_unpackhi_epi64(s0,r3);\
    q0 = _mm_unpackhi_epi64(q0,p3);\
    s1 = _mm_unpacklo_epi64(s1,r3);\
    q1 = _mm_unpacklo_epi64(q1,p3);\
    s2 = _mm_unpackhi_epi64(s2,r1);\
    q2 = _mm_unpackhi_epi64(q2,p1);\
    s3 = _mm_unpacklo_epi64(s3,r1);\
    q3 = _mm_unpacklo_epi64(q3,p1);

#define MIXTON1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3)\
    NMLTOM1024(r0,r1,r2,r3,s0,s1,s2,s3,p0,p1,p2,p3,q0,q1,q2,q3);

static void rnd512( hashState_luffa *state, __m128i msg1, __m128i msg0 );

static void finalization512( hashState_luffa *state, uint32 *b );

/* initial values of chaining variables */
static const uint32 IV[40] __attribute((aligned(16))) = {
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
static const uint32 CNS_INIT[128] __attribute((aligned(16))) = {
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


__m128i CNS128[32];
__m128i ALLONE;
__m128i MASK;

HashReturn init_luffa(hashState_luffa *state, int hashbitlen)
{
    int i;
    state->hashbitlen = hashbitlen;
    /* set the lower 32 bits to '1' */
    MASK= _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0xffffffff);
    /* set all bits to '1' */
    ALLONE = _mm_set_epi32(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
    /* set the 32-bit round constant values to the 128-bit data field */
    for ( i=0; i<32; i++ )
        CNS128[i] = _mm_load_si128( (__m128i*)&CNS_INIT[i*4] );
    for ( i=0; i<10; i++ ) 
	state->chainv[i] = _mm_load_si128( (__m128i*)&IV[i*4] );
    memset(state->buffer, 0, sizeof state->buffer );
    return SUCCESS;
}

HashReturn update_luffa( hashState_luffa *state, const BitSequence *data,
                         size_t len )
{
    int i;
    int blocks = (int)len / 32;
    state-> rembytes = (int)len % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, mm128_bswap_32( casti_m128i( data, 1 ) ),
                      mm128_bswap_32( casti_m128i( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    // store in buffer for transform in final for midstate to work
    if ( state->rembytes  )
    {
      // remaining data bytes
      casti_m128i( state->buffer, 0 ) = mm128_bswap_32( cast_m128i( data ) );
      // padding of partial block
      casti_m128i( state->buffer, 1 ) =
            _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 );
    }

    return SUCCESS;
}

HashReturn final_luffa(hashState_luffa *state, BitSequence *hashval) 
{
    // transform pad block
    if ( state->rembytes )
    {
      // not empty, data is in buffer
      rnd512( state, casti_m128i( state->buffer, 1 ),
                     casti_m128i( state->buffer, 0 ) );
    }
    else
    {
      // empty pad block, constant data
     rnd512( state, _mm_setzero_si128(),
                       _mm_set_epi8( 0,0,0,0, 0,0,0,0, 0,0,0,0, 0x80,0,0,0 ) );
    }

    finalization512(state, (uint32*) hashval);
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32*)( hashval+128 ) );
    return SUCCESS;
}

HashReturn update_and_final_luffa( hashState_luffa *state, BitSequence* output,
              const BitSequence* data, size_t inlen )
{
// Optimized for integrals of 16 bytes, good for 64 and 80 byte len
    int i;
    int blocks = (int)( inlen / 32 );
    state->rembytes = inlen % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, mm128_bswap_32( casti_m128i( data, 1 ) ),
                      mm128_bswap_32( casti_m128i( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // 16 byte partial block exists for 80 byte len
    if ( state->rembytes  )
       // padding of partial block
       rnd512( state, m128_const_i128(  0x80000000 ),
                      mm128_bswap_32( cast_m128i( data ) ) );
    else
       // empty pad block
       rnd512( state, m128_zero, m128_const_i128( 0x80000000 ) );

    finalization512( state, (uint32*) output );
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32*)( output+128 ) );

    return SUCCESS;
}


int luffa_full( hashState_luffa *state, BitSequence* output, int hashbitlen,
              const BitSequence* data, size_t inlen )
{
// Optimized for integrals of 16 bytes, good for 64 and 80 byte len
    int i;
    state->hashbitlen = hashbitlen;
    /* set the lower 32 bits to '1' */
    MASK= _mm_set_epi32(0x00000000, 0x00000000, 0x00000000, 0xffffffff);
    /* set all bits to '1' */
    ALLONE = _mm_set_epi32(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
    /* set the 32-bit round constant values to the 128-bit data field */
    for ( i=0; i<32; i++ )
        CNS128[i] = _mm_load_si128( (__m128i*)&CNS_INIT[i*4] );
    for ( i=0; i<10; i++ )
    state->chainv[i] = _mm_load_si128( (__m128i*)&IV[i*4] );
    memset(state->buffer, 0, sizeof state->buffer );

    // update

    int blocks = (int)( inlen / 32 );
    state->rembytes = inlen % 32;

    // full blocks
    for ( i = 0; i < blocks; i++ )
    {
       rnd512( state, mm128_bswap_32( casti_m128i( data, 1 ) ),
                      mm128_bswap_32( casti_m128i( data, 0 ) ) );
       data += MSG_BLOCK_BYTE_LEN;
    }

    // final

    // 16 byte partial block exists for 80 byte len
    if ( state->rembytes  )
       // padding of partial block
       rnd512( state, m128_const_i128( 0x80000000 ),
                      mm128_bswap_32( cast_m128i( data ) ) );
    else
       // empty pad block
       rnd512( state, m128_zero, m128_const_i128( 0x80000000 ) );

    finalization512( state, (uint32*) output );
    if ( state->hashbitlen > 512 )
        finalization512( state, (uint32*)( output+128 ) );

    return SUCCESS;
}


/***************************************************/
/* Round function         */
/* state: hash context    */

static void rnd512( hashState_luffa *state, __m128i msg1, __m128i msg0 )
{
    __m128i t[2];
    __m128i *chainv = state->chainv;
    __m128i tmp[2];
    __m128i x[8];

    t[0] = chainv[0];
    t[1] = chainv[1];

    t[0] = _mm_xor_si128( t[0], chainv[2] );
    t[1] = _mm_xor_si128( t[1], chainv[3] );
    t[0] = _mm_xor_si128( t[0], chainv[4] );
    t[1] = _mm_xor_si128( t[1], chainv[5] );
    t[0] = _mm_xor_si128( t[0], chainv[6] );
    t[1] = _mm_xor_si128( t[1], chainv[7] );
    t[0] = _mm_xor_si128( t[0], chainv[8] );
    t[1] = _mm_xor_si128( t[1], chainv[9] );

    MULT2( t[0], t[1] );

    msg0 = _mm_shuffle_epi32( msg0, 27 );
    msg1 = _mm_shuffle_epi32( msg1, 27 );

    chainv[0] = _mm_xor_si128( chainv[0], t[0] );
    chainv[1] = _mm_xor_si128( chainv[1], t[1] );
    chainv[2] = _mm_xor_si128( chainv[2], t[0] );
    chainv[3] = _mm_xor_si128( chainv[3], t[1] );
    chainv[4] = _mm_xor_si128( chainv[4], t[0] );
    chainv[5] = _mm_xor_si128( chainv[5], t[1] );
    chainv[6] = _mm_xor_si128( chainv[6], t[0] );
    chainv[7] = _mm_xor_si128( chainv[7], t[1] );
    chainv[8] = _mm_xor_si128( chainv[8], t[0] );
    chainv[9] = _mm_xor_si128( chainv[9], t[1] );

    t[0] = chainv[0];
    t[1] = chainv[1];

    MULT2( chainv[0], chainv[1]);

    chainv[0] = _mm_xor_si128( chainv[0], chainv[2] );
    chainv[1] = _mm_xor_si128( chainv[1], chainv[3] );

    MULT2( chainv[2], chainv[3]);

    chainv[2] = _mm_xor_si128(chainv[2], chainv[4]);
    chainv[3] = _mm_xor_si128(chainv[3], chainv[5]);

    MULT2( chainv[4], chainv[5]);

    chainv[4] = _mm_xor_si128(chainv[4], chainv[6]);
    chainv[5] = _mm_xor_si128(chainv[5], chainv[7]);

    MULT2( chainv[6], chainv[7]);

    chainv[6] = _mm_xor_si128(chainv[6], chainv[8]);
    chainv[7] = _mm_xor_si128(chainv[7], chainv[9]);

    MULT2( chainv[8], chainv[9]);

    chainv[8] = _mm_xor_si128( chainv[8], t[0] );
    chainv[9] = _mm_xor_si128( chainv[9], t[1] );

    t[0] = chainv[8];
    t[1] = chainv[9];

    MULT2( chainv[8], chainv[9]);

    chainv[8] = _mm_xor_si128( chainv[8], chainv[6] );
    chainv[9] = _mm_xor_si128( chainv[9], chainv[7] );

    MULT2( chainv[6], chainv[7]);

    chainv[6] = _mm_xor_si128( chainv[6], chainv[4] );
    chainv[7] = _mm_xor_si128( chainv[7], chainv[5] );

    MULT2( chainv[4], chainv[5]);

    chainv[4] = _mm_xor_si128( chainv[4], chainv[2] );
    chainv[5] = _mm_xor_si128( chainv[5], chainv[3] );

    MULT2( chainv[2], chainv[3] );

    chainv[2] = _mm_xor_si128( chainv[2], chainv[0] );
    chainv[3] = _mm_xor_si128( chainv[3], chainv[1] );

    MULT2( chainv[0], chainv[1] );

    chainv[0] = _mm_xor_si128( _mm_xor_si128( chainv[0], t[0] ), msg0 );
    chainv[1] = _mm_xor_si128( _mm_xor_si128( chainv[1], t[1] ), msg1 );

    MULT2( msg0, msg1);

    chainv[2] = _mm_xor_si128( chainv[2], msg0 );
    chainv[3] = _mm_xor_si128( chainv[3], msg1 );

    MULT2( msg0, msg1);

    chainv[4] = _mm_xor_si128( chainv[4], msg0 );
    chainv[5] = _mm_xor_si128( chainv[5], msg1 );

    MULT2( msg0, msg1);

    chainv[6] = _mm_xor_si128( chainv[6], msg0 );
    chainv[7] = _mm_xor_si128( chainv[7], msg1 );

    MULT2( msg0, msg1);

    chainv[8] = _mm_xor_si128( chainv[8], msg0 );
    chainv[9] = _mm_xor_si128( chainv[9], msg1 );

    MULT2( msg0, msg1);

    chainv[3] = _mm_or_si128( _mm_slli_epi32(chainv[3], 1),
                              _mm_srli_epi32(chainv[3], 31) );
    chainv[5] = _mm_or_si128( _mm_slli_epi32(chainv[5], 2),
                              _mm_srli_epi32(chainv[5], 30) );
    chainv[7] = _mm_or_si128( _mm_slli_epi32(chainv[7], 3),
                              _mm_srli_epi32(chainv[7], 29) );
    chainv[9] = _mm_or_si128( _mm_slli_epi32(chainv[9], 4),
                              _mm_srli_epi32(chainv[9], 28) );


    NMLTOM1024( chainv[0], chainv[2], chainv[4], chainv[6],
                x[0], x[1], x[2], x[3],
                chainv[1],chainv[3],chainv[5],chainv[7],
                x[4], x[5], x[6], x[7] );

    STEP_PART( &x[0], &CNS128[ 0], &tmp[0] );
    STEP_PART( &x[0], &CNS128[ 2], &tmp[0] );
    STEP_PART( &x[0], &CNS128[ 4], &tmp[0] );
    STEP_PART( &x[0], &CNS128[ 6], &tmp[0] );
    STEP_PART( &x[0], &CNS128[ 8], &tmp[0] );
    STEP_PART( &x[0], &CNS128[10], &tmp[0] );
    STEP_PART( &x[0], &CNS128[12], &tmp[0] );
    STEP_PART( &x[0], &CNS128[14], &tmp[0] );

    MIXTON1024( x[0], x[1], x[2], x[3],
                chainv[0], chainv[2], chainv[4],chainv[6],
                x[4], x[5], x[6], x[7],
                chainv[1],chainv[3],chainv[5],chainv[7]);

    /* Process last 256-bit block */
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[16], CNS128[17],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[18], CNS128[19],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[20], CNS128[21],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[22], CNS128[23],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[24], CNS128[25],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[26], CNS128[27],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[28], CNS128[29],
                tmp[0], tmp[1] );
    STEP_PART2( chainv[8], chainv[9], t[0], t[1], CNS128[30], CNS128[31],
                tmp[0], tmp[1] );
}


/***************************************************/
/* Finalization function  */
/* state: hash context    */
/* b[8]: hash values      */

#if defined (__AVX2__)

static void finalization512( hashState_luffa *state, uint32 *b )
{
    uint32   hash[8] __attribute((aligned(64)));
    __m256i* chainv = (__m256i*)state->chainv;
    __m256i  t;
    const __m128i zero = m128_zero;
    const __m256i shuff_bswap32 = m256_const_64( 0x1c1d1e1f18191a1b,
                                                 0x1415161710111213,
                                                 0x0c0d0e0f08090a0b,
                                                 0x0405060700010203 );

    rnd512( state, zero, zero );

    t = chainv[0];
    t = _mm256_xor_si256( t, chainv[1] );
    t = _mm256_xor_si256( t, chainv[2] );
    t = _mm256_xor_si256( t, chainv[3] );
    t = _mm256_xor_si256( t, chainv[4] );

    t = _mm256_shuffle_epi32( t, 27 );

    _mm256_store_si256( (__m256i*)hash, t );

    casti_m256i( b, 0 ) = _mm256_shuffle_epi8(
                                 casti_m256i( hash, 0 ), shuff_bswap32 );

    rnd512( state, zero, zero );

    t = chainv[0];
    t = _mm256_xor_si256( t, chainv[1] );
    t = _mm256_xor_si256( t, chainv[2] );
    t = _mm256_xor_si256( t, chainv[3] );
    t = _mm256_xor_si256( t, chainv[4] );
    t = _mm256_shuffle_epi32( t, 27 );

    _mm256_store_si256( (__m256i*)hash, t );

    casti_m256i( b, 1 ) = _mm256_shuffle_epi8( 
                                 casti_m256i( hash, 0 ), shuff_bswap32 );
}

#else

static void finalization512( hashState_luffa *state, uint32 *b )
{
    uint32 hash[8] __attribute((aligned(64)));
    __m128i* chainv = state->chainv;
    __m128i t[2];
    const __m128i zero = _mm_setzero_si128();

    /*---- blank round with m=0 ----*/
    rnd512( state, zero, zero );

    t[0] = chainv[0];
    t[1] = chainv[1];
    t[0] = _mm_xor_si128(t[0], chainv[2]);
    t[1] = _mm_xor_si128(t[1], chainv[3]);
    t[0] = _mm_xor_si128(t[0], chainv[4]);
    t[1] = _mm_xor_si128(t[1], chainv[5]);
    t[0] = _mm_xor_si128(t[0], chainv[6]);
    t[1] = _mm_xor_si128(t[1], chainv[7]);
    t[0] = _mm_xor_si128(t[0], chainv[8]);
    t[1] = _mm_xor_si128(t[1], chainv[9]);

    t[0] = _mm_shuffle_epi32(t[0], 27);
    t[1] = _mm_shuffle_epi32(t[1], 27);

    _mm_store_si128((__m128i*)&hash[0], t[0]);
    _mm_store_si128((__m128i*)&hash[4], t[1]);

    casti_m128i( b, 0 ) = mm128_bswap_32( casti_m128i( hash, 0 ) );
    casti_m128i( b, 1 ) = mm128_bswap_32( casti_m128i( hash, 1 ) );

    rnd512( state, zero, zero );

    t[0] = chainv[0];
    t[1] = chainv[1];
    t[0] = _mm_xor_si128(t[0], chainv[2]);
    t[1] = _mm_xor_si128(t[1], chainv[3]);
    t[0] = _mm_xor_si128(t[0], chainv[4]);
    t[1] = _mm_xor_si128(t[1], chainv[5]);
    t[0] = _mm_xor_si128(t[0], chainv[6]);
    t[1] = _mm_xor_si128(t[1], chainv[7]);
    t[0] = _mm_xor_si128(t[0], chainv[8]);
    t[1] = _mm_xor_si128(t[1], chainv[9]);

    t[0] = _mm_shuffle_epi32(t[0], 27);
    t[1] = _mm_shuffle_epi32(t[1], 27);

    _mm_store_si128((__m128i*)&hash[0], t[0]);
    _mm_store_si128((__m128i*)&hash[4], t[1]);

    casti_m128i( b, 2 ) = mm128_bswap_32( casti_m128i( hash, 0 ) );
    casti_m128i( b, 3 ) = mm128_bswap_32( casti_m128i( hash, 1 ) );
}
#endif

/***************************************************/
