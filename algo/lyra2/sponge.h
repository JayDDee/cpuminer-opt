/**
 * Header file for Blake2b's internal permutation in the form of a sponge.
 * This code is based on the original Blake2b's implementation provided by
 * Samuel Neves (https://blake2.net/)
 *
 * Author: The Lyra PHC team (http://www.lyra-kdf.net/) -- 2014.
 *
 * This software is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef SPONGE_H_
#define SPONGE_H_

#include <stdint.h>
#include "simd-utils.h"

#if defined(__GNUC__)
#define ALIGN __attribute__ ((aligned(32)))
#elif defined(_MSC_VER)
#define ALIGN __declspec(align(32))
#else
#define ALIGN
#endif


/*Blake2b IV Array*/
static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

/*Blake2b's rotation*/
static inline uint64_t rotr64( const uint64_t w, const unsigned c ){
    return ( w >> c ) | ( w << ( 64 - c ) );
}

// serial data is only 32 bytes so AVX2 is the limit for that dimension.
// However, 2 way parallel looks trivial to code for AVX512 except for
// a data dependency with rowa.

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define G2W_4X64(a,b,c,d) \
   a = _mm512_add_epi64( a, b ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 32 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 24 ); \
   a = _mm512_add_epi64( a, b ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 63 );

#define LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   G2W_4X64( s0, s1, s2, s3 ); \
   s3 = mm512_shufll256_64( s3 ); \
   s1 = mm512_shuflr256_64( s1); \
   s2 = mm512_swap256_128( s2 ); \
   G2W_4X64( s0, s1, s2, s3 ); \
   s3 = mm512_shuflr256_64( s3 ); \
   s1 = mm512_shufll256_64( s1 ); \
   s2 = mm512_swap256_128( s2 ); 

#define LYRA_12_ROUNDS_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 ) \
   LYRA_ROUND_2WAY_AVX512( s0, s1, s2, s3 )


#endif  // AVX512

#if defined __AVX2__

// process 4 columns in parallel
// returns void, updates all args
#define G_4X64(a,b,c,d) \
   a = _mm256_add_epi64( a, b ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 32 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 24 ); \
   a = _mm256_add_epi64( a, b ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 63 );

#define LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   G_4X64( s0, s1, s2, s3 ); \
   s3 = mm256_shufll_64( s3 ); \
   s1 = mm256_shuflr_64( s1); \
   s2 = mm256_swap_128( s2 ); \
   G_4X64( s0, s1, s2, s3 ); \
   s3 = mm256_shuflr_64( s3 ); \
   s1 = mm256_shufll_64( s1 ); \
   s2 = mm256_swap_128( s2 );

#define LYRA_12_ROUNDS_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 ) \
   LYRA_ROUND_AVX2( s0, s1, s2, s3 )

#endif

#if defined(__SSE2__)

// process 2 columns in parallel
// returns void, all args updated
#define G_2X64(a,b,c,d) \
   a = _mm_add_epi64( a, b ); \
   d = mm128_ror_64( _mm_xor_si128( d, a), 32 ); \
   c = _mm_add_epi64( c, d ); \
   b = mm128_ror_64( _mm_xor_si128( b, c ), 24 ); \
   a = _mm_add_epi64( a, b ); \
   d = mm128_ror_64( _mm_xor_si128( d, a ), 16 ); \
   c = _mm_add_epi64( c, d ); \
   b = mm128_ror_64( _mm_xor_si128( b, c ), 63 );

#define LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   G_2X64( s0, s2, s4, s6 ); \
   G_2X64( s1, s3, s5, s7 ); \
   mm128_vrol256_64( s6, s7 ); \
   mm128_vror256_64( s2, s3 ); \
   mm128_swap256_128( s4, s5 ); \
   G_2X64( s0, s2, s4, s6 ); \
   G_2X64( s1, s3, s5, s7 ); \
   mm128_vror256_64( s6, s7 ); \
   mm128_vrol256_64( s2, s3 ); \
   mm128_swap256_128( s4, s5 );

#define LYRA_12_ROUNDS_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7) \
   LYRA_ROUND_AVX(s0,s1,s2,s3,s4,s5,s6,s7)

#endif // AVX2 else SSE2

// Scalar
//Blake2b's G function
#define G(r,i,a,b,c,d) \
  do { \
    a = a + b; \
    d = rotr64(d ^ a, 32); \
    c = c + d; \
    b = rotr64(b ^ c, 24); \
    a = a + b; \
    d = rotr64(d ^ a, 16); \
    c = c + d; \
    b = rotr64(b ^ c, 63); \
  } while(0)


/*One Round of the Blake2b's compression function*/
#define ROUND_LYRA(r)  \
    G(r,0,v[ 0],v[ 4],v[ 8],v[12]); \
    G(r,1,v[ 1],v[ 5],v[ 9],v[13]); \
    G(r,2,v[ 2],v[ 6],v[10],v[14]); \
    G(r,3,v[ 3],v[ 7],v[11],v[15]); \
    G(r,4,v[ 0],v[ 5],v[10],v[15]); \
    G(r,5,v[ 1],v[ 6],v[11],v[12]); \
    G(r,6,v[ 2],v[ 7],v[ 8],v[13]); \
    G(r,7,v[ 3],v[ 4],v[ 9],v[14]);

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

union _ovly_512
{
  __m512i v512;
  struct
  {
     __m256i v256lo;
     __m256i v256hi;
  };
};
typedef union _ovly_512 ovly_512;


union _inout_ovly
{
   __m512i v512[3];
   __m256i v256[6];
};
typedef union _inout_ovly inout_ovly;

//---- Housekeeping
void initState_2way( uint64_t State[/*16*/] );

//---- Squeezes
void squeeze_2way( uint64_t *State, unsigned char *out, unsigned int len );
void reducedSqueezeRow0_2way( uint64_t* state, uint64_t* row, uint64_t nCols );

//---- Absorbs
void absorbBlock_2way( uint64_t *State, const uint64_t *In0,
                       const uint64_t *In1 );
void absorbBlockBlake2Safe_2way( uint64_t *State, const uint64_t *In,
                            const uint64_t nBlocks, const uint64_t block_len );

//---- Duplexes
void reducedDuplexRow1_2way( uint64_t *State, uint64_t *rowIn,
                             uint64_t *rowOut, uint64_t nCols);
void reducedDuplexRowSetup_2way( uint64_t *State, uint64_t *rowIn,
                    uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols );

void reducedDuplexRow_2way( uint64_t *State, uint64_t *rowIn,
                            uint64_t *rowInOut0, uint64_t *rowInOut1,
                            uint64_t *rowOut, uint64_t nCols);

void reducedDuplexRow_2way_X( uint64_t *State, uint64_t *rowIn,
                              uint64_t *rowInOut0, uint64_t *rowInOut1,
                              uint64_t *rowOut, uint64_t nCols);

#endif


//---- Housekeeping
void initState(uint64_t state[/*16*/]);

//---- Squeezes
void squeeze(uint64_t *state, unsigned char *out, unsigned int len);
void reducedSqueezeRow0(uint64_t* state, uint64_t* row, uint64_t nCols);

//---- Absorbs
void absorbBlock(uint64_t *state, const uint64_t *in);
void absorbBlockBlake2Safe( uint64_t *state, const uint64_t *in,
                            const uint64_t nBlocks, const uint64_t block_len );

//---- Duplexes
void reducedDuplexRow1(uint64_t *state, uint64_t *rowIn, uint64_t *rowOut, uint64_t nCols);
void reducedDuplexRowSetup(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols);
void reducedDuplexRow(uint64_t *state, uint64_t *rowIn, uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols);

#endif /* SPONGE_H_ */
