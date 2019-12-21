/**
 * A simple implementation of Blake2b's internal permutation
 * in the form of a sponge.
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

//#include "algo-gate.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <immintrin.h>
#include "sponge.h"
#include "lyra2.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

inline void squeeze_2way( uint64_t *State, byte *Out, unsigned int len )
{
    const int len_m256i = len / 32;
    const int fullBlocks = len_m256i / BLOCK_LEN_M256I;
    __m512i* state = (__m512i*)State;
    __m512i* out   = (__m512i*)Out;
    int i;

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy_512( out, state, BLOCK_LEN_M256I );
       LYRA_ROUND_2WAY_AVX512( state[0], state[1], state[2], state[3] );
       out += BLOCK_LEN_M256I;
    }
    //Squeezes remaining bytes
    memcpy_512( out, state, len_m256i % BLOCK_LEN_M256I );
}

inline void absorbBlock_2way( uint64_t *State, const uint64_t *In0,
                                               const uint64_t *In1 ) 
{
    register __m512i state0, state1, state2, state3;
    __m512i in[3];
    casti_m256i( in, 0 ) = casti_m256i( In0, 0 );
    casti_m256i( in, 1 ) = casti_m256i( In1, 1 );
    casti_m256i( in, 2 ) = casti_m256i( In0, 2 );
    casti_m256i( in, 3 ) = casti_m256i( In1, 3 );
    casti_m256i( in, 4 ) = casti_m256i( In0, 4 );
    casti_m256i( in, 5 ) = casti_m256i( In1, 5 );
    
    state0 = _mm512_load_si512( (__m512i*)State     );
    state1 = _mm512_load_si512( (__m512i*)State + 1 );
    state2 = _mm512_load_si512( (__m512i*)State + 2 );
    state3 = _mm512_load_si512( (__m512i*)State + 3 );

    state0 = _mm512_xor_si512( state0, in[0] );
    state1 = _mm512_xor_si512( state1, in[1] );
    state2 = _mm512_xor_si512( state2, in[2] );

    LYRA_12_ROUNDS_2WAY_AVX512( state0, state1, state2, state3 );

    _mm512_store_si512( (__m512i*)State,     state0 );
    _mm512_store_si512( (__m512i*)State + 1, state1 );
    _mm512_store_si512( (__m512i*)State + 2, state2 );
    _mm512_store_si512( (__m512i*)State + 3, state3 );

}

inline void absorbBlockBlake2Safe_2way( uint64_t *State, const uint64_t *In,
                      const uint64_t nBlocks, const uint64_t block_len )
{
  register __m512i state0, state1, state2, state3;

  state0 = 
  state1 = m512_zero;
  state2 = m512_const4_64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                           0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state3 = m512_const4_64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                           0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );

  for ( int i = 0; i < nBlocks; i++ )
  { 
    __m512i *in = (__m512i*)In;
    state0 = _mm512_xor_si512( state0, in[0] );
    state1 = _mm512_xor_si512( state1, in[1] );

    LYRA_12_ROUNDS_2WAY_AVX512( state0, state1, state2, state3 );
    In += block_len*2;
  }

  _mm512_store_si512( (__m512i*)State,     state0 );
  _mm512_store_si512( (__m512i*)State + 1, state1 );
  _mm512_store_si512( (__m512i*)State + 2, state2 );
  _mm512_store_si512( (__m512i*)State + 3, state3 );

}

inline void reducedSqueezeRow0_2way( uint64_t* State, uint64_t* rowOut,
                                     uint64_t nCols )
{
    int i;

    //M[row][C-1-col] = H.reduced_squeeze()


    register __m512i state0, state1, state2, state3;
    __m512i* out   = (__m512i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );

    state0 = _mm512_load_si512( (__m512i*)State     );
    state1 = _mm512_load_si512( (__m512i*)State + 1 );
    state2 = _mm512_load_si512( (__m512i*)State + 2 );
    state3 = _mm512_load_si512( (__m512i*)State + 3 );

    for ( i = 0; i < 9; i += 3)
    {
        _mm_prefetch( out - i,     _MM_HINT_T0 );
        _mm_prefetch( out - i - 2, _MM_HINT_T0 );
    }

    for ( i = 0; i < nCols; i++ )
    {
       _mm_prefetch( out -  9, _MM_HINT_T0 );
       _mm_prefetch( out - 11, _MM_HINT_T0 );

       out[0] = state0;
       out[1] = state1;
       out[2] = state2;

       //Goes to next block (column) that will receive the squeezed data
       out -= BLOCK_LEN_M256I;

       LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );
    }

    _mm512_store_si512( (__m512i*)State,     state0 );
    _mm512_store_si512( (__m512i*)State + 1, state1 );
    _mm512_store_si512( (__m512i*)State + 2, state2 );
    _mm512_store_si512( (__m512i*)State + 3, state3 );
}


inline void reducedDuplexRow1_2way( uint64_t *State, uint64_t *rowIn,
                 uint64_t *rowOut, uint64_t nCols )
{
    int i;
    register __m512i state0, state1, state2, state3;
    __m512i *in = (__m512i*)rowIn;
    __m512i *out = (__m512i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );

    state0 = _mm512_load_si512( (__m512i*)State     );
    state1 = _mm512_load_si512( (__m512i*)State + 1 );
    state2 = _mm512_load_si512( (__m512i*)State + 2 );
    state3 = _mm512_load_si512( (__m512i*)State + 3 );

    for ( i = 0; i < nCols; i++ )
    {
         state0 = _mm512_xor_si512( state0, in[0] );
         state1 = _mm512_xor_si512( state1, in[1] );
         state2 = _mm512_xor_si512( state2, in[2] );

         LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

         out[0] = _mm512_xor_si512( state0, in[0] );
         out[1] = _mm512_xor_si512( state1, in[1] );
         out[2] = _mm512_xor_si512( state2, in[2] );

         //Input: next column (i.e., next block in sequence)
         in += BLOCK_LEN_M256I;
         //Output: goes to previous column
         out -= BLOCK_LEN_M256I;
    }

    _mm512_store_si512( (__m512i*)State,     state0 );
    _mm512_store_si512( (__m512i*)State + 1, state1 );
    _mm512_store_si512( (__m512i*)State + 2, state2 );
    _mm512_store_si512( (__m512i*)State + 3, state3 );
}

inline void reducedDuplexRowSetup_2way( uint64_t *State, uint64_t *rowIn,
                       uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols )
{
    int i;
    register __m512i state0, state1, state2, state3;
    __m512i* in    = (__m512i*)rowIn;
    __m512i* inout = (__m512i*)rowInOut;
    __m512i* out   = (__m512i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );
    __m512i  t0, t1, t2;

    state0 = _mm512_load_si512( (__m512i*)State     );
    state1 = _mm512_load_si512( (__m512i*)State + 1 );
    state2 = _mm512_load_si512( (__m512i*)State + 2 );
    state3 = _mm512_load_si512( (__m512i*)State + 3 );

    for ( i = 0; i < nCols; i++ )
    {
       state0 = _mm512_xor_si512( state0,
                                  _mm512_add_epi64( in[0], inout[0] ) );
       state1 = _mm512_xor_si512( state1,
                                  _mm512_add_epi64( in[1], inout[1] ) );
       state2 = _mm512_xor_si512( state2,
                                  _mm512_add_epi64( in[2], inout[2] ) );

       LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

       out[0] = _mm512_xor_si512( state0, in[0] );
       out[1] = _mm512_xor_si512( state1, in[1] );
       out[2] = _mm512_xor_si512( state2, in[2] );

       //M[row*][col] = M[row*][col] XOR rotW(rand)
       t0 = _mm512_permutex_epi64( state0, 0x93 );
       t1 = _mm512_permutex_epi64( state1, 0x93 );
       t2 = _mm512_permutex_epi64( state2, 0x93 );

       inout[0] = _mm512_xor_si512( inout[0],
                                 _mm512_mask_blend_epi32( 0x0303, t0, t2 ) );
       inout[1] = _mm512_xor_si512( inout[1],
                                 _mm512_mask_blend_epi32( 0x0303, t1, t0 ) );
       inout[2] = _mm512_xor_si512( inout[2],
                                 _mm512_mask_blend_epi32( 0x0303, t2, t1 ) );


       //Inputs: next column (i.e., next block in sequence)
       in    += BLOCK_LEN_M256I;
       inout += BLOCK_LEN_M256I;
       //Output: goes to previous column
       out   -= BLOCK_LEN_M256I;
    }

    _mm512_store_si512( (__m512i*)State,     state0 );
    _mm512_store_si512( (__m512i*)State + 1, state1 );
    _mm512_store_si512( (__m512i*)State + 2, state2 );
    _mm512_store_si512( (__m512i*)State + 3, state3 );
}

// big ugly workaound for pointer aliasing, use a union of pointers.
// Access matrix using m512i for in and out, m256i for inout

inline void reducedDuplexRow_2way( uint64_t *State, uint64_t *rowIn,
                            uint64_t *rowInOut0, uint64_t *rowInOut1,
                            uint64_t *rowOut, uint64_t nCols)
{
   int i;
   register __m512i state0, state1, state2, state3;
   __m512i *in = (__m512i*)rowIn;
   __m256i *inout0 = (__m256i*)rowInOut0;
   __m256i *inout1 = (__m256i*)rowInOut1;
   __m512i *out = (__m512i*)rowOut;
   __m512i io[3];
   povly inout;
   inout.v512 = &io[0];
    __m512i t0, t1, t2;

   state0 = _mm512_load_si512( (__m512i*)State     );
   state1 = _mm512_load_si512( (__m512i*)State + 1 );
   state2 = _mm512_load_si512( (__m512i*)State + 2 );
   state3 = _mm512_load_si512( (__m512i*)State + 3 );
    
    _mm_prefetch( in,     _MM_HINT_T0 );
    _mm_prefetch( inout0,     _MM_HINT_T0 );
    _mm_prefetch( inout1,     _MM_HINT_T0 );
    _mm_prefetch( in     + 2, _MM_HINT_T0 );
    _mm_prefetch( inout0 + 2, _MM_HINT_T0 );
    _mm_prefetch( inout1 + 2, _MM_HINT_T0 );
    _mm_prefetch( in     + 4, _MM_HINT_T0 );
    _mm_prefetch( inout0 + 4, _MM_HINT_T0 );
    _mm_prefetch( inout1 + 4, _MM_HINT_T0 );
    _mm_prefetch( in     + 6, _MM_HINT_T0 );
    _mm_prefetch( inout0 + 6, _MM_HINT_T0 );
    _mm_prefetch( inout1 + 6, _MM_HINT_T0 );

    
    for ( i = 0; i < nCols; i++ )
    {

      //Absorbing "M[prev] [+] M[row*]"
      inout.v256[0] = inout0[0];
      inout.v256[1] = inout1[1];
      inout.v256[2] = inout0[2];
      inout.v256[3] = inout1[3];
      inout.v256[4] = inout0[4];
      inout.v256[5] = inout1[5];

      state0 = _mm512_xor_si512( state0,
                                 _mm512_add_epi64( in[0], inout.v512[0] ) );
      state1 = _mm512_xor_si512( state1,
                                 _mm512_add_epi64( in[1], inout.v512[1] ) );
      state2 = _mm512_xor_si512( state2,
                                 _mm512_add_epi64( in[2], inout.v512[2] ) );


      //Applies the reduced-round transformation f to the sponge's state
      LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

      //M[rowOut][col] = M[rowOut][col] XOR rand
      out[0] = _mm512_xor_si512( out[0], state0 );
      out[1] = _mm512_xor_si512( out[1], state1 );
      out[2] = _mm512_xor_si512( out[2], state2 );

      // if inout is the same row as out it was just overwritten, reload.
      if ( rowOut == rowInOut0 )
      {
         inout.v256[0] = inout0[0];
         inout.v256[2] = inout0[2];
         inout.v256[4] = inout0[4];
      }
      if ( rowOut == rowInOut1 )
      {
         inout.v256[1] = inout1[1];
         inout.v256[3] = inout1[3];
         inout.v256[5] = inout1[5];
      }

      //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
      t0 = _mm512_permutex_epi64( state0, 0x93 );
      t1 = _mm512_permutex_epi64( state1, 0x93 );
      t2 = _mm512_permutex_epi64( state2, 0x93 );

      inout.v512[0] = _mm512_xor_si512( inout.v512[0],
                                   _mm512_mask_blend_epi32( 0x0303, t0, t2 ) );
      inout.v512[1] = _mm512_xor_si512( inout.v512[1],
                                   _mm512_mask_blend_epi32( 0x0303, t1, t0 ) );
      inout.v512[2] = _mm512_xor_si512( inout.v512[2],
                                   _mm512_mask_blend_epi32( 0x0303, t2, t1 ) );
      
      inout0[0] = inout.v256[0];
      inout1[1] = inout.v256[1];
      inout0[2] = inout.v256[2];
      inout1[3] = inout.v256[3];
      inout0[4] = inout.v256[4];
      inout1[5] = inout.v256[5];

       //Goes to next block
       in     += BLOCK_LEN_M256I;
       inout0 += BLOCK_LEN_M256I * 2;
       inout1 += BLOCK_LEN_M256I * 2;
       out    += BLOCK_LEN_M256I;
   }

   _mm512_store_si512( (__m512i*)State,     state0 );
   _mm512_store_si512( (__m512i*)State + 1, state1 );
   _mm512_store_si512( (__m512i*)State + 2, state2 );
   _mm512_store_si512( (__m512i*)State + 3, state3 );
}

#endif // AVX512
