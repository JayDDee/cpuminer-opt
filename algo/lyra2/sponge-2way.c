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

      {
        register __m512i t0, t1, t2;
       
        //M[row*][col] = M[row*][col] XOR rotW(rand)
        t0 = _mm512_permutex_epi64( state0, 0x93 );
        t1 = _mm512_permutex_epi64( state1, 0x93 );
        t2 = _mm512_permutex_epi64( state2, 0x93 );

        inout[0] = _mm512_xor_si512( inout[0],
                                 _mm512_mask_blend_epi64( 0x11, t0, t2 ) );
        inout[1] = _mm512_xor_si512( inout[1],
                                 _mm512_mask_blend_epi64( 0x11, t1, t0 ) );
        inout[2] = _mm512_xor_si512( inout[2],
                                 _mm512_mask_blend_epi64( 0x11, t2, t1 ) );
      }

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

// reduced duplex row has three version depending on rows inout.
// If they are the same the fastest version can be used, equivalent to 
// linear version.
// If either rowinout overlaps with rowout the slowest version is used,
// to refresh local data after overwriting rowout.
// Otherwise the normal version is used, slower than unified, faster than
// overlap.
//
// The likelyhood of each case depends on the number of rows. More rows
// means unified and overlap are both less likely.
// Unified has a 1 in Nrows chances,
// Overlap has 2 in Nrows chance reduced to 1 in Nrows because if both
// overlap it's unified.
// As a result normal is Nrows-2 / Nrows.
// for 4 rows: 1 unified, 2 overlap, 1 normal.
// for 8 rows: 1 unified, 2 overlap, 56 normal.

static inline void reducedDuplexRow_2way_normal( uint64_t *State,
                   uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                            uint64_t *rowOut, uint64_t nCols)
{
   int i;
   register __m512i state0, state1, state2, state3;
   __m512i *in = (__m512i*)rowIn;
   __m512i *inout0 = (__m512i*)rowInOut0;
   __m512i *inout1 = (__m512i*)rowInOut1;
   __m512i *out = (__m512i*)rowOut;
   register __m512i io0, io1, io2;

   state0 = _mm512_load_si512( (__m512i*)State     );
   state1 = _mm512_load_si512( (__m512i*)State + 1 );
   state2 = _mm512_load_si512( (__m512i*)State + 2 );
   state3 = _mm512_load_si512( (__m512i*)State + 3 );

   for ( i = 0; i < nCols; i++ )
   {
     //Absorbing "M[prev] [+] M[row*]"
     io0 = _mm512_mask_blend_epi64( 0xf0,
                                    _mm512_load_si512( (__m512i*)inout0 ),
                                    _mm512_load_si512( (__m512i*)inout1 ) );
     io1 = _mm512_mask_blend_epi64( 0xf0,
                                    _mm512_load_si512( (__m512i*)inout0 +1 ),
                                    _mm512_load_si512( (__m512i*)inout1 +1 ) );
     io2 = _mm512_mask_blend_epi64( 0xf0,
                                    _mm512_load_si512( (__m512i*)inout0 +2 ),
                                    _mm512_load_si512( (__m512i*)inout1 +2 ) );

     state0 = _mm512_xor_si512( state0, _mm512_add_epi64( in[0], io0 ) );
     state1 = _mm512_xor_si512( state1, _mm512_add_epi64( in[1], io1 ) );
     state2 = _mm512_xor_si512( state2, _mm512_add_epi64( in[2], io2 ) );

     //Applies the reduced-round transformation f to the sponge's state
     LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

     {
       register __m512i t0, t1, t2;

       //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
       t0 = _mm512_permutex_epi64( state0, 0x93 );
       t1 = _mm512_permutex_epi64( state1, 0x93 );
       t2 = _mm512_permutex_epi64( state2, 0x93 );

       io0 = _mm512_xor_si512( io0, _mm512_mask_blend_epi64( 0x11, t0, t2 ) );
       io1 = _mm512_xor_si512( io1, _mm512_mask_blend_epi64( 0x11, t1, t0 ) );
       io2 = _mm512_xor_si512( io2, _mm512_mask_blend_epi64( 0x11, t2, t1 ) );

       //M[rowOut][col] = M[rowOut][col] XOR rand
       out[0] = _mm512_xor_si512( out[0], state0 );
       out[1] = _mm512_xor_si512( out[1], state1 );
       out[2] = _mm512_xor_si512( out[2], state2 );
     }

     _mm512_mask_store_epi64( inout0,    0x0f, io0 );
     _mm512_mask_store_epi64( inout1,    0xf0, io0 );
     _mm512_mask_store_epi64( inout0 +1, 0x0f, io1 );
     _mm512_mask_store_epi64( inout1 +1, 0xf0, io1 );
     _mm512_mask_store_epi64( inout0 +2, 0x0f, io2 );
     _mm512_mask_store_epi64( inout1 +2, 0xf0, io2 );

      //Goes to next block
      in     += BLOCK_LEN_M256I;
      inout0 += BLOCK_LEN_M256I;
      inout1 += BLOCK_LEN_M256I;
      out    += BLOCK_LEN_M256I;
   }

   _mm512_store_si512( (__m512i*)State,     state0 );
   _mm512_store_si512( (__m512i*)State + 1, state1 );
   _mm512_store_si512( (__m512i*)State + 2, state2 );
   _mm512_store_si512( (__m512i*)State + 3, state3 );
}

static inline void reducedDuplexRow_2way_overlap( uint64_t *State,
                   uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                            uint64_t *rowOut, uint64_t nCols)
{
   int i;
   register __m512i state0, state1, state2, state3;
   __m512i *in = (__m512i*)rowIn;
   __m512i *inout0 = (__m512i*)rowInOut0;
   __m512i *inout1 = (__m512i*)rowInOut1;
   __m512i *out = (__m512i*)rowOut;
//   inout_ovly io;
   ovly_512 io0, io1, io2;

   state0 = _mm512_load_si512( (__m512i*)State     );
   state1 = _mm512_load_si512( (__m512i*)State + 1 );
   state2 = _mm512_load_si512( (__m512i*)State + 2 );
   state3 = _mm512_load_si512( (__m512i*)State + 3 );
    
   for ( i = 0; i < nCols; i++ )
   {
     //Absorbing "M[prev] [+] M[row*]"
     io0.v512 = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 ),
                                  _mm512_load_si512( (__m512i*)inout1 ) );
     io1.v512 = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 +1 ),
                                  _mm512_load_si512( (__m512i*)inout1 +1 ) );
     io2.v512 = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 +2 ),
                                  _mm512_load_si512( (__m512i*)inout1 +2 ) );

     state0 = _mm512_xor_si512( state0, _mm512_add_epi64( in[0], io0.v512 ) );
     state1 = _mm512_xor_si512( state1, _mm512_add_epi64( in[1], io1.v512 ) );
     state2 = _mm512_xor_si512( state2, _mm512_add_epi64( in[2], io2.v512 ) );
     
/* 
     io.v512[0] = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 ),
                                  _mm512_load_si512( (__m512i*)inout1 ) );
     io.v512[1] = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 +1 ),
                                  _mm512_load_si512( (__m512i*)inout1 +1 ) );
     io.v512[2] = _mm512_mask_blend_epi64( 0xf0,
                                  _mm512_load_si512( (__m512i*)inout0 +2 ),
                                  _mm512_load_si512( (__m512i*)inout1 +2 ) );

     state0 = _mm512_xor_si512( state0, _mm512_add_epi64( in[0], io.v512[0] ) );
     state1 = _mm512_xor_si512( state1, _mm512_add_epi64( in[1], io.v512[1] ) );
     state2 = _mm512_xor_si512( state2, _mm512_add_epi64( in[2], io.v512[2] ) );
*/

     //Applies the reduced-round transformation f to the sponge's state
     LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

     {
       __m512i t0, t1, t2;

       //M[rowOut][col] = M[rowOut][col] XOR rand
       out[0] = _mm512_xor_si512( out[0], state0 );
       out[1] = _mm512_xor_si512( out[1], state1 );
       out[2] = _mm512_xor_si512( out[2], state2 );

       // if out is the same row as inout, update with new data.
       if ( rowOut == rowInOut0 )
       {
          io0.v512 = _mm512_mask_blend_epi64( 0x0f, io0.v512, out[0] );
          io1.v512 = _mm512_mask_blend_epi64( 0x0f, io1.v512, out[1] );
          io2.v512 = _mm512_mask_blend_epi64( 0x0f, io2.v512, out[2] );

       }
       if ( rowOut == rowInOut1 )
       {
          io0.v512 = _mm512_mask_blend_epi64( 0xf0, io0.v512, out[0] );
          io1.v512 = _mm512_mask_blend_epi64( 0xf0, io1.v512, out[1] );
          io2.v512 = _mm512_mask_blend_epi64( 0xf0, io2.v512, out[2] );
       }

/*
       if ( rowOut == rowInOut0 )
       {
          io.v512[0] = _mm512_mask_blend_epi64( 0x0f, io.v512[0], out[0] );
          io.v512[1] = _mm512_mask_blend_epi64( 0x0f, io.v512[1], out[1] );
          io.v512[2] = _mm512_mask_blend_epi64( 0x0f, io.v512[2], out[2] );

       }
       if ( rowOut == rowInOut1 )
       {
          io.v512[0] = _mm512_mask_blend_epi64( 0xf0, io.v512[0], out[0] );
          io.v512[1] = _mm512_mask_blend_epi64( 0xf0, io.v512[1], out[1] );
          io.v512[2] = _mm512_mask_blend_epi64( 0xf0, io.v512[2], out[2] );
       }
*/

       //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
       t0 = _mm512_permutex_epi64( state0, 0x93 );
       t1 = _mm512_permutex_epi64( state1, 0x93 );
       t2 = _mm512_permutex_epi64( state2, 0x93 );

       io0.v512 = _mm512_xor_si512( io0.v512,
                                 _mm512_mask_blend_epi64( 0x11, t0, t2 ) );
       io1.v512 = _mm512_xor_si512( io1.v512,
                                 _mm512_mask_blend_epi64( 0x11, t1, t0 ) );
       io2.v512 = _mm512_xor_si512( io2.v512,
                                 _mm512_mask_blend_epi64( 0x11, t2, t1 ) );
     }

      casti_m256i( inout0, 0 ) = io0.v256lo;
      casti_m256i( inout1, 1 ) = io0.v256hi;
      casti_m256i( inout0, 2 ) = io1.v256lo;
      casti_m256i( inout1, 3 ) = io1.v256hi;
      casti_m256i( inout0, 4 ) = io2.v256lo;
      casti_m256i( inout1, 5 ) = io2.v256hi;
/*     
     _mm512_mask_store_epi64( inout0,    0x0f, io.v512[0] );
     _mm512_mask_store_epi64( inout1,    0xf0, io.v512[0] );
     _mm512_mask_store_epi64( inout0 +1, 0x0f, io.v512[1] );
     _mm512_mask_store_epi64( inout1 +1, 0xf0, io.v512[1] );
     _mm512_mask_store_epi64( inout0 +2, 0x0f, io.v512[2] );
     _mm512_mask_store_epi64( inout1 +2, 0xf0, io.v512[2] );
*/
      //Goes to next block
      in     += BLOCK_LEN_M256I;
      inout0 += BLOCK_LEN_M256I;
      inout1 += BLOCK_LEN_M256I;
      out    += BLOCK_LEN_M256I;
   }

   _mm512_store_si512( (__m512i*)State,     state0 );
   _mm512_store_si512( (__m512i*)State + 1, state1 );
   _mm512_store_si512( (__m512i*)State + 2, state2 );
   _mm512_store_si512( (__m512i*)State + 3, state3 );

}

static inline void reducedDuplexRow_2way_overlap_X( uint64_t *State,
                    uint64_t *rowIn, uint64_t *rowInOut0, uint64_t *rowInOut1,
                    uint64_t *rowOut, uint64_t nCols)
{
   int i;
   register __m512i state0, state1, state2, state3;
   __m512i *in = (__m512i*)rowIn;
   __m256i *inout0 = (__m256i*)rowInOut0;
   __m256i *inout1 = (__m256i*)rowInOut1;
   __m512i *out = (__m512i*)rowOut;
   inout_ovly inout;
   __m512i t0, t1, t2;

   state0 = _mm512_load_si512( (__m512i*)State     );
   state1 = _mm512_load_si512( (__m512i*)State + 1 );
   state2 = _mm512_load_si512( (__m512i*)State + 2 );
   state3 = _mm512_load_si512( (__m512i*)State + 3 );

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
         inout.v256[0] = ( (__m256i*)out )[0];
         inout.v256[2] = ( (__m256i*)out )[2];
         inout.v256[4] = ( (__m256i*)out )[4];
      }
      if ( rowOut == rowInOut1 )
      {
         inout.v256[1] = ( (__m256i*)out )[1];
         inout.v256[3] = ( (__m256i*)out )[3];
         inout.v256[5] = ( (__m256i*)out )[5];
      }

      //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
      t0 = _mm512_permutex_epi64( state0, 0x93 );
      t1 = _mm512_permutex_epi64( state1, 0x93 );
      t2 = _mm512_permutex_epi64( state2, 0x93 );

      inout.v512[0] = _mm512_xor_si512( inout.v512[0],
                                   _mm512_mask_blend_epi64( 0x11, t0, t2 ) );
      inout.v512[1] = _mm512_xor_si512( inout.v512[1],
                                   _mm512_mask_blend_epi64( 0x11, t1, t0 ) );
      inout.v512[2] = _mm512_xor_si512( inout.v512[2],
                                   _mm512_mask_blend_epi64( 0x11, t2, t1 ) );

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

// rowInOut0 == rowInOut1, fastest, least likely: 1 / nrows
static inline void reducedDuplexRow_2way_unified( uint64_t *State,
                   uint64_t *rowIn, uint64_t *rowInOut0,
                            uint64_t *rowOut, uint64_t nCols)
{
   int i;
   register __m512i state0, state1, state2, state3;
   __m512i *in = (__m512i*)rowIn;
   __m512i *inout = (__m512i*)rowInOut0;
   __m512i *out = (__m512i*)rowOut;

   state0 = _mm512_load_si512( (__m512i*)State     );
   state1 = _mm512_load_si512( (__m512i*)State + 1 );
   state2 = _mm512_load_si512( (__m512i*)State + 2 );
   state3 = _mm512_load_si512( (__m512i*)State + 3 );

   for ( i = 0; i < nCols; i++ )
   {
     //Absorbing "M[prev] [+] M[row*]"
     state0 = _mm512_xor_si512( state0, _mm512_add_epi64( in[0], inout[0] ) );
     state1 = _mm512_xor_si512( state1, _mm512_add_epi64( in[1], inout[1] ) );
     state2 = _mm512_xor_si512( state2, _mm512_add_epi64( in[2], inout[2] ) );

     //Applies the reduced-round transformation f to the sponge's state
     LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

     {
       register __m512i t0, t1, t2;

       //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
       t0 = _mm512_permutex_epi64( state0, 0x93 );
       t1 = _mm512_permutex_epi64( state1, 0x93 );
       t2 = _mm512_permutex_epi64( state2, 0x93 );

       inout[0] = _mm512_xor_si512( inout[0],
                                    _mm512_mask_blend_epi64( 0x11, t0, t2 ) );
       inout[1] = _mm512_xor_si512( inout[1],
                                    _mm512_mask_blend_epi64( 0x11, t1, t0 ) );
       inout[2] = _mm512_xor_si512( inout[2],
                                    _mm512_mask_blend_epi64( 0x11, t2, t1 ) );

       out[0] = _mm512_xor_si512( out[0], state0 );
       out[1] = _mm512_xor_si512( out[1], state1 );
       out[2] = _mm512_xor_si512( out[2], state2 );

     }

     //Goes to next block
     in    += BLOCK_LEN_M256I;
     inout += BLOCK_LEN_M256I;
     out   += BLOCK_LEN_M256I;
   }

   _mm512_store_si512( (__m512i*)State,     state0 );
   _mm512_store_si512( (__m512i*)State + 1, state1 );
   _mm512_store_si512( (__m512i*)State + 2, state2 );
   _mm512_store_si512( (__m512i*)State + 3, state3 );
}

// Multi level specialization.
// There are three cases that need to be handled:
// unified: inout data is contiguous, fastest, unlikely.
// normal: inout data is not contiguous with no overlap with out, likely. 
// overlap: inout data is not contiguous and one lane overlaps with out
//          slowest, unlikely.
//
// In adition different algos prefer different coding. x25x and x22i prefer
// 256 bit memory acceses to handle the diverged data while all other
// algos prefer 512 bit memory accesses with masking and blending.

 
//  Wrapper
inline void reducedDuplexRow_2way( uint64_t *State, uint64_t *rowIn,
                                   uint64_t *rowInOut0, uint64_t *rowInOut1,
                                   uint64_t *rowOut, uint64_t nCols )
{
  if ( rowInOut0 == rowInOut1 )
     reducedDuplexRow_2way_unified( State, rowIn, rowInOut0, rowOut, nCols );
  else if ( ( rowInOut0 == rowOut ) || ( rowInOut1 == rowOut ) )
     reducedDuplexRow_2way_overlap( State, rowIn, rowInOut0, rowInOut1,
                                    rowOut, nCols );
  else
     reducedDuplexRow_2way_normal( State, rowIn, rowInOut0, rowInOut1,
                                   rowOut, nCols );
}

inline void reducedDuplexRow_2way_X( uint64_t *State, uint64_t *rowIn,
                                     uint64_t *rowInOut0, uint64_t *rowInOut1,
                                     uint64_t *rowOut, uint64_t nCols )
{
   if ( rowInOut0 == rowInOut1 )
      reducedDuplexRow_2way_unified( State, rowIn, rowInOut0, rowOut, nCols );
   else if ( ( rowInOut0 == rowOut ) || ( rowInOut1 == rowOut ) )
   {
      asm volatile ( "nop" );  // Prevent GCC from optimizing
      reducedDuplexRow_2way_overlap_X( State, rowIn, rowInOut0, rowInOut1,
                                       rowOut, nCols );
   }
   else
      reducedDuplexRow_2way_normal( State, rowIn, rowInOut0, rowInOut1,
                                    rowOut, nCols );
}


#endif // AVX512
