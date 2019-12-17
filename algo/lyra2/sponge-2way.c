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
    const int fullBlocks = len / 32;
    __m512i* state = (__m512i*)State;
    __m512i* out   = (__m512i*)Out;
    int i;

//printf("squeeze 1, len= %d, full  %d\n", len,fullBlocks);

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {

//printf("squeeze 1, %d\n",i);

       memcpy_512( out, state, BLOCK_LEN_M256I*2 );

//printf("squeeze 2\n");

       LYRA_ROUND_2WAY_AVX512( state[0], state[1], state[2], state[3] );

//printf("squeeze 2\n");

       out += BLOCK_LEN_M256I;
    }
    //Squeezes remaining bytes
//    memcpy_512( out, state, ( (len * 2 ) );
}

inline void absorbBlock_2way( uint64_t *State, const uint64_t *In ) 
{
    register __m512i state0, state1, state2, state3;
    __m512i *in = (__m512i*)In;

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
                                 _mm512_mask_blend_epi32( 0x03, t0, t2 ) );
       inout[1] = _mm512_xor_si512( inout[1],
                                 _mm512_mask_blend_epi32( 0x03, t1, t0 ) );
       inout[2] = _mm512_xor_si512( inout[2],
                                 _mm512_mask_blend_epi32( 0x03, t2, t1 ) );

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
inline void reducedDuplexRow_2way( uint64_t *State, povly matrix,
                                   uint64_t rowIn,
                                   uint64_t rowInOut0, uint64_t rowInOut1,
                                   uint64_t rowOut, uint64_t nCols )
{
   int i;

   const uint64_t ROW_LEN_M256I = BLOCK_LEN_INT64 * nCols / 4;
   __m512i state0, state1, state2, state3;
//   register __m512i state0, state1, state2, state3;
   __m512i *in = &matrix.v512[ rowIn * ROW_LEN_M256I ];
   __m256i *inout0 = &matrix.v256[ 2 * rowInOut0 * ROW_LEN_M256I ];
   __m256i *inout1 = &matrix.v256[ 2 * rowInOut1 * ROW_LEN_M256I ];
   __m512i *out   = &matrix.v512[ rowOut * ROW_LEN_M256I ];
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

//uint64_t *ii = (uint64_t*)in0;
//printf("RDRV0 IO %016lx %016lx %016lx %016lx\n",ii[0],ii[1],ii[2],ii[3]);
    
    for ( i = 0; i < nCols; i++ )
    {

/*       
//printf("RDR: loop %d\n",i);
uint64_t *io1 = (uint64_t*)inout1;
printf("RDRV0 col= %d\n", i);
printf("RDRV0 IO1 %016lx %016lx %016lx %016lx\n",io1[0],io1[1],io1[2],io1[3]);
printf("RDRV0 IO1 %016lx %016lx %016lx %016lx\n",io1[4],io1[5],io1[6],io1[7]);
printf("RDRV0 IO1 %016lx %016lx %016lx %016lx\n",io1[8],io1[9],io1[10],io1[11]);
printf("RDRV0 IO1 %016lx %016lx %016lx %016lx\n",io1[12],io1[13],io1[14],io1[153]);
*/


      //Absorbing "M[prev] [+] M[row*]"
      inout.v256[0] = inout0[0];
      inout.v256[1] = inout1[1];
      inout.v256[2] = inout0[2];
      inout.v256[3] = inout1[3];
      inout.v256[4] = inout0[4];
      inout.v256[5] = inout1[5];

/*      
uint64_t *io = (uint64_t*)inout.u64;
uint64_t *ii = (uint64_t*)in;

printf("RDRV1 col= %d\n", i);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[0],io[1],io[2],io[3]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[4],io[5],io[6],io[7]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[8],io[9],io[10],io[11]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[12],io[13],io[14],io[15]);
printf("RDRV1 IN %016lx %016lx %016lx %016lx\n",ii[0],ii[1],ii[2],ii[3]);
printf("RDRV1 IN %016lx %016lx %016lx %016lx\n",ii[4],ii[5],ii[6],ii[7]);
printf("RDRV1 IN %016lx %016lx %016lx %016lx\n",ii[8],ii[9],ii[10],ii[11]);
printf("RDRV1 IN %016lx %016lx %016lx %016lx\n",ii[12],ii[13],ii[14],ii[15]);
*/

      state0 = _mm512_xor_si512( state0,
                                 _mm512_add_epi64( in[0], inout.v512[0] ) );
      state1 = _mm512_xor_si512( state1,
                                 _mm512_add_epi64( in[1], inout.v512[1] ) );
      state2 = _mm512_xor_si512( state2,
                                 _mm512_add_epi64( in[2], inout.v512[2] ) );

//printf("RDR: round\n");

      //Applies the reduced-round transformation f to the sponge's state
      LYRA_ROUND_2WAY_AVX512( state0, state1, state2, state3 );

//printf("RDR 3\n");

      //M[rowOut][col] = M[rowOut][col] XOR rand
      out[0] = _mm512_xor_si512( out[0], state0 );
      out[1] = _mm512_xor_si512( out[1], state1 );
      out[2] = _mm512_xor_si512( out[2], state2 );

      //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
      t0 = _mm512_permutex_epi64( state0, 0x93 );
      t1 = _mm512_permutex_epi64( state1, 0x93 );
      t2 = _mm512_permutex_epi64( state2, 0x93 );
/*
uint64_t *st = (uint64_t*)&state0;
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);
st = (uint64_t*)&state1;
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);
st = (uint64_t*)&state2;
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);

st = (uint64_t*)&t0;
printf("RDRV2 t0 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 t0 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);
st = (uint64_t*)&t1;
printf("RDRV2 t1 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 t1 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);
st = (uint64_t*)&t2;
printf("RDRV2 t2 %016lx %016lx %016lx %016lx\n",st[0],st[1],st[2],st[3]);
printf("RDRv2 t2 %016lx %016lx %016lx %016lx\n",st[4],st[5],st[6],st[7]);
*/
/*
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[8],st[9],st[10],st[11]);
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[12],st[13],st[14],st[15]);
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[16],st[17],st[18],st[19]);
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[20],st[21],st[22],st[23]);
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[24],st[25],st[26],st[271]);
printf("RDRV2 %016lx %016lx %016lx %016lx\n",st[28],st[29],st[30],st[31]);
*/
      
//printf("RDR 4\n");    
/*
//uint64_t *io = (uint64_t*)&inout;
printf("RDRV1 col= %d\n", i);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[0],io[1],io[2],io[3]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[4],io[5],io[6],io[7]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[8],io[9],io[10],io[11]);
printf("RDRV1 IO %016lx %016lx %016lx %016lx\n",io[12],io[13],io[14],io[15]);
*/

// need to split inout for write

      inout.v512[0] = _mm512_xor_si512( inout.v512[0],
                                   _mm512_mask_blend_epi32( 0x03, t0, t2 ) );
      inout.v512[1] = _mm512_xor_si512( inout.v512[1],
                                   _mm512_mask_blend_epi32( 0x03, t1, t0 ) );
      inout.v512[2] = _mm512_xor_si512( inout.v512[2],
                                   _mm512_mask_blend_epi32( 0x03, t2, t1 ) );
/*
printf("RDRV3 IO %016lx %016lx %016lx %016lx\n",io[0],io[1],io[2],io[3]);
printf("RDRV3 IO %016lx %016lx %016lx %016lx\n",io[4],io[5],io[6],io[7]);
printf("RDRV3 IO %016lx %016lx %016lx %016lx\n",io[8],io[9],io[10],io[11]);
printf("RDRV3 IO %016lx %016lx %016lx %016lx\n",io[12],io[13],io[14],io[153]);
*/    
      
      inout0[0] = inout.v256[0];
      inout1[1] = inout.v256[1];
      inout0[2] = inout.v256[2];
      inout1[3] = inout.v256[3];
      inout0[4] = inout.v256[4];
      inout1[5] = inout.v256[5];
      
      
//printf("RDR 5\n"); 

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
