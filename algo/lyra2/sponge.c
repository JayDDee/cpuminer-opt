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

#include <string.h>
#include <stdio.h>
#include <time.h>
#include "simd-utils.h"
#include "sponge.h"
#include "lyra2.h"

inline void initState( uint64_t State[/*16*/] )
{

/*
#if defined (__AVX2__)

  __m256i* state = (__m256i*)State;
  const __m256i zero = m256_zero; 
  state[0] = zero;
  state[1] = zero;
  state[2] = _mm256_set_epi64x( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                                0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state[3] = _mm256_set_epi64x( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                                0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );

#elif defined (__SSE2__)

  v128u64_t* state = (v128u64_t*)State;
  const v128u64_t zero = v128_zero;   

  state[0] = zero;
  state[1] = zero;
  state[2] = zero;
  state[3] = zero;
  state[4] = v128_set64( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state[5] = v128_set64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
  state[6] = v128_set64( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
  state[7] = v128_set64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

#else
    //First 512 bis are zeros
    memset( State, 0, 64 );
    //Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
    State[8]  = blake2b_IV[0];
    State[9]  = blake2b_IV[1];
    State[10] = blake2b_IV[2];
    State[11] = blake2b_IV[3];
    State[12] = blake2b_IV[4];
    State[13] = blake2b_IV[5];
    State[14] = blake2b_IV[6];
    State[15] = blake2b_IV[7];
#endif
*/

}

//#if !defined(__AVX512F__) && !defined(__AVX2__) && !defined(__SSE2__)

inline static void blake2bLyra( uint64_t *v )
{
    ROUND_LYRA( 0);
    ROUND_LYRA( 1);
    ROUND_LYRA( 2);
    ROUND_LYRA( 3);
    ROUND_LYRA( 4);
    ROUND_LYRA( 5);
    ROUND_LYRA( 6);
    ROUND_LYRA( 7);
    ROUND_LYRA( 8);
    ROUND_LYRA( 9);
    ROUND_LYRA(10);
    ROUND_LYRA(11);
}

inline static void reducedBlake2bLyra( uint64_t *v )
{
    ROUND_LYRA(0);
}

//#endif

inline void squeeze( uint64_t *State, byte *Out, unsigned int len )
{
#if defined (__AVX2__)

    const int len_m256i = len / 32;
    const int fullBlocks = len_m256i / BLOCK_LEN_256;
    __m256i* state = (__m256i*)State;
    __m256i* out   = (__m256i*)Out;
    int i;

    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy_256( out, state, BLOCK_LEN_256 );
       LYRA_ROUND_AVX2( state[0], state[1], state[2], state[3] );
       out += BLOCK_LEN_256;
    }
    memcpy_256( out, state, ( len_m256i % BLOCK_LEN_256 ) );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    const int len_128 = len / 16;
    const int fullBlocks = len_128 / BLOCK_LEN_128;
    v128u64_t* state = (v128u64_t*)State;
    v128u64_t* out   = (v128u64_t*)Out;
    int i;

    for ( i = 0; i < fullBlocks; i++ )
    {
       v128_memcpy( out, state, BLOCK_LEN_128 );
       LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                       state[4], state[5], state[6], state[7] );
       out += BLOCK_LEN_128;
    }
    v128_memcpy( out, state, ( len_128 % BLOCK_LEN_128 ) );

#else

    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *out = Out;
    int i;

    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy( out, State, BLOCK_LEN_BYTES );
       blake2bLyra( State );
       out += BLOCK_LEN_BYTES;
    }
    memcpy( out, State, (len % BLOCK_LEN_BYTES) );

#endif
}

inline void absorbBlock( uint64_t *State, const uint64_t *In ) 
{
#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i *in = (__m256i*)In;

    state0 = _mm256_load_si256( (__m256i*)State     );
    state1 = _mm256_load_si256( (__m256i*)State + 1 );
    state2 = _mm256_load_si256( (__m256i*)State + 2 );
    state3 = _mm256_load_si256( (__m256i*)State + 3 );

    state0 = _mm256_xor_si256( state0, in[0] );
    state1 = _mm256_xor_si256( state1, in[1] );
    state2 = _mm256_xor_si256( state2, in[2] );

    LYRA_12_ROUNDS_AVX2( state0, state1, state2, state3 );

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    v128u64_t* state = (v128u64_t*)State;
    v128u64_t* in    = (v128u64_t*)In;

    state[0] = v128_xor( state[0], in[0] );
    state[1] = v128_xor( state[1], in[1] );
    state[2] = v128_xor( state[2], in[2] );
    state[3] = v128_xor( state[3], in[3] );
    state[4] = v128_xor( state[4], in[4] );
    state[5] = v128_xor( state[5], in[5] );

    LYRA_12_ROUNDS_AVX( state[0], state[1], state[2], state[3],
                        state[4], state[5], state[6], state[7] );

#else

    State[ 0] ^= In[ 0];
    State[ 1] ^= In[ 1];
    State[ 2] ^= In[ 2];
    State[ 3] ^= In[ 3];
    State[ 4] ^= In[ 4];
    State[ 5] ^= In[ 5];
    State[ 6] ^= In[ 6];
    State[ 7] ^= In[ 7];
    State[ 8] ^= In[ 8];
    State[ 9] ^= In[ 9];
    State[10] ^= In[10];
    State[11] ^= In[11];

    blake2bLyra(State);

#endif
}

inline void absorbBlockBlake2Safe( uint64_t *State, const uint64_t *In,
                      const uint64_t nBlocks, const uint64_t block_len )
{
#if defined (__AVX2__)

  register __m256i state0, state1, state2, state3;

  state0 = 
  state1 = m256_zero;
  state2 = _mm256_set_epi64x( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                              0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state3 = _mm256_set_epi64x( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                              0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );

  for ( int i = 0; i < nBlocks; i++ )
  { 
    __m256i *in = (__m256i*)In;
    state0 = _mm256_xor_si256( state0, in[0] );
    state1 = _mm256_xor_si256( state1, in[1] );

    LYRA_12_ROUNDS_AVX2( state0, state1, state2, state3 );
    In += block_len;
  }

  _mm256_store_si256( (__m256i*)State,     state0 );
  _mm256_store_si256( (__m256i*)State + 1, state1 );
  _mm256_store_si256( (__m256i*)State + 2, state2 );
  _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

  v128u64_t state0, state1, state2, state3, state4, state5, state6, state7;

  state0 = 
  state1 =
  state2 =
  state3 = v128_zero;
  state4 = v128_set64( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state5 = v128_set64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
  state6 = v128_set64( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
  state7 = v128_set64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

  for ( int i = 0; i < nBlocks; i++ )
  { 
    v128u64_t* in    = (v128u64_t*)In;

    state0 = v128_xor( state0, in[0] );
    state1 = v128_xor( state1, in[1] );
    state2 = v128_xor( state2, in[2] );
    state3 = v128_xor( state3, in[3] );

    LYRA_12_ROUNDS_AVX( state0, state1, state2, state3,
                        state4, state5, state6, state7 );
    In += block_len;
  }

   v128_store( (v128u64_t*)State,     state0 );
   v128_store( (v128u64_t*)State + 1, state1 );
   v128_store( (v128u64_t*)State + 2, state2 );
   v128_store( (v128u64_t*)State + 3, state3 );
   v128_store( (v128u64_t*)State + 4, state4 );
   v128_store( (v128u64_t*)State + 5, state5 );
   v128_store( (v128u64_t*)State + 6, state6 );
   v128_store( (v128u64_t*)State + 7, state7 );
  
#else

   memset( State, 0, 64 );
   State[ 8] = blake2b_IV[0];
   State[ 9] = blake2b_IV[1];
   State[10] = blake2b_IV[2];
   State[11] = blake2b_IV[3];
   State[12] = blake2b_IV[4];
   State[13] = blake2b_IV[5];
   State[14] = blake2b_IV[6];
   State[15] = blake2b_IV[7];

   for ( int i = 0; i < nBlocks; i++ )
   {
      State[0] ^= In[0];
      State[1] ^= In[1];
      State[2] ^= In[2];
      State[3] ^= In[3];
      State[4] ^= In[4];
      State[5] ^= In[5];
      State[6] ^= In[6];
      State[7] ^= In[7];

      blake2bLyra( State );

      In += block_len;
   }
#endif
}

inline void reducedSqueezeRow0( uint64_t* State, uint64_t* rowOut,
                                uint64_t nCols )
{
    int i;

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_256 );

    state0 = _mm256_load_si256( (__m256i*)State     );
    state1 = _mm256_load_si256( (__m256i*)State + 1 );
    state2 = _mm256_load_si256( (__m256i*)State + 2 );
    state3 = _mm256_load_si256( (__m256i*)State + 3 );

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

       out -= BLOCK_LEN_256;

       LYRA_ROUND_AVX2( state0, state1, state2, state3 );
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    v128u64_t *state = (v128u64_t*)State;
    v128u64_t  state0 = v128_load(  state    );
    v128u64_t  state1 = v128_load( &state[1] );
    v128u64_t  state2 = v128_load( &state[2] );
    v128u64_t  state3 = v128_load( &state[3] );
    v128u64_t  state4 = v128_load( &state[4] );
    v128u64_t  state5 = v128_load( &state[5] );
    v128u64_t  state6 = v128_load( &state[6] );
    v128u64_t  state7 = v128_load( &state[7] );

    v128u64_t* out = (v128u64_t*)rowOut + ( (nCols-1) * BLOCK_LEN_128 );

    for ( i = 0; i < nCols; i++ )
    {
       out[0] = state0;
       out[1] = state1;
       out[2] = state2;
       out[3] = state3;
       out[4] = state4;
       out[5] = state5;

       out -= BLOCK_LEN_128;

       LYRA_ROUND_AVX( state0, state1, state2, state3,
                       state4, state5, state6, state7 );
    }

   v128_store( state,     state0 );
   v128_store( &state[1], state1 );
   v128_store( &state[2], state2 );
   v128_store( &state[3], state3 );
   v128_store( &state[4], state4 );
   v128_store( &state[5], state5 );
   v128_store( &state[6], state6 );
   v128_store( &state[7], state7 );

#else

    uint64_t* ptrWord = rowOut + (nCols-1)*BLOCK_LEN_INT64;

    for ( i = 0; i < nCols; i++ )
    {
       ptrWord[ 0] = State[ 0];
       ptrWord[ 1] = State[ 1];
       ptrWord[ 2] = State[ 2];
       ptrWord[ 3] = State[ 3];
       ptrWord[ 4] = State[ 4];
       ptrWord[ 5] = State[ 5];
       ptrWord[ 6] = State[ 6];
       ptrWord[ 7] = State[ 7];
       ptrWord[ 8] = State[ 8];
       ptrWord[ 9] = State[ 9];
       ptrWord[10] = State[10];
       ptrWord[11] = State[11];

       ptrWord -= BLOCK_LEN_INT64;

       reducedBlake2bLyra( State);
    }
#endif
}

inline void reducedDuplexRow1( uint64_t *State, uint64_t *rowIn,
                               uint64_t *rowOut, uint64_t nCols )
{
    int i;

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* in    = (__m256i*)rowIn;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_256 );

    state0 = _mm256_load_si256( (__m256i*)State     );
    state1 = _mm256_load_si256( (__m256i*)State + 1 );
    state2 = _mm256_load_si256( (__m256i*)State + 2 );
    state3 = _mm256_load_si256( (__m256i*)State + 3 );

    for ( i = 0; i < 9; i += 3)
    {
        _mm_prefetch( in  + i,     _MM_HINT_T0 );
        _mm_prefetch( in  + i + 2, _MM_HINT_T0 );
        _mm_prefetch( out - i,     _MM_HINT_T0 );
        _mm_prefetch( out - i - 2, _MM_HINT_T0 );
    }

    for ( i = 0; i < nCols; i++ )
    {

        _mm_prefetch( in  +  9, _MM_HINT_T0 );
        _mm_prefetch( in  + 11, _MM_HINT_T0 );
        _mm_prefetch( out -  9, _MM_HINT_T0 );
        _mm_prefetch( out - 11, _MM_HINT_T0 );
 
         state0 = _mm256_xor_si256( state0, in[0] );
         state1 = _mm256_xor_si256( state1, in[1] );
         state2 = _mm256_xor_si256( state2, in[2] );

         LYRA_ROUND_AVX2( state0, state1, state2, state3 );

         out[0] = _mm256_xor_si256( state0, in[0] );
         out[1] = _mm256_xor_si256( state1, in[1] );
         out[2] = _mm256_xor_si256( state2, in[2] );

         in += BLOCK_LEN_256;
         out -= BLOCK_LEN_256;
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    v128u64_t* state = (v128u64_t*)State;
    v128u64_t  state0 = v128_load(  state    );
    v128u64_t  state1 = v128_load( &state[1] );
    v128u64_t  state2 = v128_load( &state[2] );
    v128u64_t  state3 = v128_load( &state[3] );
    v128u64_t  state4 = v128_load( &state[4] );
    v128u64_t  state5 = v128_load( &state[5] );
    v128u64_t  state6 = v128_load( &state[6] );
    v128u64_t  state7 = v128_load( &state[7] );

    v128u64_t*  in   = (v128u64_t*)rowIn;
    v128u64_t* out   = (v128u64_t*)rowOut + ( (nCols-1) * BLOCK_LEN_128 );

    for ( i = 0; i < nCols; i++ )
    {
         state0 = v128_xor( state0, in[0] );
         state1 = v128_xor( state1, in[1] );
         state2 = v128_xor( state2, in[2] );
         state3 = v128_xor( state3, in[3] );
         state4 = v128_xor( state4, in[4] );
         state5 = v128_xor( state5, in[5] );

         LYRA_ROUND_AVX( state0, state1, state2, state3,
                         state4, state5, state6, state7 );

         out[0] = v128_xor( state0, in[0] );
         out[1] = v128_xor( state1, in[1] );
         out[2] = v128_xor( state2, in[2] );
         out[3] = v128_xor( state3, in[3] );
         out[4] = v128_xor( state4, in[4] );
         out[5] = v128_xor( state5, in[5] );

         in += BLOCK_LEN_128;
         out -= BLOCK_LEN_128;
    }

   v128_store(  state,    state0 );
   v128_store( &state[1], state1 );
   v128_store( &state[2], state2 );
   v128_store( &state[3], state3 );
   v128_store( &state[4], state4 );
   v128_store( &state[5], state5 );
   v128_store( &state[6], state6 );
   v128_store( &state[7], state7 );

#else

    uint64_t* ptrWordIn  = rowIn;
    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64;

    for ( i = 0; i < nCols; i++ )
    {
        State[ 0] ^= ptrWordIn[ 0];
        State[ 1] ^= ptrWordIn[ 1];
        State[ 2] ^= ptrWordIn[ 2];
        State[ 3] ^= ptrWordIn[ 3];
        State[ 4] ^= ptrWordIn[ 4];
        State[ 5] ^= ptrWordIn[ 5];
        State[ 6] ^= ptrWordIn[ 6];
        State[ 7] ^= ptrWordIn[ 7];
        State[ 8] ^= ptrWordIn[ 8];
        State[ 9] ^= ptrWordIn[ 9];
        State[10] ^= ptrWordIn[10];
        State[11] ^= ptrWordIn[11];

        reducedBlake2bLyra( State );

        ptrWordOut[ 0] = ptrWordIn[ 0] ^ State[ 0];
        ptrWordOut[ 1] = ptrWordIn[ 1] ^ State[ 1];
        ptrWordOut[ 2] = ptrWordIn[ 2] ^ State[ 2];
        ptrWordOut[ 3] = ptrWordIn[ 3] ^ State[ 3];
        ptrWordOut[ 4] = ptrWordIn[ 4] ^ State[ 4];
        ptrWordOut[ 5] = ptrWordIn[ 5] ^ State[ 5];
        ptrWordOut[ 6] = ptrWordIn[ 6] ^ State[ 6];
        ptrWordOut[ 7] = ptrWordIn[ 7] ^ State[ 7];
        ptrWordOut[ 8] = ptrWordIn[ 8] ^ State[ 8];
        ptrWordOut[ 9] = ptrWordIn[ 9] ^ State[ 9];
        ptrWordOut[10] = ptrWordIn[10] ^ State[10];
        ptrWordOut[11] = ptrWordIn[11] ^ State[11];

       ptrWordIn  += BLOCK_LEN_INT64;
       ptrWordOut -= BLOCK_LEN_INT64;
   }
#endif
}

inline void reducedDuplexRowSetup( uint64_t *State, uint64_t *rowIn,
                         uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols )
{
    int i;

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* in    = (__m256i*)rowIn;
    __m256i* inout = (__m256i*)rowInOut;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_256 );
    __m256i  t0, t1, t2;

    state0 = _mm256_load_si256( (__m256i*)State     );
    state1 = _mm256_load_si256( (__m256i*)State + 1 );
    state2 = _mm256_load_si256( (__m256i*)State + 2 );
    state3 = _mm256_load_si256( (__m256i*)State + 3 );

    for ( i = 0; i < 9; i += 3)
    {
        _mm_prefetch( in    + i,     _MM_HINT_T0 );
        _mm_prefetch( in    + i + 2, _MM_HINT_T0 );
        _mm_prefetch( inout + i,     _MM_HINT_T0 );
        _mm_prefetch( inout + i + 2, _MM_HINT_T0 );
        _mm_prefetch( out   - i,     _MM_HINT_T0 );
        _mm_prefetch( out   - i - 2, _MM_HINT_T0 );
    }

    for ( i = 0; i < nCols; i++ )
    {
       _mm_prefetch( in    +  9, _MM_HINT_T0 );
       _mm_prefetch( in    + 11, _MM_HINT_T0 );
       _mm_prefetch( inout +  9, _MM_HINT_T0 );
       _mm_prefetch( inout + 11, _MM_HINT_T0 );
       _mm_prefetch( out   -  9, _MM_HINT_T0 );
       _mm_prefetch( out   - 11, _MM_HINT_T0 );

       state0 = _mm256_xor_si256( state0,
                                  _mm256_add_epi64( in[0], inout[0] ) );
       state1 = _mm256_xor_si256( state1,
                                  _mm256_add_epi64( in[1], inout[1] ) );
       state2 = _mm256_xor_si256( state2,
                                  _mm256_add_epi64( in[2], inout[2] ) );

       LYRA_ROUND_AVX2( state0, state1, state2, state3 );

       out[0] = _mm256_xor_si256( state0, in[0] );
       out[1] = _mm256_xor_si256( state1, in[1] );
       out[2] = _mm256_xor_si256( state2, in[2] );

       t0 = _mm256_permute4x64_epi64( state0, 0x93 );
       t1 = _mm256_permute4x64_epi64( state1, 0x93 );
       t2 = _mm256_permute4x64_epi64( state2, 0x93 );

       inout[0] = _mm256_xor_si256( inout[0],
                                    _mm256_blend_epi32( t0, t2, 0x03 ) );
       inout[1] = _mm256_xor_si256( inout[1],
                                    _mm256_blend_epi32( t1, t0, 0x03 ) );
       inout[2] = _mm256_xor_si256( inout[2],
                                    _mm256_blend_epi32( t2, t1, 0x03 ) );

       in    += BLOCK_LEN_256;
       inout += BLOCK_LEN_256;
       out   -= BLOCK_LEN_256;
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    v128u64_t* in    = (v128u64_t*)rowIn;
    v128u64_t* inout = (v128u64_t*)rowInOut;
    v128u64_t* out   = (v128u64_t*)rowOut + ( (nCols-1) * BLOCK_LEN_128 );
    v128u64_t* state = (v128u64_t*)State;

    for ( i = 0; i < nCols; i++ )
    {
        state[0] = v128_xor( state[0], v128_add64( in[0], inout[0] ) );
        state[1] = v128_xor( state[1], v128_add64( in[1], inout[1] ) );
        state[2] = v128_xor( state[2], v128_add64( in[2], inout[2] ) );
        state[3] = v128_xor( state[3], v128_add64( in[3], inout[3] ) );
        state[4] = v128_xor( state[4], v128_add64( in[4], inout[4] ) );
        state[5] = v128_xor( state[5], v128_add64( in[5], inout[5] ) );

        LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                        state[4], state[5], state[6], state[7] );

        out[0] = v128_xor( state[0], in[0] );
        out[1] = v128_xor( state[1], in[1] );
        out[2] = v128_xor( state[2], in[2] );
        out[3] = v128_xor( state[3], in[3] );
        out[4] = v128_xor( state[4], in[4] );
        out[5] = v128_xor( state[5], in[5] );

        inout[0] = v128_xor( inout[0], v128_alignr64( state[0], state[5], 1 ) );
        inout[1] = v128_xor( inout[1], v128_alignr64( state[1], state[0], 1 ) );
        inout[2] = v128_xor( inout[2], v128_alignr64( state[2], state[1], 1 ) );
        inout[3] = v128_xor( inout[3], v128_alignr64( state[3], state[2], 1 ) );
        inout[4] = v128_xor( inout[4], v128_alignr64( state[4], state[3], 1 ) );
        inout[5] = v128_xor( inout[5], v128_alignr64( state[5], state[4], 1 ) );

        inout += BLOCK_LEN_128;
        in    += BLOCK_LEN_128;
        out   -= BLOCK_LEN_128;
    }

#else

    uint64_t* ptrWordIn    = rowIn;
    uint64_t* ptrWordInOut = rowInOut;
    uint64_t* ptrWordOut   = rowOut + (nCols-1)*BLOCK_LEN_INT64;

    for ( i = 0; i < nCols; i++ )
    {
       State[ 0] ^= ( ptrWordIn[ 0] + ptrWordInOut[ 0] );
       State[ 1] ^= ( ptrWordIn[ 1] + ptrWordInOut[ 1] );
       State[ 2] ^= ( ptrWordIn[ 2] + ptrWordInOut[ 2] );
       State[ 3] ^= ( ptrWordIn[ 3] + ptrWordInOut[ 3] );
       State[ 4] ^= ( ptrWordIn[ 4] + ptrWordInOut[ 4] );
       State[ 5] ^= ( ptrWordIn[ 5] + ptrWordInOut[ 5] );
       State[ 6] ^= ( ptrWordIn[ 6] + ptrWordInOut[ 6] );
       State[ 7] ^= ( ptrWordIn[ 7] + ptrWordInOut[ 7] );
       State[ 8] ^= ( ptrWordIn[ 8] + ptrWordInOut[ 8] );
       State[ 9] ^= ( ptrWordIn[ 9] + ptrWordInOut[ 9] );
       State[10] ^= ( ptrWordIn[10] + ptrWordInOut[10] );
       State[11] ^= ( ptrWordIn[11] + ptrWordInOut[11] );

       reducedBlake2bLyra( State );

       ptrWordOut[ 0] = ptrWordIn[ 0] ^ State[0];
       ptrWordOut[ 1] = ptrWordIn[ 1] ^ State[1];
       ptrWordOut[ 2] = ptrWordIn[ 2] ^ State[2];
       ptrWordOut[ 3] = ptrWordIn[ 3] ^ State[3];
       ptrWordOut[ 4] = ptrWordIn[ 4] ^ State[4];
       ptrWordOut[ 5] = ptrWordIn[ 5] ^ State[5];
       ptrWordOut[ 6] = ptrWordIn[ 6] ^ State[6];
       ptrWordOut[ 7] = ptrWordIn[ 7] ^ State[7];
       ptrWordOut[ 8] = ptrWordIn[ 8] ^ State[8];
       ptrWordOut[ 9] = ptrWordIn[ 9] ^ State[9];
       ptrWordOut[10] = ptrWordIn[10] ^ State[10];
       ptrWordOut[11] = ptrWordIn[11] ^ State[11];

       ptrWordInOut[ 0] ^= State[11];
       ptrWordInOut[ 1] ^= State[ 0];
       ptrWordInOut[ 2] ^= State[ 1];
       ptrWordInOut[ 3] ^= State[ 2];
       ptrWordInOut[ 4] ^= State[ 3];
       ptrWordInOut[ 5] ^= State[ 4];
       ptrWordInOut[ 6] ^= State[ 5];
       ptrWordInOut[ 7] ^= State[ 6];
       ptrWordInOut[ 8] ^= State[ 7];
       ptrWordInOut[ 9] ^= State[ 8];
       ptrWordInOut[10] ^= State[ 9];
       ptrWordInOut[11] ^= State[10];

       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn    += BLOCK_LEN_INT64;
       ptrWordOut   -= BLOCK_LEN_INT64;
    }
#endif
}

inline void reducedDuplexRow( uint64_t *State, uint64_t *rowIn,
                    uint64_t *rowInOut, uint64_t *rowOut, uint64_t nCols )
{
    int i;

#if defined __AVX2__

   register __m256i state0, state1, state2, state3;
   __m256i* in    = (__m256i*)rowIn;
   __m256i* inout = (__m256i*)rowInOut;
   __m256i* out   = (__m256i*)rowOut;
   __m256i  t0, t1, t2;

   state0 = _mm256_load_si256( (__m256i*)State     );
   state1 = _mm256_load_si256( (__m256i*)State + 1 );
   state2 = _mm256_load_si256( (__m256i*)State + 2 );
   state3 = _mm256_load_si256( (__m256i*)State + 3 );

   for ( i = 0; i < 9; i += 3)
   {
       _mm_prefetch( in    + i,     _MM_HINT_T0 );
       _mm_prefetch( in    + i + 2, _MM_HINT_T0 );
       _mm_prefetch( out   + i,     _MM_HINT_T0 );
       _mm_prefetch( out   + i + 2, _MM_HINT_T0 );
       _mm_prefetch( inout + i,     _MM_HINT_T0 );
       _mm_prefetch( inout + i + 2, _MM_HINT_T0 );
   }

   for ( i = 0; i < nCols; i++ )
   {
      _mm_prefetch( in    +  9, _MM_HINT_T0 );
      _mm_prefetch( in    + 11, _MM_HINT_T0 );
      _mm_prefetch( out   +  9, _MM_HINT_T0 );
      _mm_prefetch( out   + 11, _MM_HINT_T0 );
      _mm_prefetch( inout +  9, _MM_HINT_T0 );
      _mm_prefetch( inout + 11, _MM_HINT_T0 );

      state0 = _mm256_xor_si256( state0, _mm256_add_epi64( in[0], inout[0] ) );
      state1 = _mm256_xor_si256( state1, _mm256_add_epi64( in[1], inout[1] ) );
      state2 = _mm256_xor_si256( state2, _mm256_add_epi64( in[2], inout[2] ) );

      LYRA_ROUND_AVX2( state0, state1, state2, state3 );

      out[0] = _mm256_xor_si256( out[0], state0 );
      out[1] = _mm256_xor_si256( out[1], state1 );
      out[2] = _mm256_xor_si256( out[2], state2 );

      t0 = _mm256_permute4x64_epi64( state0, 0x93 );
      t1 = _mm256_permute4x64_epi64( state1, 0x93 );
      t2 = _mm256_permute4x64_epi64( state2, 0x93 );

      inout[0] = _mm256_xor_si256( inout[0],
                                   _mm256_blend_epi32( t0, t2, 0x03 ) );
      inout[1] = _mm256_xor_si256( inout[1],
                                   _mm256_blend_epi32( t1, t0, 0x03 ) );
      inout[2] = _mm256_xor_si256( inout[2],
                                   _mm256_blend_epi32( t2, t1, 0x03 ) );

      in    += BLOCK_LEN_256;
      out   += BLOCK_LEN_256;
      inout += BLOCK_LEN_256;
   }

   _mm256_store_si256( (__m256i*)State,     state0 );
   _mm256_store_si256( (__m256i*)State + 1, state1 );
   _mm256_store_si256( (__m256i*)State + 2, state2 );
   _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__) || defined(__ARM_NEON)

    v128u64_t* state = (v128u64_t*)State;
    v128u64_t* in    = (v128u64_t*)rowIn;
    v128u64_t* inout = (v128u64_t*)rowInOut;
    v128u64_t* out   = (v128u64_t*)rowOut;

    for ( i = 0; i < nCols; i++)
    {
       state[0] = v128_xor( state[0], v128_add64( in[0], inout[0] ) );
       state[1] = v128_xor( state[1], v128_add64( in[1], inout[1] ) );
       state[2] = v128_xor( state[2], v128_add64( in[2], inout[2] ) );
       state[3] = v128_xor( state[3], v128_add64( in[3], inout[3] ) );
       state[4] = v128_xor( state[4], v128_add64( in[4], inout[4] ) );
       state[5] = v128_xor( state[5], v128_add64( in[5], inout[5] ) );

      LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                      state[4], state[5], state[6], state[7] );

      out[0] = v128_xor( state[0], out[0] );
      out[1] = v128_xor( state[1], out[1] );
      out[2] = v128_xor( state[2], out[2] );
      out[3] = v128_xor( state[3], out[3] );
      out[4] = v128_xor( state[4], out[4] );
      out[5] = v128_xor( state[5], out[5] );

      inout[0] = v128_xor( inout[0], v128_alignr64( state[0], state[5], 1 ) );
      inout[1] = v128_xor( inout[1], v128_alignr64( state[1], state[0], 1 ) );
      inout[2] = v128_xor( inout[2], v128_alignr64( state[2], state[1], 1 ) );
      inout[3] = v128_xor( inout[3], v128_alignr64( state[3], state[2], 1 ) );
      inout[4] = v128_xor( inout[4], v128_alignr64( state[4], state[3], 1 ) );
      inout[5] = v128_xor( inout[5], v128_alignr64( state[5], state[4], 1 ) );
 
      out   += BLOCK_LEN_128;
      inout += BLOCK_LEN_128;
      in    += BLOCK_LEN_128;
    }

#else

    uint64_t* ptrWordInOut = rowInOut;
    uint64_t* ptrWordIn    = rowIn;
    uint64_t* ptrWordOut   = rowOut;

    for ( i = 0; i < nCols; i++)
    {
       State[ 0] ^= ( ptrWordIn[ 0] + ptrWordInOut[ 0] );
       State[ 1] ^= ( ptrWordIn[ 1] + ptrWordInOut[ 1] );
       State[ 2] ^= ( ptrWordIn[ 2] + ptrWordInOut[ 2] );
       State[ 3] ^= ( ptrWordIn[ 3] + ptrWordInOut[ 3] );
       State[ 4] ^= ( ptrWordIn[ 4] + ptrWordInOut[ 4] );
       State[ 5] ^= ( ptrWordIn[ 5] + ptrWordInOut[ 5] );
       State[ 6] ^= ( ptrWordIn[ 6] + ptrWordInOut[ 6] );
       State[ 7] ^= ( ptrWordIn[ 7] + ptrWordInOut[ 7] );
       State[ 8] ^= ( ptrWordIn[ 8] + ptrWordInOut[ 8] );
       State[ 9] ^= ( ptrWordIn[ 9] + ptrWordInOut[ 9] );
       State[10] ^= ( ptrWordIn[10] + ptrWordInOut[10] );
       State[11] ^= ( ptrWordIn[11] + ptrWordInOut[11] );

       reducedBlake2bLyra( State);

       ptrWordOut[ 0] ^= State[ 0];
       ptrWordOut[ 1] ^= State[ 1];
       ptrWordOut[ 2] ^= State[ 2];
       ptrWordOut[ 3] ^= State[ 3];
       ptrWordOut[ 4] ^= State[ 4];
       ptrWordOut[ 5] ^= State[ 5];
       ptrWordOut[ 6] ^= State[ 6];
       ptrWordOut[ 7] ^= State[ 7];
       ptrWordOut[ 8] ^= State[ 8];
       ptrWordOut[ 9] ^= State[ 9];
       ptrWordOut[10] ^= State[10];
       ptrWordOut[11] ^= State[11];

       ptrWordInOut[ 0] ^= State[11];
       ptrWordInOut[ 1] ^= State[ 0];
       ptrWordInOut[ 2] ^= State[ 1];
       ptrWordInOut[ 3] ^= State[ 2];
       ptrWordInOut[ 4] ^= State[ 3];
       ptrWordInOut[ 5] ^= State[ 4];
       ptrWordInOut[ 6] ^= State[ 5];
       ptrWordInOut[ 7] ^= State[ 6];
       ptrWordInOut[ 8] ^= State[ 7];
       ptrWordInOut[ 9] ^= State[ 8];
       ptrWordInOut[10] ^= State[ 9];
       ptrWordInOut[11] ^= State[10];

       ptrWordOut   += BLOCK_LEN_INT64;
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn    += BLOCK_LEN_INT64;
    }
#endif
}


