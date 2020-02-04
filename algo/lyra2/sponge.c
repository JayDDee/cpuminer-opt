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
#include <immintrin.h>
#include "sponge.h"
#include "lyra2.h"


/**
 * Initializes the Sponge State. The first 512 bits are set to zeros and the remainder
 * receive Blake2b's IV as per Blake2b's specification. <b>Note:</b> Even though sponges
 * typically have their internal state initialized with zeros, Blake2b's G function
 * has a fixed point: if the internal state and message are both filled with zeros. the
 * resulting permutation will always be a block filled with zeros; this happens because
 * Blake2b does not use the constants originally employed in Blake2 inside its G function,
 * relying on the IV for avoiding possible fixed points.
 *
 * @param state         The 1024-bit array to be initialized
 */
inline void initState( uint64_t State[/*16*/] )
{

   /*
#if defined (__AVX2__)

  __m256i* state = (__m256i*)State;
  const __m256i zero = m256_zero; 
  state[0] = zero;
  state[1] = zero;
  state[2] = m256_const_64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                            0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state[3] = m256_const_64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
                            0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );

#elif defined (__SSE2__)

  __m128i* state = (__m128i*)State;
  const __m128i zero = m128_zero;   

  state[0] = zero;
  state[1] = zero;
  state[2] = zero;
  state[3] = zero;
  state[4] = m128_const_64( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state[5] = m128_const_64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
  state[6] = m128_const_64( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
  state[7] = m128_const_64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

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

/**
 * Execute Blake2b's G function, with all 12 rounds.
 *
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */

#if !defined(__AVX512F__) && !defined(__AVX2__) && !defined(__SSE2__)

inline static void blake2bLyra( uint64_t *v )
{
    ROUND_LYRA(0);
    ROUND_LYRA(1);
    ROUND_LYRA(2);
    ROUND_LYRA(3);
    ROUND_LYRA(4);
    ROUND_LYRA(5);
    ROUND_LYRA(6);
    ROUND_LYRA(7);
    ROUND_LYRA(8);
    ROUND_LYRA(9);
    ROUND_LYRA(10);
    ROUND_LYRA(11);
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
inline static void reducedBlake2bLyra( uint64_t *v )
{
    ROUND_LYRA(0);
}

#endif

/**
 * Performs a squeeze operation, using Blake2b's G function as the
 * internal permutation
 *
 * @param state      The current state of the sponge
 * @param out        Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
inline void squeeze( uint64_t *State, byte *Out, unsigned int len )
{
#if defined (__AVX2__)

    const int len_m256i = len / 32;
    const int fullBlocks = len_m256i / BLOCK_LEN_M256I;
    __m256i* state = (__m256i*)State;
    __m256i* out   = (__m256i*)Out;
    int i;

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy_256( out, state, BLOCK_LEN_M256I );
       LYRA_ROUND_AVX2( state[0], state[1], state[2], state[3] );
       out += BLOCK_LEN_M256I;
    }
    //Squeezes remaining bytes
    memcpy_256( out, state, ( len_m256i % BLOCK_LEN_M256I ) );

#elif defined (__SSE2__)

    const int len_m128i = len / 16;
    const int fullBlocks = len_m128i / BLOCK_LEN_M128I;
    __m128i* state = (__m128i*)State;
    __m128i* out   = (__m128i*)Out;
    int i;

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy_128( out, state, BLOCK_LEN_M128I );
       LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                       state[4], state[5], state[6], state[7] );
       out += BLOCK_LEN_M128I;
    }
    //Squeezes remaining bytes
    memcpy_128( out, state, ( len_m128i % BLOCK_LEN_M128I ) );

#else

    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *out = Out;
    int i;

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy( out, State, BLOCK_LEN_BYTES );
       blake2bLyra( State );
       out += BLOCK_LEN_BYTES;
    }
    //Squeezes remaining bytes
    memcpy( out, State, (len % BLOCK_LEN_BYTES) );

#endif
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 *
 * @param state The current state of the sponge
 * @param in    The block to be absorbed (BLOCK_LEN_INT64 words)
 */
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

#elif defined (__SSE2__)

    __m128i* state = (__m128i*)State;
    __m128i* in    = (__m128i*)In;

    state[0] = _mm_xor_si128( state[0], in[0] );
    state[1] = _mm_xor_si128( state[1], in[1] );
    state[2] = _mm_xor_si128( state[2], in[2] );
    state[3] = _mm_xor_si128( state[3], in[3] );
    state[4] = _mm_xor_si128( state[4], in[4] );
    state[5] = _mm_xor_si128( state[5], in[5] );

    //Applies the transformation f to the sponge's state
    LYRA_12_ROUNDS_AVX( state[0], state[1], state[2], state[3],
                        state[4], state[5], state[6], state[7] );

#else

    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    State[0]  ^= In[0];
    State[1]  ^= In[1];
    State[2]  ^= In[2];
    State[3]  ^= In[3];
    State[4]  ^= In[4];
    State[5]  ^= In[5];
    State[6]  ^= In[6];
    State[7]  ^= In[7];
    State[8]  ^= In[8];
    State[9]  ^= In[9];
    State[10] ^= In[10];
    State[11] ^= In[11];

    //Applies the transformation f to the sponge's state
    blake2bLyra(State);

#endif
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_BLAKE2_SAFE_INT64
 * words of type uint64_t), using Blake2b's G function as the internal permutation
 *
 * @param state The current state of the sponge
 * @param in    The block to be absorbed (BLOCK_LEN_BLAKE2_SAFE_INT64 words)
 */
inline void absorbBlockBlake2Safe( uint64_t *State, const uint64_t *In,
                      const uint64_t nBlocks, const uint64_t block_len )
{
// XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with
// the IV.
#if defined (__AVX2__)

  register __m256i state0, state1, state2, state3;

  state0 = 
  state1 = m256_zero;
  state2 = m256_const_64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
                          0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state3 = m256_const_64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
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

#elif defined (__SSE2__)

  __m128i state0, state1, state2, state3, state4, state5, state6, state7;

  state0 = 
  state1 =
  state2 =
  state3 = m128_zero;
  state4 = m128_const_64( 0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL );
  state5 = m128_const_64( 0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL );
  state6 = m128_const_64( 0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL );
  state7 = m128_const_64( 0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL );

  for ( int i = 0; i < nBlocks; i++ )
  { 
    __m128i* in    = (__m128i*)In;

    state0 = _mm_xor_si128( state0, in[0] );
    state1 = _mm_xor_si128( state1, in[1] );
    state2 = _mm_xor_si128( state2, in[2] );
    state3 = _mm_xor_si128( state3, in[3] );

    //Applies the transformation f to the sponge's state
    LYRA_12_ROUNDS_AVX( state0, state1, state2, state3,
                        state4, state5, state6, state7 );
    In += block_len;
  }

  _mm_store_si128( (__m128i*)State,     state0 );
  _mm_store_si128( (__m128i*)State + 1, state1 );
  _mm_store_si128( (__m128i*)State + 2, state2 );
  _mm_store_si128( (__m128i*)State + 3, state3 );
  _mm_store_si128( (__m128i*)State + 4, state4 );
  _mm_store_si128( (__m128i*)State + 5, state5 );
  _mm_store_si128( (__m128i*)State + 6, state6 );
  _mm_store_si128( (__m128i*)State + 7, state7 );
  
#else

    State[0] ^= In[0];
    State[1] ^= In[1];
    State[2] ^= In[2];
    State[3] ^= In[3];
    State[4] ^= In[4];
    State[5] ^= In[5];
    State[6] ^= In[6];
    State[7] ^= In[7];

    //Applies the transformation f to the sponge's state
    blake2bLyra(State);
#endif

}

/**
 * Performs a reduced squeeze operation for a single row, from the highest to
 * the lowest index, using the reduced-round Blake2b's G function as the
 * internal permutation
 *
 * @param state     The current state of the sponge
 * @param rowOut    Row to receive the data squeezed
 */
inline void reducedSqueezeRow0( uint64_t* State, uint64_t* rowOut,
                                uint64_t nCols )
{
    int i;

    //M[row][C-1-col] = H.reduced_squeeze()

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );

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

//printf("S RSR0 col= %d, out= %x\n",i,out);


       out[0] = state0;
       out[1] = state1;
       out[2] = state2;

       //Goes to next block (column) that will receive the squeezed data
       out -= BLOCK_LEN_M256I;

       LYRA_ROUND_AVX2( state0, state1, state2, state3 );
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__)

    __m128i* state = (__m128i*)State;
    __m128i  state0 = _mm_load_si128(  state    );
    __m128i  state1 = _mm_load_si128( &state[1] );
    __m128i  state2 = _mm_load_si128( &state[2] );
    __m128i  state3 = _mm_load_si128( &state[3] );
    __m128i  state4 = _mm_load_si128( &state[4] );
    __m128i  state5 = _mm_load_si128( &state[5] );
    __m128i  state6 = _mm_load_si128( &state[6] );
    __m128i  state7 = _mm_load_si128( &state[7] );

    __m128i* out   = (__m128i*)rowOut + ( (nCols-1) * BLOCK_LEN_M128I );

    for ( i = 0; i < 6; i += 3)
    {
        _mm_prefetch( out - i,     _MM_HINT_T0 );
        _mm_prefetch( out - i - 2, _MM_HINT_T0 );
    }

    for ( i = 0; i < nCols; i++ )
    {
       _mm_prefetch( out - 6, _MM_HINT_T0 );
       _mm_prefetch( out - 7, _MM_HINT_T0 );

       out[0] = state0;
       out[1] = state1;
       out[2] = state2;
       out[3] = state3;
       out[4] = state4;
       out[5] = state5;

       //Goes to next block (column) that will receive the squeezed data
       out -= BLOCK_LEN_M128I;

       //Applies the reduced-round transformation f to the sponge's state
       LYRA_ROUND_AVX( state0, state1, state2, state3,
                       state4, state5, state6, state7 );
    }

   _mm_store_si128( state,     state0 );
   _mm_store_si128( &state[1], state1 );
   _mm_store_si128( &state[2], state2 );
   _mm_store_si128( &state[3], state3 );
   _mm_store_si128( &state[4], state4 );
   _mm_store_si128( &state[5], state5 );
   _mm_store_si128( &state[6], state6 );
   _mm_store_si128( &state[7], state7 );

#else

    uint64_t* ptrWord = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to M[0][C-1]

    for ( i = 0; i < nCols; i++ )
    {
       ptrWord[0]  = State[0];
       ptrWord[1]  = State[1];
       ptrWord[2]  = State[2];
       ptrWord[3]  = State[3];
       ptrWord[4]  = State[4];
       ptrWord[5]  = State[5];
       ptrWord[6]  = State[6];
       ptrWord[7]  = State[7];
       ptrWord[8]  = State[8];
       ptrWord[9]  = State[9];
       ptrWord[10] = State[10];
       ptrWord[11] = State[11];

       //Goes to next block (column) that will receive the squeezed data
       ptrWord -= BLOCK_LEN_INT64;

       //Applies the reduced-round transformation f to the sponge's state
       reducedBlake2bLyra( State);
    }
#endif
}

/**
 * Performs a reduced duplex operation for a single row, from the highest to
 * the lowest index, using the reduced-round Blake2b's G function as the
 * internal permutation
 *
 * @param state		The current state of the sponge
 * @param rowIn		Row to feed the sponge
 * @param rowOut	Row to receive the sponge's output
 */
inline void reducedDuplexRow1( uint64_t *State, uint64_t *rowIn,
                               uint64_t *rowOut, uint64_t nCols )
{
    int i;

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* in    = (__m256i*)rowIn;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );

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

         //Input: next column (i.e., next block in sequence)
         in += BLOCK_LEN_M256I;
         //Output: goes to previous column
         out -= BLOCK_LEN_M256I;
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__)

    __m128i* state = (__m128i*)State;
    __m128i  state0 = _mm_load_si128(  state    );
    __m128i  state1 = _mm_load_si128( &state[1] );
    __m128i  state2 = _mm_load_si128( &state[2] );
    __m128i  state3 = _mm_load_si128( &state[3] );
    __m128i  state4 = _mm_load_si128( &state[4] );
    __m128i  state5 = _mm_load_si128( &state[5] );
    __m128i  state6 = _mm_load_si128( &state[6] );
    __m128i  state7 = _mm_load_si128( &state[7] );

    __m128i*  in   = (__m128i*)rowIn;
    __m128i* out   = (__m128i*)rowOut + ( (nCols-1) * BLOCK_LEN_M128I );

    for ( i = 0; i < 6; i += 3)
    {
        _mm_prefetch( in  + i,     _MM_HINT_T0 );
        _mm_prefetch( in  + i + 2, _MM_HINT_T0 );
        _mm_prefetch( out - i,     _MM_HINT_T0 );
        _mm_prefetch( out - i - 2, _MM_HINT_T0 );
    }

    for ( i = 0; i < nCols; i++ )
    {
         _mm_prefetch( in  - 6, _MM_HINT_T0 );
         _mm_prefetch( in  - 7, _MM_HINT_T0 );
         _mm_prefetch( out - 6, _MM_HINT_T0 );
         _mm_prefetch( out - 7, _MM_HINT_T0 );

         state0 = _mm_xor_si128( state0, in[0] );
         state1 = _mm_xor_si128( state1, in[1] );
         state2 = _mm_xor_si128( state2, in[2] );
         state3 = _mm_xor_si128( state3, in[3] );
         state4 = _mm_xor_si128( state4, in[4] );
         state5 = _mm_xor_si128( state5, in[5] );

        //Applies the reduced-round transformation f to the sponge's state
        LYRA_ROUND_AVX( state0, state1, state2, state3,
                        state4, state5, state6, state7 );

         out[0] = _mm_xor_si128( state0, in[0] );
         out[1] = _mm_xor_si128( state1, in[1] );
         out[2] = _mm_xor_si128( state2, in[2] );
         out[3] = _mm_xor_si128( state3, in[3] );
         out[4] = _mm_xor_si128( state4, in[4] );
         out[5] = _mm_xor_si128( state5, in[5] );

         //Input: next column (i.e., next block in sequence)
         in += BLOCK_LEN_M128I;
         //Output: goes to previous column
         out -= BLOCK_LEN_M128I;
    }

   _mm_store_si128( state,     state0 );
   _mm_store_si128( &state[1], state1 );
   _mm_store_si128( &state[2], state2 );
   _mm_store_si128( &state[3], state3 );
   _mm_store_si128( &state[4], state4 );
   _mm_store_si128( &state[5], state5 );
   _mm_store_si128( &state[6], state6 );
   _mm_store_si128( &state[7], state7 );

#else

    uint64_t* ptrWordIn = rowIn;        //In Lyra2: pointer to prev
    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to row

    for ( i = 0; i < nCols; i++ )
    {

        //Absorbing "M[prev][col]"
        State[0]  ^= (ptrWordIn[0]);
        State[1]  ^= (ptrWordIn[1]);
        State[2]  ^= (ptrWordIn[2]);
        State[3]  ^= (ptrWordIn[3]);
        State[4]  ^= (ptrWordIn[4]);
        State[5]  ^= (ptrWordIn[5]);
        State[6]  ^= (ptrWordIn[6]);
        State[7]  ^= (ptrWordIn[7]);
        State[8]  ^= (ptrWordIn[8]);
        State[9]  ^= (ptrWordIn[9]);
        State[10] ^= (ptrWordIn[10]);
        State[11] ^= (ptrWordIn[11]);

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra( State );

        //M[row][C-1-col] = M[prev][col] XOR rand
        ptrWordOut[0]  = ptrWordIn[0]  ^ State[0];
        ptrWordOut[1]  = ptrWordIn[1]  ^ State[1];
        ptrWordOut[2]  = ptrWordIn[2]  ^ State[2];
        ptrWordOut[3]  = ptrWordIn[3]  ^ State[3];
        ptrWordOut[4]  = ptrWordIn[4]  ^ State[4];
        ptrWordOut[5]  = ptrWordIn[5]  ^ State[5];
        ptrWordOut[6]  = ptrWordIn[6]  ^ State[6];
        ptrWordOut[7]  = ptrWordIn[7]  ^ State[7];
        ptrWordOut[8]  = ptrWordIn[8]  ^ State[8];
        ptrWordOut[9]  = ptrWordIn[9]  ^ State[9];
        ptrWordOut[10] = ptrWordIn[10] ^ State[10];
        ptrWordOut[11] = ptrWordIn[11] ^ State[11];

       //Input: next column (i.e., next block in sequence)
       ptrWordIn += BLOCK_LEN_INT64;
       //Output: goes to previous column
       ptrWordOut -= BLOCK_LEN_INT64;

   }
#endif
}

/**
 * Performs a duplexing operation over "M[rowInOut][col] [+] M[rowIn][col]" (i.e.,
 * the wordwise addition of two columns, ignoring carries between words). The
 * output of this operation, "rand", is then used to make
 * "M[rowOut][(N_COLS-1)-col] = M[rowIn][col] XOR rand" and
 * "M[rowInOut][col] =  M[rowInOut][col] XOR rotW(rand)", where rotW is a 64-bit
 * rotation to the left and N_COLS is a system parameter.
 *
 * @param state          The current state of the sponge
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 *
 */
inline void reducedDuplexRowSetup( uint64_t *State, uint64_t *rowIn,
                                   uint64_t *rowInOut, uint64_t *rowOut,
                                   uint64_t nCols )
{
    int i;

#if defined (__AVX2__)

    register __m256i state0, state1, state2, state3;
    __m256i* in    = (__m256i*)rowIn;
    __m256i* inout = (__m256i*)rowInOut;
    __m256i* out   = (__m256i*)rowOut + ( (nCols-1) * BLOCK_LEN_M256I );
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

/*
printf("s duplexsetup col= %d\n",i); 
uint64_t * o = (uint64_t*)out;
printf("S out %016lx %016lx %016lx %016lx\n",o[0],o[1],o[2],o[3]);
printf("S out %016lx %016lx %016lx %016lx\n",o[4],o[5],o[6],o[7]);
printf("S out %016lx %016lx %016lx %016lx\n",o[8],o[9],o[10],o[11]);
printf("S out %016lx %016lx %016lx %016lx\n",o[12],o[13],o[14],o[15]);
printf("S out %016lx %016lx %016lx %016lx\n",o[16],o[17],o[18],o[19]);
printf("S out %016lx %016lx %016lx %016lx\n",o[20],o[21],o[22],o[23]);
*/

       //M[row*][col] = M[row*][col] XOR rotW(rand)
       t0 = _mm256_permute4x64_epi64( state0, 0x93 );
       t1 = _mm256_permute4x64_epi64( state1, 0x93 );
       t2 = _mm256_permute4x64_epi64( state2, 0x93 );

/*
uint64_t *t = (uint64_t*)&t0;
printf("S t0 %016lx %016lx %016lx %016lx\n",t[0],t[1],t[2],t[3]);

o = (uint64_t*)inout;
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[0],o[1],o[2],o[3]);
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[4],o[5],o[6],o[7]);
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[8],o[9],o[10],o[11]);
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[12],o[13],o[14],o[15]);
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[16],o[17],o[18],o[19]);
printf("S inout0 %016lx %016lx %016lx %016lx\n",o[20],o[21],o[22],o[23]);
*/       
       inout[0] = _mm256_xor_si256( inout[0],
                                    _mm256_blend_epi32( t0, t2, 0x03 ) );
       inout[1] = _mm256_xor_si256( inout[1],
                                    _mm256_blend_epi32( t1, t0, 0x03 ) );
       inout[2] = _mm256_xor_si256( inout[2],
                                    _mm256_blend_epi32( t2, t1, 0x03 ) );

/*
o = (uint64_t*)inout;
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[0],o[1],o[2],o[3]);
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[4],o[5],o[6],o[7]);
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[8],o[9],o[10],o[11]);
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[12],o[13],o[14],o[15]);
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[16],o[17],o[18],o[19]);
printf("S inout1 %016lx %016lx %016lx %016lx\n",o[20],o[21],o[22],o[23]);
*/

//Inputs: next column (i.e., next block in sequence)
       in    += BLOCK_LEN_M256I;
       inout += BLOCK_LEN_M256I;
       //Output: goes to previous column
       out   -= BLOCK_LEN_M256I;
    }

    _mm256_store_si256( (__m256i*)State,     state0 );
    _mm256_store_si256( (__m256i*)State + 1, state1 );
    _mm256_store_si256( (__m256i*)State + 2, state2 );
    _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__)

    __m128i* in    = (__m128i*)rowIn;
    __m128i* inout = (__m128i*)rowInOut;
    __m128i* out   = (__m128i*)rowOut + ( (nCols-1) * BLOCK_LEN_M128I );

    for ( i = 0; i < 6; i += 3)
    {
        _mm_prefetch( in    + i,     _MM_HINT_T0 );
        _mm_prefetch( in    + i + 2, _MM_HINT_T0 );
        _mm_prefetch( inout + i,     _MM_HINT_T0 );
        _mm_prefetch( inout + i + 2, _MM_HINT_T0 );
        _mm_prefetch( out   - i,     _MM_HINT_T0 );
        _mm_prefetch( out   - i - 2, _MM_HINT_T0 );
    }

    __m128i* state = (__m128i*)State;

    // For the last round in this function not optimized for AVX
//    uint64_t* ptrWordIn = rowIn;        //In Lyra2: pointer to prev
//    uint64_t* ptrWordInOut = rowInOut;  //In Lyra2: pointer to row*
//    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to row

    for ( i = 0; i < nCols; i++ )
    {
       _mm_prefetch( in    + 6, _MM_HINT_T0 );
       _mm_prefetch( in    + 7, _MM_HINT_T0 );
       _mm_prefetch( inout + 6, _MM_HINT_T0 );
       _mm_prefetch( inout + 7, _MM_HINT_T0 );
       _mm_prefetch( out   - 6, _MM_HINT_T0 );
       _mm_prefetch( out   - 7, _MM_HINT_T0 );

        state[0] = _mm_xor_si128( state[0],
                                  _mm_add_epi64( in[0], inout[0] ) );
        state[1] = _mm_xor_si128( state[1],
                                  _mm_add_epi64( in[1], inout[1] ) );
        state[2] = _mm_xor_si128( state[2],
                                  _mm_add_epi64( in[2], inout[2] ) );
        state[3] = _mm_xor_si128( state[3],
                                  _mm_add_epi64( in[3], inout[3] ) );
        state[4] = _mm_xor_si128( state[4],
                                  _mm_add_epi64( in[4], inout[4] ) );
        state[5] = _mm_xor_si128( state[5],
                                  _mm_add_epi64( in[5], inout[5] ) );

        //Applies the reduced-round transformation f to the sponge's state
        LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                        state[4], state[5], state[6], state[7] );

        out[0] = _mm_xor_si128( state[0], in[0] );
        out[1] = _mm_xor_si128( state[1], in[1] );
        out[2] = _mm_xor_si128( state[2], in[2] );
        out[3] = _mm_xor_si128( state[3], in[3] );
        out[4] = _mm_xor_si128( state[4], in[4] );
        out[5] = _mm_xor_si128( state[5], in[5] );


       __m128i t0, t1;
       t0 = _mm_srli_si128( state[0], 8 );
       t1 = _mm_srli_si128( state[1], 8 );
       inout[0] = _mm_xor_si128( inout[0],
                              _mm_or_si128( _mm_slli_si128( state[0], 8 ),
                                            _mm_srli_si128( state[5], 8 ) ) );
       inout[1] = _mm_xor_si128( inout[1],
                        _mm_or_si128( _mm_slli_si128( state[1], 8 ), t0 ) );
       t0 = _mm_srli_si128( state[2], 8 );
       inout[2] = _mm_xor_si128( inout[2],
                        _mm_or_si128( _mm_slli_si128( state[2], 8 ), t1 ) );
       t1 = _mm_srli_si128( state[3], 8 );
       inout[3] = _mm_xor_si128( inout[3],
                        _mm_or_si128( _mm_slli_si128( state[3], 8 ), t0 ) );
       t0 = _mm_srli_si128( state[4], 8 );
       inout[4] = _mm_xor_si128( inout[4],
                        _mm_or_si128( _mm_slli_si128( state[4], 8 ), t1 ) );
       inout[5] = _mm_xor_si128( inout[5],
                        _mm_or_si128( _mm_slli_si128( state[5], 8 ), t0 ) );

/*
        ptrWordInOut[0]  ^= State[11];
        ptrWordInOut[1]  ^= State[0];
        ptrWordInOut[2]  ^= State[1];
        ptrWordInOut[3]  ^= State[2];
        ptrWordInOut[4]  ^= State[3];
        ptrWordInOut[5]  ^= State[4];
        ptrWordInOut[6]  ^= State[5];
        ptrWordInOut[7]  ^= State[6];
        ptrWordInOut[8]  ^= State[7];
        ptrWordInOut[9]  ^= State[8];
        ptrWordInOut[10] ^= State[9];
        ptrWordInOut[11] ^= State[10];

        //Inputs: next column (i.e., next block in sequence)
        ptrWordInOut += BLOCK_LEN_INT64;
        ptrWordIn += BLOCK_LEN_INT64;
        //Output: goes to previous column
        ptrWordOut -= BLOCK_LEN_INT64;
*/
        inout += BLOCK_LEN_M128I;
        in    += BLOCK_LEN_M128I;
        out   -= BLOCK_LEN_M128I;
    }

#else

    uint64_t* ptrWordIn = rowIn;        //In Lyra2: pointer to prev
    uint64_t* ptrWordInOut = rowInOut;  //In Lyra2: pointer to row*
    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to row

    for ( i = 0; i < nCols; i++ )
    {

       //Absorbing "M[prev] [+] M[row*]"
       State[0]  ^= (ptrWordIn[0]  + ptrWordInOut[0]);
       State[1]  ^= (ptrWordIn[1]  + ptrWordInOut[1]);
       State[2]  ^= (ptrWordIn[2]  + ptrWordInOut[2]);
       State[3]  ^= (ptrWordIn[3]  + ptrWordInOut[3]);
       State[4]  ^= (ptrWordIn[4]  + ptrWordInOut[4]);
       State[5]  ^= (ptrWordIn[5]  + ptrWordInOut[5]);
       State[6]  ^= (ptrWordIn[6]  + ptrWordInOut[6]);
       State[7]  ^= (ptrWordIn[7]  + ptrWordInOut[7]);
       State[8]  ^= (ptrWordIn[8]  + ptrWordInOut[8]);
       State[9]  ^= (ptrWordIn[9]  + ptrWordInOut[9]);
       State[10] ^= (ptrWordIn[10] + ptrWordInOut[10]);
       State[11] ^= (ptrWordIn[11] + ptrWordInOut[11]);

       //Applies the reduced-round transformation f to the sponge's state
       reducedBlake2bLyra( State );

       //M[row][col] = M[prev][col] XOR rand
       ptrWordOut[0]  = ptrWordIn[0]  ^ State[0];
       ptrWordOut[1]  = ptrWordIn[1]  ^ State[1];
       ptrWordOut[2]  = ptrWordIn[2]  ^ State[2];
       ptrWordOut[3]  = ptrWordIn[3]  ^ State[3];
       ptrWordOut[4]  = ptrWordIn[4]  ^ State[4];
       ptrWordOut[5]  = ptrWordIn[5]  ^ State[5];
       ptrWordOut[6]  = ptrWordIn[6]  ^ State[6];
       ptrWordOut[7]  = ptrWordIn[7]  ^ State[7];
       ptrWordOut[8]  = ptrWordIn[8]  ^ State[8];
       ptrWordOut[9]  = ptrWordIn[9]  ^ State[9];
       ptrWordOut[10] = ptrWordIn[10] ^ State[10];
       ptrWordOut[11] = ptrWordIn[11] ^ State[11];

       ptrWordInOut[0]  ^= State[11];
       ptrWordInOut[1]  ^= State[0];
       ptrWordInOut[2]  ^= State[1];
       ptrWordInOut[3]  ^= State[2];
       ptrWordInOut[4]  ^= State[3];
       ptrWordInOut[5]  ^= State[4];
       ptrWordInOut[6]  ^= State[5];
       ptrWordInOut[7]  ^= State[6];
       ptrWordInOut[8]  ^= State[7];
       ptrWordInOut[9]  ^= State[8];
       ptrWordInOut[10] ^= State[9];
       ptrWordInOut[11] ^= State[10];

       //Inputs: next column (i.e., next block in sequence)
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
       //Output: goes to previous column
       ptrWordOut -= BLOCK_LEN_INT64;
    }

#endif

}

/**
 * Performs a duplexing operation over "M[rowInOut][col] [+] M[rowIn][col]" (i.e.,
 * the wordwise addition of two columns, ignoring carries between words). The
 * output of this operation, "rand", is then used to make
 * "M[rowOut][col] = M[rowOut][col] XOR rand" and
 * "M[rowInOut][col] =  M[rowInOut][col] XOR rotW(rand)", where rotW is a 64-bit
 * rotation to the left.
 *
 * @param state          The current state of the sponge
 * @param rowIn          Row used only as input
 * @param rowInOut       Row used as input and to receive output after rotation
 * @param rowOut         Row receiving the output
 *
 */

inline void reducedDuplexRow( uint64_t *State, uint64_t *rowIn,
                              uint64_t *rowInOut, uint64_t *rowOut,
                              uint64_t nCols )
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

/*
uint64_t *io = (uint64_t*)inout;
uint64_t *ii = (uint64_t*)in;

printf("RDRS1 col= %d\n", i);
printf("RDRS1 IO %016lx %016lx %016lx %016lx\n",io[0],io[1],io[2],io[3]);
printf("RDRS1 IO %016lx %016lx %016lx %016lx\n",io[4],io[5],io[6],io[7]);
printf("RDRS1 IO %016lx %016lx %016lx %016lx\n",io[8],io[9],io[10],io[11]);
printf("RDRS1 IO %016lx %016lx %016lx %016lx\n",io[12],io[13],io[14],io[15]);
printf("RDRS1 IN %016lx %016lx %016lx %016lx\n",ii[0],ii[1],ii[2],ii[3]);
printf("RDRS1 IN %016lx %016lx %016lx %016lx\n",ii[4],ii[5],ii[6],ii[7]);
printf("RDRS1 IN %016lx %016lx %016lx %016lx\n",ii[8],ii[9],ii[10],ii[11]);
printf("RDRS1 IN %016lx %016lx %016lx %016lx\n",ii[12],ii[13],ii[14],ii[15]);
*/


      //Absorbing "M[prev] [+] M[row*]"
      state0 = _mm256_xor_si256( state0,
                                     _mm256_add_epi64( in[0], inout[0] ) );
      state1 = _mm256_xor_si256( state1,
                                     _mm256_add_epi64( in[1], inout[1] ) );
      state2 = _mm256_xor_si256( state2,
                                     _mm256_add_epi64( in[2], inout[2] ) );

      //Applies the reduced-round transformation f to the sponge's state
      LYRA_ROUND_AVX2( state0, state1, state2, state3 );

      //M[rowOut][col] = M[rowOut][col] XOR rand
      out[0] = _mm256_xor_si256( out[0], state0 );
      out[1] = _mm256_xor_si256( out[1], state1 );
      out[2] = _mm256_xor_si256( out[2], state2 );

      //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
      t0 = _mm256_permute4x64_epi64( state0, 0x93 );
      t1 = _mm256_permute4x64_epi64( state1, 0x93 );
      t2 = _mm256_permute4x64_epi64( state2, 0x93 );

      inout[0] = _mm256_xor_si256( inout[0],
                                   _mm256_blend_epi32( t0, t2, 0x03 ) );
      inout[1] = _mm256_xor_si256( inout[1],
                                   _mm256_blend_epi32( t1, t0, 0x03 ) );
      inout[2] = _mm256_xor_si256( inout[2],
                                   _mm256_blend_epi32( t2, t1, 0x03 ) );

       //Goes to next block
       in    += BLOCK_LEN_M256I;
       out   += BLOCK_LEN_M256I;
       inout += BLOCK_LEN_M256I;
   }

   _mm256_store_si256( (__m256i*)State,     state0 );
   _mm256_store_si256( (__m256i*)State + 1, state1 );
   _mm256_store_si256( (__m256i*)State + 2, state2 );
   _mm256_store_si256( (__m256i*)State + 3, state3 );

#elif defined (__SSE2__)

    __m128i* state = (__m128i*)State;
    __m128i* in    = (__m128i*)rowIn;
    __m128i* inout = (__m128i*)rowInOut;
    __m128i* out   = (__m128i*)rowOut;

    for ( i = 0; i < 6; i += 3)
    {
        _mm_prefetch( in    + i,     _MM_HINT_T0 );
        _mm_prefetch( in    + i + 2, _MM_HINT_T0 );
        _mm_prefetch( out   - i,     _MM_HINT_T0 );
        _mm_prefetch( out   - i - 2, _MM_HINT_T0 );
        _mm_prefetch( inout + i,     _MM_HINT_T0 );
        _mm_prefetch( inout + i + 2, _MM_HINT_T0 );
    }

    // for the last round in this function that isn't optimized for AVX
    uint64_t* ptrWordInOut = rowInOut; //In Lyra2: pointer to row*
    uint64_t* ptrWordIn = rowIn; //In Lyra2: pointer to prev
    uint64_t* ptrWordOut = rowOut; //In Lyra2: pointer to row

    for ( i = 0; i < nCols; i++)
    {
       _mm_prefetch( in    + 6, _MM_HINT_T0 );
       _mm_prefetch( in    + 7, _MM_HINT_T0 );
       _mm_prefetch( out   - 6, _MM_HINT_T0 );
       _mm_prefetch( out   - 7, _MM_HINT_T0 );
       _mm_prefetch( inout + 6, _MM_HINT_T0 );
       _mm_prefetch( inout + 7, _MM_HINT_T0 );

       state[0] = _mm_xor_si128( state[0],
                                 _mm_add_epi64( in[0], inout[0] ) );
       state[1] = _mm_xor_si128( state[1],
                                        _mm_add_epi64( in[1],
                                                       inout[1] ) );
       state[2] =  _mm_xor_si128( state[2],
                                        _mm_add_epi64( in[2],
                                                       inout[2] ) );
       state[3] =  _mm_xor_si128( state[3],
                                        _mm_add_epi64( in[3],
                                                       inout[3] ) );
       state[4] =  _mm_xor_si128( state[4],
                                        _mm_add_epi64( in[4],
                                                       inout[4] ) );
       state[5] =  _mm_xor_si128( state[5],
                                        _mm_add_epi64( in[5],
                                                       inout[5] ) );

      //Applies the reduced-round transformation f to the sponge's state
      LYRA_ROUND_AVX( state[0], state[1], state[2], state[3],
                      state[4], state[5], state[6], state[7] );

      out[0] = _mm_xor_si128( state[0], out[0] );
      out[1] = _mm_xor_si128( state[1], out[1] );
      out[2] = _mm_xor_si128( state[2], out[2] );
      out[3] = _mm_xor_si128( state[3], out[3] );
      out[4] = _mm_xor_si128( state[4], out[4] );
      out[5] = _mm_xor_si128( state[5], out[5] );

      //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
      ptrWordInOut[0] ^= State[11];
      ptrWordInOut[1] ^= State[0];
      ptrWordInOut[2] ^= State[1];
      ptrWordInOut[3] ^= State[2];
      ptrWordInOut[4] ^= State[3];
      ptrWordInOut[5] ^= State[4];
      ptrWordInOut[6] ^= State[5];
      ptrWordInOut[7] ^= State[6];
      ptrWordInOut[8] ^= State[7];
      ptrWordInOut[9] ^= State[8];
      ptrWordInOut[10] ^= State[9];
      ptrWordInOut[11] ^= State[10];

      //Goes to next block
      ptrWordOut += BLOCK_LEN_INT64;
      ptrWordInOut += BLOCK_LEN_INT64;
      ptrWordIn += BLOCK_LEN_INT64;

      out   += BLOCK_LEN_M128I;
      inout += BLOCK_LEN_M128I;
      in    += BLOCK_LEN_M128I;
    }

#else

    uint64_t* ptrWordInOut = rowInOut; //In Lyra2: pointer to row*
    uint64_t* ptrWordIn = rowIn; //In Lyra2: pointer to prev
    uint64_t* ptrWordOut = rowOut; //In Lyra2: pointer to row

    for ( i = 0; i < nCols; i++)
    {

       //Absorbing "M[prev] [+] M[row*]"
       State[0]  ^= (ptrWordIn[0]  + ptrWordInOut[0]);
       State[1]  ^= (ptrWordIn[1]  + ptrWordInOut[1]);
       State[2]  ^= (ptrWordIn[2]  + ptrWordInOut[2]);
       State[3]  ^= (ptrWordIn[3]  + ptrWordInOut[3]);
       State[4]  ^= (ptrWordIn[4]  + ptrWordInOut[4]);
       State[5]  ^= (ptrWordIn[5]  + ptrWordInOut[5]);
       State[6]  ^= (ptrWordIn[6]  + ptrWordInOut[6]);
       State[7]  ^= (ptrWordIn[7]  + ptrWordInOut[7]);
       State[8]  ^= (ptrWordIn[8]  + ptrWordInOut[8]);
       State[9]  ^= (ptrWordIn[9]  + ptrWordInOut[9]);
       State[10] ^= (ptrWordIn[10] + ptrWordInOut[10]);
       State[11] ^= (ptrWordIn[11] + ptrWordInOut[11]);

       //Applies the reduced-round transformation f to the sponge's state
       reducedBlake2bLyra( State);

       ptrWordOut[0]  ^= State[0];
       ptrWordOut[1]  ^= State[1];
       ptrWordOut[2]  ^= State[2];
       ptrWordOut[3]  ^= State[3];
       ptrWordOut[4]  ^= State[4];
       ptrWordOut[5]  ^= State[5];
       ptrWordOut[6]  ^= State[6];
       ptrWordOut[7]  ^= State[7];
       ptrWordOut[8]  ^= State[8];
       ptrWordOut[9]  ^= State[9];
       ptrWordOut[10] ^= State[10];
       ptrWordOut[11] ^= State[11];

       //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
       ptrWordInOut[0]  ^= State[11];
       ptrWordInOut[1]  ^= State[0];
       ptrWordInOut[2]  ^= State[1];
       ptrWordInOut[3]  ^= State[2];
       ptrWordInOut[4]  ^= State[3];
       ptrWordInOut[5]  ^= State[4];
       ptrWordInOut[6]  ^= State[5];
       ptrWordInOut[7]  ^= State[6];
       ptrWordInOut[8]  ^= State[7];
       ptrWordInOut[9]  ^= State[8];
       ptrWordInOut[10] ^= State[9];
       ptrWordInOut[11] ^= State[10];

       //Goes to next block
       ptrWordOut += BLOCK_LEN_INT64;
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
    }
#endif
}


