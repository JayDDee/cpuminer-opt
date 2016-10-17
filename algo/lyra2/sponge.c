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
inline void initState(uint64_t state[/*16*/]) {
#ifdef __AVX2__
  (*(__m256i*)(&state[0])) = _mm256_setzero_si256();
  (*(__m256i*)(&state[4])) = _mm256_setzero_si256();

  (*(__m256i*)(&state[8])) = _mm256_set_epi64x( blake2b_IV[3],
                                                blake2b_IV[2],
                                                blake2b_IV[1],
                                                blake2b_IV[0] );
  (*(__m256i*)(&state[12])) = _mm256_set_epi64x(blake2b_IV[7],
                                                blake2b_IV[6],
                                                blake2b_IV[5],
                                                blake2b_IV[4] );

//AVX is around the same number of instructions as unnoptimized
//#elif defined __AVX__

#else
    //First 512 bis are zeros
    memset(state, 0, 64);
    //Remainder BLOCK_LEN_BLAKE2_SAFE_BYTES are reserved to the IV
    state[8] = blake2b_IV[0];
    state[9] = blake2b_IV[1];
    state[10] = blake2b_IV[2];
    state[11] = blake2b_IV[3];
    state[12] = blake2b_IV[4];
    state[13] = blake2b_IV[5];
    state[14] = blake2b_IV[6];
    state[15] = blake2b_IV[7];
#endif
}

/**
 * Execute Blake2b's G function, with all 12 rounds.
 *
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
inline static void blake2bLyra(uint64_t *v) {
#if defined __AVX2__
// may be still used by squeeze
   LYRA_INIT_AVX2;         // defines local a[4]
   LYRA_12_ROUNDS_AVX2( a[0], a[1], a[2], a[3] );
   LYRA_CLOSE_AVX2;

#elif defined __AVX__

   LYRA_INIT_AVX;         // defines locals a0[4], a1[4]
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_ROUND_AVX;
   LYRA_CLOSE_AVX;

#else
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
#endif
}

/**
 * Executes a reduced version of Blake2b's G function with only one round
 * @param v     A 1024-bit (16 uint64_t) array to be processed by Blake2b's G function
 */
inline static void reducedBlake2bLyra(uint64_t *v) {
    ROUND_LYRA(0);
}

/**
 * Performs a squeeze operation, using Blake2b's G function as the
 * internal permutation
 *
 * @param state      The current state of the sponge
 * @param out        Array that will receive the data squeezed
 * @param len        The number of bytes to be squeezed into the "out" array
 */
inline void squeeze( uint64_t *state, byte *out, unsigned int len )
{
    int fullBlocks = len / BLOCK_LEN_BYTES;
    byte *ptr = out;
    int i;

    //Squeezes full blocks
    for ( i = 0; i < fullBlocks; i++ )
    {
       memcpy(ptr, state, BLOCK_LEN_BYTES);
       blake2bLyra(state);
       ptr += BLOCK_LEN_BYTES;
    }
    //Squeezes remaining bytes
    memcpy(ptr, state, (len % BLOCK_LEN_BYTES));
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_INT64 words
 * of type uint64_t), using Blake2b's G function as the internal permutation
 *
 * @param state The current state of the sponge
 * @param in    The block to be absorbed (BLOCK_LEN_INT64 words)
 */
inline void absorbBlock(uint64_t *state, const uint64_t *in) {
#if defined __AVX2__

    __m256i state_v[4], in_v[3];

    // only state is guaranteed aligned 256
    state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
    in_v   [0] = _mm256_loadu_si256( (__m256i*)(&in[0]) );
    state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
    in_v   [1] = _mm256_loadu_si256( (__m256i*)(&in[4]) );
    state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
    in_v   [2] = _mm256_loadu_si256( (__m256i*)(&in[8]) ); 
    state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );

    state_v[0] = _mm256_xor_si256( state_v[0], in_v[0] );
    state_v[1] = _mm256_xor_si256( state_v[1], in_v[1] );
    state_v[2] = _mm256_xor_si256( state_v[2], in_v[2] );

    LYRA_12_ROUNDS_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

    _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
    _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
    _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
    _mm256_store_si256( (__m256i*)&state[12], state_v[3] );

#elif defined __AVX__

    __m128i state_v[6], in_v[6];

    state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
    state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
    state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
    state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
    state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
    state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

    in_v[0]    = _mm_load_si128( (__m128i*)(&in[0]) );
    in_v[1]    = _mm_load_si128( (__m128i*)(&in[2]) );
    in_v[2]    = _mm_load_si128( (__m128i*)(&in[4]) );
    in_v[3]    = _mm_load_si128( (__m128i*)(&in[6]) );
    in_v[4]    = _mm_load_si128( (__m128i*)(&in[8]) );
    in_v[5]    = _mm_load_si128( (__m128i*)(&in[10]) );

// do blake2bLyra without init
// LYRA_ROUND_AVX2( state_v )
    _mm_store_si128( (__m128i*)(&state[0]),
                       _mm_xor_si128( state_v[0], in_v[0] ) );
    _mm_store_si128( (__m128i*)(&state[2]),
                       _mm_xor_si128( state_v[1], in_v[1] ) );
    _mm_store_si128( (__m128i*)(&state[4]),
                       _mm_xor_si128( state_v[2], in_v[2] ) );
    _mm_store_si128( (__m128i*)(&state[6]),
                       _mm_xor_si128( state_v[3], in_v[3] ) );
    _mm_store_si128( (__m128i*)(&state[8]),
                       _mm_xor_si128( state_v[4], in_v[4] ) );
    _mm_store_si128( (__m128i*)(&state[10]),
                       _mm_xor_si128( state_v[5], in_v[5] ) );

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);

#else
    //XORs the first BLOCK_LEN_INT64 words of "in" with the current state
    state[0] ^= in[0];
    state[1] ^= in[1];
    state[2] ^= in[2];
    state[3] ^= in[3];
    state[4] ^= in[4];
    state[5] ^= in[5];
    state[6] ^= in[6];
    state[7] ^= in[7];
    state[8] ^= in[8];
    state[9] ^= in[9];
    state[10] ^= in[10];
    state[11] ^= in[11];

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);

#endif
}

/**
 * Performs an absorb operation for a single block (BLOCK_LEN_BLAKE2_SAFE_INT64
 * words of type uint64_t), using Blake2b's G function as the internal permutation
 *
 * @param state The current state of the sponge
 * @param in    The block to be absorbed (BLOCK_LEN_BLAKE2_SAFE_INT64 words)
 */
inline void absorbBlockBlake2Safe(uint64_t *state, const uint64_t *in) {
    //XORs the first BLOCK_LEN_BLAKE2_SAFE_INT64 words of "in" with the current state
#if defined __AVX2__

    __m256i state_v[4], in_v[2];

    state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
    in_v   [0] = _mm256_loadu_si256( (__m256i*)(&in[0]) );
    state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
    in_v   [1] = _mm256_loadu_si256( (__m256i*)(&in[4]) );
    state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
    state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );

    state_v[0] = _mm256_xor_si256( state_v[0], in_v[0] );
    state_v[1] = _mm256_xor_si256( state_v[1], in_v[1] );

    LYRA_12_ROUNDS_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

    _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
    _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
    _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
    _mm256_store_si256( (__m256i*)&state[12], state_v[3] );

#elif defined __AVX__

    __m128i state_v[4], in_v[4];

    state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
    state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
    state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
    state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );

    in_v[0]    = _mm_load_si128( (__m128i*)(&in[0]) );
    in_v[1]    = _mm_load_si128( (__m128i*)(&in[2]) );
    in_v[2]    = _mm_load_si128( (__m128i*)(&in[4]) );
    in_v[3]    = _mm_load_si128( (__m128i*)(&in[6]) );

    _mm_store_si128( (__m128i*)(&state[0]),
                       _mm_xor_si128( state_v[0], in_v[0] ) );
    _mm_store_si128( (__m128i*)(&state[2]),
                       _mm_xor_si128( state_v[1], in_v[1] ) );
    _mm_store_si128( (__m128i*)(&state[4]),
                       _mm_xor_si128( state_v[2], in_v[2] ) );
    _mm_store_si128( (__m128i*)(&state[6]),
                        _mm_xor_si128( state_v[3], in_v[3] ) );

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);

#else

    state[0] ^= in[0];
    state[1] ^= in[1];
    state[2] ^= in[2];
    state[3] ^= in[3];
    state[4] ^= in[4];
    state[5] ^= in[5];
    state[6] ^= in[6];
    state[7] ^= in[7];

    //Applies the transformation f to the sponge's state
    blake2bLyra(state);
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
inline void reducedSqueezeRow0( uint64_t* state, uint64_t* rowOut,
                                uint64_t nCols )
{
    uint64_t* ptrWord = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to M[0][C-1]
    int i;
    //M[row][C-1-col] = H.reduced_squeeze()

#if defined __AVX2__
       __m256i state_v[4];
       state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
       state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
       state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
       state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );
#endif

    for ( i = 0; i < nCols; i++ )
    {

#if defined __AVX2__

       _mm256_storeu_si256( (__m256i*)&ptrWord[0], state_v[0] );
       _mm256_storeu_si256( (__m256i*)&ptrWord[4], state_v[1] );
       _mm256_storeu_si256( (__m256i*)&ptrWord[8], state_v[2] );

       //Goes to next block (column) that will receive the squeezed data
       ptrWord -= BLOCK_LEN_INT64;

       LYRA_ROUND_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

#elif defined __AVX__

      _mm_store_si128( (__m128i*)(&ptrWord[0]),
                       _mm_load_si128( (__m128i*)(&state[0]) ) );
      _mm_store_si128( (__m128i*)(&ptrWord[2]),
                       _mm_load_si128( (__m128i*)(&state[2]) ) );
      _mm_store_si128( (__m128i*)(&ptrWord[4]),
                       _mm_load_si128( (__m128i*)(&state[4]) ) );
      _mm_store_si128( (__m128i*)(&ptrWord[6]),
                       _mm_load_si128( (__m128i*)(&state[6]) ) );
      _mm_store_si128( (__m128i*)(&ptrWord[8]),
                       _mm_load_si128( (__m128i*)(&state[8]) ) );
      _mm_store_si128( (__m128i*)(&ptrWord[10]),
                       _mm_load_si128( (__m128i*)(&state[10]) ) );

    //Goes to next block (column) that will receive the squeezed data
    ptrWord -= BLOCK_LEN_INT64;

    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);

#else
    ptrWord[0] = state[0];
    ptrWord[1] = state[1];
    ptrWord[2] = state[2];
    ptrWord[3] = state[3];
    ptrWord[4] = state[4];
    ptrWord[5] = state[5];
    ptrWord[6] = state[6];
    ptrWord[7] = state[7];
    ptrWord[8] = state[8];
    ptrWord[9] = state[9];
    ptrWord[10] = state[10];
    ptrWord[11] = state[11];

    //Goes to next block (column) that will receive the squeezed data
    ptrWord -= BLOCK_LEN_INT64;

    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);
#endif

    }

#if defined __AVX2__
    _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
    _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
    _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
    _mm256_store_si256( (__m256i*)&state[12], state_v[3] );
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
inline void reducedDuplexRow1( uint64_t *state, uint64_t *rowIn,
                               uint64_t *rowOut, uint64_t nCols )
{
    uint64_t* ptrWordIn = rowIn;	//In Lyra2: pointer to prev
    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to row
    int i;

#if defined __AVX2__
         __m256i state_v[4], in_v[3];
         state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
         state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
         state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
         state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );
#endif

    for ( i = 0; i < nCols; i++ )
    {
#if defined __AVX2__

         in_v   [0] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[0]) );
         in_v   [1] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[4]) );
         in_v   [2] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[8]) );
 
         state_v[0] = _mm256_xor_si256( state_v[0], in_v[0] );
         state_v[1] = _mm256_xor_si256( state_v[1], in_v[1] );
         state_v[2] = _mm256_xor_si256( state_v[2], in_v[2] );

         LYRA_ROUND_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[0]),
                              _mm256_xor_si256( state_v[0], in_v[0] ) );
         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[4]),
                              _mm256_xor_si256( state_v[1], in_v[1] ) );
         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[8]),
                              _mm256_xor_si256( state_v[2], in_v[2] ) );

#elif defined __AVX__

        __m128i state_v[6], in_v[6];

         state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
         state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
         state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
         state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
         state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
         state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

         in_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordIn[0]) );
         in_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordIn[2]) );
         in_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordIn[4]) );
         in_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordIn[6]) );
         in_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordIn[8]) );
         in_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordIn[10]) );

         _mm_store_si128( (__m128i*)(&state[0]),
                           _mm_xor_si128( state_v[0], in_v[0] ) );
         _mm_store_si128( (__m128i*)(&state[2]),
                           _mm_xor_si128( state_v[1], in_v[1] ) );
         _mm_store_si128( (__m128i*)(&state[4]),
                           _mm_xor_si128( state_v[2], in_v[2] ) );
         _mm_store_si128( (__m128i*)(&state[6]),
                           _mm_xor_si128( state_v[3], in_v[3] ) );
         _mm_store_si128( (__m128i*)(&state[8]),
                           _mm_xor_si128( state_v[4], in_v[4] ) );
         _mm_store_si128( (__m128i*)(&state[10]),
                           _mm_xor_si128( state_v[5], in_v[5] ) );

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);

#else

        //Absorbing "M[prev][col]"
        state[0]  ^= (ptrWordIn[0]);
        state[1]  ^= (ptrWordIn[1]);
        state[2]  ^= (ptrWordIn[2]);
        state[3]  ^= (ptrWordIn[3]);
        state[4]  ^= (ptrWordIn[4]);
        state[5]  ^= (ptrWordIn[5]);
        state[6]  ^= (ptrWordIn[6]);
        state[7]  ^= (ptrWordIn[7]);
        state[8]  ^= (ptrWordIn[8]);
        state[9]  ^= (ptrWordIn[9]);
        state[10] ^= (ptrWordIn[10]);
        state[11] ^= (ptrWordIn[11]);

        //Applies the reduced-round transformation f to the sponge's state
        reducedBlake2bLyra(state);
#endif

      #if defined __AVX2__
/*         state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
         state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
         state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );

         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[0]),
                              _mm256_xor_si256( state_v[0], in_v[0] ) );
         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[4]),
                              _mm256_xor_si256( state_v[1], in_v[1] ) );
         _mm256_storeu_si256( (__m256i*)(&ptrWordOut[8]),
                              _mm256_xor_si256( state_v[2], in_v[2] ) );
*/
      #elif defined __AVX__

         state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
         state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
         state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
         state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
         state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
         state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

         _mm_storeu_si128( (__m128i*)(&ptrWordOut[0]),
                           _mm_xor_si128( state_v[0], in_v[0] ) );
         _mm_storeu_si128( (__m128i*)(&ptrWordOut[2]),
                           _mm_xor_si128( state_v[1], in_v[1] ) );
         _mm_storeu_si128( (__m128i*)(&ptrWordOut[4]),
                           _mm_xor_si128( state_v[2], in_v[2] ) );
         _mm_storeu_si128( (__m128i*)(&ptrWordOut[6]),
                           _mm_xor_si128( state_v[3], in_v[3] ) );
         _mm_storeu_si128( (__m128i*)(&ptrWordOut[8]),
                           _mm_xor_si128( state_v[4], in_v[4] ) );
         _mm_storeu_si128( (__m128i*)(&ptrWordOut[10]),
                            _mm_xor_si128( state_v[5], in_v[5] ) );

      #else

    //M[row][C-1-col] = M[prev][col] XOR rand
    ptrWordOut[0] = ptrWordIn[0]  ^ state[0];
    ptrWordOut[1] = ptrWordIn[1]  ^ state[1];
    ptrWordOut[2] = ptrWordIn[2]  ^ state[2];
    ptrWordOut[3] = ptrWordIn[3]  ^ state[3];
    ptrWordOut[4] = ptrWordIn[4]  ^ state[4];
    ptrWordOut[5] = ptrWordIn[5]  ^ state[5];
    ptrWordOut[6] = ptrWordIn[6]  ^ state[6];
    ptrWordOut[7] = ptrWordIn[7]  ^ state[7];
    ptrWordOut[8] = ptrWordIn[8]  ^ state[8];
    ptrWordOut[9] = ptrWordIn[9]  ^ state[9];
    ptrWordOut[10] = ptrWordIn[10] ^ state[10];
    ptrWordOut[11] = ptrWordIn[11] ^ state[11];
#endif

       //Input: next column (i.e., next block in sequence)
       ptrWordIn += BLOCK_LEN_INT64;
       //Output: goes to previous column
       ptrWordOut -= BLOCK_LEN_INT64;
    }

#if defined __AVX2__
    _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
    _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
    _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
    _mm256_store_si256( (__m256i*)&state[12], state_v[3] );
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
inline void reducedDuplexRowSetup( uint64_t *state, uint64_t *rowIn,
                                   uint64_t *rowInOut, uint64_t *rowOut,
                                   uint64_t nCols )
{
    uint64_t* ptrWordIn = rowIn;	//In Lyra2: pointer to prev
    uint64_t* ptrWordInOut = rowInOut;	//In Lyra2: pointer to row*
    uint64_t* ptrWordOut = rowOut + (nCols-1)*BLOCK_LEN_INT64; //In Lyra2: pointer to row
    int i;

#if defined __AVX2__
    __m256i state_v[4], in_v[3], inout_v[3];
    #define t_state in_v

    state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
    state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
    state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
    state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );

    for ( i = 0; i < nCols; i++ )
    {
       in_v   [0] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[0]) );
       inout_v[0] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[0]) );
       in_v   [1] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[4]) );
       inout_v[1] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[4]) );
       in_v   [2] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[8]) );
       inout_v[2] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[8]) );

       state_v[0] = _mm256_xor_si256( state_v[0],  _mm256_add_epi64( in_v[0],
                                                                inout_v[0] ) );
       state_v[1] = _mm256_xor_si256( state_v[1],  _mm256_add_epi64( in_v[1],
                                                                inout_v[1] ) );
       state_v[2] = _mm256_xor_si256( state_v[2],  _mm256_add_epi64( in_v[2],
                                                                inout_v[2] ) );

       LYRA_ROUND_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[0]),
                              _mm256_xor_si256( state_v[0], in_v[0] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[4]),
                              _mm256_xor_si256( state_v[1], in_v[1] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[8]),
                              _mm256_xor_si256( state_v[2], in_v[2] ) );

       //M[row*][col] = M[row*][col] XOR rotW(rand)
      t_state[0] = _mm256_permute4x64_epi64( state_v[0], 0x93 );
      t_state[1] = _mm256_permute4x64_epi64( state_v[1], 0x93 );
      t_state[2] = _mm256_permute4x64_epi64( state_v[2], 0x93 );

      inout_v[0] = _mm256_xor_si256( inout_v[0],
                         _mm256_blend_epi32( t_state[0], t_state[2], 0x03 ) );
      inout_v[1] = _mm256_xor_si256( inout_v[1],
                         _mm256_blend_epi32( t_state[1], t_state[0], 0x03 ) );
      inout_v[2] = _mm256_xor_si256( inout_v[2],
                         _mm256_blend_epi32( t_state[2], t_state[1], 0x03 ) );

      _mm256_storeu_si256( (__m256i*)&ptrWordInOut[0], inout_v[0] );
      _mm256_storeu_si256( (__m256i*)&ptrWordInOut[4], inout_v[1] );
      _mm256_storeu_si256( (__m256i*)&ptrWordInOut[8], inout_v[2] );

       //Inputs: next column (i.e., next block in sequence)
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
       //Output: goes to previous column
       ptrWordOut -= BLOCK_LEN_INT64;
    }

    _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
    _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
    _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
    _mm256_store_si256( (__m256i*)&state[12], state_v[3] );

    #undef t_state 

#elif defined __AVX__

        __m128i state_v[6], in_v[6], inout_v[6];

    for ( i = 0; i < nCols; i++ )
    {

        state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
        state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
        state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
        state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
        state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
        state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

        inout_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[0]) );
        inout_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[2]) );
        inout_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[4]) );
        inout_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[6]) );
        inout_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[8]) );
        inout_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[10]) );

        in_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordIn[0]) );
        in_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordIn[2]) );
        in_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordIn[4]) );
        in_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordIn[6]) );
        in_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordIn[8]) );
        in_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordIn[10]) );

        _mm_store_si128( (__m128i*)(&state[0]),
                          _mm_xor_si128( state_v[0],
                                         _mm_add_epi64( in_v[0],
                                                        inout_v[0] ) ) );
        _mm_store_si128( (__m128i*)(&state[2]),
                          _mm_xor_si128( state_v[1],
                                         _mm_add_epi64( in_v[1],
                                                        inout_v[1] ) ) );
        _mm_store_si128( (__m128i*)(&state[4]),
                          _mm_xor_si128( state_v[2],
                                         _mm_add_epi64( in_v[2],
                                                        inout_v[2] ) ) );
        _mm_store_si128( (__m128i*)(&state[6]),
                          _mm_xor_si128( state_v[3],
                                         _mm_add_epi64( in_v[3],
                                                        inout_v[3] ) ) );
        _mm_store_si128( (__m128i*)(&state[8]),
                          _mm_xor_si128( state_v[4],
                                         _mm_add_epi64( in_v[4],
                                                        inout_v[4] ) ) );
        _mm_store_si128( (__m128i*)(&state[10]),
                          _mm_xor_si128( state_v[5],
                                         _mm_add_epi64( in_v[5],
                                                        inout_v[5] ) ) );

    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);
#else
    for ( i = 0; i < nCols; i++ )
    {

    //Absorbing "M[prev] [+] M[row*]"
    state[0]  ^= (ptrWordIn[0]  + ptrWordInOut[0]);
    state[1]  ^= (ptrWordIn[1]  + ptrWordInOut[1]);
    state[2]  ^= (ptrWordIn[2]  + ptrWordInOut[2]);
    state[3]  ^= (ptrWordIn[3]  + ptrWordInOut[3]);
    state[4]  ^= (ptrWordIn[4]  + ptrWordInOut[4]);
    state[5]  ^= (ptrWordIn[5]  + ptrWordInOut[5]);
    state[6]  ^= (ptrWordIn[6]  + ptrWordInOut[6]);
    state[7]  ^= (ptrWordIn[7]  + ptrWordInOut[7]);
    state[8]  ^= (ptrWordIn[8]  + ptrWordInOut[8]);
    state[9]  ^= (ptrWordIn[9]  + ptrWordInOut[9]);
    state[10] ^= (ptrWordIn[10] + ptrWordInOut[10]);
    state[11] ^= (ptrWordIn[11] + ptrWordInOut[11]);
    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);

    //M[row][col] = M[prev][col] XOR rand
#endif


      #if defined __AVX2__

      #elif defined __AVX__

         state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
         state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
         state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
         state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
         state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
         state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

         _mm_store_si128( (__m128i*)(&ptrWordOut[0]),
                           _mm_xor_si128( state_v[0], in_v[0] ) );
         _mm_store_si128( (__m128i*)(&ptrWordOut[2]),
                           _mm_xor_si128( state_v[1], in_v[1] ) );
         _mm_store_si128( (__m128i*)(&ptrWordOut[4]),
                           _mm_xor_si128( state_v[2], in_v[2] ) );
         _mm_store_si128( (__m128i*)(&ptrWordOut[6]),
                           _mm_xor_si128( state_v[3], in_v[3] ) );
         _mm_store_si128( (__m128i*)(&ptrWordOut[8]),
                           _mm_xor_si128( state_v[4], in_v[4] ) );
         _mm_store_si128( (__m128i*)(&ptrWordOut[10]),
                           _mm_xor_si128( state_v[5], in_v[5] ) );

      #else

    ptrWordOut[0] = ptrWordIn[0]  ^ state[0];
    ptrWordOut[1] = ptrWordIn[1]  ^ state[1];
    ptrWordOut[2] = ptrWordIn[2]  ^ state[2];
    ptrWordOut[3] = ptrWordIn[3]  ^ state[3];
    ptrWordOut[4] = ptrWordIn[4]  ^ state[4];
    ptrWordOut[5] = ptrWordIn[5]  ^ state[5];
    ptrWordOut[6] = ptrWordIn[6]  ^ state[6];
    ptrWordOut[7] = ptrWordIn[7]  ^ state[7];
    ptrWordOut[8] = ptrWordIn[8]  ^ state[8];
    ptrWordOut[9] = ptrWordIn[9]  ^ state[9];
    ptrWordOut[10] = ptrWordIn[10] ^ state[10];
    ptrWordOut[11] = ptrWordIn[11] ^ state[11];
#endif

    //M[row*][col] = M[row*][col] XOR rotW(rand)
// Need to fix this before taking state load/store out of loop
#ifdef __AVX2__


#else

    ptrWordInOut[0]  ^= state[11];
    ptrWordInOut[1]  ^= state[0];
    ptrWordInOut[2]  ^= state[1];
    ptrWordInOut[3]  ^= state[2];
    ptrWordInOut[4]  ^= state[3];
    ptrWordInOut[5]  ^= state[4];
    ptrWordInOut[6]  ^= state[5];
    ptrWordInOut[7]  ^= state[6];
    ptrWordInOut[8]  ^= state[7];
    ptrWordInOut[9]  ^= state[8];
    ptrWordInOut[10] ^= state[9];
    ptrWordInOut[11] ^= state[10];

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
inline void reducedDuplexRow( uint64_t *state, uint64_t *rowIn,
                              uint64_t *rowInOut, uint64_t *rowOut,
                              uint64_t nCols )
{
    uint64_t* ptrWordInOut = rowInOut; //In Lyra2: pointer to row*
    uint64_t* ptrWordIn = rowIn; //In Lyra2: pointer to prev
    uint64_t* ptrWordOut = rowOut; //In Lyra2: pointer to row
    int i;


#if defined __AVX2__

    for ( i = 0; i < nCols; i++)
    {

       //Absorbing "M[prev] [+] M[row*]"

       __m256i state_v[4], in_v[3], inout_v[3];
       #define out_v in_v    // reuse register in next code block
       #define t_state in_v
       state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
       in_v   [0] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[0]) );
       inout_v[0] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[0]) );
       state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
       in_v   [1] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[4]) );
       inout_v[1] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[4]) );
       state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
       in_v   [2] = _mm256_loadu_si256( (__m256i*)(&ptrWordIn[8]) );
       inout_v[2] = _mm256_loadu_si256( (__m256i*)(&ptrWordInOut[8]) );
       state_v[3] = _mm256_load_si256( (__m256i*)(&state[12]) );

       state_v[0] = _mm256_xor_si256( state_v[0], _mm256_add_epi64( in_v[0],
                                                               inout_v[0] ) );
       state_v[1] = _mm256_xor_si256( state_v[1], _mm256_add_epi64( in_v[1],
                                                               inout_v[1] ) );
       state_v[2] = _mm256_xor_si256( state_v[2], _mm256_add_epi64( in_v[2],
                                                               inout_v[2] ) );

       out_v[0] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[0]) );
       out_v[1] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[4]) );
       out_v[2] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[8]) );

       LYRA_ROUND_AVX2( state_v[0], state_v[1], state_v[2], state_v[3] );

       _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
       _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
       _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
       _mm256_store_si256( (__m256i*)&state[12], state_v[3] );

       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[0]),
                            _mm256_xor_si256( state_v[0], out_v[0] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[4]),
                            _mm256_xor_si256( state_v[1], out_v[1] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[8]),
                            _mm256_xor_si256( state_v[2], out_v[2] ) );

/*
       t_state[0] = _mm256_permute4x64_epi64( state_v[0], 0x93 );
       t_state[1] = _mm256_permute4x64_epi64( state_v[1], 0x93 );
       t_state[2] = _mm256_permute4x64_epi64( state_v[2], 0x93 );

       inout_v[0] = _mm256_xor_si256( inout_v[0],
                        _mm256_blend_epi32( t_state[0], t_state[2], 0x03 ) );
       inout_v[1] = _mm256_xor_si256( inout_v[1], 
                        _mm256_blend_epi32( t_state[1], t_state[0], 0x03 ) );
       inout_v[2] = _mm256_xor_si256( inout_v[2], 
                        _mm256_blend_epi32( t_state[2], t_state[1], 0x03 ) );

       _mm256_storeu_si256( (__m256i*)(&ptrWordInOut[0]), inout_v[0] );
       _mm256_storeu_si256( (__m256i*)(&ptrWordInOut[4]), inout_v[1] );
       _mm256_storeu_si256( (__m256i*)(&ptrWordInOut[8]), inout_v[2] );

       _mm256_store_si256( (__m256i*)&state[0], state_v[0] );
       _mm256_store_si256( (__m256i*)&state[4], state_v[1] );
       _mm256_store_si256( (__m256i*)&state[8], state_v[2] );
       _mm256_store_si256( (__m256i*)&state[12], state_v[3] );
*/
       #undef out_v
       #undef t_state 

    //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
    ptrWordInOut[0] ^= state[11];
    ptrWordInOut[1] ^= state[0];
    ptrWordInOut[2] ^= state[1];
    ptrWordInOut[3] ^= state[2];
    ptrWordInOut[4] ^= state[3];
    ptrWordInOut[5] ^= state[4];
    ptrWordInOut[6] ^= state[5];
    ptrWordInOut[7] ^= state[6];
    ptrWordInOut[8] ^= state[7];
    ptrWordInOut[9] ^= state[8];
    ptrWordInOut[10] ^= state[9];
    ptrWordInOut[11] ^= state[10];

       //Goes to next block
       ptrWordOut += BLOCK_LEN_INT64;
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
    }

   #elif defined __AVX__

    for ( i = 0; i < nCols; i++)
    {

       __m128i state_v[6], in_v[6], inout_v[6];
       #define out_v in_v    // reuse register in next code block

       state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
       state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
       state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
       state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
       state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
       state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

       inout_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[0]) );
       inout_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[2]) );
       inout_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[4]) );
       inout_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[6]) );
       inout_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[8]) );
       inout_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordInOut[10]) );

       in_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordIn[0]) );
       in_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordIn[2]) );
       in_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordIn[4]) );
       in_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordIn[6]) );
       in_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordIn[8]) );
       in_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordIn[10]) );

       _mm_store_si128( (__m128i*)(&state[0]),
                         _mm_xor_si128( state_v[0],
                                        _mm_add_epi64( in_v[0],
                                                       inout_v[0] ) ) );
       _mm_store_si128( (__m128i*)(&state[2]),
                         _mm_xor_si128( state_v[1],
                                        _mm_add_epi64( in_v[1],
                                                       inout_v[1] ) ) );
       _mm_store_si128( (__m128i*)(&state[4]),
                         _mm_xor_si128( state_v[2],
                                        _mm_add_epi64( in_v[2],
                                                       inout_v[2] ) ) );
       _mm_store_si128( (__m128i*)(&state[6]),
                         _mm_xor_si128( state_v[3],
                                        _mm_add_epi64( in_v[3],
                                                       inout_v[3] ) ) );
       _mm_store_si128( (__m128i*)(&state[8]),
                         _mm_xor_si128( state_v[4],
                                        _mm_add_epi64( in_v[4],
                                                       inout_v[4] ) ) );
       _mm_store_si128( (__m128i*)(&state[10]),
                         _mm_xor_si128( state_v[5],
                                        _mm_add_epi64( in_v[5],
                                                       inout_v[5] ) ) );

    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);

   #else

    for ( i = 0; i < nCols; i++)
    {

    state[0]  ^= (ptrWordIn[0]  + ptrWordInOut[0]);
    state[1]  ^= (ptrWordIn[1]  + ptrWordInOut[1]);
    state[2]  ^= (ptrWordIn[2]  + ptrWordInOut[2]);
    state[3]  ^= (ptrWordIn[3]  + ptrWordInOut[3]);
    state[4]  ^= (ptrWordIn[4]  + ptrWordInOut[4]);
    state[5]  ^= (ptrWordIn[5]  + ptrWordInOut[5]);
    state[6]  ^= (ptrWordIn[6]  + ptrWordInOut[6]);
    state[7]  ^= (ptrWordIn[7]  + ptrWordInOut[7]);
    state[8]  ^= (ptrWordIn[8]  + ptrWordInOut[8]);
    state[9]  ^= (ptrWordIn[9]  + ptrWordInOut[9]);
    state[10] ^= (ptrWordIn[10] + ptrWordInOut[10]);
    state[11] ^= (ptrWordIn[11] + ptrWordInOut[11]);

    //Applies the reduced-round transformation f to the sponge's state
    reducedBlake2bLyra(state);
#endif

    //M[rowOut][col] = M[rowOut][col] XOR rand

    #if defined __AVX2__
/*
       state_v[0] = _mm256_load_si256( (__m256i*)(&state[0]) );
       out_v  [0] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[0]) );
       state_v[1] = _mm256_load_si256( (__m256i*)(&state[4]) );
       out_v  [1] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[4]) );
       state_v[2] = _mm256_load_si256( (__m256i*)(&state[8]) );
       out_v  [2] = _mm256_loadu_si256( (__m256i*)(&ptrWordOut[8]) );

       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[0]),
                            _mm256_xor_si256( state_v[0], out_v[0] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[4]),
                            _mm256_xor_si256( state_v[1], out_v[1] ) );
       _mm256_storeu_si256( (__m256i*)(&ptrWordOut[8]),
                            _mm256_xor_si256( state_v[2], out_v[2] ) );
*/
    #elif defined __AVX__

       state_v[0] = _mm_load_si128( (__m128i*)(&state[0]) );
       state_v[1] = _mm_load_si128( (__m128i*)(&state[2]) );
       state_v[2] = _mm_load_si128( (__m128i*)(&state[4]) );
       state_v[3] = _mm_load_si128( (__m128i*)(&state[6]) );
       state_v[4] = _mm_load_si128( (__m128i*)(&state[8]) );
       state_v[5] = _mm_load_si128( (__m128i*)(&state[10]) );

       out_v[0]    = _mm_load_si128( (__m128i*)(&ptrWordOut[0]) );
       out_v[1]    = _mm_load_si128( (__m128i*)(&ptrWordOut[2]) );
       out_v[2]    = _mm_load_si128( (__m128i*)(&ptrWordOut[4]) );
       out_v[3]    = _mm_load_si128( (__m128i*)(&ptrWordOut[6]) );
       out_v[4]    = _mm_load_si128( (__m128i*)(&ptrWordOut[8]) );
       out_v[5]    = _mm_load_si128( (__m128i*)(&ptrWordOut[10]) );

       _mm_store_si128( (__m128i*)(&ptrWordOut[0]),
                         _mm_xor_si128( state_v[0], out_v[0] ) );
       _mm_store_si128( (__m128i*)(&ptrWordOut[2]),
                         _mm_xor_si128( state_v[1], out_v[1] ) );
       _mm_store_si128( (__m128i*)(&ptrWordOut[4]),
                         _mm_xor_si128( state_v[2], out_v[2] ) );
       _mm_store_si128( (__m128i*)(&ptrWordOut[6]),
                         _mm_xor_si128( state_v[3], out_v[3] ) );
       _mm_store_si128( (__m128i*)(&ptrWordOut[8]),
                         _mm_xor_si128( state_v[4], out_v[4] ) );
       _mm_store_si128( (__m128i*)(&ptrWordOut[10]),
                         _mm_xor_si128( state_v[5], out_v[5] ) );

    //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
    ptrWordInOut[0] ^= state[11];
    ptrWordInOut[1] ^= state[0];
    ptrWordInOut[2] ^= state[1];
    ptrWordInOut[3] ^= state[2];
    ptrWordInOut[4] ^= state[3];
    ptrWordInOut[5] ^= state[4];
    ptrWordInOut[6] ^= state[5];
    ptrWordInOut[7] ^= state[6];
    ptrWordInOut[8] ^= state[7];
    ptrWordInOut[9] ^= state[8];
    ptrWordInOut[10] ^= state[9];
    ptrWordInOut[11] ^= state[10];

       //Goes to next block
       ptrWordOut += BLOCK_LEN_INT64;
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
    }

#else
    ptrWordOut[0] ^= state[0];
    ptrWordOut[1] ^= state[1];
    ptrWordOut[2] ^= state[2];
    ptrWordOut[3] ^= state[3];
    ptrWordOut[4] ^= state[4];
    ptrWordOut[5] ^= state[5];
    ptrWordOut[6] ^= state[6];
    ptrWordOut[7] ^= state[7];
    ptrWordOut[8] ^= state[8];
    ptrWordOut[9] ^= state[9];
    ptrWordOut[10] ^= state[10];
    ptrWordOut[11] ^= state[11];

    //M[rowInOut][col] = M[rowInOut][col] XOR rotW(rand)
    ptrWordInOut[0] ^= state[11];
    ptrWordInOut[1] ^= state[0];
    ptrWordInOut[2] ^= state[1];
    ptrWordInOut[3] ^= state[2];
    ptrWordInOut[4] ^= state[3];
    ptrWordInOut[5] ^= state[4];
    ptrWordInOut[6] ^= state[5];
    ptrWordInOut[7] ^= state[6];
    ptrWordInOut[8] ^= state[7];
    ptrWordInOut[9] ^= state[8];
    ptrWordInOut[10] ^= state[9];
    ptrWordInOut[11] ^= state[10];

       //Goes to next block
       ptrWordOut += BLOCK_LEN_INT64;
       ptrWordInOut += BLOCK_LEN_INT64;
       ptrWordIn += BLOCK_LEN_INT64;
    }
#endif
}
