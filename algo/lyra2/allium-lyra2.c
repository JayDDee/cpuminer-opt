/*
 * Allium-specialized Lyra2RE.
 *
 * The generic Lyra2 code is retained as a correctness oracle. These fixed
 * parameter paths preserve the existing Allium memory layout exactly while
 * removing per-hash allocation and redundant input staging.
 */

#include <stdint.h>
#include <string.h>

#include "miner.h"
#include "compat.h"
#include "lyra2.h"
#include "sponge.h"
#include "allium-lyra2.h"

int LYRA2RE_ALLIUM(void *K, uint64_t *wholeMatrix)
{
   uint64_t _ALIGN(256) state[16];
   const int64_t row_len = BLOCK_LEN_INT64 * ALLIUM_LYRA2_NCOLS;
   int64_t row = 2;
   int64_t prev = 1;
   int64_t rowa = 0;
   int64_t step = 1;
   int64_t window = 2;
   int64_t gap = 1;

   if (K == NULL || wholeMatrix == NULL)
      return -1;

#if defined(__AVX2__)
   /*
    * Historical nCols=8 behavior advances 64 uint64_t words between absorb
    * blocks. Block 0 is exactly K || K; block 1 is zero. Build the identical
    * sponge state directly instead of staging those blocks in the matrix.
    */
   {
      __m256i input = _mm256_loadu_si256((const __m256i*)K);
      __m256i state0 = input;
      __m256i state1 = input;
      __m256i state2 = _mm256_set_epi64x(
          0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
          0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL);
      __m256i state3 = _mm256_set_epi64x(
          0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
          0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL);

      LYRA_12_ROUNDS_AVX2(state0, state1, state2, state3);
      LYRA_12_ROUNDS_AVX2(state0, state1, state2, state3);

      _mm256_store_si256((__m256i*)state, state0);
      _mm256_store_si256((__m256i*)state + 1, state1);
      _mm256_store_si256((__m256i*)state + 2, state2);
      _mm256_store_si256((__m256i*)state + 3, state3);
   }
#else
   memcpy((byte*)wholeMatrix, K, 32);
   memcpy((byte*)wholeMatrix + 32, K, 32);
   memset((byte*)wholeMatrix + 512, 0, 64);
   absorbBlockBlake2Safe(state, wholeMatrix, 2,
                         BLOCK_LEN_BLAKE2_SAFE_BYTES);
#endif

   reducedSqueezeRow0(state, &wholeMatrix[0], ALLIUM_LYRA2_NCOLS);
   reducedDuplexRow1(state, &wholeMatrix[0], &wholeMatrix[row_len],
                     ALLIUM_LYRA2_NCOLS);

   do
   {
      reducedDuplexRowSetup(state, &wholeMatrix[prev * row_len],
                            &wholeMatrix[rowa * row_len],
                            &wholeMatrix[row * row_len],
                            ALLIUM_LYRA2_NCOLS);

      rowa = (rowa + step) & (window - 1);
      prev = row;
      row++;

      if (rowa == 0)
      {
         step = window + gap;
         window *= 2;
         gap = -gap;
      }
   } while (row < ALLIUM_LYRA2_NROWS);

   row = 0;
   step = ALLIUM_LYRA2_NROWS / 2 - 1;
   do
   {
      rowa = state[0] & (ALLIUM_LYRA2_NROWS - 1);
      reducedDuplexRow(state, &wholeMatrix[prev * row_len],
                       &wholeMatrix[rowa * row_len],
                       &wholeMatrix[row * row_len],
                       ALLIUM_LYRA2_NCOLS);
      prev = row;
      row = (row + step) & (ALLIUM_LYRA2_NROWS - 1);
   } while (row != 0);

   absorbBlock(state, &wholeMatrix[rowa * row_len]);
   squeeze(state, K, 32);
   return 0;
}

int LYRA2RE_ALLIUM_selftest(void)
{
   uint8_t source[32] __attribute__ ((aligned (64)));
   uint8_t reference[32] __attribute__ ((aligned (64)));
   uint8_t optimized[32] __attribute__ ((aligned (64)));
   uint64_t scratch[ALLIUM_LYRA2_MATRIX_WORDS]
      __attribute__ ((aligned (64)));

   for (int vector = 0; vector < 32; vector++)
   {
      uint32_t seed = 0x9e3779b9u ^ (uint32_t)vector * 0x85ebca6bu;
      for (int i = 0; i < 32; i++)
      {
         if (vector == 0) source[i] = 0x00;
         else if (vector == 1) source[i] = 0xff;
         else if (vector == 2) source[i] = (uint8_t)i;
         else if (vector == 3) source[i] = (uint8_t)(255 - i);
         else {
            seed = seed * 1664525u + 1013904223u;
            source[i] = (uint8_t)(seed >> 24);
         }
      }

      memcpy(reference, source, sizeof(reference));
      memcpy(optimized, source, sizeof(optimized));
      if (LYRA2RE(reference, 32, reference, 32, reference, 32, 1, 8, 8) != 0)
         return 0;
      if (LYRA2RE_ALLIUM(optimized, scratch) != 0)
         return 0;
      if (memcmp(reference, optimized, sizeof(reference)) != 0)
         return 0;
   }
   return 1;
}

#if defined(SIMD512)

int LYRA2RE_2WAY_ALLIUM(void *K, uint64_t *wholeMatrix)
{
   uint64_t _ALIGN(256) state[32];
   const int64_t row_len = BLOCK_LEN_INT64 * ALLIUM_LYRA2_NCOLS;
   int64_t row = 2;
   int64_t prev = 1;
   int64_t rowa0 = 0;
   int64_t rowa1 = 0;
   int64_t step = 1;
   int64_t window = 2;
   int64_t gap = 1;

   if (K == NULL || wholeMatrix == NULL)
      return -1;

   {
      __m512i input = _mm512_loadu_si512(K);
      __m512i state0 = input;
      __m512i state1 = input;
      __m512i state2 = _mm512_set4_epi64(
          0xa54ff53a5f1d36f1ULL, 0x3c6ef372fe94f82bULL,
          0xbb67ae8584caa73bULL, 0x6a09e667f3bcc908ULL);
      __m512i state3 = _mm512_set4_epi64(
          0x5be0cd19137e2179ULL, 0x1f83d9abfb41bd6bULL,
          0x9b05688c2b3e6c1fULL, 0x510e527fade682d1ULL);

      LYRA_12_ROUNDS_2WAY_AVX512(state0, state1, state2, state3);
      LYRA_12_ROUNDS_2WAY_AVX512(state0, state1, state2, state3);

      _mm512_store_si512((__m512i*)state, state0);
      _mm512_store_si512((__m512i*)state + 1, state1);
      _mm512_store_si512((__m512i*)state + 2, state2);
      _mm512_store_si512((__m512i*)state + 3, state3);
   }

   reducedSqueezeRow0_2way(state, &wholeMatrix[0], ALLIUM_LYRA2_NCOLS);
   reducedDuplexRow1_2way(state, &wholeMatrix[0],
                          &wholeMatrix[2 * row_len], ALLIUM_LYRA2_NCOLS);

   do
   {
      reducedDuplexRowSetup_2way(
          state,
          &wholeMatrix[2 * prev * row_len],
          &wholeMatrix[2 * rowa0 * row_len],
          &wholeMatrix[2 * row * row_len],
          ALLIUM_LYRA2_NCOLS);
      rowa0 = (rowa0 + step) & (window - 1);
      prev = row;
      row++;
      if (rowa0 == 0)
      {
         step = window + gap;
         window *= 2;
         gap = -gap;
      }
   } while (row < ALLIUM_LYRA2_NROWS);

   row = 0;
   step = (ALLIUM_LYRA2_NROWS >> 1) - 1;
   do
   {
      rowa0 = state[0] & (ALLIUM_LYRA2_NROWS - 1);
      rowa1 = state[4] & (ALLIUM_LYRA2_NROWS - 1);
      reducedDuplexRow_2way(
          state,
          &wholeMatrix[2 * prev * row_len],
          &wholeMatrix[2 * rowa0 * row_len],
          &wholeMatrix[2 * rowa1 * row_len],
          &wholeMatrix[2 * row * row_len],
          ALLIUM_LYRA2_NCOLS);
      prev = row;
      row = (row + step) & (ALLIUM_LYRA2_NROWS - 1);
   } while (row != 0);

   absorbBlock_2way(state,
                    &wholeMatrix[2 * rowa0 * row_len],
                    &wholeMatrix[2 * rowa1 * row_len]);
   squeeze_2way(state, K, 32);
   return 0;
}

int LYRA2RE_2WAY_ALLIUM_selftest(void)
{
   uint8_t source[64] __attribute__ ((aligned (64)));
   uint8_t reference[64] __attribute__ ((aligned (64)));
   uint8_t optimized[64] __attribute__ ((aligned (64)));
   uint64_t scratch[ALLIUM_LYRA2_2WAY_MATRIX_WORDS]
      __attribute__ ((aligned (64)));

   for (int vector = 0; vector < 32; vector++)
   {
      uint32_t seed = 0x243f6a88u ^ (uint32_t)vector * 0x9e3779b9u;
      for (int i = 0; i < 64; i++)
      {
         if (vector == 0) source[i] = 0x00;
         else if (vector == 1) source[i] = 0xff;
         else if (vector == 2) source[i] = (uint8_t)i;
         else if (vector == 3) source[i] = (uint8_t)(255 - i);
         else {
            seed = seed * 1664525u + 1013904223u;
            source[i] = (uint8_t)(seed >> 24);
         }
      }

      memcpy(reference, source, sizeof(reference));
      memcpy(optimized, source, sizeof(optimized));
      if (LYRA2RE_2WAY(reference, 32, reference, 32, 1, 8, 8) != 0)
         return 0;
      if (LYRA2RE_2WAY_ALLIUM(optimized, scratch) != 0)
         return 0;
      if (memcmp(reference, optimized, sizeof(reference)) != 0)
         return 0;
   }
   return 1;
}

#endif
