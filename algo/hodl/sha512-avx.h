#ifndef _SHA512_H
#define _SHA512_H

#include <stdint.h>
#include "emmintrin.h"

//SHA-512 block size
#define SHA512_BLOCK_SIZE 128
//SHA-512 digest size
#define SHA512_DIGEST_SIZE 64

/*
#ifndef __AVX2__
#ifndef __AVX__
#error "Either AVX or AVX2 supported needed"
#endif // __AVX__
#endif // __AVX2__
*/

typedef struct
{
#ifdef __AVX2__
   __m256i h[8];
   __m256i w[80];
#elif defined(__SSE4_2__)
//#elif defined(__AVX__)
   __m128i h[8];
   __m128i w[80];
#else
   int dummy;
#endif
} Sha512Context;

#ifdef __AVX2__
#define SHA512_PARALLEL_N 8
#elif defined(__SSE4_2__)
//#elif defined(__AVX__)
#define SHA512_PARALLEL_N 4
#else
#define SHA512_PARALLEL_N 1   // dummy value
#endif

//SHA-512 related functions
void sha512Compute32b_parallel(
        uint64_t *data[SHA512_PARALLEL_N],
        uint64_t *digest[SHA512_PARALLEL_N]);

void sha512ProcessBlock(Sha512Context *context);

#endif
