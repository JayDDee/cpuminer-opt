#ifndef CUBEHASH_SSE2_H__
#define CUBEHASH_SSE2_H__

#include "compat.h"
#include <stdint.h>
#include "algo/sha/sha3-defs.h"

#define	OPTIMIZE_SSE2

#include <emmintrin.h>

/*!\brief Holds all the parameters necessary for the CUBEHASH algorithm.
 * \ingroup HASH_cubehash_m
 */

struct _cubehashParam
{
    int hashlen;           // __m128i
    int rounds;
    int blocksize;         // __m128i
    int pos;	           // number of __m128i read into x from current block
    __m128i _ALIGN(64) x[8];  // aligned for __m256i
};

typedef struct _cubehashParam cubehashParam;

#ifdef __cplusplus
extern "C" {
#endif

int cubehashInit(cubehashParam* sp, int hashbitlen, int rounds, int blockbytes);
// reinitialize context with same parameters, much faster.
int cubehashReinit( cubehashParam* sp );

int cubehashUpdate(cubehashParam* sp, const byte *data, size_t size);

int cubehashDigest(cubehashParam* sp, byte *digest);

int cubehashUpdateDigest( cubehashParam *sp, byte *digest, const byte *data,
                          size_t size );

int cubehash_full( cubehashParam* sp, byte *digest, int hashbitlen,
                   const byte *data, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* H_CUBEHASH */
