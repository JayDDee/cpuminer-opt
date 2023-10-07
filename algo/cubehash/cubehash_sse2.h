#ifndef CUBEHASH_SSE2_H__
#define CUBEHASH_SSE2_H__

#include "compat.h"
#include <stdint.h>
#include "simd-utils.h"

/*!\brief Holds all the parameters necessary for the CUBEHASH algorithm.
 * \ingroup HASH_cubehash_m
 */

struct _cubehashParam
{
    v128_t _ALIGN(64) x[8];  // aligned for __m512i
    int hashlen;           // __m128i
    int rounds;
    int blocksize;         // __m128i
    int pos;	           // number of __m128i read into x from current block
};

typedef struct _cubehashParam cubehashParam;

#ifdef __cplusplus
extern "C" {
#endif

int cubehashInit(cubehashParam* sp, int hashbitlen, int rounds, int blockbytes);
// reinitialize context with same parameters, much faster.
int cubehashReinit( cubehashParam* sp );

int cubehashUpdate(cubehashParam* sp, const void *data, size_t size);

int cubehashDigest(cubehashParam* sp, void *digest);

int cubehashUpdateDigest( cubehashParam *sp, void *digest,
                          const void *data, size_t size );

int cubehash_full( cubehashParam* sp, void *digest, int hashbitlen,
                   const void *data, size_t size );

#ifdef __cplusplus
}
#endif

#endif /* H_CUBEHASH */
