#ifndef CUBE_HASH_2WAY_H__
#define CUBE_HASH_2WAY_H__

#if defined(__AVX2__)

#include <stdint.h>
#include "avxdefs.h"

// 2x128, 2 way parallel SSE2

struct _cube_2way_context
{
    int hashlen;           // __m128i
    int rounds;
    int blocksize;         // __m128i
    int pos;               // number of __m128i read into x from current block
    __m256i h[8] __attribute__ ((aligned (64)));
};

typedef struct _cube_2way_context cube_2way_context;

int cube_2way_init( cube_2way_context* sp, int hashbitlen, int rounds,
                       int blockbytes );
// reinitialize context with same parameters, much faster.
int cube_2way_reinit( cube_2way_context *sp );

int cube_2way_update( cube_2way_context *sp, const void *data, size_t size );

int cube_2way_close( cube_2way_context *sp, void *output );

int cube_2way_update_close( cube_2way_context *sp, void *output,
                            const void *data, size_t size );


#endif
#endif
