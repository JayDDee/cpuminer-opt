#ifndef CUBE_HASH_2WAY_H__
#define CUBE_HASH_2WAY_H__ 1

#include <stdint.h>
#include "simd-utils.h"

#if defined(__AVX2__)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

struct _cube_4way_context
{
    __m512i h[8];
    int hashlen;
    int rounds;
    int blocksize;
    int pos; 
} __attribute__ ((aligned (128)));

struct _cube_4way_2buf_context
{
    __m512i h0[8];
    __m512i h1[8];
    int hashlen;
    int rounds;
    int blocksize;
    int pos;
} __attribute__ ((aligned (128)));


typedef struct _cube_4way_context cube_4way_context;

typedef struct _cube_4way_2buf_context cube_4way_2buf_context;

int cube_4way_init( cube_4way_context* sp, int hashbitlen, int rounds,
                    int blockbytes );

int cube_4way_update( cube_4way_context *sp, const void *data, size_t size );

int cube_4way_close( cube_4way_context *sp, void *output );

int cube_4way_update_close( cube_4way_context *sp, void *output,
                            const void *data, size_t size );

int cube_4way_full( cube_4way_context *sp, void *output, int hashbitlen,
                    const void *data, size_t size );

int cube_4way_2buf_full( cube_4way_2buf_context *sp,
                         void *output0, void *output1, int hashbitlen,
                         const void *data0, const void *data1, size_t size );

#endif

// 2x128, 2 way parallel AVX2

struct _cube_2way_context
{
    __m256i h[8];
    int hashlen;           // __m128i
    int rounds;
    int blocksize;         // __m128i
    int pos;               // number of __m128i read into x from current block
} __attribute__ ((aligned (128)));

typedef struct _cube_2way_context cube_2way_context;

int cube_2way_init( cube_2way_context* sp, int hashbitlen, int rounds,
                       int blockbytes );
int cube_2way_update( cube_2way_context *sp, const void *data, size_t size );
int cube_2way_close( cube_2way_context *sp, void *output );
int cube_2way_update_close( cube_2way_context *sp, void *output,
                            const void *data, size_t size );
int cube_2way_full( cube_2way_context *sp, void *output, int hashbitlen,
                    const void *data, size_t size );


#endif
#endif
