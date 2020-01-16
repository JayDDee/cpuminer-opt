#if !defined(ECHO_HASH_4WAY_H__)
#define ECHO_HASH_4WAY_H__ 1

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#include "simd-utils.h"

typedef struct
{
   __m512i    state[4][4];
   __m512i    buffer[ 4 * 192 / 16 ];  // 4x128 interleaved 192 bytes
   __m512i    k;
   __m512i    hashsize;
   __m512i    const1536;

   unsigned int   uRounds;
   unsigned int   uHashSize;
   unsigned int   uBlockLength;
   unsigned int   uBufferBytes;
   unsigned int   processed_bits;

} echo_4way_context __attribute__ ((aligned (64)));

int echo_4way_init( echo_4way_context *state, int hashbitlen );


int echo_4way_update( echo_4way_context *state, const void *data,
    unsigned int databitlen);

int echo_close( echo_4way_context *state, void *hashval );

int echo_4way_update_close( echo_4way_context *state, void *hashval,
                              const void *data, int databitlen );

int echo_4way_full( echo_4way_context *ctx, void *hashval, int nHashSize,
                    const void *data, int datalen );

#endif 
#endif
