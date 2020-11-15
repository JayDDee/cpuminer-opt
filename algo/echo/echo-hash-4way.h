#if !defined(ECHO_HASH_4WAY_H__)
#define ECHO_HASH_4WAY_H__ 1

#if defined(__VAES__)

#include "simd-utils.h"

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

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
#define echo512_4way_context echo_4way_context

int echo_4way_init( echo_4way_context *state, int hashbitlen );
#define echo512_4way_init( state ) echo_4way_init( state, 512 )
#define echo256_4way_init( state ) echo_4way_init( state, 256 )

int echo_4way_update( echo_4way_context *state, const void *data,
    unsigned int databitlen);
#define echo512_4way_update echo_4way_update

// int echo_4way_close( echo_4way_context *state, void *hashval );
// #define echo512_4way_close echo_4way_close

int echo_4way_update_close( echo_4way_context *state, void *hashval,
                              const void *data, int databitlen );
#define echo512_4way_update_close echo_4way_update_close

int echo_4way_full( echo_4way_context *ctx, void *hashval, int nHashSize,
                    const void *data, int datalen );
#define echo512_4way_full( state, hashval, data, datalen ) \
           echo_4way_full( state, hashval, 512, data, datalen )
#define echo256_4way_full( state, hashval, data, datalen ) \
           echo_4way_full( state, hashval, 256, data, datalen )

#endif   // AVX512

typedef struct
{
   __m256i    state[4][4];
   __m256i    buffer[ 4 * 192 / 16 ];  // 4x128 interleaved 192 bytes
   __m256i    k;
   __m256i    hashsize;
   __m256i    const1536;

   unsigned int   uRounds;
   unsigned int   uHashSize;
   unsigned int   uBlockLength;
   unsigned int   uBufferBytes;
   unsigned int   processed_bits;

} echo_2way_context __attribute__ ((aligned (64)));
#define echo512_2way_context echo_2way_context

int echo_2way_init( echo_2way_context *state, int hashbitlen );
#define echo512_2way_init( state ) echo_2way_init( state, 512 )
#define echo256_2way_init( state ) echo_2way_init( state, 256 )

int echo_2way_update( echo_2way_context *state, const void *data,
    unsigned int databitlen);
#define echo512_2way_update echo_2way_update

int echo_2way_update_close( echo_2way_context *state, void *hashval,
                              const void *data, int databitlen );
#define echo512_2way_update_close echo_2way_update_close

int echo_2way_full( echo_2way_context *ctx, void *hashval, int nHashSize,
                    const void *data, int datalen );
#define echo512_2way_full( state, hashval, data, datalen ) \
           echo_2way_full( state, hashval, 512, data, datalen )
#define echo256_2way_full( state, hashval, data, datalen ) \
           echo_2way_full( state, hashval, 256, data, datalen )


#endif  // VAES

#endif   // ECHO_HASH_4WAY_H__
