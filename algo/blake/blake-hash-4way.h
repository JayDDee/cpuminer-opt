#ifndef BLAKE_HASH_4WAY__
#define BLAKE_HASH_4WAY__ 1

#include <stddef.h>
#include "simd-utils.h"

/////////////////////////
//
//  Blake-256 1 way SSE2

void  blake256_transform_le( uint32_t *H, const uint32_t *buf,
                             const uint32_t T0, const uint32_t T1, int rounds );

/////////////////////////
//
//  Blake-512 1 way SSE2

void  blake512_transform_le( uint64_t *H, const uint64_t *buf,
                             const uint64_t T0, const uint64_t T1 );

//////////////////////////
//
//   Blake-256 4 way SSE2

typedef struct {
   unsigned char buf[64<<2];
   uint32_t H[8<<2];
   size_t ptr;
   uint32_t T0, T1;
   int rounds;   // 14 for blake, 8 for blakecoin & vanilla
} blake_4way_small_context __attribute__ ((aligned (64)));

// Default, 14 rounds
typedef blake_4way_small_context blake256_4way_context;
void blake256_4way_init(void *ctx);
void blake256_4way_update(void *ctx, const void *data, size_t len);
void blake256_4way_close(void *ctx, void *dst);

// 14 rounds
typedef blake_4way_small_context blake256r14_4way_context;
void blake256r14_4way_init(void *cc);
void blake256r14_4way_update(void *cc, const void *data, size_t len);
void blake256r14_4way_close(void *cc, void *dst);

// 8 rounds, blakecoin, vanilla
typedef blake_4way_small_context blake256r8_4way_context;
void blake256r8_4way_init(void *cc);
void blake256r8_4way_update(void *cc, const void *data, size_t len);
void blake256r8_4way_close(void *cc, void *dst);

#ifdef __AVX2__

//////////////////////////
//
//   Blake-256 8 way AVX2

typedef struct {
   __m256i buf[16] __attribute__ ((aligned (64)));
   __m256i H[8];
   size_t ptr;
   uint32_t T0, T1;
   int rounds;   // 14 for blake, 8 for blakecoin & vanilla
} blake_8way_small_context;

// Default 14 rounds
typedef blake_8way_small_context blake256_8way_context;
void blake256_8way_init(void *cc);
void blake256_8way_update(void *cc, const void *data, size_t len);
void blake256_8way_close(void *cc, void *dst);
void blake256_8way_update_le(void *cc, const void *data, size_t len);
void blake256_8way_close_le(void *cc, void *dst);
void blake256_8way_round0_prehash_le( void *midstate, const void *midhash,
                                      void *data );
void blake256_8way_final_rounds_le( void *final_hash, const void *midstate,
                    const void *midhash, const void *data, const int rounds );

// 14 rounds, blake, decred
typedef blake_8way_small_context blake256r14_8way_context;
void blake256r14_8way_init(void *cc);
void blake256r14_8way_update(void *cc, const void *data, size_t len);
void blake256r14_8way_close(void *cc, void *dst);

// 8 rounds, blakecoin, vanilla
typedef blake_8way_small_context blake256r8_8way_context;
void blake256r8_8way_init(void *cc);
void blake256r8_8way_update(void *cc, const void *data, size_t len);
void blake256r8_8way_close(void *cc, void *dst);

// Blake-512 4 way AVX2

typedef struct {
   __m256i buf[16];
   __m256i H[8];
   __m256i S[4];   
   size_t ptr;
   uint64_t T0, T1;
} blake_4way_big_context __attribute__ ((aligned (128)));

typedef blake_4way_big_context blake512_4way_context;

void blake512_4way_init( blake_4way_big_context *sc );
void blake512_4way_update( void *cc, const void *data, size_t len );
void blake512_4way_close( void *cc, void *dst );
void blake512_4way_full( blake_4way_big_context *sc, void * dst,
                         const void *data, size_t len );
void blake512_4way_full_le( blake_4way_big_context *sc, void * dst,
                            const void *data, size_t len );
void blake512_4way_prehash_le( blake_4way_big_context *sc, __m256i *midstate,
                               const void *data );
void blake512_4way_final_le( blake_4way_big_context *sc, void *hash,
                             const __m256i nonce, const __m256i *midstate );

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

////////////////////////////
//
//   Blake-256 16 way AVX512

typedef struct {
   __m512i buf[16];
   __m512i H[8];
   size_t ptr;
   uint32_t T0, T1;
   int rounds;   // 14 for blake, 8 for blakecoin & vanilla
} blake_16way_small_context __attribute__ ((aligned (128)));

// Default 14 rounds
typedef blake_16way_small_context blake256_16way_context;
void blake256_16way_init(void *cc);
void blake256_16way_update(void *cc, const void *data, size_t len);
void blake256_16way_close(void *cc, void *dst);
// Expects data in little endian order, no byte swap needed
void blake256_16way_update_le(void *cc, const void *data, size_t len);
void blake256_16way_close_le(void *cc, void *dst);
void blake256_16way_round0_prehash_le( void *midstate, const void *midhash,
                                       void *data );
void blake256_16way_final_rounds_le( void *final_hash, const void *midstate,
                     const void *midhash, const void *data, const int rounds );


// 14 rounds, blake, decred
typedef blake_16way_small_context blake256r14_16way_context;
void blake256r14_16way_init(void *cc);
void blake256r14_16way_update(void *cc, const void *data, size_t len);
void blake256r14_16way_close(void *cc, void *dst);

// 8 rounds, blakecoin, vanilla
typedef blake_16way_small_context blake256r8_16way_context;
void blake256r8_16way_init(void *cc);
void blake256r8_16way_update(void *cc, const void *data, size_t len);
void blake256r8_16way_close(void *cc, void *dst);

////////////////////////////
//
//// Blake-512 8 way AVX512

typedef struct {
   __m512i buf[16];
   __m512i H[8];
   __m512i S[4];
   size_t ptr;
   uint64_t T0, T1;
} blake_8way_big_context __attribute__ ((aligned (128)));

typedef blake_8way_big_context blake512_8way_context;

void blake512_8way_init( blake_8way_big_context *sc );
void blake512_8way_update( void *cc, const void *data, size_t len );
void blake512_8way_close( void *cc, void *dst );
void blake512_8way_full( blake_8way_big_context *sc, void * dst,
                        const void *data, size_t len );
void blake512_8way_full_le( blake_8way_big_context *sc, void * dst,
                            const void *data, size_t len );
void blake512_8way_prehash_le( blake_8way_big_context *sc, __m512i *midstate,
                               const void *data );
void blake512_8way_final_le( blake_8way_big_context *sc, void *hash,
                             const __m512i nonce, const __m512i *midstate );

#endif  // AVX512
#endif  // AVX2

#endif  // BLAKE_HASH_4WAY_H__
