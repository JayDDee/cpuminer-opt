#ifndef KECCAK_HASH_4WAY_H__
#define KECCAK_HASH_4WAY_H__

#include <stddef.h>
#include "simd-utils.h"

#if defined(SIMD512)

typedef struct
{
   __m512i buf[144*8];
   __m512i w[25];
   size_t ptr, lim;
} keccak64_ctx_m512i __attribute__((aligned(128)));

typedef keccak64_ctx_m512i keccak256_8x64_context;
typedef keccak64_ctx_m512i keccak512_8x64_context;

void keccak256_8x64_init(void *cc);
void keccak256_8x64_update(void *cc, const void *data, size_t len);
void keccak256_8x64_close(void *cc, void *dst);
void keccak256_8x64_ctx( void *cc, void *dst, const void *data, size_t len );

void keccak512_8x64_init(void *cc);
void keccak512_8x64_update(void *cc, const void *data, size_t len);
void keccak512_8x64_close(void *cc, void *dst);
void keccak512_8x64_ctx( void *cc, void *dst, const void *data, size_t len );

// legacy naming
#define keccak512_8way_context keccak512_8x64_context
#define keccak512_8way_init    keccak512_8x64_init
#define keccak512_8way_update  keccak512_8x64_update
#define keccak512_8way_close   keccak512_8x64_close
#define keccak256_8way_context keccak256_8x64_context
#define keccak256_8way_init    keccak256_8x64_init
#define keccak256_8way_update  keccak256_8x64_update
#define keccak256_8way_close   keccak256_8x64_close

#endif   

#if defined(__AVX2__)

typedef struct
{
   __m256i buf[144*8];  
   __m256i w[25];
   size_t ptr, lim;
} keccak64_ctx_m256i __attribute__((aligned(128)));

typedef keccak64_ctx_m256i keccak256_4x64_context;
typedef keccak64_ctx_m256i keccak512_4x64_context;

void keccak256_4x64_init(void *cc);
void keccak256_4x64_update(void *cc, const void *data, size_t len);
void keccak256_4x64_close(void *cc, void *dst);
void keccak256_4x64_ctx( void *cc, void *dst, const void *data, size_t len );

void keccak512_4x64_init(void *cc);
void keccak512_4x64_update(void *cc, const void *data, size_t len);
void keccak512_4x64_close(void *cc, void *dst);
void keccak512_4x64_ctx( void *cc, void *dst, const void *data, size_t len );

// legacy naming
#define keccak512_4way_context keccak512_4x64_context
#define keccak512_4way_init    keccak512_4x64_init
#define keccak512_4way_update  keccak512_4x64_update
#define keccak512_4way_close   keccak512_4x64_close
#define keccak256_4way_context keccak256_4x64_context
#define keccak256_4way_init    keccak256_4x64_init
#define keccak256_4way_update  keccak256_4x64_update
#define keccak256_4way_close   keccak256_4x64_close

#endif

typedef struct
{
   v128_t buf[144*8];
   v128_t w[25];
   size_t ptr, lim;
} keccak64_ctx_v128 __attribute__((aligned(128)));

typedef keccak64_ctx_v128 keccak256_2x64_context;
typedef keccak64_ctx_v128 keccak512_2x64_context;

void keccak256_2x64_init (void *cc );
void keccak256_2x64_update( void *cc, const void *data, size_t len );
void keccak256_2x64_close( void *cc, void *dst );
void keccak256_2x64_ctx( void *cc, void *dst, const void *data, size_t len );

void keccak512_2x64_init( void *cc );
void keccak512_2x64_update( void *cc, const void *data, size_t len );
void keccak512_2x64_close( void *cc, void *dst );
void keccak512_2x64_ctx( void *cc, void *dst, const void *data, size_t len );



#endif

