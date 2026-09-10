#ifndef KECCAK_HASH_4WAY_H__
#define KECCAK_HASH_4WAY_H__

#include <stddef.h>
#include "simd-utils.h"

/*
 * buf holds one 64-bit rate LANE per element, so it needs rate/8 elements.
 * Widest Keccak rate is 144 B (keccak224) = 18 lanes; keccak256 uses 17,
 * keccak512 9.
 *
 * NOTE: Was 144*8 -- a unit error from the scalar sph context, whose buf
 * really is 144 *bytes*.  That made the struct 75,392 B instead of 2,816 B,
 * and since the x-family unions it with every other hash context, keccak alone
 * set a ~75 KB stack frame in ~30 files.
 *
 * NOTE: Keep this outside the per-ISA #if blocks: all three structs use it,
 * only the first is guarded by SIMD512.
 */
#define KECCAK64_BUF_LANES   (144/8)

// Scalar single-block SHA3-256 from a pre-padded state: one permutation, no
// buffer, no padding VLA, 2 NOT64s instead of 6. `dst` is 32 bytes.
// NOTE: SHA3 padding (0x06) is baked in and hard_coded_eb is IGNORED -- not usable
// for keccak/sha3d, which need 0x01. Inputs must be exactly 80 / 32 bytes, each
// of which fits the 136-byte rate in a single block. Little-endian hosts.
// Must stay OUTSIDE the per-ISA blocks below: plain uint64_t, every target.
void sha3_256_prepad80( void *dst, const void *src );
void sha3_256_prepad32( void *dst, const void *src );

#if defined(SIMD512)

typedef struct
{
   __m512i buf[KECCAK64_BUF_LANES];
   __m512i w[25];
   size_t ptr, lim;
} keccak64_ctx_m512i __attribute__((aligned(128)));

typedef keccak64_ctx_m512i keccak256_8x64_context;
typedef keccak64_ctx_m512i keccak512_8x64_context;

// sha3t only: triple SHA3-256 of an 80-byte header, driven from pre-padded
// state. SHA3 padding is baked in; ignores hard_coded_eb. See the definition.
// The 4x64 and 2x64 forms are declared in their own ISA blocks below.
void sha3t_8x64_prepad( void *dst, const void *vdata );

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
   __m256i buf[KECCAK64_BUF_LANES];   // see the note above, not 144*8
   __m256i w[25];
   size_t ptr, lim;
} keccak64_ctx_m256i __attribute__((aligned(128)));

typedef keccak64_ctx_m256i keccak256_4x64_context;
typedef keccak64_ctx_m256i keccak512_4x64_context;

void sha3t_4x64_prepad( void *dst, const void *vdata );   // see sha3t_8x64_prepad

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
   v128_t buf[KECCAK64_BUF_LANES];   // see the note above, not 144*8
   v128_t w[25];
   size_t ptr, lim;
} keccak64_ctx_v128 __attribute__((aligned(128)));

typedef keccak64_ctx_v128 keccak256_2x64_context;
typedef keccak64_ctx_v128 keccak512_2x64_context;

void sha3t_2x64_prepad( void *dst, const void *vdata );   // see sha3t_8x64_prepad

void keccak256_2x64_init (void *cc );
void keccak256_2x64_update( void *cc, const void *data, size_t len );
void keccak256_2x64_close( void *cc, void *dst );
void keccak256_2x64_ctx( void *cc, void *dst, const void *data, size_t len );

void keccak512_2x64_init( void *cc );
void keccak512_2x64_update( void *cc, const void *data, size_t len );
void keccak512_2x64_close( void *cc, void *dst );
void keccak512_2x64_ctx( void *cc, void *dst, const void *data, size_t len );



#endif

