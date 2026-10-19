/* BC3's BLAKE2 personalization helpers.

 * Same convention as algo/equihash/equihash-impl.h: static inline over the
 * pristine algo/blake/sph_blake2b.c and algo/blake/sph-blake2s.c, never an
 * edit to those -- both are vendored and shared with argon2d, yespower and
 * equihash.

 * BC3 uses the PERSONAL field, never KEY and never SALT. Personal sits in
 * words 6 and 7 of the parameter block at both widths (BLAKE2 spec: bytes
 * 48..63 of blake2b's 64-byte block, 24..31 of blake2s's 32-byte block). The
 * mainnet vectors in bc3hash-kat.h pin it. */
#ifndef BC3HASH_IMPL_H__
#define BC3HASH_IMPL_H__ 1

#include "../blake/sph_blake2b.h"
#include "../blake/sph-blake2s.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>

static inline uint64_t bc3_load64le( const uint8_t *p )
{
   uint64_t v = 0;
   for ( int i = 0; i < 8; i++ )
      v |= ((uint64_t)p[i]) << (8*i);
   return v;
}

static inline uint32_t bc3_load32le( const uint8_t *p )
{
   uint32_t v = 0;
   for ( int i = 0; i < 4; i++ )
      v |= ((uint32_t)p[i]) << (8*i);
   return v;
}

static inline void bc3_blake2b_init_pers( sph_blake2b_ctx *ctx, size_t outlen,
                                         const uint8_t *personal )
{
   static const uint64_t iv[8] = {
      0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
      0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
      0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
      0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
   };
   memset( ctx, 0, sizeof(*ctx) );
   ctx->outlen = outlen;
   for ( int i = 0; i < 8; i++ )
      ctx->h[i] = iv[i];
   ctx->h[0] ^= (uint64_t)outlen | (1ULL << 16) | (1ULL << 24);
   if ( personal ) {
      ctx->h[6] ^= bc3_load64le( personal );
      ctx->h[7] ^= bc3_load64le( personal + 8 );
   }
}

static inline void bc3_blake2s_init_pers( blake2s_state *S, uint8_t outlen,
                                         const uint8_t *personal )
{
   static const uint32_t iv[8] = {
      0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
      0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
   };
   memset( S, 0, sizeof(*S) );
   for ( int i = 0; i < 8; i++ )
      S->h[i] = iv[i];
   S->h[0] ^= (uint32_t)outlen | (1UL << 16) | (1UL << 24);
   if ( personal ) {
      S->h[6] ^= bc3_load32le( personal );
      S->h[7] ^= bc3_load32le( personal + 4 );
   }
}

#endif
