/* Balloon (Mateable) — the AES-128-CTR block-index stream and its SHA-256 key
 * derivation, plus the hash construction itself. The stream depends only on
 * the salt, so it is built once per block and reused across every nonce hashed
 * against it.                                                               */

#include "balloon.h"
#include "balloon-aes128.h"
#include "balloon-kat.h"
#include "algo/sha/sha256-hash.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <malloc.h>
#define posix_memalign(p, a, s) (((*(p)) = _aligned_malloc((s), (a))), *(p) ?0 :errno)
#endif

/* Every integer the construction hashes is little-endian, written out byte by
 * byte so no digest depends on host endianness.                              */

static inline void balloon_put_le64( uint8_t *p, uint64_t v )
{
   for ( int i = 0; i < 8; i++ ) p[i] = (uint8_t)( v >> ( 8*i ) );
}

static inline void balloon_put_le32( uint8_t *p, uint32_t v )
{
   for ( int i = 0; i < 4; i++ ) p[i] = (uint8_t)( v >> ( 8*i ) );
}

void balloon_bitstream_key( uint8_t key[32], const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost )
{
   uint8_t seed[ BALLOON_SALT_LEN + 8 + 4 ];

   memcpy( seed, salt, BALLOON_SALT_LEN );
   balloon_put_le64( seed + BALLOON_SALT_LEN,     (uint64_t)s_cost );
   balloon_put_le32( seed + BALLOON_SALT_LEN + 8, (uint32_t)t_cost );

   sha256_full( key, seed, sizeof seed );
}

void balloon_bitstream_raw( uint8_t *out, size_t outlen,
                            const uint8_t salt[BALLOON_SALT_LEN],
                            int64_t s_cost, int32_t t_cost )
{
   uint8_t key[32];
   balloon_aes128_ctx aes;

   balloon_bitstream_key( key, salt, s_cost, t_cost );
   balloon_aes128_init( &aes, key );          /* first 16 bytes of the digest */
   balloon_aes128_keystream( &aes, 0, out, outlen );
}

void balloon_build_indices( uint16_t *idx, const uint8_t salt[BALLOON_SALT_LEN] )
{
   uint8_t key[32];
   balloon_aes128_ctx aes;
   uint8_t block[16];

   balloon_bitstream_key( key, salt, BALLOON_S_COST, BALLOON_T_COST );
   balloon_aes128_init( &aes, key );

   /* Two indices per 16-byte keystream block, generated in place rather than
    * materialising the whole ~384 KB byte stream first.                     */
   uint64_t counter = 0;
   for ( size_t j = 0; j < BALLOON_N_INDICES; j += 2 )
   {
      balloon_aes128_keystream( &aes, counter++, block, 16 );

      for ( int half = 0; half < 2; half++ )
      {
         if ( j + half >= BALLOON_N_INDICES ) break;

         const uint8_t *b = block + 8*half;
         uint64_t v = 0;
         for ( int i = 7; i >= 0; i-- ) v = ( v << 8 ) | b[i];   /* LE64 */

         idx[ j + half ] = (uint16_t)( v % BALLOON_N_BLOCKS );
      }
   }
}

/* ── SHA-256 driver ───────────────────────────────────────────────────────
 * 53,250 compressions per hash over three fixed message lengths, so
 * sha256_full()'s per-call init, copy, pad and length store are all either
 * constant or already done by us. Drive the block transform directly instead;
 * `sha256_transform_be` is a macro over the SHA-NI, ARMv8-SHA2 and portable
 * paths, so the scalar build still works.
 *
 * Worth only ~4%: the bookkeeping overlaps with the SHA dependency chain that
 * is the real critical path. Timing the primitive suggests 2x; it is not.   */

/* WARNING: Not `SHA256_IV` from algo/sha/sha256-hash.h: that is declared with no
 * initializer, so every consumer gets a zero-filled copy and would silently
 * hash from a zero state. The real values have internal linkage there.      */
static const uint32_t balloon_sha256_iv[8] =
{
   0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

/* `blk` must already hold `nblocks` complete, padded 64-byte blocks.
 *
 * WARNING: State and message must both be 16-byte aligned — the transforms use
 * aligned vector loads and segfault otherwise. Undocumented at the
 * declaration; in-tree callers get it free from `sha256_context`.          */
static inline void balloon_sha256_blocks( uint8_t *out, const uint8_t *blk,
                                          const int nblocks )
{
   uint32_t state[8] __attribute__((aligned(64)));

   memcpy( state, balloon_sha256_iv, sizeof state );
   for ( int i = 0; i < nblocks; i++ )
      sha256_transform_be( state, blk + 64*i, state );

   for ( int i = 0; i < 8; i++ )
      ( (uint32_t*)out )[i] = bswap_32( state[i] );
}

/* Write the SHA-256 padding for a message of `len` bytes into a buffer of
 * `padded` bytes: the 0x80 marker, zeros, and the big-endian bit count. */
static inline void balloon_pad( uint8_t *blk, size_t len, size_t padded )
{
   const uint64_t bits = (uint64_t)len * 8;

   blk[ len ] = 0x80;
   memset( blk + len + 1, 0, padded - len - 9 );
   for ( int i = 0; i < 8; i++ )
      blk[ padded - 1 - i ] = (uint8_t)( bits >> ( 8*i ) );
}

/* ── The hash ─────────────────────────────────────────────────────────────
 *
 * Three phases, all of them SHA-256 over a small contiguous buffer: fill
 * block 0 from the header, expand it into a chain across the whole buffer,
 * then t_cost mixing rounds that rewrite every block in place from its
 * predecessor, itself, and BALLOON_N_NEIGHBORS indexed blocks.
 *
 * `counter` is hashed as the first 8 bytes of every one of those digests and
 * runs unbroken across all three phases: 1 + (n-1) + t_cost*n compressions.
 * The index sequence likewise runs unbroken across the mixing rounds.       */

#define BALLOON_MIX_BLOCKS  ( 2 + BALLOON_N_NEIGHBORS )
#define BALLOON_LAST        ( ( BALLOON_N_BLOCKS - 1 ) * BALLOON_BLOCK_SIZE )

void balloon_hash_header( balloon_ctx *ctx, const void *input, void *digest )
{
   const uint8_t *in  = (const uint8_t*)input;
   const uint8_t *salt = in;                 /* header bytes 0..31 */
   uint8_t *buf = ctx->buf;
   uint64_t counter = 0;

   /* The index stream is a function of the salt alone, so it survives a nonce
    * change and is rebuilt only when the salt moves — see balloon.h.        */
   if ( !ctx->idx_valid
        || memcmp( ctx->idx_salt, salt, BALLOON_SALT_LEN ) != 0 )
   {
      balloon_build_indices( ctx->idx, salt );
      memcpy( ctx->idx_salt, salt, BALLOON_SALT_LEN );
      ctx->idx_valid = true;
   }

   /* The padding of all three message shapes is constant — write it once here,
    * not inside 53,250 digests. Only the prefixes change below.             */
   balloon_pad( ctx->mfill,   BALLOON_MSG_FILL,   sizeof ctx->mfill   );
   balloon_pad( ctx->mexpand, BALLOON_MSG_EXPAND, sizeof ctx->mexpand );
   balloon_pad( ctx->mmix,    BALLOON_MSG_MIX,    sizeof ctx->mmix    );

   /* Fill: the salt appears twice, once on its own and once as the head of
    * the full header. That is the construction, not a transcription slip.   */
   {
      uint8_t *p = ctx->mfill;

      balloon_put_le64( p, counter++ );                p += 8;
      memcpy( p, salt, BALLOON_SALT_LEN );             p += BALLOON_SALT_LEN;
      memcpy( p, in, BALLOON_INPUT_LEN );              p += BALLOON_INPUT_LEN;
      balloon_put_le64( p, BALLOON_S_COST );           p += 8;
      balloon_put_le32( p, BALLOON_T_COST );

      balloon_sha256_blocks( buf, ctx->mfill, sizeof ctx->mfill / 64 );
   }

   /* Expand: buf[i] = SHA256( LE64(ctr++) || buf[i-1] ). */
   {
      uint8_t *msg = ctx->mexpand;

      for ( int i = 1; i < BALLOON_N_BLOCKS; i++ )
      {
         balloon_put_le64( msg, counter++ );
         memcpy( msg + 8, buf + ( i - 1 ) * BALLOON_BLOCK_SIZE,
                 BALLOON_BLOCK_SIZE );
         balloon_sha256_blocks( buf + i * BALLOON_BLOCK_SIZE, msg, 1 );
      }
   }

   /* Mix. Blocks are updated in place, so a neighbour already visited this
    * round contributes its new value and one not yet visited its old one —
    * that sequential dependency is what makes the hash memory-hard.         */
   {
      uint8_t *msg = ctx->mmix;
      const uint16_t *idx = ctx->idx;

      for ( int round = 0; round < BALLOON_T_COST; round++ )
      for ( int i = 0; i < BALLOON_N_BLOCKS; i++ )
      {
         uint8_t *cur = buf + i * BALLOON_BLOCK_SIZE;

         balloon_put_le64( msg, counter++ );
         memcpy( msg + 8, i ? cur - BALLOON_BLOCK_SIZE : buf + BALLOON_LAST,
                 BALLOON_BLOCK_SIZE );
         memcpy( msg + 8 + BALLOON_BLOCK_SIZE, cur, BALLOON_BLOCK_SIZE );

         for ( int k = 0; k < BALLOON_N_NEIGHBORS; k++ )
            memcpy( msg + 8 + BALLOON_BLOCK_SIZE * ( 2 + k ),
                    buf + *idx++ * BALLOON_BLOCK_SIZE, BALLOON_BLOCK_SIZE );

         balloon_sha256_blocks( cur, msg, 3 );
      }
   }

   memcpy( digest, buf + BALLOON_LAST, BALLOON_BLOCK_SIZE );
}

#if BALLOON_HAVE_2WAY

/* Two independent digests, one interleaved pass. Same alignment contract. */
static inline void balloon_sha256_blocks_2( uint8_t *out0, uint8_t *out1,
                                            const uint8_t *blk0,
                                            const uint8_t *blk1,
                                            const int nblocks )
{
   uint32_t s0[8] __attribute__((aligned(64)));
   uint32_t s1[8] __attribute__((aligned(64)));

   memcpy( s0, balloon_sha256_iv, sizeof s0 );
   memcpy( s1, balloon_sha256_iv, sizeof s1 );

   for ( int i = 0; i < nblocks; i++ )
      sha256_2x_transform_be( s0, s1, blk0 + 64*i, blk1 + 64*i, s0, s1 );

   for ( int i = 0; i < 8; i++ )
   {
      ( (uint32_t*)out0 )[i] = bswap_32( s0[i] );
      ( (uint32_t*)out1 )[i] = bswap_32( s1[i] );
   }
}

void balloon_hash_header_2way( balloon_ctx *ctx,
                               const void *input0, const void *input1,
                               void *digest0, void *digest1 )
{
   const uint8_t *in0 = (const uint8_t*)input0;
   const uint8_t *in1 = (const uint8_t*)input1;
   const uint8_t *salt = in0;          /* shared by contract — see balloon.h */
   uint8_t *buf0 = ctx->buf;
   uint8_t *buf1 = ctx->buf1;
   uint64_t counter = 0;

   if ( !ctx->idx_valid
        || memcmp( ctx->idx_salt, salt, BALLOON_SALT_LEN ) != 0 )
   {
      balloon_build_indices( ctx->idx, salt );
      memcpy( ctx->idx_salt, salt, BALLOON_SALT_LEN );
      ctx->idx_valid = true;
   }

   balloon_pad( ctx->mfill,    BALLOON_MSG_FILL,   sizeof ctx->mfill    );
   balloon_pad( ctx->mfill1,   BALLOON_MSG_FILL,   sizeof ctx->mfill1   );
   balloon_pad( ctx->mexpand,  BALLOON_MSG_EXPAND, sizeof ctx->mexpand  );
   balloon_pad( ctx->mexpand1, BALLOON_MSG_EXPAND, sizeof ctx->mexpand1 );
   balloon_pad( ctx->mmix,     BALLOON_MSG_MIX,    sizeof ctx->mmix     );
   balloon_pad( ctx->mmix1,    BALLOON_MSG_MIX,    sizeof ctx->mmix1    );

   /* Fill — the only phase where the lanes differ, since the nonce lives in
    * the header and nowhere else.                                          */
   {
      balloon_put_le64( ctx->mfill,  counter   );
      balloon_put_le64( ctx->mfill1, counter++ );
      memcpy( ctx->mfill  + 8, salt, BALLOON_SALT_LEN );
      memcpy( ctx->mfill1 + 8, salt, BALLOON_SALT_LEN );
      memcpy( ctx->mfill  + 40, in0, BALLOON_INPUT_LEN );
      memcpy( ctx->mfill1 + 40, in1, BALLOON_INPUT_LEN );
      balloon_put_le64( ctx->mfill  + 120, BALLOON_S_COST );
      balloon_put_le64( ctx->mfill1 + 120, BALLOON_S_COST );
      balloon_put_le32( ctx->mfill  + 128, BALLOON_T_COST );
      balloon_put_le32( ctx->mfill1 + 128, BALLOON_T_COST );

      balloon_sha256_blocks_2( buf0, buf1, ctx->mfill, ctx->mfill1,
                               sizeof ctx->mfill / 64 );
   }

   /* Expand — identical shape in both lanes, so one loop drives both. */
   {
      uint8_t *m0 = ctx->mexpand, *m1 = ctx->mexpand1;

      for ( int i = 1; i < BALLOON_N_BLOCKS; i++ )
      {
         const int prev = ( i - 1 ) * BALLOON_BLOCK_SIZE;

         balloon_put_le64( m0, counter   );
         balloon_put_le64( m1, counter++ );
         memcpy( m0 + 8, buf0 + prev, BALLOON_BLOCK_SIZE );
         memcpy( m1 + 8, buf1 + prev, BALLOON_BLOCK_SIZE );

         balloon_sha256_blocks_2( buf0 + i * BALLOON_BLOCK_SIZE,
                                  buf1 + i * BALLOON_BLOCK_SIZE, m0, m1, 1 );
      }
   }

   /* Mix — one index stream, two buffers. This is the whole reason the pairing
    * is cheap: both lanes read the same offsets, so there is no gather and no
    * divergence.                                                            */
   {
      uint8_t *m0 = ctx->mmix, *m1 = ctx->mmix1;
      const uint16_t *idx = ctx->idx;

      for ( int round = 0; round < BALLOON_T_COST; round++ )
      for ( int i = 0; i < BALLOON_N_BLOCKS; i++ )
      {
         const int cur  = i * BALLOON_BLOCK_SIZE;
         const int prev = i ? cur - BALLOON_BLOCK_SIZE : BALLOON_LAST;

         balloon_put_le64( m0, counter   );
         balloon_put_le64( m1, counter++ );
         memcpy( m0 + 8, buf0 + prev, BALLOON_BLOCK_SIZE );
         memcpy( m1 + 8, buf1 + prev, BALLOON_BLOCK_SIZE );
         memcpy( m0 + 40, buf0 + cur, BALLOON_BLOCK_SIZE );
         memcpy( m1 + 40, buf1 + cur, BALLOON_BLOCK_SIZE );

         for ( int k = 0; k < BALLOON_N_NEIGHBORS; k++ )
         {
            const int n = *idx++ * BALLOON_BLOCK_SIZE;
            memcpy( m0 + 72 + 32*k, buf0 + n, BALLOON_BLOCK_SIZE );
            memcpy( m1 + 72 + 32*k, buf1 + n, BALLOON_BLOCK_SIZE );
         }

         balloon_sha256_blocks_2( buf0 + cur, buf1 + cur, m0, m1, 3 );
      }
   }

   memcpy( digest0, buf0 + BALLOON_LAST, BALLOON_BLOCK_SIZE );
   memcpy( digest1, buf1 + BALLOON_LAST, BALLOON_BLOCK_SIZE );
}

#endif  /* BALLOON_HAVE_2WAY */

/* ── Per-thread scratch ───────────────────────────────────────────────────
 *
 * GPU miners keep the equivalents — the index buffer and the block scratch —
 * at file scope, which is fine for one host thread per device and a data race
 * here, where -t N threads run this code. It is not a benign race either: the
 * index table feeds the digest, so two threads on different jobs would quietly
 * mine rejects rather than crash.                                           */

static __thread balloon_ctx *tl_ctx = NULL;

balloon_ctx *balloon_thread_ctx( void )
{
   if ( !tl_ctx )
   {
      void *p = NULL;
      if ( posix_memalign( &p, 64, sizeof( balloon_ctx ) ) || !p )
         return NULL;
      tl_ctx = (balloon_ctx*)p;
      balloon_ctx_reset( tl_ctx );
   }
   return tl_ctx;
}

/* Release this thread's context. The index table inside it is consensus state
 * keyed on the salt, so dropping it is always safe: the next hash rebuilds it.
 * Idempotent, and the ctx is lazily reallocated on the next call above.     */
void balloon_thread_ctx_free( void )
{
#if defined(_WIN32)
   _aligned_free( tl_ctx );      /* posix_memalign is mapped to _aligned_malloc */
#else
   free( tl_ctx );
#endif
   tl_ctx = NULL;
}

/* ── Self-test ────────────────────────────────────────────────────────────
 *
 * Checked from the innermost primitive outwards so a failure localises: the
 * cipher, then the index bitstream built on it, then the whole construction.
 * See balloon-kat.h for where each vector comes from.                       */

const char *balloon_self_test( void )
{
   balloon_aes128_ctx aes;
   uint8_t out[64];

   balloon_aes128_init( &aes, balloon_kat_aes_key );
   balloon_aes128_encrypt_block( &aes, balloon_kat_aes_in, out );
   if ( memcmp( out, balloon_kat_aes_out, 16 ) )
      return "AES-128, FIPS-197 C.1";

   balloon_bitstream_key( out, balloon_kat_salt,
                          BALLOON_S_COST, BALLOON_T_COST );
   if ( memcmp( out, balloon_kat_key, 32 ) )
      return "index bitstream key derivation";

   balloon_bitstream_raw( out, 64, balloon_kat_salt,
                          BALLOON_S_COST, BALLOON_T_COST );
   if ( memcmp( out, balloon_kat_keystream, 64 ) )
      return "index bitstream keystream";

   /* Through the per-thread accessor, so startup also proves the 224 KiB
    * allocation works rather than leaving it to the first hash.             */
   balloon_ctx *ctx = balloon_thread_ctx();
   if ( !ctx ) return "scratch allocation";

   for ( size_t i = 0; i < BALLOON_N_KATS; i++ )
   {
      balloon_hash_header( ctx, balloon_kats[i].header, out );
      if ( memcmp( out, balloon_kats[i].digest, BALLOON_BLOCK_SIZE ) )
         return balloon_kats[i].name;
   }

   return NULL;
}
