#include "flex-gate.h"
#include "flex-cryptonight.h"
#include "../gr/cryptonight.h"   // cryptonight_free_scratchpad(), shared cores
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../cubehash/sph_cubehash.h"
#include "../echo/sph_echo.h"
#include "../fugue/sph_fugue.h"
#include "../groestl/sph_groestl.h"
#include "../hamsi/sph_hamsi.h"
#include "../keccak/sph_keccak.h"
#include "../keccak/keccak-gate.h"      // hard_coded_eb
#include "../luffa/sph_luffa.h"
#include "../shabal/sph_shabal.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../skein/sph_skein.h"
#include "../whirlpool/sph_whirlpool.h"
#include "../sha/sha256d.h"

// Optimized single-hash cores (same algorithms, faster implementations; output
// is bit-identical to the sph reference). Mirrors gr-gate.c's scalar dispatch.
#include "../blake/blake512-hash.h"
#include "../luffa/luffa_for_sse2.h"
#include "../cubehash/cubehash_sse2.h"
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "../groestl/aes_ni/hash-groestl.h"
  #include "../echo/aes_ni/hash_api.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Flex (Kylacoin "flex").
 *
 * A GhostRider sibling. Differences from GhostRider (algo/gr):
 *   - 14 core algorithms (the x16 set without JH and SHA), not 15.
 *   - The core order and CN triple are derived from keccak512(header) rather
 *     than from a nonce-independent header region, so the selection — and hence
 *     the whole hash — depends on the nonce. (This is why there is no
 *     4-way-across-nonces path here: each nonce takes a different chain.)
 *   - The high 32 bytes of the working buffer are NOT zeroed after a CN round.
 *   - A final keccak256 is applied to the last chain output.
 *   - SHA3-style keccak padding (hard_coded_eb = 6) and a keccak-based (sha3d)
 *     merkle root.
 *
 * Faithful port of the reference flex-gate.c (Kylacoin cpuminer-flex); the
 * memory-hard CryptoNight rounds reuse this repo's optimized GhostRider cores.
 */

enum Algo
{
   BLAKE = 0, BMW, GROESTL, KECCAK, SKEIN, LUFFA, CUBEHASH, SHAVITE,
   SIMD, ECHO, HAMSI, FUGUE, SHABAL, WHIRLPOOL,
   HASH_FUNC_COUNT
};

enum CNAlgo
{
   CNDark = 0, CNDarklite, CNFast, CNLite, CNTurtle, CNTurtlelite,
   CN_HASH_FUNC_COUNT
};

static void selectAlgo( unsigned char nibble, bool *selectedAlgos,
                        uint8_t *selectedIndex, int algoCount,
                        int *currentCount )
{
   uint8_t algoDigit = ( nibble & 0x0F ) % algoCount;
   if ( !selectedAlgos[ algoDigit ] )
   {
      selectedAlgos[ algoDigit ] = true;
      selectedIndex[ currentCount[0] ] = algoDigit;
      currentCount[0] += 1;
   }
   algoDigit = ( nibble >> 4 ) % algoCount;
   if ( !selectedAlgos[ algoDigit ] )
   {
      selectedAlgos[ algoDigit ] = true;
      selectedIndex[ currentCount[0] ] = algoDigit;
      currentCount[0] += 1;
   }
}

static void getAlgoString( const void *mem, unsigned int size,
                           uint8_t *selectedAlgoOutput, int algoCount )
{
   unsigned char *p = (unsigned char*)mem;
   unsigned int len = size / 2;
   bool selectedAlgo[ HASH_FUNC_COUNT ] = { false };  // >= max algoCount (14)
   int selectedCount = 0;

   for ( unsigned int i = 0; i < len; i++ )
   {
      selectAlgo( p[i], selectedAlgo, selectedAlgoOutput, algoCount,
                  &selectedCount );
      if ( selectedCount == algoCount ) break;
   }
   if ( selectedCount < algoCount )
      for ( uint8_t i = 0; i < algoCount; i++ )
         if ( !selectedAlgo[i] )
            selectedAlgoOutput[ selectedCount++ ] = i;
}

static void doCNAlgo( uint8_t algo, const void *in, void *hash, int size )
{
   const char *i = (const char*)in;
   char *o = (char*)hash;
   // The reference runs each CN round in-place (input buffer == output buffer).
   // With HASH_SIZE=64 the blake finalization writes only the low 32 bytes, so
   // the high 32 bytes of the result are the CN round's own input bytes. We use
   // separate ping-pong buffers, so pre-seed the output with the input to
   // reproduce those bytes (skein overwrites all 64, making this a no-op there).
   memcpy( o, i, size );
   switch ( algo )
   {
      case CNDark:       flex_cryptonightdark_hash      ( i, o, size, 1 ); break;
      case CNDarklite:   flex_cryptonightdarklite_hash  ( i, o, size, 1 ); break;
      case CNFast:       flex_cryptonightfast_hash      ( i, o, size, 1 ); break;
      case CNLite:       flex_cryptonightlite_hash      ( i, o, size, 1 ); break;
      case CNTurtle:     flex_cryptonightturtle_hash    ( i, o, size, 1 ); break;
      case CNTurtlelite: flex_cryptonightturtlelite_hash( i, o, size, 1 ); break;
   }
}

static void doCoreAlgo( uint8_t algo, const void *in, void *hash, int size )
{
   switch ( algo )
   {
      case BLAKE:
      {  blake512_context ctx;
         blake512_init( &ctx ); blake512_update( &ctx, in, size );
         blake512_close( &ctx, hash ); break; }
      case BMW:
      {  sph_bmw512_context ctx;
         sph_bmw512_init( &ctx ); sph_bmw512( &ctx, in, size );
         sph_bmw512_close( &ctx, hash ); break; }
      case GROESTL:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
      {  hashState_groestl ctx;
         groestl512_full( &ctx, hash, in, (uint64_t)size << 3 ); break; }
#else
      {  sph_groestl512_context ctx;
         sph_groestl512_init( &ctx ); sph_groestl512( &ctx, in, size );
         sph_groestl512_close( &ctx, hash ); break; }
#endif
      case KECCAK:
      {  sph_keccak512_context ctx;
         sph_keccak512_init( &ctx ); sph_keccak512( &ctx, in, size );
         sph_keccak512_close( &ctx, hash ); break; }
      case SKEIN:
      {  sph_skein512_context ctx;
         sph_skein512_init( &ctx ); sph_skein512( &ctx, in, size );
         sph_skein512_close( &ctx, hash ); break; }
      case LUFFA:
      {  hashState_luffa ctx;
         luffa_full( &ctx, hash, 512, in, size ); break; }
      case CUBEHASH:
      {  cubehashParam ctx;
         cubehash_full( &ctx, hash, 512, in, size ); break; }
      case SHAVITE:
      {  sph_shavite512_context ctx;
         sph_shavite512_init( &ctx ); sph_shavite512( &ctx, in, size );
         sph_shavite512_close( &ctx, hash ); break; }
      case SIMD:
      {  sph_simd512_context ctx;
         sph_simd512_init( &ctx ); sph_simd512( &ctx, in, size );
         sph_simd512_close( &ctx, hash ); break; }
      case ECHO:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
      {  hashState_echo ctx;
         echo_full( &ctx, hash, 512, in, size ); break; }
#else
      {  sph_echo512_context ctx;
         sph_echo512_init( &ctx ); sph_echo512( &ctx, in, size );
         sph_echo512_close( &ctx, hash ); break; }
#endif
      case HAMSI:
      {  sph_hamsi512_context ctx;
         sph_hamsi512_init( &ctx ); sph_hamsi512( &ctx, in, size );
         sph_hamsi512_close( &ctx, hash ); break; }
      case FUGUE:
      {  sph_fugue512_context ctx;
         sph_fugue512_init( &ctx ); sph_fugue512( &ctx, in, size );
         sph_fugue512_close( &ctx, hash ); break; }
      case SHABAL:
      {  sph_shabal512_context ctx;
         sph_shabal512_init( &ctx ); sph_shabal512( &ctx, in, size );
         sph_shabal512_close( &ctx, hash ); break; }
      case WHIRLPOOL:
      {  sph_whirlpool_context ctx;
         sph_whirlpool_init( &ctx ); sph_whirlpool( &ctx, in, size );
         sph_whirlpool_close( &ctx, hash ); break; }
   }
}

void flex_hash( void *output, const void *input )
{
   uint8_t hash_1[64] __attribute__ ((aligned (64)));
   uint8_t hash_2[64] __attribute__ ((aligned (64)));
   uint8_t seed[64]   __attribute__ ((aligned (64)));
   // coreOrder[14] is intentionally left 0 (= BLAKE): getAlgoString fills only
   // [0..13] for a 14-entry pool, but the chain references slot 14. This
   // reproduces the reference's uninitialized-slot behaviour (consensus).
   uint8_t coreOrder[15] = { 0 };
   uint8_t cnOrder[6];

   // Selection seed: keccak512 of the full 80-byte header (nonce-dependent).
   {  sph_keccak512_context ctx;
      sph_keccak512_init( &ctx ); sph_keccak512( &ctx, input, 80 );
      sph_keccak512_close( &ctx, seed ); }

   getAlgoString( seed, 64, coreOrder, HASH_FUNC_COUNT );  // 14
   getAlgoString( seed, 64, cnOrder,   CN_HASH_FUNC_COUNT ); // 6

   // Group 1: first core round consumes the full 80-byte header.
   doCoreAlgo( coreOrder[0], input,  hash_1, 80 );
   doCoreAlgo( coreOrder[1], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[2], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[3], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[4], hash_2, hash_1, 64 );
   doCNAlgo  ( cnOrder[0],   hash_1, hash_2, 64 );
   // No memset of hash_2[32..64) — Flex does not zero (unlike GhostRider).

   // Group 2.
   doCoreAlgo( coreOrder[5], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[6], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[7], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[8], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[9], hash_2, hash_1, 64 );
   doCNAlgo  ( cnOrder[1],   hash_1, hash_2, 64 );

   // Group 3.
   doCoreAlgo( coreOrder[10], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[11], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[12], hash_2, hash_1, 64 );
   doCoreAlgo( coreOrder[13], hash_1, hash_2, 64 );
   doCoreAlgo( coreOrder[14], hash_2, hash_1, 64 );  // slot 14 == BLAKE
   doCNAlgo  ( cnOrder[2],    hash_1, hash_2, 64 );

   // Final keccak256 of the last chain output.
   {  sph_keccak256_context ctx;
      sph_keccak256_init( &ctx ); sph_keccak256( &ctx, hash_2, 64 );
      sph_keccak256_close( &ctx, output ); }
}

// sha3d (double keccak-256) over arbitrary input — used for the Flex merkle root.
static void flex_sha3d( void *state, const void *input, int len )
{
   uint8_t buffer[32];
   sph_keccak256_context ctx;

   sph_keccak256_init( &ctx ); sph_keccak256( &ctx, input, len );
   sph_keccak256_close( &ctx, buffer );

   sph_keccak256_init( &ctx ); sph_keccak256( &ctx, buffer, 32 );
   sph_keccak256_close( &ctx, state );
}

static void flex_gen_merkle_root( char *merkle_root, struct stratum_ctx *sctx )
{
   flex_sha3d( merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size );
   for ( int i = 0; i < sctx->job.merkle_count; i++ )
   {
      memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
      sha256d( (unsigned char*)merkle_root, (unsigned char*)merkle_root, 64 );
   }
}

// Known-answer self-test, taken from a REAL pool-accepted share produced by the
// upstream Kylacoin cpuminer-flex reference (zpool.ca job 4fb5b, 2026-06-26).
// flex_test_input is the 80-byte header exactly as flex_hash receives it — the
// be32enc'd work->data words (big-endian). flex_test_expected is the resulting
// 32-byte digest (little-endian words: hash[0]=0x0441f067 .. hash[7]=0x00007a82),
// which the pool accepted, so it is consensus-correct by construction.
static const uint8_t flex_test_input[80] =
{
   0x00,0x80,0x00,0x20, 0xe8,0xa4,0x6b,0x94, 0x55,0x33,0x33,0x0a, 0x80,0x53,0x6b,0x4b,
   0x8e,0x02,0xc7,0x09, 0xa9,0x1a,0xad,0xcb, 0x31,0x5a,0xd3,0xf9, 0x13,0xa1,0x59,0x72,
   0xf8,0x68,0xe4,0x8a, 0x12,0xb9,0x63,0xf1, 0xe9,0x87,0xc4,0xb3, 0xb1,0x7f,0x6a,0x40,
   0xc4,0x15,0xba,0xe8, 0xf5,0x04,0x4d,0x3d, 0x72,0x99,0x1d,0x74, 0xbe,0x0d,0xce,0xe3,
   0x9b,0xe2,0x7d,0xe2, 0xad,0x9a,0x3e,0x6a, 0xa1,0x11,0x01,0x1e, 0x60,0x00,0x01,0x7e
};

static const uint8_t flex_test_expected[32] =
{
   0x67,0xf0,0x41,0x04, 0xc6,0x3b,0xbf,0xde, 0xa3,0xd1,0x22,0x9e, 0x6f,0xf4,0x93,0xfa,
   0x84,0x7e,0x81,0x06, 0xce,0x3c,0x90,0xa0, 0x61,0xc1,0xb4,0x9f, 0x82,0x7a,0x00,0x00
};

bool flex_self_test( void )
{
   uint8_t hash[32];
   flex_hash( hash, flex_test_input );

   if ( memcmp( hash, flex_test_expected, 32 ) == 0 )
   {
      applog( LOG_NOTICE, "Flex self-test PASSED (consensus KAT)" );
      return true;
   }

   char got[65], exp[65];
   for ( int i = 0; i < 32; i++ )
   {
      sprintf( got + i * 2, "%02x", hash[i] );
      sprintf( exp + i * 2, "%02x", flex_test_expected[i] );
   }
   applog( LOG_ERR, "Flex self-test FAILED (consensus KAT mismatch)" );
   applog( LOG_ERR, "  got:      %s", got );
   applog( LOG_ERR, "  expected: %s", exp );
   return false;
}

int scanhash_flex( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                   struct thr_info *mythr )
{
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t _ALIGN(64) hash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t n = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   for ( int i = 0; i < 19; i++ )
      be32enc( &endiandata[i], pdata[i] );

   do
   {
      be32enc( &endiandata[19], n );
      flex_hash( hash, endiandata );

      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = n;
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < max_nonce && !(*restart) );

   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

/* Flex uses its own CryptoNight cores but the same per-thread scratchpad. */
static void flex_thread_free( int thr_id )
{
   (void)thr_id;
   cryptonight_free_scratchpad();
}

bool register_flex_algo( algo_gate_t *gate )
{
   // SHA3-style keccak padding for every keccak in the Flex chain (consensus).
   hard_coded_eb = 6;

   if ( !flex_self_test() )
   {
      applog( LOG_ERR, "Flex self-test failed" );
      return false;
   }
   gate->scanhash        = (void*)&scanhash_flex;
gate->miner_thread_free = (void*)&flex_thread_free;
   gate->hash            = (void*)&flex_hash;
   gate->gen_merkle_root = (void*)&flex_gen_merkle_root;
   gate->optimizations   = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   return true;
}
