#include "gr-gate.h"
#include "cryptonight.h"
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../cubehash/sph_cubehash.h"
#include "../echo/sph_echo.h"
#include "../fugue/sph_fugue.h"
#include "../groestl/sph_groestl.h"
#include "../hamsi/sph_hamsi.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../luffa/sph_luffa.h"
#include "../shabal/sph_shabal.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../skein/sph_skein.h"
#include "../whirlpool/sph_whirlpool.h"

// Optimized single-hash cores (same algorithms, faster implementations; output
// is bit-identical to the sph reference). Mirrors x16r's scalar dispatch.
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
 * GhostRider (Raptoreum "gr").
 *
 * Combines 15 "core" algorithms (the x16 set without SHA) with 6 CryptoNight
 * variants, of which 3 are used per hash. Both the core order and the CN triple
 * are derived from bytes [4..68) of the (byteswapped) block header. The chain is
 * three groups of five core rounds, each followed by one CN round; the high 32
 * bytes of the working buffer are zeroed after each CN round.
 *
 * Scalar reference port from michal-zurkowski/cpuminer-gr with CryptoNight
 * parameters corrected against WyvernTKC cpuminer-gr (the consensus miner).
 */

enum Algo
{
   BLAKE = 0, BMW, GROESTL, JH, KECCAK, SKEIN, LUFFA, CUBEHASH,
   SHAVITE, SIMD, ECHO, HAMSI, FUGUE, SHABAL, WHIRLPOOL,
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

// Shared with `mike` (VKAX/FortuneBlock), which is this same walk with
// algoCount = 11. Exported via gr-gate.h; see algo/mike/mike-gate.c.
void gr_get_algo_string( const void *mem, unsigned int size,
                         uint8_t *selectedAlgoOutput, int algoCount )
{
   unsigned char *p = (unsigned char*)mem;
   unsigned int len = size / 2;
   bool selectedAlgo[ HASH_FUNC_COUNT ] = { false };  // >= max algoCount (15)
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

// Shared with `mike`; the six CryptoNight variants and their parameters are
// identical between the two algos (verified against VKAX Core slow-hash.h).
void gr_do_cn_algo( uint8_t algo, const void *in, void *hash, int size )
{
   switch ( algo )
   {
      case CNDark:       cryptonightdark_hash      ( in, hash, size, 1 ); break;
      case CNDarklite:   cryptonightdarklite_hash  ( in, hash, size, 1 ); break;
      case CNFast:       cryptonightfast_hash      ( in, hash, size, 1 ); break;
      case CNLite:       cryptonightlite_hash      ( in, hash, size, 1 ); break;
      case CNTurtle:     cryptonightturtle_hash    ( in, hash, size, 1 ); break;
      case CNTurtlelite: cryptonightturtlelite_hash( in, hash, size, 1 ); break;
   }
}

// Shared with `mike`, which selects from entries 0..10 of this same table.
void gr_do_core_algo( uint8_t algo, const void *in, void *hash, int size )
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
      case SKEIN:
      {  sph_skein512_context ctx;
         sph_skein512_init( &ctx ); sph_skein512( &ctx, in, size );
         sph_skein512_close( &ctx, hash ); break; }
      case JH:
      {  sph_jh512_context ctx;
         sph_jh512_init( &ctx ); sph_jh512( &ctx, in, size );
         sph_jh512_close( &ctx, hash ); break; }
      case KECCAK:
      {  sph_keccak512_context ctx;
         sph_keccak512_init( &ctx ); sph_keccak512( &ctx, in, size );
         sph_keccak512_close( &ctx, hash ); break; }
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

void gr_hash( void *output, const void *input )
{
   uint8_t hash_1[64] __attribute__ ((aligned (64)));
   uint8_t hash_2[64] __attribute__ ((aligned (64)));
   uint8_t coreOrder[15];
   uint8_t cnOrder[6];

   gr_get_algo_string((const uint8_t*)input + 4, 64, coreOrder, 15 );
   gr_get_algo_string((const uint8_t*)input + 4, 64, cnOrder,    6 );

   // Group 1: first core round consumes the full 80-byte header.
   gr_do_core_algo( coreOrder[0], input,  hash_1, 80 );
   gr_do_core_algo( coreOrder[1], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[2], hash_2, hash_1, 64 );
   gr_do_core_algo( coreOrder[3], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[4], hash_2, hash_1, 64 );
   gr_do_cn_algo  ( cnOrder[0],   hash_1, hash_2, 64 );
   memset( hash_2 + 32, 0, 32 );

   // Group 2.
   gr_do_core_algo( coreOrder[5], hash_2, hash_1, 64 );
   gr_do_core_algo( coreOrder[6], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[7], hash_2, hash_1, 64 );
   gr_do_core_algo( coreOrder[8], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[9], hash_2, hash_1, 64 );
   gr_do_cn_algo  ( cnOrder[1],   hash_1, hash_2, 64 );
   memset( hash_2 + 32, 0, 32 );

   // Group 3.
   gr_do_core_algo( coreOrder[10], hash_2, hash_1, 64 );
   gr_do_core_algo( coreOrder[11], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[12], hash_2, hash_1, 64 );
   gr_do_core_algo( coreOrder[13], hash_1, hash_2, 64 );
   gr_do_core_algo( coreOrder[14], hash_2, hash_1, 64 );
   gr_do_cn_algo  ( cnOrder[2],    hash_1, hash_2, 64 );

   memcpy( output, hash_2, 32 );
}

// Known-answer self-test. The 80-byte input is the reference header from
// npq7721/gr_hash test.py; the expected digest was captured from this
// implementation, whose components are independently verified for consensus
// correctness:
//   - CryptoNight core: matches the authoritative xmrig cn/v1 KAT byte-for-byte
//   - algo selection + 5/CN/5/CN/5/CN chain: matches xmrig ghostrider.cpp
//   - the six CryptoNight parameter sets: match WyvernTKC cpuminer-gr (consensus)
// It therefore doubles as a regression guard. End-to-end consensus is finally
// confirmed by pool-accepted shares.
static const uint8_t gr_test_input[80] =
{
   0x70,0x00,0x00,0x00,0x5d,0x38,0x5b,0xa1,0x14,0xd0,0x79,0x97,0x0b,0x29,0xa9,0x41,
   0x8f,0xd0,0x54,0x9e,0x7d,0x68,0xa9,0x5c,0x7f,0x16,0x86,0x21,0xa3,0x14,0x20,0x10,
   0x00,0x00,0x00,0x00,0x57,0x85,0x86,0xd1,0x49,0xfd,0x07,0xb2,0x2f,0x3a,0x8a,0x34,
   0x7c,0x51,0x6d,0xe7,0x05,0x2f,0x03,0x4d,0x2b,0x76,0xff,0x68,0xe0,0xd6,0xec,0xff,
   0x9b,0x77,0xa4,0x54,0x89,0xe3,0xfd,0x51,0x17,0x32,0x01,0x1d,0xf0,0x73,0x10,0x00
};

static const uint8_t gr_test_expected[32] =
{
   0x57,0x28,0x99,0x3c,0x46,0xe9,0x78,0x21,0x1b,0x52,0x84,0xc4,0x6d,0xc2,0x89,0x3f,
   0x51,0x1b,0x28,0x79,0x4a,0x25,0x14,0x98,0x67,0xec,0x8c,0x33,0xa5,0xef,0xb5,0x69
};

bool gr_self_test( void )
{
   uint8_t hash[32];
   gr_hash( hash, gr_test_input );

   if ( memcmp( hash, gr_test_expected, 32 ) != 0 )
   {
      char hex[65];
      for ( int i = 0; i < 32; i++ )
         sprintf( hex + i * 2, "%02x", hash[i] );
      applog( LOG_ERR, "GhostRider self-test mismatch: got %s", hex );
      return false;
   }
   return true;
}

// GR_CN_LANES nonces at once. The core order and CN triple depend only on the
// header's prevblock region (bytes [4..36)), which is identical across the
// lanes' nonces, so both are derived once; the three CN stages run interleaved
// via cryptonight_4way to hide scratchpad memory latency.
static void gr_hash_4way( void *const out[GR_CN_LANES],
                          const void *const in[GR_CN_LANES] )
{
   uint8_t h1[GR_CN_LANES][64] __attribute__ ((aligned (64)));
   uint8_t h2[GR_CN_LANES][64] __attribute__ ((aligned (64)));
   const void *cin[GR_CN_LANES];
   void *cout[GR_CN_LANES];
   uint8_t coreOrder[15], cnOrder[6];
   int l;

   gr_get_algo_string((const uint8_t*)in[0] + 4, 64, coreOrder, 15 );
   gr_get_algo_string((const uint8_t*)in[0] + 4, 64, cnOrder,    6 );

   for ( l = 0; l < GR_CN_LANES; l++ )
      { cin[l] = h1[l]; cout[l] = h2[l]; }

   // Group 1 (first core round consumes 80 bytes).
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[0], in[l], h1[l], 80 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[1], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[2], h2[l], h1[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[3], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[4], h2[l], h1[l], 64 );
   cryptonight_4way( cnOrder[0], cin, cout, 64 );          // h1 -> h2
   for ( l = 0; l < GR_CN_LANES; l++ ) memset( h2[l] + 32, 0, 32 );

   // Group 2.
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[5], h2[l], h1[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[6], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[7], h2[l], h1[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[8], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[9], h2[l], h1[l], 64 );
   cryptonight_4way( cnOrder[1], cin, cout, 64 );          // h1 -> h2
   for ( l = 0; l < GR_CN_LANES; l++ ) memset( h2[l] + 32, 0, 32 );

   // Group 3.
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[10], h2[l], h1[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[11], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[12], h2[l], h1[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[13], h1[l], h2[l], 64 );
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[14], h2[l], h1[l], 64 );
   cryptonight_4way( cnOrder[2], cin, cout, 64 );          // h1 -> h2

   for ( l = 0; l < GR_CN_LANES; l++ ) memcpy( out[l], h2[l], 32 );
}

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                 struct thr_info *mythr )
{
   uint32_t _ALIGN(64) edata[GR_CN_LANES][20];
   uint32_t _ALIGN(64) hash[GR_CN_LANES][8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;
   const void *in[GR_CN_LANES];
   void *out[GR_CN_LANES];

   v128_bswap32_80( edata[0], pdata );
   for ( int l = 1; l < GR_CN_LANES; l++ )
      memcpy( edata[l], edata[0], 80 );
   for ( int l = 0; l < GR_CN_LANES; l++ )
      { in[l] = edata[l]; out[l] = hash[l]; }

   static volatile int logged_backing = 0;

   do
   {
      for ( int l = 0; l < GR_CN_LANES; l++ )
         edata[l][19] = nonce + l;

      gr_hash_4way( out, in );

      if ( thr_id == 0 && !logged_backing )
      {
         logged_backing = 1;
         applog( LOG_INFO, "GhostRider: CryptoNight scratchpad backing: %s",
                 cryptonight_scratchpad_backing() );
      }

      for ( int l = 0; l < GR_CN_LANES; l++ )
         if ( unlikely( valid_hash( hash[l], ptarget ) && !bench ) )
         {
            pdata[19] = bswap_32( nonce + l );
            submit_solution( work, hash[l], mythr );
         }
      nonce += GR_CN_LANES;
   } while ( nonce < max_nonce && !(*restart) );

   pdata[19] = nonce;
   *hashes_done = nonce - first_nonce;
   return 0;
}

/* GhostRider's three CryptoNight scratchpads are 2 MiB each and may be huge
 * pages or mmap; cryptonight_free_scratchpad() knows which. */
static void gr_thread_free( int thr_id )
{
   (void)thr_id;
   cryptonight_free_scratchpad();
}

bool register_gr_algo( algo_gate_t *gate )
{
   if ( !gr_self_test() )
   {
      applog( LOG_ERR, "GhostRider self-test failed" );
      return false;
   }
   gate->scanhash     = (void*)&scanhash_gr;
gate->miner_thread_free = (void*)&gr_thread_free;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   opt_target_factor  = 65536.0;
   return true;
}
