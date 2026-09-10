#include "mike-gate.h"
#include "../gr/gr-gate.h"
#include "../gr/cryptonight.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

/*
 * Mike (VKAX, FortuneBlock).
 *
 * GhostRider with an 11-wide core pool instead of 15. The chain consumes the
 * core order in groups of five, so the third group is one round, not five:
 *
 *     gr    5 core, CN, 5 core, CN, 5 core, CN   (15 core + 3 CN, 18 steps)
 *     mike  5 core, CN, 5 core, CN, 1 core, CN   (11 core + 3 CN, 14 steps)
 *
 * Everything else matches GhostRider and is reused unmodified from algo/gr/:
 * core hash table (entries 0..10), all six CryptoNight-v1 variants, the CN
 * finalization, HASH_SIZE, the post-CN zeroing and the nibble walk. No final
 * hash after the chain; the digest is the low 32 bytes of the last CN output.
 *
 * WARNING: the core order is a permutation of 0..10 from reducing each header
 * nibble % 11. It is NOT GhostRider's 15-wide permutation truncated to 11.
 * Using 15 gives a wrong hash on nearly every input, with no symptom until a
 * pool rejects the share. MIKE_CORE_ALGO_COUNT keeps that number in one place.
 *
 * Do not "fix" gr_get_algo_string() to match VKAX Core's descending nibble
 * loop: uint256::GetNibble() starts with `index = 63 - index`, so VKAX's
 * descending loop already yields ascending raw nibble order, same as ours.
 *
 * Reference: VKAX Core src/hash.h (Mike()), src/hash_selection.cpp,
 * src/uint256.h, src/primitives/block.cpp, src/cryptonote/slow-hash.{c,h};
 * cross-checked against xmrig PR #3131.
 */

#define MIKE_CORE_ALGO_COUNT 11

void mike_hash( void *output, const void *input )
{
   uint8_t hash_1[64] __attribute__ ((aligned (64)));
   uint8_t hash_2[64] __attribute__ ((aligned (64)));
   uint8_t coreOrder[MIKE_CORE_ALGO_COUNT];
   uint8_t cnOrder[GR_CN_ALGO_COUNT];

   // Both orders come from the prevblock region, bytes [4..36), i.e. 64
   // nibbles. Nonce-independent, which is what makes 4-way batching legal.
   gr_get_algo_string( (const uint8_t*)input + 4, 64, coreOrder,
                       MIKE_CORE_ALGO_COUNT );
   gr_get_algo_string( (const uint8_t*)input + 4, 64, cnOrder,
                       GR_CN_ALGO_COUNT );

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

   // Group 3: only one core round, the pool is exhausted at index 10.
   gr_do_core_algo( coreOrder[10], hash_2, hash_1, 64 );
   gr_do_cn_algo  ( cnOrder[2],    hash_1, hash_2, 64 );

   memcpy( output, hash_2, 32 );
}

/* GR_CN_LANES nonces at once. Both orders depend only on the prevblock region
 * (bytes [4..36)), which is identical across the lanes' nonces, so they are
 * derived once and the CN stages run interleaved via cryptonight_4way to hide
 * scratchpad latency. Same batching, and same justification, as GhostRider.
 *
 * Buffer parity: cin/cout are pinned to h1/h2, so every group must leave its
 * last core round's output in h1. Groups 1 and 2 run five rounds (odd, group 2
 * starting from h2), group 3 runs one; all three end in h1. */
static void mike_hash_4way( void *const out[GR_CN_LANES],
                            const void *const in[GR_CN_LANES] )
{
   uint8_t h1[GR_CN_LANES][64] __attribute__ ((aligned (64)));
   uint8_t h2[GR_CN_LANES][64] __attribute__ ((aligned (64)));
   const void *cin[GR_CN_LANES];
   void *cout[GR_CN_LANES];
   uint8_t coreOrder[MIKE_CORE_ALGO_COUNT];
   uint8_t cnOrder[GR_CN_ALGO_COUNT];
   int l;

   gr_get_algo_string( (const uint8_t*)in[0] + 4, 64, coreOrder,
                       MIKE_CORE_ALGO_COUNT );
   gr_get_algo_string( (const uint8_t*)in[0] + 4, 64, cnOrder,
                       GR_CN_ALGO_COUNT );

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

   // Group 3: one core round.
   for ( l = 0; l < GR_CN_LANES; l++ ) gr_do_core_algo( coreOrder[10], h2[l], h1[l], 64 );
   cryptonight_4way( cnOrder[2], cin, cout, 64 );          // h1 -> h2

   for ( l = 0; l < GR_CN_LANES; l++ ) memcpy( out[l], h2[l], 32 );
}

/* Known-answer test 1 of 2: test_output_gr_mike[256] from xmrig PR #3131
 * (src/crypto/cn/CryptoNight_test.h), built as CpuWorker<N>::verify() does:
 * eight 80-byte all-zero blobs with blob[0] = lane index; hash them once with
 * blob[4..5] = {0x10,0x02} and again with {0x43,0x05}; the reference is the
 * XOR of the two 8x32 outputs.
 *
 * This covers the chain shape, the six CN variants, the finalization and the
 * post-CN zeroing, but NOT the % 11 selection: the blobs are almost all zero,
 * so the nibble walk runs out early and counts 11 and 15 both fall through to
 * the same ascending fill. It passes even with the wrong count.
 * mike_dense_kat[] below is what pins the selection. */
static const uint8_t mike_test_expected[256] =
{
   0x4a, 0xad, 0xfc, 0x1b, 0xad, 0x21, 0x65, 0xa7,
   0x69, 0x6f, 0x87, 0x3e, 0x5d, 0xb7, 0x3c, 0x20,
   0x5f, 0x3a, 0x4b, 0x87, 0xa3, 0x4b, 0x54, 0x35,
   0x70, 0xca, 0xfc, 0x95, 0x48, 0xab, 0x5b, 0x74,
   0xfc, 0x9c, 0x0b, 0xd8, 0xe5, 0x98, 0x01, 0xf1,
   0x9f, 0x9e, 0x7f, 0xd4, 0xe4, 0xaf, 0x7d, 0x14,
   0x7d, 0xde, 0x8e, 0x8a, 0xdf, 0xe6, 0x4a, 0x30,
   0x9a, 0x92, 0xf5, 0x12, 0x3f, 0x16, 0xf3, 0xf0,
   0xc7, 0x2f, 0xf7, 0x4b, 0x06, 0x82, 0xa5, 0x50,
   0xa0, 0xb3, 0xb8, 0x81, 0x0a, 0xde, 0x29, 0x4e,
   0xcd, 0x72, 0x57, 0x60, 0x4e, 0xc1, 0x23, 0x46,
   0x1b, 0x39, 0x23, 0xcc, 0x4a, 0x64, 0x7b, 0x2d,
   0x8b, 0x04, 0xa1, 0xea, 0xa4, 0xa0, 0xf9, 0x3d,
   0x7d, 0x26, 0x22, 0xf0, 0xa6, 0x0a, 0x18, 0x2c,
   0xd5, 0x88, 0x4f, 0x47, 0xb7, 0x72, 0x83, 0xa9,
   0xcd, 0x17, 0x24, 0x0b, 0x39, 0x3c, 0x54, 0x51,
   0x47, 0xef, 0x77, 0x55, 0x0a, 0x9b, 0x56, 0x06,
   0x47, 0xbe, 0xdb, 0x85, 0x78, 0x3a, 0x15, 0x31,
   0x8c, 0x60, 0xce, 0xe9, 0x9a, 0x1f, 0xdd, 0x8c,
   0xcc, 0xf0, 0x17, 0xa5, 0x99, 0x17, 0xb5, 0x5d,
   0x30, 0xae, 0x8d, 0x7a, 0xd2, 0xfd, 0xd5, 0x66,
   0xdd, 0x23, 0xa0, 0xca, 0x56, 0x66, 0x64, 0x6c,
   0x38, 0xda, 0xdf, 0x91, 0x12, 0x06, 0x9a, 0x11,
   0x13, 0x4e, 0xcf, 0x71, 0xf4, 0x0b, 0x26, 0x50,
   0x7d, 0x00, 0x6f, 0xc4, 0x39, 0xb5, 0x0d, 0xaa,
   0xa3, 0x60, 0x5e, 0x41, 0x82, 0xe0, 0xce, 0x38,
   0x7f, 0x37, 0x90, 0xac, 0x53, 0xbe, 0x46, 0xb4,
   0x6a, 0xc4, 0xb8, 0xe1, 0x9f, 0x31, 0x9f, 0xf4,
   0xff, 0x46, 0x73, 0x92, 0xee, 0x64, 0xa6, 0x44,
   0xac, 0xd4, 0x33, 0xb8, 0x3b, 0x84, 0x42, 0x7e,
   0x9a, 0x80, 0xf0, 0xa8, 0x71, 0xf0, 0x81, 0xc4,
   0xc1, 0x52, 0xff, 0x27, 0x4e, 0x07, 0xf0, 0x70
};

/* Known-answer test 2 of 2: dense prevhashes, which is what pins the % 11
 * selection. Digests generated from VKAX Core's own sources (src/hash.h
 * Mike() over its hash_selection.cpp, sph cores and cryptonote/slow-hash.c).
 *
 * Vector 0 reuses GhostRider's test header (gr_test_input in algo/gr/gr-gate.c)
 * so both algos are exercised on the same input; vectors 1-3 use
 * prevhash = sha256(0|1|2) with nonce 0/1/2 for three more rotations.
 * All four fail if MIKE_CORE_ALGO_COUNT is wrong. */
typedef struct { uint8_t hdr[80]; uint8_t expected[32]; } mike_kat_t;

static const mike_kat_t mike_dense_kat[] =
{
   { {
        0x70, 0x00, 0x00, 0x00, 0x5d, 0x38, 0x5b, 0xa1, 0x14, 0xd0, 0x79, 0x97, 0x0b, 0x29, 0xa9, 0x41,
        0x8f, 0xd0, 0x54, 0x9e, 0x7d, 0x68, 0xa9, 0x5c, 0x7f, 0x16, 0x86, 0x21, 0xa3, 0x14, 0x20, 0x10,
        0x00, 0x00, 0x00, 0x00, 0x57, 0x85, 0x86, 0xd1, 0x49, 0xfd, 0x07, 0xb2, 0x2f, 0x3a, 0x8a, 0x34,
        0x7c, 0x51, 0x6d, 0xe7, 0x05, 0x2f, 0x03, 0x4d, 0x2b, 0x76, 0xff, 0x68, 0xe0, 0xd6, 0xec, 0xff,
        0x9b, 0x77, 0xa4, 0x54, 0x89, 0xe3, 0xfd, 0x51, 0x17, 0x32, 0x01, 0x1d, 0xf0, 0x73, 0x10, 0x00,
     }, {
        0xbe, 0x0d, 0x67, 0xc6, 0x80, 0xcd, 0x74, 0x02, 0x6f, 0xce, 0x7d, 0xaa, 0xf1, 0x23, 0xdc, 0xc3,
        0xbb, 0x1b, 0x45, 0x91, 0x53, 0x8e, 0x42, 0x53, 0x77, 0x67, 0xff, 0x4e, 0x17, 0x04, 0x4f, 0x08,
     } },
   { {
        0x70, 0x00, 0x00, 0x00, 0x6e, 0x34, 0x0b, 0x9c, 0xff, 0xb3, 0x7a, 0x98, 0x9c, 0xa5, 0x44, 0xe6,
        0xbb, 0x78, 0x0a, 0x2c, 0x78, 0x90, 0x1d, 0x3f, 0xb3, 0x37, 0x38, 0x76, 0x85, 0x11, 0xa3, 0x06,
        0x17, 0xaf, 0xa0, 0x1d, 0x57, 0x85, 0x86, 0xd1, 0x49, 0xfd, 0x07, 0xb2, 0x2f, 0x3a, 0x8a, 0x34,
        0x7c, 0x51, 0x6d, 0xe7, 0x05, 0x2f, 0x03, 0x4d, 0x2b, 0x76, 0xff, 0x68, 0xe0, 0xd6, 0xec, 0xff,
        0x9b, 0x77, 0xa4, 0x54, 0x89, 0xe3, 0xfd, 0x51, 0x17, 0x32, 0x01, 0x1d, 0x00, 0x00, 0x00, 0x00,
     }, {
        0xc3, 0x77, 0x80, 0xcf, 0x1c, 0x34, 0xce, 0x7c, 0x9f, 0x17, 0x2d, 0x1d, 0xf9, 0xc1, 0x6a, 0xd1,
        0xa4, 0xb9, 0x88, 0x31, 0xe9, 0xba, 0xe8, 0x82, 0xcc, 0x49, 0xbe, 0xf4, 0xc9, 0xfa, 0xfe, 0x34,
     } },
   { {
        0x70, 0x00, 0x00, 0x00, 0x4b, 0xf5, 0x12, 0x2f, 0x34, 0x45, 0x54, 0xc5, 0x3b, 0xde, 0x2e, 0xbb,
        0x8c, 0xd2, 0xb7, 0xe3, 0xd1, 0x60, 0x0a, 0xd6, 0x31, 0xc3, 0x85, 0xa5, 0xd7, 0xcc, 0xe2, 0x3c,
        0x77, 0x85, 0x45, 0x9a, 0x57, 0x85, 0x86, 0xd1, 0x49, 0xfd, 0x07, 0xb2, 0x2f, 0x3a, 0x8a, 0x34,
        0x7c, 0x51, 0x6d, 0xe7, 0x05, 0x2f, 0x03, 0x4d, 0x2b, 0x76, 0xff, 0x68, 0xe0, 0xd6, 0xec, 0xff,
        0x9b, 0x77, 0xa4, 0x54, 0x89, 0xe3, 0xfd, 0x51, 0x17, 0x32, 0x01, 0x1d, 0x01, 0x00, 0x00, 0x00,
     }, {
        0x4f, 0x5b, 0xcf, 0xf3, 0x68, 0x45, 0xde, 0x07, 0xf4, 0xa2, 0x47, 0xc2, 0xa8, 0xb1, 0x3a, 0xae,
        0x57, 0xd0, 0x0b, 0x82, 0xb8, 0x8c, 0x77, 0x33, 0x24, 0x2b, 0x64, 0xe1, 0x1b, 0x10, 0xdb, 0xe9,
     } },
   { {
        0x70, 0x00, 0x00, 0x00, 0xdb, 0xc1, 0xb4, 0xc9, 0x00, 0xff, 0xe4, 0x8d, 0x57, 0x5b, 0x5d, 0xa5,
        0xc6, 0x38, 0x04, 0x01, 0x25, 0xf6, 0x5d, 0xb0, 0xfe, 0x3e, 0x24, 0x49, 0x4b, 0x76, 0xea, 0x98,
        0x64, 0x57, 0xd9, 0x86, 0x57, 0x85, 0x86, 0xd1, 0x49, 0xfd, 0x07, 0xb2, 0x2f, 0x3a, 0x8a, 0x34,
        0x7c, 0x51, 0x6d, 0xe7, 0x05, 0x2f, 0x03, 0x4d, 0x2b, 0x76, 0xff, 0x68, 0xe0, 0xd6, 0xec, 0xff,
        0x9b, 0x77, 0xa4, 0x54, 0x89, 0xe3, 0xfd, 0x51, 0x17, 0x32, 0x01, 0x1d, 0x02, 0x00, 0x00, 0x00,
     }, {
        0x12, 0xd7, 0x92, 0x84, 0x1d, 0x19, 0x3b, 0xd5, 0x34, 0x99, 0x46, 0x5f, 0x75, 0xff, 0x61, 0x97,
        0xd1, 0xfe, 0x3d, 0x73, 0xfb, 0xd3, 0xbf, 0x1e, 0x85, 0xe9, 0x51, 0x3e, 0xc1, 0x68, 0xf9, 0xdf,
     } },
};

#define MIKE_DENSE_KAT_COUNT \
   ( (int)( sizeof mike_dense_kat / sizeof mike_dense_kat[0] ) )

/* Each dense vector serves as both a lane-0 KAT and a 1-way/4-way differential.
 * The four lanes are the vector's header with nonce n..n+3, exactly what
 * scanhash feeds the 4-way path: lane 0 keeps the original nonce and must match
 * the reference digest, lanes 1..3 must match their 1-way results. Varying the
 * nonce rather than repeating one header is what catches lane crosstalk; the
 * prevhash is untouched so all four lanes share one rotation, which is the
 * precondition for batching. */
static bool mike_dense_self_test( void )
{
   for ( int v = 0; v < MIKE_DENSE_KAT_COUNT; v++ )
   {
      uint8_t hdr[GR_CN_LANES][80] __attribute__ ((aligned (64)));
      uint8_t ref[GR_CN_LANES][32] __attribute__ ((aligned (64)));
      uint8_t got[GR_CN_LANES][32] __attribute__ ((aligned (64)));
      const void *in[GR_CN_LANES];
      void *out[GR_CN_LANES];
      uint32_t nonce;
      char hex[65];
      int l, i;

      memcpy( &nonce, mike_dense_kat[v].hdr + 76, 4 );

      for ( l = 0; l < GR_CN_LANES; l++ )
      {
         uint32_t n = nonce + (uint32_t)l;
         memcpy( hdr[l], mike_dense_kat[v].hdr, 80 );
         memcpy( hdr[l] + 76, &n, 4 );
         in[l]  = hdr[l];
         out[l] = got[l];
         mike_hash( ref[l], hdr[l] );
      }

      if ( memcmp( ref[0], mike_dense_kat[v].expected, 32 ) != 0 )
      {
         for ( i = 0; i < 32; i++ ) sprintf( hex + i * 2, "%02x", ref[0][i] );
         applog( LOG_ERR, "Mike dense KAT %d mismatch: got      %s", v, hex );
         for ( i = 0; i < 32; i++ )
            sprintf( hex + i * 2, "%02x", mike_dense_kat[v].expected[i] );
         applog( LOG_ERR, "Mike dense KAT %d mismatch: expected %s", v, hex );
         return false;
      }

      mike_hash_4way( out, in );

      for ( l = 0; l < GR_CN_LANES; l++ )
         if ( memcmp( got[l], ref[l], 32 ) != 0 )
         {
            for ( i = 0; i < 32; i++ ) sprintf( hex + i * 2, "%02x", got[l][i] );
            applog( LOG_ERR, "Mike 4-way differential failed, vector %d lane %d:"
                             " 4-way %s", v, l, hex );
            for ( i = 0; i < 32; i++ ) sprintf( hex + i * 2, "%02x", ref[l][i] );
            applog( LOG_ERR, "Mike 4-way differential failed, vector %d lane %d:"
                             " 1-way %s", v, l, hex );
            return false;
         }
   }
   return true;
}

#define MIKE_KAT_LANES 8

bool mike_self_test( void )
{
   uint8_t blob[MIKE_KAT_LANES][80] __attribute__ ((aligned (64)));
   uint8_t h1[MIKE_KAT_LANES][32]  __attribute__ ((aligned (64)));
   uint8_t h2[MIKE_KAT_LANES][32]  __attribute__ ((aligned (64)));
   uint8_t got[256];
   int i, nonzero = 0;

   memset( blob, 0, sizeof blob );
   for ( i = 0; i < MIKE_KAT_LANES; i++ )
   {
      blob[i][0] = (uint8_t)i;  blob[i][4] = 0x10;  blob[i][5] = 0x02;
   }
   for ( i = 0; i < MIKE_KAT_LANES; i++ )  mike_hash( h1[i], blob[i] );

   for ( i = 0; i < MIKE_KAT_LANES; i++ )
   {
      blob[i][0] = (uint8_t)i;  blob[i][4] = 0x43;  blob[i][5] = 0x05;
   }
   for ( i = 0; i < MIKE_KAT_LANES; i++ )  mike_hash( h2[i], blob[i] );

   for ( i = 0; i < 256; i++ )
   {
      got[i] = ((const uint8_t*)h1)[i] ^ ((const uint8_t*)h2)[i];
      nonzero |= got[i];
   }

   // Guard against a vacuous pass: two identical rotations would XOR to zero.
   if ( !nonzero )
   {
      applog( LOG_ERR, "Mike self-test vacuous: the two passes agree" );
      return false;
   }

   if ( memcmp( got, mike_test_expected, 256 ) != 0 )
   {
      char hex[65];
      for ( i = 0; i < 32; i++ ) sprintf( hex + i * 2, "%02x", got[i] );
      applog( LOG_ERR, "Mike self-test mismatch: first 32 bytes got %s", hex );
      for ( i = 0; i < 32; i++ )
         sprintf( hex + i * 2, "%02x", mike_test_expected[i] );
      applog( LOG_ERR, "Mike self-test mismatch: first 32 bytes expected %s",
              hex );
      return false;
   }

   // The vector above cannot see the `% 11` selection; this one can.
   return mike_dense_self_test();
}

int scanhash_mike( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
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

      mike_hash_4way( out, in );

      if ( thr_id == 0 && !logged_backing )
      {
         logged_backing = 1;
         applog( LOG_INFO, "Mike: CryptoNight scratchpad backing: %s",
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

/* Mike's three CryptoNight scratchpads are shared with GhostRider's allocator
 * (2 MiB each, huge pages or mmap); cryptonight_free_scratchpad() knows which. */
static void mike_thread_free( int thr_id )
{
   (void)thr_id;
   cryptonight_free_scratchpad();
}

bool register_mike_algo( algo_gate_t *gate )
{
   if ( !mike_self_test() )
   {
      applog( LOG_ERR, "Mike self-test failed" );
      return false;
   }
   gate->scanhash     = (void*)&scanhash_mike;
   gate->miner_thread_free = (void*)&mike_thread_free;
   gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | NEON_OPT;
   // VKAX's powLimit is byte-identical to Raptoreum's (00ffffff..., the same
   // `~uint256(0) >> 20`), so the pool difficulty convention matches gr's.
   opt_target_factor  = 65536.0;
   return true;
}
