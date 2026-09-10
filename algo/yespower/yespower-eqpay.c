/* EqPay (EQPAY) -- yespower 1.0 over a Qtum-style EXTENDED block header.
 *
 * This is not a yespower parameter variant. EqPay is Qtum-derived and its
 * proof-of-work covers 181 bytes, not 80: GetWorkHash() hashes the full
 * serialization of CBlockHeaderUncached, which appends the EVM state roots and
 * the proof-of-stake fields to the usual header.
 *
 *   offset  size  field
 *   0       4     nVersion
 *   4       32    hashPrevBlock
 *   36      32    hashMerkleRoot
 *   68      4     nTime
 *   72      4     nBits
 *   76      4     nNonce
 *   80      32    hashStateRoot        (pool-supplied)
 *   112     32    hashUTXORoot         (pool-supplied)
 *   144     32    prevoutStake.hash    zero for proof-of-work
 *   176     4     prevoutStake.n       0xffffffff, COutPoint::NULL_INDEX
 *   180     1     vchBlockSigDlgt length, 0 (empty vector) while mining
 *
 * The layout is checked at startup: sha256d over these bytes must reproduce
 * the genesis hash chainparams.cpp asserts. The two roots come from the
 * Stratum job as a tenth notify parameter.
 */
#include "yespower.h"
#include "algo-gate-api.h"
#include "algo/sha/sha256-hash.h"
#include <string.h>

// 181 hashed bytes, rounded up to whole words for the work buffer.
#define EQPAY_HDR_SIZE   181
#define EQPAY_HDR_WORDS  ( ( EQPAY_HDR_SIZE + 3 ) / 4 )   // 46

// Offsets of the parts this algo appends past the standard 80 bytes.
#define EQPAY_STATE_ROOT_OFS   80
#define EQPAY_UTXO_ROOT_OFS   112
#define EQPAY_STAKE_OFS       144
#define EQPAY_STAKE_N_OFS     176
#define EQPAY_SIGLEN_OFS      180

static const char *eqpay_pers =
   "The gods had gone away, and the ritual of the religion continued "
   "senselessly, uselessly.";

static yespower_params_t eqpay_params;

#if defined(__SSE2__) || defined(__aarch64__)
  #define EQPAY_TLS   yespower_tls
  #define EQPAY_PATH  "SIMD"
#else
  #define EQPAY_TLS   yespower_tls_ref
  #define EQPAY_PATH  "reference"
#endif

// srclen != 80, so yespower takes its sha256_full branch and never consults
// sha256_prehash_ctx. No prehash is set up here, and none is needed.
int eqpay_hash( const char *input, char *output, int thrid )
{
   return EQPAY_TLS( (const uint8_t*)input, EQPAY_HDR_SIZE, &eqpay_params,
                     (yespower_binary_t*)output, thrid );
}

int scanhash_eqpay( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) hdr[ EQPAY_HDR_WORDS ];
   uint32_t _ALIGN(64) vhash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;

   // Bytes 0..75: standard fields, to wire order as the rest of the family.
   for ( int k = 0; k < 19; k++ )
      be32enc( &hdr[k], pdata[k] );

   // Bytes 80..180 are already wire order: byte strings, not integers, so
   // they are copied verbatim and never endian-swapped.
   memcpy( (uint8_t*)hdr + 80, (uint8_t*)pdata + 80, EQPAY_HDR_SIZE - 80 );

   do {
      hdr[19] = n;
      if ( eqpay_hash( (const char*)hdr, (char*)vhash, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
         be32enc( pdata + 19, n );
         submit_solution( work, vhash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

// The standard builder fills bytes 0..79 and memsets the rest of work->data,
// so the tail is appended after it runs, not before.
void eqpay_build_extraheader( struct work *work, struct stratum_ctx *sctx )
{
   uint8_t *d = (uint8_t*)work->data;

   std_build_extraheader( work, sctx );

   /* Both roots arrive as one 64-byte parameter after prevhash -- the slot
    * phi2 uses, so the generic notify parse leaves them in job.extra. Each is
    * sent with its 32-bit words byte-swapped; undo that per word, keeping the
    * word order. A whole-32-byte reversal is wrong. */
   for ( int t = 0; t < 16; t++ )
   {
      const uint8_t *s = sctx->job.extra + t * 4;
      uint8_t       *o = d + EQPAY_STATE_ROOT_OFS + t * 4;
      o[0] = s[3]; o[1] = s[2]; o[2] = s[1]; o[3] = s[0];
   }

   /* prevoutStake is null for proof-of-work: a zero hash, then
    * n = COutPoint::NULL_INDEX. Leaving n zero yields a well-formed digest the
    * pool rejects, so the memset covers only the 32-byte hash. */
   memset( d + EQPAY_STAKE_OFS, 0, 32 );
   d[ EQPAY_STAKE_N_OFS + 0 ] = 0xff;
   d[ EQPAY_STAKE_N_OFS + 1 ] = 0xff;
   d[ EQPAY_STAKE_N_OFS + 2 ] = 0xff;
   d[ EQPAY_STAKE_N_OFS + 3 ] = 0xff;

   // Empty vchBlockSigDlgt: a CompactSize zero, one byte.
   d[ EQPAY_SIGLEN_OFS ] = 0x00;
}

// --------------------------------------------------------------- self-test
//
// EqPay mainnet genesis, from chainparams.cpp: nVersion/nTime/nBits/nNonce and
// the asserted block hash, plus the two roots. GetHash() is sha256d over the
// same bytes GetWorkHash() hashes, so the asserted hash validates the
// serialization independently of this code.
static const uint8_t eqpay_kat_header[ EQPAY_HDR_SIZE ] =
{
   0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0xe1,0xa7,0xff,0x0f,0x99,0xf5,0xe6,0x92,0xa1,0x6f,0x69,0x69,
   0xe0,0x09,0xca,0xf9,0x51,0x86,0x57,0xe6,0x7b,0x12,0xa5,0xac,
   0x15,0xf8,0x53,0x39,0x5c,0x7f,0xed,0xaa, 0x25,0xc6,0x55,0x61,
   0xff,0xff,0x3f,0x1f, 0x53,0x01,0x00,0x00,
   0xe9,0x65,0xff,0xd0,0x02,0xcd,0x6a,0xd0,0xe2,0xdc,0x40,0x2b,
   0x80,0x44,0xde,0x83,0x3e,0x06,0xb2,0x31,0x27,0xea,0x8c,0x3d,
   0x80,0xae,0xc9,0x14,0x10,0x77,0x14,0x95,
   0x56,0xe8,0x1f,0x17,0x1b,0xcc,0x55,0xa6,0xff,0x83,0x45,0xe6,
   0x92,0xc0,0xf8,0x6e,0x5b,0x48,0xe0,0x1b,0x99,0x6c,0xad,0xc0,
   0x01,0x62,0x2f,0xb5,0xe3,0x63,0xb4,0x21,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
   0xff,0xff,0xff,0xff,
   0x00
};

// The hash chainparams.cpp asserts for genesis, internal byte order.
static const uint8_t eqpay_kat_block_id[32] =
{
   0x83,0x1d,0xb9,0x7c,0x0d,0x95,0x24,0xa6,0xd2,0xdf,0x3c,0x9d,
   0x6a,0xff,0x4d,0x9b,0xf9,0x9d,0x38,0x5a,0xd3,0x16,0xe5,0x7f,
   0x90,0x3a,0xaf,0x3e,0xe4,0xbd,0x31,0x49
};

static const uint8_t eqpay_kat_digest[32] =
{
   0x56,0xda,0x66,0x12,0x94,0xe4,0xac,0xf5,0x60,0xea,0x4d,0x73,
   0x12,0x1a,0xc9,0xd8,0xd8,0xf8,0xd3,0x09,0xf0,0x6e,0xe3,0x32,
   0x4e,0x7b,0xe3,0x36,0x01,0x56,0x04,0x00
};

// nBits 0x1f3fffff expanded, little-endian as valid_hash() reads it.
static const uint32_t eqpay_kat_target[8] =
{
   0x00000000, 0x00000000, 0x00000000, 0x00000000,
   0x00000000, 0x00000000, 0x00000000, 0x003fffff
};

/* The family shares one thread-local region; the sibling helper is static. */
static void eqpay_thread_free( int thr_id )
{
   (void)thr_id;
   yespower_tls_free();
}

static struct work_restart eqpay_kat_restart[1];

static bool eqpay_self_test( void )
{
   struct work_restart *saved = work_restart;
   uint8_t sd[32], sd2[32], out[32], alt[ EQPAY_HDR_SIZE ];
   const char *fail = NULL;

   // 1. Serialization, against a value the chain asserts.
   sha256_full( sd, eqpay_kat_header, EQPAY_HDR_SIZE );
   sha256_full( sd2, sd, 32 );
   if ( memcmp( sd2, eqpay_kat_block_id, 32 ) )
   {  fail = "genesis serialization (sha256d != asserted block hash)";
      goto done;
   }

   if ( !work_restart ) work_restart = eqpay_kat_restart;

   // 2. The PoW digest itself.
   if ( !eqpay_hash( (const char*)eqpay_kat_header, (char*)out, 0 ) )
   {  fail = "hash failed"; goto done; }
   if ( memcmp( out, eqpay_kat_digest, 32 ) )
   {  fail = "genesis digest"; goto done; }

   // 3. It must clear the block's own nBits, or it is not a proof of work.
   if ( !valid_hash( (uint32_t*)out, eqpay_kat_target ) )
   {  fail = "genesis digest does not clear its nBits target"; goto done; }

   // 4. Non-vacuity, specifically that the extended tail is hashed: an
   //    80-byte hash or a wrong length would pass every check above.
   memcpy( alt, eqpay_kat_header, EQPAY_HDR_SIZE );
   alt[ EQPAY_STATE_ROOT_OFS ] ^= 0x01;
   if ( !eqpay_hash( (const char*)alt, (char*)sd, 0 )
        || !memcmp( sd, out, 32 ) )
   {  fail = "hashStateRoot does not affect the digest"; goto done; }

   memcpy( alt, eqpay_kat_header, EQPAY_HDR_SIZE );
   alt[ EQPAY_SIGLEN_OFS ] ^= 0x01;
   if ( !eqpay_hash( (const char*)alt, (char*)sd, 0 )
        || !memcmp( sd, out, 32 ) )
   {  fail = "last header byte does not affect the digest"; goto done; }

done:
   work_restart = saved;
   if ( fail )
   {
      applog( LOG_ERR, "eqpay self-test FAILED (%s path): %s",
              EQPAY_PATH, fail );
      return false;
   }
   applog( LOG_NOTICE,
           "eqpay self-test PASSED (%s path, genesis, %d-byte header)",
           EQPAY_PATH, EQPAY_HDR_SIZE );
   return true;
}

bool register_yespowereqpay_algo( algo_gate_t* gate )
{
   eqpay_params.version = YESPOWER_1_0;
   eqpay_params.N       = 2048;
   eqpay_params.r       = 32;
   eqpay_params.pers    = (const uint8_t*)eqpay_pers;
   eqpay_params.perslen = strlen( eqpay_pers );

   gate->optimizations     = SSE2_OPT | SHA256_OPT | NEON_OPT;
   gate->scanhash          = (void*)&scanhash_eqpay;
   gate->hash              = (void*)&eqpay_hash;
   gate->build_extraheader = (void*)&eqpay_build_extraheader;
   gate->miner_thread_free = (void*)&eqpay_thread_free;
   opt_target_factor       = 65536.0;

   applog( LOG_NOTICE,
           "EqPay: yespower 1.0, N= %d, R= %d, key length= %d, header= %d bytes",
           eqpay_params.N, eqpay_params.r, (int)eqpay_params.perslen,
           EQPAY_HDR_SIZE );

   return eqpay_self_test();
}
