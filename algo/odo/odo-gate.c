#include "odo-gate.h"
#include "odocrypt.h"
#include <stdio.h>
#include <string.h>

/*
 * Odocrypt (DigiByte, algo name "odo").
 *
 * hash = first 32 bytes of KeccakP800_12( OdoCrypt(key).Encrypt( header||0x01 ) )
 * where the 80-byte header is zero-padded into a 100-byte Keccak-p[800] state
 * with a 0x01 byte at offset 80, and key = nTime - (nTime % shapechange).
 *
 * The cipher tables depend only on the epoch key (not the nonce), so they are
 * built once per epoch per thread and reused across the whole nonce range.
 */

static __thread OdoCrypt  odo_ctx;
static __thread uint32_t  odo_ctx_key;
static __thread int       odo_ctx_ready = 0;

static inline void odo_ensure_key( uint32_t key )
{
   if ( !odo_ctx_ready || odo_ctx_key != key )
   {
      odocrypt_init( &odo_ctx, key );
      odo_ctx_key = key;
      odo_ctx_ready = 1;
   }
}

void odo_hash( void *output, const void *input )
{
   char cipher[100];
   memset( cipher, 0, sizeof cipher );
   memcpy( cipher, input, ODO_DIGEST_SIZE );   // 80-byte header
   cipher[ODO_DIGEST_SIZE] = 1;                // padding byte at offset 80
   odocrypt_encrypt( &odo_ctx, cipher, cipher );
   odo_keccakp800_12( (uint8_t*)cipher );
   memcpy( output, cipher, 32 );
}

// Known-answer test, validated byte-for-byte against DigiByte Core's reference
// (src/crypto/odocrypt.cpp + KeccakP-800-reference.cpp): input[i] = i*7+1,
// key = 0x12345678 rounded down to the epoch boundary.
static const uint8_t odo_test_expected[32] =
{
   0x28,0x66,0xb2,0xe8,0xff,0x9a,0xdb,0x62,0xfe,0x16,0x00,0x79,0x29,0x51,0x62,0xca,
   0x46,0x24,0x3b,0xae,0xe9,0xd6,0xab,0x7e,0xbc,0x87,0xe1,0x96,0x7f,0xd4,0xbc,0x7c
};

bool odo_self_test( void )
{
   uint8_t in[ODO_DIGEST_SIZE], h[32];
   for ( int i = 0; i < ODO_DIGEST_SIZE; i++ ) in[i] = (uint8_t)( i * 7 + 1 );
   const uint32_t key = 0x12345678u - ( 0x12345678u % ODO_SHAPECHANGE_INTERVAL );
   odo_ensure_key( key );
   odo_hash( h, in );
   if ( memcmp( h, odo_test_expected, 32 ) != 0 )
   {
      char hex[65];
      for ( int i = 0; i < 32; i++ ) sprintf( hex + i * 2, "%02x", h[i] );
      applog( LOG_ERR, "Odocrypt self-test mismatch: got %s", hex );
      return false;
   }
#if defined(ODO_8WAY)
   // Verify the AVX512 8-way path matches too (lane 0).
   {
      unsigned char in8[8][ODO_DIGEST_SIZE], ct[8][ODO_DIGEST_SIZE];
      for ( int l = 0; l < 8; l++ ) memcpy( in8[l], in, ODO_DIGEST_SIZE );
      odocrypt_encrypt_8way( &odo_ctx, ct,
                             (const unsigned char (*)[ODO_DIGEST_SIZE])in8 );
      uint8_t st[100];
      memset( st, 0, sizeof st );
      memcpy( st, ct[0], ODO_DIGEST_SIZE );
      st[ODO_DIGEST_SIZE] = 1;
      odo_keccakp800_12( st );
      if ( memcmp( st, odo_test_expected, 32 ) != 0 )
      {
         applog( LOG_ERR, "Odocrypt 8-way self-test mismatch" );
         return false;
      }
   }
#endif
   return true;
}

int scanhash_odo( struct work *work, uint32_t max_nonce, uint64_t *hashes_done,
                  struct thr_info *mythr )
{
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id;
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );
   const bool bench = opt_benchmark;

   uint32_t _ALIGN(64) ed0[20];
   v128_bswap32_80( ed0, pdata );

   // Prefer the pool-supplied epoch key ("odokey" notify field); otherwise
   // derive it from nTime (header word 17). Tables are built once per epoch.
   uint32_t key = work->odokey;
   if ( !key )
   {
      const uint32_t ntime = ed0[17];
      key = ntime - ( ntime % ODO_SHAPECHANGE_INTERVAL );
   }
   odo_ensure_key( key );

#if defined(ODO_8WAY)
   uint32_t _ALIGN(64) edata[8][20];
   uint32_t _ALIGN(64) hash[8][8];
   for ( int l = 0; l < 8; l++ ) memcpy( edata[l], ed0, 80 );
   do
   {
      for ( int l = 0; l < 8; l++ ) edata[l][19] = nonce + l;

      unsigned char ct[8][ODO_DIGEST_SIZE];
      odocrypt_encrypt_8way( &odo_ctx, ct,
                             (const unsigned char (*)[ODO_DIGEST_SIZE])edata );
      for ( int l = 0; l < 8; l++ )
      {
         uint8_t st[100];
         memset( st, 0, sizeof st );
         memcpy( st, ct[l], ODO_DIGEST_SIZE );
         st[ODO_DIGEST_SIZE] = 1;
         odo_keccakp800_12( st );
         memcpy( hash[l], st, 32 );
         if ( unlikely( valid_hash( hash[l], ptarget ) && !bench ) )
         {
            pdata[19] = bswap_32( nonce + l );
            submit_solution( work, hash[l], mythr );
         }
      }
      nonce += 8;
   } while ( nonce < max_nonce && !(*restart) );
#else
   uint32_t _ALIGN(64) edata[20];
   uint32_t _ALIGN(64) hash[8];
   memcpy( edata, ed0, 80 );
   do
   {
      edata[19] = nonce;
      odo_hash( hash, edata );
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );
#endif

   pdata[19] = nonce;
   *hashes_done = nonce - first_nonce;
   return 0;
}

bool register_odo_algo( algo_gate_t *gate )
{
   if ( !odo_self_test() )
   {
      applog( LOG_ERR, "Odocrypt self-test failed" );
      return false;
   }
   gate->scanhash      = (void*)&scanhash_odo;
   gate->optimizations = SSE2_OPT | AVX512_OPT;   // AVX512 8-way SPN when available
   return true;
}
