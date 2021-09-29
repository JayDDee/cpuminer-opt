#include "x16r-gate.h"
#include "algo/sha/sha256d.h"

__thread char x16r_hash_order[ X16R_HASH_FUNC_COUNT + 1 ] = { 0 };

void (*x16_r_s_getAlgoString) ( const uint8_t*, char* ) = NULL;

#if defined (X16R_8WAY)

__thread x16r_8way_context_overlay x16r_ctx;

#elif defined (X16R_4WAY)

__thread x16r_4way_context_overlay x16r_ctx;

#endif

__thread x16r_context_overlay x16_ctx;


void x16r_getAlgoString( const uint8_t* prevblock, char *output )
{
   char *sptr = output;
   for ( int j = 0; j < X16R_HASH_FUNC_COUNT; j++ )
   {
      uint8_t b = (15 - j) >> 1; // 16 first ascii hex chars (lsb in uint256)
      uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
      if (algoDigit >= 10)
          sprintf(sptr, "%c", 'A' + (algoDigit - 10));
      else
          sprintf(sptr, "%u", (uint32_t) algoDigit);
      sptr++;
   }
   *sptr = '\0';
}

void x16s_getAlgoString( const uint8_t* prevblock, char *output )
{
   strcpy( output, "0123456789ABCDEF" );
   for ( int i = 0; i < 16; i++ )
   {
      uint8_t b = (15 - i) >> 1; // 16 ascii hex chars, reversed
      uint8_t algoDigit = (i & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
      int offset = algoDigit;
      // insert the nth character at the front
      char oldVal = output[offset];
      for( int j = offset; j-- > 0; )
         output[j+1] = output[j];
      output[0] = oldVal;
   }
}

bool register_x16r_algo( algo_gate_t* gate )
{
#if defined (X16R_8WAY)
  gate->scanhash  = (void*)&scanhash_x16r_8way;
  gate->hash      = (void*)&x16r_8way_hash;
#elif defined (X16R_4WAY)
  gate->scanhash  = (void*)&scanhash_x16r_4way;
  gate->hash      = (void*)&x16r_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x16r;
  gate->hash      = (void*)&x16r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                VAES_OPT | VAES256_OPT;
  x16_r_s_getAlgoString = (void*)&x16r_getAlgoString;
  opt_target_factor = 256.0;
  return true;
};

bool register_x16rv2_algo( algo_gate_t* gate )
{
#if defined (X16RV2_8WAY)
  gate->scanhash  = (void*)&scanhash_x16rv2_8way;
  gate->hash      = (void*)&x16rv2_8way_hash;
#elif defined (X16RV2_4WAY)
  gate->scanhash  = (void*)&scanhash_x16rv2_4way;
  gate->hash      = (void*)&x16rv2_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x16rv2;
  gate->hash      = (void*)&x16rv2_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                VAES_OPT | VAES256_OPT;
  x16_r_s_getAlgoString = (void*)&x16r_getAlgoString;
  opt_target_factor = 256.0;
  return true;
};

bool register_x16s_algo( algo_gate_t* gate )
{
#if defined (X16R_8WAY)
  gate->scanhash  = (void*)&scanhash_x16r_8way;
  gate->hash      = (void*)&x16r_8way_hash;
#elif defined (X16R_4WAY)
  gate->scanhash  = (void*)&scanhash_x16r_4way;
  gate->hash      = (void*)&x16r_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x16r;
  gate->hash      = (void*)&x16r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                VAES_OPT | VAES256_OPT;
  x16_r_s_getAlgoString = (void*)&x16s_getAlgoString;
  opt_target_factor = 256.0;
  return true;
};

////////////////
//
//   X16RT


void x16rt_getTimeHash( const uint32_t timeStamp, void* timeHash )
{
    int32_t maskedTime = timeStamp & 0xffffff80;
    sha256d( (unsigned char*)timeHash, (const unsigned char*)( &maskedTime ),
             sizeof( maskedTime ) );
}

void x16rt_getAlgoString( const uint32_t *timeHash, char *output)
{
   char *sptr = output;
   uint8_t* data = (uint8_t*)timeHash;

   for (uint8_t j = 0; j < X16R_HASH_FUNC_COUNT; j++) {
      uint8_t b = (15 - j) >> 1; // 16 ascii hex chars, reversed
      uint8_t algoDigit = (j & 1) ? data[b] & 0xF : data[b] >> 4;

      if (algoDigit >= 10)
         sprintf(sptr, "%c", 'A' + (algoDigit - 10));
      else
         sprintf(sptr, "%u", (uint32_t) algoDigit);
      sptr++;
   }
   *sptr = '\0';
}

void veil_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uint32_t merkleroothash[8];
   uint32_t witmerkleroothash[8];
   uint32_t denom10[8];
   uint32_t denom100[8];
   uint32_t denom1000[8];
   uint32_t denom10000[8];
   int i;
   uchar merkle_tree[64] = { 0 };

   algo_gate.gen_merkle_root( merkle_tree, sctx );

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = le32dec( sctx->job.version );

   if ( have_stratum )
      for ( i = 0; i < 8; i++ )
         g_work->data[ 1+i ] = le32dec( (uint32_t*)sctx->job.prevhash + i );
   else
      for (i = 0; i < 8; i++)
         g_work->data[ 8-i ] = le32dec( (uint32_t*)sctx->job.prevhash + i );

   g_work->data[ algo_gate.ntime_index ] = le32dec( sctx->job.ntime );
   g_work->data[ algo_gate.nbits_index ] = le32dec( sctx->job.nbits );
   g_work->data[20] = 0x80000000;
   g_work->data[31] = 0x00000280;

   for ( i = 0; i < 8; i++ )
      merkleroothash[7 - i] = be32dec((uint32_t *)merkle_tree + i);
   for ( i = 0; i < 8; i++ )
      witmerkleroothash[7 - i] = be32dec((uint32_t *)merkle_tree + i);
   for ( i = 0; i < 8; i++ )
      denom10[i] =    le32dec((uint32_t *)sctx->job.denom10 + i);
   for ( i = 0; i < 8; i++ )
      denom100[i] =   le32dec((uint32_t *)sctx->job.denom100 + i);
   for ( i = 0; i < 8; i++ )
      denom1000[i] =  le32dec((uint32_t *)sctx->job.denom1000 + i);
   for ( i = 0; i < 8; i++ )
      denom10000[i] = le32dec((uint32_t *)sctx->job.denom10000 + i);

   uint32_t pofnhash[8];
   memset(pofnhash, 0x00, 32);

   char denom10_str      [ 2 * sizeof( denom10 )           + 1 ];
   char denom100_str     [ 2 * sizeof( denom100 )          + 1 ];
   char denom1000_str    [ 2 * sizeof( denom1000 )         + 1 ];
   char denom10000_str   [ 2 * sizeof( denom10000 )        + 1 ];
   char merkleroot_str   [ 2 * sizeof( merkleroothash )    + 1 ];
   char witmerkleroot_str[ 2 * sizeof( witmerkleroothash ) + 1 ];
   char pofn_str         [ 2 * sizeof( pofnhash )                  + 1 ];

   cbin2hex( denom10_str,       (char*) denom10,           32 );
   cbin2hex( denom100_str,      (char*) denom100,          32 );
   cbin2hex( denom1000_str,     (char*) denom1000,         32 );
   cbin2hex( denom10000_str,    (char*) denom10000,        32 );
   cbin2hex( merkleroot_str,    (char*) merkleroothash,    32 );
   cbin2hex( witmerkleroot_str, (char*) witmerkleroothash, 32 );
   cbin2hex( pofn_str,          (char*) pofnhash,                  32 );

   if ( true )
   {
       char* data;
       data = (char*)malloc( 2 + strlen( denom10_str ) * 4 + 16 * 4
                             + strlen( merkleroot_str ) * 3 );
       // Build the block header veildatahash in hex
       sprintf( data, "%s%s%s%s%s%s%s%s%s%s%s%s",
                       merkleroot_str, witmerkleroot_str, "04",
                       "0a00000000000000", denom10_str,
                       "6400000000000000", denom100_str,
                       "e803000000000000", denom1000_str,
                       "1027000000000000", denom10000_str, pofn_str );
       // Covert the hex to binary
       uint32_t test[100];
       hex2bin( (unsigned char*)(&test), data, 257);
       // Compute the sha256d of the binary
       uint32_t _ALIGN(64) hash[8];
       sha256d( (unsigned char*)hash, (unsigned char*)&(test), 257);
       // assign the veildatahash in the blockheader
       for ( i = 0; i < 8; i++ )
           g_work->data[16 - i] = le32dec(hash + i);
       free(data);
    }
}

bool register_x16rt_algo( algo_gate_t* gate )
{
#if defined (X16R_8WAY)
  gate->scanhash  = (void*)&scanhash_x16rt_8way;
  gate->hash      = (void*)&x16r_8way_hash;
#elif defined (X16R_4WAY)
  gate->scanhash  = (void*)&scanhash_x16rt_4way;
  gate->hash      = (void*)&x16r_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x16rt;
  gate->hash      = (void*)&x16r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                VAES_OPT | VAES256_OPT;
  opt_target_factor = 256.0;
  return true;
};

bool register_x16rt_veil_algo( algo_gate_t* gate )
{
#if defined (X16R_8WAY)
  gate->scanhash  = (void*)&scanhash_x16rt_8way;
  gate->hash      = (void*)&x16r_8way_hash;
#elif defined (X16R_4WAY)
  gate->scanhash  = (void*)&scanhash_x16rt_4way;
  gate->hash      = (void*)&x16r_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x16rt;
  gate->hash      = (void*)&x16r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                VAES_OPT | VAES256_OPT;
  gate->build_extraheader = (void*)&veil_build_extraheader;
  opt_target_factor = 256.0;
  return true;
};

////////////////////
//
//    HEX

bool register_hex_algo( algo_gate_t* gate )
{
  gate->scanhash        = (void*)&scanhash_hex;
  gate->hash            = (void*)&x16r_hash;
  gate->optimizations   = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  opt_target_factor = 128.0;
  return true;
};

///////////////////////////////
//
//   X21S

bool register_x21s_algo( algo_gate_t* gate )
{
#if defined (X16R_8WAY)
  gate->scanhash          = (void*)&scanhash_x21s_8way;
  gate->hash              = (void*)&x21s_8way_hash;
  gate->miner_thread_init = (void*)&x21s_8way_thread_init;
#elif defined (X16R_4WAY)
  gate->scanhash          = (void*)&scanhash_x21s_4way;
  gate->hash              = (void*)&x21s_4way_hash;
  gate->miner_thread_init = (void*)&x21s_4way_thread_init;
#else
  gate->scanhash          = (void*)&scanhash_x21s;
  gate->hash              = (void*)&x21s_hash;
  gate->miner_thread_init = (void*)&x21s_thread_init;
#endif
  gate->optimizations     = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT |
	                    VAES_OPT | VAES256_OPT;
  x16_r_s_getAlgoString   = (void*)&x16s_getAlgoString;
  opt_target_factor = 256.0;
  return true;
};

