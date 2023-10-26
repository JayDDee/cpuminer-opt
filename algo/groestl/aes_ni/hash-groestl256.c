/* hash.c     Aug 2011
 *
 * Groestl implementation for different versions.
 * Author: Krystian Matusiewicz, Günther A. Roland, Martin Schläffer
 *
 * This code is placed in the public domain
 */

#include <memory.h>
#include "hash-groestl256.h"
#include "miner.h"
#include "simd-utils.h"

#if defined(__AES__) || defined(__ARM_FEATURE_AES)

#include "groestl256-intr-aes.h"

/* initialise context */
int init_groestl256( hashState_groestl256* ctx, int hashlen )
{
  int i;

  ctx->hashlen = hashlen;

  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = v128_zero;
     ctx->buffer[i]   = v128_zero;
  }
  ((u64*)ctx->chaining)[COLS-1] = U64BIG((u64)LENGTH);
  INIT256( ctx->chaining );
  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}


int reinit_groestl256(hashState_groestl256* ctx)
 {
  int i;

  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = v128_zero;
     ctx->buffer[i]   = v128_zero;
  }

  ctx->chaining[ 3 ] = v128_set64( 0, 0x0100000000000000 );

  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}

// Use this only for midstate and never for cryptonight
int update_groestl256( hashState_groestl256* ctx, const void* input,
                                 int databitlen )
{
   v128_t* in = (v128_t*)input;
   const int len = (int)databitlen / 128;  // bits to v128_t
   const int blocks = len / SIZE256;    // __M128i to blocks
   int rem = ctx->rem_ptr;
   int i;

   ctx->blk_count = blocks;
   ctx->databitlen = databitlen;

   // digest any full blocks 
   for ( i = 0; i < blocks; i++ )
       TF512( ctx->chaining, &in[ i * SIZE256 ] );
   // adjust buf_ptr to last block
   ctx->buf_ptr = blocks * SIZE256;

   // Copy any remainder to buffer
   for ( i = 0; i < len % SIZE256; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   // adjust rem_ptr for new data
   ctx->rem_ptr += i;

   return 0;
}

// don't use this at all
int final_groestl256( hashState_groestl256* ctx, void* output )
{
   const int len = (int)ctx->databitlen / 128;  // bits to v128_t 
   const int blocks = ctx->blk_count + 1;       // adjust for final block
   const int rem_ptr = ctx->rem_ptr;      // end of data start of padding
   const int hashlen_m128i = ctx->hashlen / 16;  // bytes to v128_t
   const int hash_offset = SIZE256 - hashlen_m128i;  // where in buffer
   int i;

   // first pad byte = 0x80, last pad byte = block count
   // everything in between is zero

   if ( rem_ptr == len - 1 )
   {
       // all padding at once
       ctx->buffer[rem_ptr] = v128_set8( blocks,0,0,0, 0,0,0,0,
                                         0,0,0,0, 0,0,0,0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[rem_ptr] = v128_set8( 0,0,0,0, 0,0,0,0,
                                         0,0,0,0, 0,0,0,0x80 );
       // add zero padding
       for ( i = rem_ptr + 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = v128_zero;
       // add length padding
       // cheat since we know the block count is trivial, good if block < 256
       ctx->buffer[i] = v128_set8( blocks,0,0,0, 0,0,0,0,  0,0,0,0, 0,0,0,0 );
   }

   // digest final padding block and do output transform
   TF512( ctx->chaining, ctx->buffer );
   OF512( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_v128( output, i ) = ctx->chaining[ hash_offset + i];

   return 0;
}

int update_and_final_groestl256( hashState_groestl256* ctx,
                   void* output, const void* input, int databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to v128_t
   const int hash_offset = SIZE256 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   int blocks = len / SIZE256;
   v128_t* in = (v128_t*)input;
   int i;

   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF512( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // cryptonight has 200 byte input, an odd number of v128_t
   // remainder is only 8 bytes, ie u64.
   if ( databitlen % 128 !=0 )
   {
      // must be cryptonight, copy 64 bits of data
      *(uint64_t*)(ctx->buffer) = *(uint64_t*)(&in[ ctx->buf_ptr ] );
      i = -1; // signal for odd length
   }
   else   
   { 
      // Copy any remaining data to buffer for final transform
      for ( i = 0; i < len % SIZE256; i++ )
          ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
      i += rem;   // use i as rem_ptr in final
   }

   //--- final ---

   // adjust for final block
   blocks++;

   if ( i == len - 1 )
   {
       // all padding at once
       ctx->buffer[i] = v128_set8( blocks,blocks>>8,0,0, 0,0,0,0,
                                        0,        0,0,0, 0,0,0,0x80 );
   }
   else
   {
      if ( i == -1 )
      {
         // cryptonight odd length
         ((uint64_t*)ctx->buffer)[ 1 ] = 0x80ull;
         // finish the block with zero and length padding as normal
         i = 0;
       }
       else
       {
          // add first padding
          ctx->buffer[i] = v128_set8( 0,0,0,0, 0,0,0,0,
                                      0,0,0,0, 0,0,0,0x80 );
       }
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = v128_zero;
       // add length padding
       // cheat since we know the block count is trivial, good if block < 256
       ctx->buffer[i] = v128_set8( blocks, blocks>>8,0,0, 0,0,0,0,
                                         0,        0,0,0, 0,0,0,0 );
   }

   // digest final padding block and do output transform
   TF512( ctx->chaining, ctx->buffer );
   OF512( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_v128( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

int groestl256_full( hashState_groestl256* ctx,
                   void* output, const void* input, int databitlen )
{
   int i;
   ctx->hashlen = 32;
  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = v128_zero;
     ctx->buffer[i]   = v128_zero;
  }
  ((u64*)ctx->chaining)[COLS-1] = U64BIG((u64)LENGTH);
  INIT256( ctx->chaining );
  ctx->buf_ptr = 0;

   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to v128_t
   const int hash_offset = SIZE256 - hashlen_m128i;
   int blocks = len / SIZE256;
   v128_t* in = (v128_t*)input;

   // --- update ---

   // digest any full blocks, process directly from input
   for ( i = 0; i < blocks; i++ )
      TF512( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // cryptonight has 200 byte input, an odd number of v128_t
   // remainder is only 8 bytes, ie u64.
   if ( databitlen % 128 != 0 )
   {
      // must be cryptonight, copy 64 bits of data
      *(uint64_t*)(ctx->buffer) = *(uint64_t*)(&in[ ctx->buf_ptr ] );
      i = -1; // signal for odd length
   }
   else
   {
      // Copy any remaining data to buffer for final transform
      for ( i = 0; i < len % SIZE256; i++ )
          ctx->buffer[ i ] = in[ ctx->buf_ptr + i ];
      // use i as rem_ptr in final
   }

   //--- final ---

   // adjust for final block
   blocks++;

   if ( i == len - 1 )
   {
       // all padding at once
       ctx->buffer[i] = v128_set8( blocks,blocks>>8,0,0, 0,0,0,0,
                                        0,        0,0,0, 0,0,0,0x80 );
   }
   else
   {
      if ( i == -1 )
      {
         // cryptonight odd length
         ((uint64_t*)ctx->buffer)[ 1 ] = 0x80ull;
         // finish the block with zero and length padding as normal
         i = 0;
       }
       else
       {
          // add first padding
          ctx->buffer[i] = v128_set8( 0,0,0,0, 0,0,0,0,
                                      0,0,0,0, 0,0,0,0x80 );
       }
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = v128_zero;
       // add length padding
       // cheat since we know the block count is trivial, good if block < 256
       ctx->buffer[i] = v128_set8( blocks,blocks>>8,0,0, 0,0,0,0,
                                        0,        0,0,0, 0,0,0,0 );
   }

   // digest final padding block and do output transform
   TF512( ctx->chaining, ctx->buffer );
   OF512( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_v128( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}


/* hash bit sequence */
int hash_groestl256(int hashbitlen, const void* data, int databitlen,
                uint8_t* hashval)
{
  int ret;
  hashState_groestl256 context;

  /* initialise */
  if ((ret = init_groestl256(&context, hashbitlen/8)) != SUCCESS_GR)
    return ret;

  /* process message */
  if ((ret = update_groestl256(&context, data, databitlen)) != SUCCESS_GR)
    return ret;

  /* finalise */
  ret = final_groestl256(&context, hashval);

  return ret;
}

/* eBash API */
//#ifdef crypto_hash_BYTES
//int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
//{
//  if (hash_groestl(crypto_hash_BYTES * 8, in, inlen * 8,out) == SUCCESS_GR) return 0;
//  return -1;
//}
//#endif

#endif // SSSE3 or NEON
