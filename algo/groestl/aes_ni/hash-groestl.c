/* hash.c     Aug 2011
 *
 * Groestl implementation for different versions.
 * Author: Krystian Matusiewicz, Günther A. Roland, Martin Schläffer
 *
 * This code is placed in the public domain
 */

// Optimized for hash and data length that are integrals of __m128i 


#include <memory.h>
#include "hash-groestl.h"
#include "miner.h"
#include "simd-utils.h"

#ifdef __AES__

#include "groestl-intr-aes.h"

HashReturn_gr init_groestl( hashState_groestl* ctx, int hashlen )
{
  int i;

  ctx->hashlen = hashlen;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL_GR;

  for ( i = 0; i < SIZE512; i++ )
  {
     ctx->chaining[i] = _mm_setzero_si128();
     ctx->buffer[i]   = _mm_setzero_si128();
  }

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 6 ] = m128_const_64( 0x0200000000000000, 0 );

  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return SUCCESS_GR;
}

HashReturn_gr reinit_groestl( hashState_groestl* ctx )
{
  int i;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return FAIL_GR;

  for ( i = 0; i < SIZE512; i++ )
  {
     ctx->chaining[i] = _mm_setzero_si128();
     ctx->buffer[i]   = _mm_setzero_si128();
  }
  ctx->chaining[ 6 ] = m128_const_64( 0x0200000000000000, 0 );
  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return SUCCESS_GR;
}
//// midstate is broken
// To use midstate:
// 1. midstate must process all full blocks.
// 2. tail must be less than a full block and may not straddle a
//    block boundary.
// 3. midstate and tail each must be multiples of 128 bits.
// 4. For best performance midstate length is a multiple of block size.
// 5. Midstate will work at reduced impact than full hash, if total hash
//    (midstate + tail) is less than 1 block.
//    This, unfortunately, is the case with all current users.
// 6. the more full blocks the bigger the gain

// use only for midstate precalc
HashReturn_gr update_groestl( hashState_groestl* ctx, const void* input,
                              DataLength_gr databitlen )
{
   __m128i* in = (__m128i*)input;
   const int len = (int)databitlen / 128;  // bits to __m128i
   const int blocks = len / SIZE512;    // __M128i to blocks
   int rem = ctx->rem_ptr;
   int i;

   ctx->blk_count  = blocks;
   ctx->databitlen = databitlen;

   // digest any full blocks 
   for ( i = 0; i < blocks; i++ )
       TF1024( ctx->chaining, &in[ i * SIZE512 ] );
   // adjust buf_ptr to last block
   ctx->buf_ptr = blocks * SIZE512;

   // copy any remaining data to buffer for final hash, it may already
   // contain data from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   // adjust rem_ptr for possible  new data
   ctx->rem_ptr += i;

   return SUCCESS_GR;
}

// deprecated do not use
HashReturn_gr final_groestl( hashState_groestl* ctx, void* output )
{
   const int len = (int)ctx->databitlen / 128; // bits to __m128i 
   const uint64_t blocks = ctx->blk_count + 1; // adjust for final block
   const int rem_ptr = ctx->rem_ptr;           // end of data start of padding
   const int hashlen_m128i = ctx->hashlen / 16;     // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i; // where in buffer
   int i;

   // first pad byte = 0x80, last pad byte = block count
   // everything in between is zero

   if ( rem_ptr == len - 1 )
   {
       // only 128 bits left in buffer, all padding at once
      ctx->buffer[rem_ptr] = _mm_set_epi64x( blocks << 56, 0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[rem_ptr] = m128_const_64( 0, 0x80 );
       // add zero padding
       for ( i = rem_ptr + 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = _mm_setzero_si128();

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = _mm_set_epi64x( blocks << 56, 0 );
   }

   // digest final padding block and do output transform
   TF1024( ctx->chaining, ctx->buffer );
   OF1024( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m128i( output, i ) = ctx->chaining[ hash_offset + i];

   return SUCCESS_GR;
}

int groestl512_full( hashState_groestl* ctx, void* output,
                                const void* input, uint64_t databitlen )
{

   int i;
   ctx->hashlen = 64;

   for ( i = 0; i < SIZE512; i++ )
   {
      ctx->chaining[i] = _mm_setzero_si128();
      ctx->buffer[i]   = _mm_setzero_si128();
   }
   ctx->chaining[ 6 ] = m128_const_64( 0x0200000000000000, 0 );
   ctx->buf_ptr = 0;
   ctx->rem_ptr = 0;

   // --- update ---
   
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE512;
   __m128i* in = (__m128i*)input;

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF1024( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == len -1 )
   {
       // only 128 bits left in buffer, all padding at once
      ctx->buffer[i] = _mm_set_epi64x( blocks << 56, 0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[i] = m128_const_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = _mm_setzero_si128();

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = _mm_set_epi64x( blocks << 56, 0 ); 
   }

   // digest final padding block and do output transform
   TF1024( ctx->chaining, ctx->buffer );
   OF1024( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m128i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}
   

HashReturn_gr update_and_final_groestl( hashState_groestl* ctx, void* output,
                                const void* input, DataLength_gr databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE512;
   __m128i* in = (__m128i*)input;
   int i;

   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF1024( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == len -1 )
   {        
       // only 128 bits left in buffer, all padding at once
      ctx->buffer[i] = _mm_set_epi64x( blocks << 56, 0x80 );
   }   
   else
   {
       // add first padding
       ctx->buffer[i] = m128_const_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = _mm_setzero_si128();

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = _mm_set_epi64x( blocks << 56, 0 );
   }

   // digest final padding block and do output transform
   TF1024( ctx->chaining, ctx->buffer );
   OF1024( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m128i( output, i ) = ctx->chaining[ hash_offset + i ];

   return SUCCESS_GR;
}

/* hash bit sequence */
HashReturn_gr hash_groestl(int hashbitlen,
		const BitSequence_gr* data, 
		DataLength_gr databitlen,
		BitSequence_gr* hashval) {
  HashReturn_gr ret;
  hashState_groestl context;

  /* initialise */
  if ((ret = init_groestl( &context, hashbitlen/8 )) != SUCCESS_GR)
    return ret;

  /* process message */
  if ((ret = update_groestl(&context, data, databitlen)) != SUCCESS_GR)
    return ret;

  /* finalise */
  ret = final_groestl(&context, hashval);

  return ret;
}

/* eBash API */
#ifdef crypto_hash_BYTES
int crypto_hash(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
  if (hash_groestl(crypto_hash_BYTES * 8, in, inlen * 8,out) == SUCCESS_GR) return 0;
  return -1;
}
#endif

#endif
