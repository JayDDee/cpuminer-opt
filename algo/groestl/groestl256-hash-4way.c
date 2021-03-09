/* hash.c     Aug 2011
 * groestl512-hash-4way https://github.com/JayDDee/cpuminer-opt  2019-12.
 *
 * Groestl implementation for different versions.
 * Author: Krystian Matusiewicz, Günther A. Roland, Martin Schläffer
 *
 * This code is placed in the public domain
 */

// Optimized for hash and data length that are integrals of __m128i 


#include <memory.h>
#include "groestl256-intr-4way.h"
#include "miner.h"
#include "simd-utils.h"

#if defined(__AVX2__) && defined(__VAES__)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)


int groestl256_4way_init( groestl256_4way_context* ctx, uint64_t hashlen )
{
  int i;

  ctx->hashlen = hashlen;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return 1;

  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = m512_zero;
     ctx->buffer[i]   = m512_zero;
  }

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 3 ] = m512_const2_64( 0, 0x0100000000000000 );

  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}

int groestl256_4way_full( groestl256_4way_context* ctx, void* output,
                                const void* input, uint64_t datalen )
{
   const int len = (int)datalen >> 4;
   const int hashlen_m128i = 32 >> 4;   // bytes to __m128i
   const int hash_offset = SIZE256 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE256;
   __m512i* in = (__m512i*)input;
   int i;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return 1;

  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = m512_zero;
     ctx->buffer[i]   = m512_zero;
  }

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 3 ] = m512_const2_64( 0, 0x0100000000000000 );
  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;
   
   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF512_4way( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE256; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE256 - 1 )
   {        
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = m512_const2_64( blocks << 56, 0x80 ); 
   }   
   else
   {
       // add first padding
       ctx->buffer[i] = m512_const2_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = m512_zero;

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = m512_const2_64( blocks << 56, 0 );
   }

   // digest final padding block and do output transform
   TF512_4way( ctx->chaining, ctx->buffer );

   OF512_4way( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m512i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

int groestl256_4way_update_close( groestl256_4way_context* ctx, void* output,
                                const void* input, uint64_t databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to __m128i
   const int hash_offset = SIZE256 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE256;
   __m512i* in = (__m512i*)input;
   int i;

   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF512_4way( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE256; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE256 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = m512_const2_64( blocks << 56, 0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[i] = m512_const2_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = m512_zero;

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = m512_const2_64( blocks << 56, 0 );
   }

// digest final padding block and do output transform
   TF512_4way( ctx->chaining, ctx->buffer );

   OF512_4way( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m512i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

#endif   // AVX512

// AVX2 + VAES

int groestl256_2way_init( groestl256_2way_context* ctx, uint64_t hashlen )
{
  int i;

  ctx->hashlen = hashlen;

  if (ctx->chaining == NULL || ctx->buffer == NULL)
    return 1;

  for ( i = 0; i < SIZE256; i++ )
  {
     ctx->chaining[i] = m256_zero;
     ctx->buffer[i]   = m256_zero;
  }

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 3 ] = m256_const2_64( 0, 0x0100000000000000 );

  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}

int groestl256_2way_full( groestl256_2way_context* ctx, void* output,
                                const void* input, uint64_t datalen )
{
   const int len = (int)datalen >> 4;
   const int hashlen_m128i = 32 >> 4;   // bytes to __m128i
   const int hash_offset = SIZE256 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE256;
   __m256i* in = (__m256i*)input;
   int i;

   if (ctx->chaining == NULL || ctx->buffer == NULL)
     return 1;

   for ( i = 0; i < SIZE256; i++ )
   {
     ctx->chaining[i] = m256_zero;
     ctx->buffer[i]   = m256_zero;
   }

   // The only non-zero in the IV is len. It can be hard coded.
   ctx->chaining[ 3 ] = m256_const2_64( 0, 0x0100000000000000 );
   ctx->buf_ptr = 0;
   ctx->rem_ptr = 0;

   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF512_2way( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE256; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE256 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
      ctx->buffer[i] = m256_const2_64( blocks << 56, 0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[i] = m256_const2_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = m256_zero;

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = m256_const2_64( blocks << 56, 0 );
   }

   // digest final padding block and do output transform
   TF512_2way( ctx->chaining, ctx->buffer );

   OF512_2way( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m256i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}
int groestl256_2way_update_close( groestl256_2way_context* ctx, void* output,
                                const void* input, uint64_t databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = ctx->hashlen / 16;   // bytes to __m128i
   const int hash_offset = SIZE256 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE256;
   __m256i* in = (__m256i*)input;
   int i;

   // --- update ---

   // digest any full blocks, process directly from input 
   for ( i = 0; i < blocks; i++ )
      TF512_2way( ctx->chaining, &in[ i * SIZE256 ] );
   ctx->buf_ptr = blocks * SIZE256;

   // copy any remaining data to buffer, it may already contain data
   // from a previous update for a midstate precalc
   for ( i = 0; i < len % SIZE256; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;    // use i as rem_ptr in final

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE256 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = m256_const2_64( blocks << 56, 0x80 );
   }
   else
   {
       // add first padding
       ctx->buffer[i] = m256_const2_64( 0, 0x80 );
       // add zero padding
       for ( i += 1; i < SIZE256 - 1; i++ )
           ctx->buffer[i] = m256_zero;

       // add length padding, second last byte is zero unless blocks > 255
       ctx->buffer[i] = m256_const2_64( blocks << 56, 0 );
   }

// digest final padding block and do output transform
   TF512_2way( ctx->chaining, ctx->buffer );

   OF512_2way( ctx->chaining );

   // store hash result in output 
   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m256i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

#endif  // VAES
