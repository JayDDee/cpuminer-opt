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
#include "groestl512-intr-4way.h"
#include "miner.h"
#include "simd-utils.h"

#if defined(__AVX2__) && defined(__VAES__)

#if defined(SIMD512)

int groestl512_4way_init( groestl512_4way_context* ctx, uint64_t hashlen )
{
  memset_zero_512( ctx->chaining, SIZE512 );
  memset_zero_512( ctx->buffer, SIZE512 );

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 6 ] = mm512_bcast128hi_64( 0x0200000000000000 );
  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}

int groestl512_4way_update_close( groestl512_4way_context* ctx, void* output,
                                const void* input, uint64_t databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = 64 / 16;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE512;
   __m512i* in = (__m512i*)input;
   int i;

   // --- update ---

   for ( i = 0; i < blocks; i++ )
      TF1024_4way( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem; 

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE512 - 1 )
   {        
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = mm512_set2_64( blocks << 56, 0x80 );
   }   
   else
   {
       ctx->buffer[i] = mm512_bcast128lo_64( 0x80 );
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = m512_zero;
       ctx->buffer[i] = mm512_bcast128hi_64( blocks << 56 );
   }

   TF1024_4way( ctx->chaining, ctx->buffer );
   OF1024_4way( ctx->chaining );

   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m512i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

int groestl512_4way_full( groestl512_4way_context* ctx, void* output,
                          const void* input, uint64_t datalen )
{
   const int len = (int)datalen >> 4;
   const int hashlen_m128i = 64 >> 4;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   uint64_t blocks = len / SIZE512;
   __m512i* in = (__m512i*)input;
   int i;

   // --- init ---

   memset_zero_512( ctx->chaining, SIZE512 );
   memset_zero_512( ctx->buffer, SIZE512 );
   ctx->chaining[ 6 ] = mm512_bcast128hi_64( 0x0200000000000000 );
   ctx->buf_ptr = 0;

   // --- update ---

   for ( i = 0; i < blocks; i++ )
      TF1024_4way( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ i ] = in[ ctx->buf_ptr + i ];

   // --- close ---

   blocks++;   

   if ( i == SIZE512 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = mm512_set2_64( blocks << 56, 0x80 );
   }
   else
   {
       ctx->buffer[i] = mm512_bcast128lo_64( 0x80 );
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = m512_zero;
       ctx->buffer[i] = mm512_bcast128hi_64( blocks << 56 );
   }

   TF1024_4way( ctx->chaining, ctx->buffer );
   OF1024_4way( ctx->chaining );

   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m512i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

#endif   // AVX512


// AVX2 + VAES

int groestl512_2way_init( groestl512_2way_context* ctx, uint64_t hashlen )
{
  memset_zero_256( ctx->chaining, SIZE512 );
  memset_zero_256( ctx->buffer, SIZE512 );

  // The only non-zero in the IV is len. It can be hard coded.
  ctx->chaining[ 6 ] = mm256_bcast128hi_64( 0x0200000000000000 );

  ctx->buf_ptr = 0;
  ctx->rem_ptr = 0;

  return 0;
}

int groestl512_2way_update_close( groestl512_2way_context* ctx, void* output,
                                const void* input, uint64_t databitlen )
{
   const int len = (int)databitlen / 128;
   const int hashlen_m128i = 64 / 16;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   int rem = ctx->rem_ptr;
   uint64_t blocks = len / SIZE512;
   __m256i* in = (__m256i*)input;
   int i;

   // --- update ---

   for ( i = 0; i < blocks; i++ )
      TF1024_2way( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ rem + i ] = in[ ctx->buf_ptr + i ];
   i += rem;

   //--- final ---

   blocks++;      // adjust for final block

   if ( i == SIZE512 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = mm256_set2_64( blocks << 56, 0x80 );
   }
   else
   {
       ctx->buffer[i] = mm256_bcast128lo_64( 0x80 );
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = m256_zero;
       ctx->buffer[i] = mm256_bcast128hi_64( blocks << 56 );
   }

   TF1024_2way( ctx->chaining, ctx->buffer );
   OF1024_2way( ctx->chaining );

   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m256i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}

int groestl512_2way_full( groestl512_2way_context* ctx, void* output,
                          const void* input, uint64_t datalen )
{
   const int len = (int)datalen >> 4;
   const int hashlen_m128i = 64 >> 4;   // bytes to __m128i
   const int hash_offset = SIZE512 - hashlen_m128i;
   uint64_t blocks = len / SIZE512;
   __m256i* in = (__m256i*)input;
   int i;

   // --- init ---

   memset_zero_256( ctx->chaining, SIZE512 );
   memset_zero_256( ctx->buffer, SIZE512 );
   ctx->chaining[ 6 ] = mm256_bcast128hi_64( 0x0200000000000000 );
   ctx->buf_ptr = 0;

   // --- update ---

   for ( i = 0; i < blocks; i++ )
      TF1024_2way( ctx->chaining, &in[ i * SIZE512 ] );
   ctx->buf_ptr = blocks * SIZE512;

   for ( i = 0; i < len % SIZE512; i++ )
       ctx->buffer[ i ] = in[ ctx->buf_ptr + i ];

   // --- close ---

   blocks++;

   if ( i == SIZE512 - 1 )
   {
       // only 1 vector left in buffer, all padding at once
       ctx->buffer[i] = mm256_set2_64( blocks << 56, 0x80 );
   }
   else
   {
       ctx->buffer[i] = mm256_bcast128lo_64( 0x80 );
       for ( i += 1; i < SIZE512 - 1; i++ )
           ctx->buffer[i] = m256_zero;
       ctx->buffer[i] = mm256_bcast128hi_64( blocks << 56 );
   }

   TF1024_2way( ctx->chaining, ctx->buffer );
   OF1024_2way( ctx->chaining );

   for ( i = 0; i < hashlen_m128i; i++ )
      casti_m256i( output, i ) = ctx->chaining[ hash_offset + i ];

   return 0;
}
   
#endif   // VAES

