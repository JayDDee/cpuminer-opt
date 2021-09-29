#include "shavite-hash-4way.h"
#include <stdint.h>

#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static const uint32_t IV512[] =
{
        0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
        0xD1901A06, 0x430AE307, 0xB29F5CD1, 0xDF07FBFC,
        0x8E45D73D, 0x681AB538, 0xBDE86578, 0xDD577E47,
        0xE275EADE, 0x502D9FCD, 0xB9357178, 0x022A4B9A
};

#define mm512_ror2x512hi_1x32( a, b ) \
   _mm512_mask_blend_epi32( 0x8888, mm512_shuflr128_32( a ), \
                                    mm512_shuflr128_32( b ) )

static void
c512_4way( shavite512_4way_context *ctx, const void *msg )
{
   register __m512i X;
   register __m512i P0, P1, P2, P3;
   register __m512i K0, K1, K2, K3, K4, K5, K6, K7;
   __m512i *M = (__m512i*)msg;
   __m512i *H = (__m512i*)ctx->h;
   const __m512i count = _mm512_set4_epi32( ctx->count3, ctx->count2,
                                            ctx->count1, ctx->count0 );
   int r;

   P0 = H[0];
   P1 = H[1];
   P2 = H[2];
   P3 = H[3];

   K0 = M[0];
   K1 = M[1];
   K2 = M[2];
   K3 = M[3];
   K4 = M[4];
   K5 = M[5];
   K6 = M[6];
   K7 = M[7];

   X = _mm512_aesenc_epi128( _mm512_xor_si512( P1, K0 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K1 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K2 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K3 ), m512_zero );

   P0 = _mm512_xor_si512( P0, X );

   X = _mm512_aesenc_epi128( _mm512_xor_si512( P3, K4 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K5 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K6 ), m512_zero );
   X = _mm512_aesenc_epi128( _mm512_xor_si512(  X, K7 ), m512_zero );

   P2 = _mm512_xor_si512( P2, X );

   // round
   for ( r = 0; r < 3; r ++ )
   {
      // round 1, 5, 9

     K0 = _mm512_xor_si512( K7, mm512_shuflr128_32(
                                  _mm512_aesenc_epi128( K0, m512_zero ) ) );

     if ( r == 0 )
        K0 = _mm512_xor_si512( K0,
                    _mm512_mask_xor_epi32( count, 0x8888, count, m512_neg1 ) );

     X = _mm512_aesenc_epi128( _mm512_xor_si512( P0, K0 ), m512_zero );
     K1 = _mm512_xor_si512( K0,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K1, m512_zero ) ) );

     if ( r == 1 )
        K1 = _mm512_xor_si512( K1, mm512_shuflr128_32(
                 _mm512_mask_xor_epi32( count, 0x1111, count, m512_neg1 ) ) );

     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K1 ), m512_zero );
     K2 = _mm512_xor_si512( K1,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K2, m512_zero ) ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K2 ), m512_zero );
     K3 = _mm512_xor_si512( K2,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K3, m512_zero ) ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K3 ), m512_zero );

     P3 = _mm512_xor_si512( P3, X );

     K4 = _mm512_xor_si512( K3,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K4, m512_zero ) ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P2, K4 ), m512_zero );
     K5 = _mm512_xor_si512( K4,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K5, m512_zero ) ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K5 ), m512_zero );
     K6 = _mm512_xor_si512( K5,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K6, m512_zero ) ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K6 ), m512_zero );
     K7 = _mm512_xor_si512( K6,
		           mm512_shuflr128_32( _mm512_aesenc_epi128( K7, m512_zero ) ) );

     if ( r == 2 )
        K7 = _mm512_xor_si512( K7, mm512_swap128_64(
                 _mm512_mask_xor_epi32( count, 0x2222, count, m512_neg1 ) ) );
 
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K7 ), m512_zero );
     P1 = _mm512_xor_si512( P1, X );
     
     // round 2, 6, 10

     K0 = _mm512_xor_si512( K0, mm512_ror2x512hi_1x32( K6, K7 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P3, K0 ), m512_zero );
     K1 = _mm512_xor_si512( K1, mm512_ror2x512hi_1x32( K7, K0 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K1 ), m512_zero );
     K2 = _mm512_xor_si512( K2, mm512_ror2x512hi_1x32( K0, K1 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K2 ), m512_zero );
     K3 = _mm512_xor_si512( K3, mm512_ror2x512hi_1x32( K1, K2 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K3 ), m512_zero );

     P2 = _mm512_xor_si512( P2, X );

     K4 = _mm512_xor_si512( K4, mm512_ror2x512hi_1x32( K2, K3 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P1, K4 ), m512_zero );
     K5 = _mm512_xor_si512( K5, mm512_ror2x512hi_1x32( K3, K4 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K5 ), m512_zero );
     K6 = _mm512_xor_si512( K6, mm512_ror2x512hi_1x32( K4, K5 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K6 ), m512_zero );
     K7 = _mm512_xor_si512( K7, mm512_ror2x512hi_1x32( K5, K6 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K7 ), m512_zero );

     P0 = _mm512_xor_si512( P0, X );

     // round 3, 7, 11

     K0 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K0, m512_zero ) ), K7 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P2, K0 ), m512_zero );
     K1 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K1, m512_zero ) ), K0 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K1 ), m512_zero );
     K2 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K2, m512_zero ) ), K1 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K2 ), m512_zero );
     K3 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K3, m512_zero ) ), K2 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K3 ), m512_zero );

     P1 = _mm512_xor_si512( P1, X );

     K4 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K4, m512_zero ) ), K3 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P0, K4 ), m512_zero );
     K5 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K5, m512_zero ) ), K4 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K5 ), m512_zero );
     K6 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K6, m512_zero ) ), K5 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K6 ), m512_zero );
     K7 = _mm512_xor_si512( mm512_shuflr128_32(
                               _mm512_aesenc_epi128( K7, m512_zero ) ), K6 );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K7 ), m512_zero );

     P3 = _mm512_xor_si512( P3, X );

     // round 4, 8, 12

     K0 = _mm512_xor_si512( K0, mm512_ror2x512hi_1x32( K6, K7 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P1, K0 ), m512_zero );
     K1 = _mm512_xor_si512( K1, mm512_ror2x512hi_1x32( K7, K0 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K1 ), m512_zero );
     K2 = _mm512_xor_si512( K2, mm512_ror2x512hi_1x32( K0, K1 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K2 ), m512_zero );
     K3 = _mm512_xor_si512( K3, mm512_ror2x512hi_1x32( K1, K2 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K3 ), m512_zero );

     P0 = _mm512_xor_si512( P0, X );

     K4 = _mm512_xor_si512( K4, mm512_ror2x512hi_1x32( K2, K3 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( P3, K4 ), m512_zero );
     K5 = _mm512_xor_si512( K5, mm512_ror2x512hi_1x32( K3, K4 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K5 ), m512_zero );
     K6 = _mm512_xor_si512( K6, mm512_ror2x512hi_1x32( K4, K5 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K6 ), m512_zero );
     K7 = _mm512_xor_si512( K7, mm512_ror2x512hi_1x32( K5, K6 ) );
     X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K7 ), m512_zero );

     P2 = _mm512_xor_si512( P2, X );
   }

   // round 13

   K0 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K0, m512_zero ) ), K7  );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( P0, K0 ), m512_zero );
   K1 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K1, m512_zero ) ), K0 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K1 ), m512_zero );
   K2 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K2, m512_zero ) ), K1 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K2 ), m512_zero );
   K3 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K3, m512_zero ) ), K2 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K3 ), m512_zero );

   P3 = _mm512_xor_si512( P3, X );

   K4 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K4, m512_zero ) ), K3 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( P2, K4 ), m512_zero );
   K5 = _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K5, m512_zero ) ), K4 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K5 ), m512_zero );

   K6 = mm512_shuflr128_32( _mm512_aesenc_epi128( K6, m512_zero ) );
   K6 = _mm512_xor_si512( K6, _mm512_xor_si512( K5, _mm512_set4_epi32(
	       ~ctx->count2, ctx->count3, ctx->count0, ctx->count1 ) ) );

   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K6 ), m512_zero );
   K7= _mm512_xor_si512( mm512_shuflr128_32(
			             _mm512_aesenc_epi128( K7, m512_zero ) ), K6 );
   X = _mm512_aesenc_epi128( _mm512_xor_si512( X, K7 ), m512_zero );

   P1 = _mm512_xor_si512( P1, X );

   H[0] = _mm512_xor_si512( H[0], P2 );
   H[1] = _mm512_xor_si512( H[1], P3 );
   H[2] = _mm512_xor_si512( H[2], P0 );
   H[3] = _mm512_xor_si512( H[3], P1 );
}

void shavite512_4way_init( shavite512_4way_context *ctx )
{
    __m512i *h = (__m512i*)ctx->h;
    __m128i *iv = (__m128i*)IV512;
   
   h[0] = m512_const1_128( iv[0] );
   h[1] = m512_const1_128( iv[1] );
   h[2] = m512_const1_128( iv[2] );
   h[3] = m512_const1_128( iv[3] );

   ctx->ptr    = 0;
   ctx->count0 = 0;
   ctx->count1 = 0;
   ctx->count2 = 0;
   ctx->count3 = 0;
}

// not tested, use update_close
void shavite512_4way_update( shavite512_4way_context *ctx, const void *data,
                             size_t len )
{
   unsigned char *buf = ctx->buf;
   size_t         ptr = ctx->ptr;

   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof ctx->buf) - ptr;
      if ( clen > len << 2 )
         clen = len << 2;
      memcpy( buf + ptr, data, clen );
      data = (const unsigned char *)data + clen;
      ptr += clen;
      len -= clen >> 2;
      if ( ptr == sizeof ctx->buf )
      {
         if ( ( ctx->count0 = ctx->count0 + 1024 )  == 0 )
         {
             ctx->count1 = ctx->count1 + 1;
             if ( ctx->count1 == 0 )
             {
                ctx->count2 = ctx->count2 + 1;
                if ( ctx->count2 == 0 )
                   ctx->count3 = ctx->count3 + 1;
             }
         }
         c512_4way( ctx, buf );
         ptr = 0;
      }
   }
   ctx->ptr = ptr;
}

// not tested
void shavite512_4way_close( shavite512_4way_context *ctx, void *dst )
{
    unsigned char *buf;
    union 
    {
       uint32_t u32[4];
       uint16_t u16[8];
    } count;

    buf = ctx->buf;
    uint32_t vp = ctx->ptr>>6;

    // Terminating byte then zero pad
    casti_m512i( buf, vp++ ) = m512_const1_i128( 0x0000000000000080 );

    // Zero pad full vectors up to count
    for ( ; vp < 6; vp++ )      
        casti_m512i( buf, vp ) = m512_zero;

    // Count = { 0, 16, 64, 80 }. Outsize = 16 u32 = 512 bits = 0x0200
    // Count is misaligned to 16 bits and straddles a vector.
    // Use u32 overlay to stage then u16 to load buf.
    count.u32[0] = ctx->count0 += (ctx->ptr << 1);  // ptr/4 * 8
    count.u32[1] = ctx->count1;
    count.u32[2] = ctx->count2;
    count.u32[3] = ctx->count3;

    casti_m512i( buf, 6 ) = m512_const1_128(
                  _mm_insert_epi16( m128_zero, count.u16[0], 7 ) ); 
    casti_m512i( buf, 7 ) = m512_const1_128( _mm_set_epi16(
                  0x0200,       count.u16[7], count.u16[6], count.u16[5],
                  count.u16[4], count.u16[3], count.u16[2], count.u16[1] ) );
                
    c512_4way( ctx, buf);

    casti_m512i( dst, 0 ) = casti_m512i( ctx->h, 0 );
    casti_m512i( dst, 1 ) = casti_m512i( ctx->h, 1 );
    casti_m512i( dst, 2 ) = casti_m512i( ctx->h, 2 );
    casti_m512i( dst, 3 ) = casti_m512i( ctx->h, 3 );
}

void shavite512_4way_update_close( shavite512_4way_context *ctx, void *dst,
                                   const void *data, size_t len )
{
   unsigned char *buf = ctx->buf;
   size_t         ptr = ctx->ptr;

   // process full blocks and load buf with remainder.
   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof ctx->buf) - ptr;
      if ( clen > len << 2 )
         clen = len << 2;
      memcpy( buf + ptr, data, clen );
      data = (const unsigned char *)data + clen;
      ptr += clen;
      len -= (clen >> 2);
      if ( ptr == sizeof ctx->buf )
      {
         if ( ( ctx->count0 = ctx->count0 + 1024 )  == 0 )
         {
             ctx->count1 = ctx->count1 + 1;
             if ( ctx->count1 == 0 )
             {
                ctx->count2 = ctx->count2 + 1;
                if ( ctx->count2 == 0 )
                   ctx->count3 = ctx->count3 + 1;
             }
         }
         c512_4way( ctx, buf );
         ptr = 0;
      }
   }

   uint32_t vp = ptr>>6;
   // Count = { 0, 16, 64, 80 }. Outsize = 16 u32 = 512 bits = 0x0200
   // Count is misaligned to 16 bits and straddles 2 vectors.
   // Use u32 overlay to stage then u16 to load buf.
   union
   {
      uint32_t u32[4];
      uint16_t u16[8];
   } count;

   count.u32[0] = ctx->count0 += (ptr << 1);  // ptr/4 * 8
   count.u32[1] = ctx->count1;
   count.u32[2] = ctx->count2;
   count.u32[3] = ctx->count3;

   if ( vp == 0 )    // empty buf, xevan.
   { 
      casti_m512i( buf, 0 ) = m512_const1_i128( 0x0000000000000080 );
      memset_zero_512( (__m512i*)buf + 1, 5 );
      ctx->count0 = ctx->count1 = ctx->count2 = ctx->count3 = 0;
   }
   else     // half full buf, everyone else.
   {
    casti_m512i( buf, vp++ ) = m512_const1_i128( 0x0000000000000080 );
      memset_zero_512( (__m512i*)buf + vp, 6 - vp );
   }

    casti_m512i( buf, 6 ) = m512_const1_128(
                  _mm_insert_epi16( m128_zero, count.u16[0], 7 ) ); 
    casti_m512i( buf, 7 ) = m512_const1_128( _mm_set_epi16(
                  0x0200,       count.u16[7], count.u16[6], count.u16[5],
                  count.u16[4], count.u16[3], count.u16[2], count.u16[1] ) );

   c512_4way( ctx, buf);

   casti_m512i( dst, 0 ) = casti_m512i( ctx->h, 0 );
   casti_m512i( dst, 1 ) = casti_m512i( ctx->h, 1 );
   casti_m512i( dst, 2 ) = casti_m512i( ctx->h, 2 );
   casti_m512i( dst, 3 ) = casti_m512i( ctx->h, 3 );
}


void shavite512_4way_full( shavite512_4way_context *ctx, void *dst,
                           const void *data, size_t len )
{
    __m512i *h = (__m512i*)ctx->h;
    __m128i *iv = (__m128i*)IV512;

   h[0] = m512_const1_128( iv[0] );
   h[1] = m512_const1_128( iv[1] );
   h[2] = m512_const1_128( iv[2] );
   h[3] = m512_const1_128( iv[3] );

   ctx->ptr    = 
   ctx->count0 = 
   ctx->count1 =
   ctx->count2 =
   ctx->count3 = 0;

   unsigned char *buf = ctx->buf;
   size_t         ptr = ctx->ptr;

   // process full blocks and load buf with remainder.
   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof ctx->buf) - ptr;
      if ( clen > len << 2 )
         clen = len << 2;
      memcpy( buf + ptr, data, clen );
      data = (const unsigned char *)data + clen;
      ptr += clen;
      len -= (clen >> 2);
      if ( ptr == sizeof ctx->buf )
      {
         if ( ( ctx->count0 = ctx->count0 + 1024 )  == 0 )
         {
             ctx->count1 = ctx->count1 + 1;
             if ( ctx->count1 == 0 )
             {
                ctx->count2 = ctx->count2 + 1;
                if ( ctx->count2 == 0 )
                   ctx->count3 = ctx->count3 + 1;
             }
         }
         c512_4way( ctx, buf );
         ptr = 0;
      }
   }

   uint32_t vp = ptr>>6;
   // Count = { 0, 16, 64, 80 }. Outsize = 16 u32 = 512 bits = 0x0200
   // Count is misaligned to 16 bits and straddles 2 vectors.
   // Use u32 overlay to stage then u16 to load buf.
   union
   {
      uint32_t u32[4];
      uint16_t u16[8];
   } count;

   count.u32[0] = ctx->count0 += (ptr << 1);  // ptr/4 * 8
   count.u32[1] = ctx->count1;
   count.u32[2] = ctx->count2;
   count.u32[3] = ctx->count3;

   if ( vp == 0 )    // empty buf, xevan.
   {
      casti_m512i( buf, 0 ) = m512_const1_i128( 0x0000000000000080 );
      memset_zero_512( (__m512i*)buf + 1, 5 );
      ctx->count0 = ctx->count1 = ctx->count2 = ctx->count3 = 0;
   }
   else     // half full buf, everyone else.
   {
    casti_m512i( buf, vp++ ) = m512_const1_i128( 0x0000000000000080 );
      memset_zero_512( (__m512i*)buf + vp, 6 - vp );
   }

    casti_m512i( buf, 6 ) = m512_const1_128(
                  _mm_insert_epi16( m128_zero, count.u16[0], 7 ) );
    casti_m512i( buf, 7 ) = m512_const1_128( _mm_set_epi16(
                  0x0200,       count.u16[7], count.u16[6], count.u16[5],
                  count.u16[4], count.u16[3], count.u16[2], count.u16[1] ) );

   c512_4way( ctx, buf);

   casti_m512i( dst, 0 ) = casti_m512i( ctx->h, 0 );
   casti_m512i( dst, 1 ) = casti_m512i( ctx->h, 1 );
   casti_m512i( dst, 2 ) = casti_m512i( ctx->h, 2 );
   casti_m512i( dst, 3 ) = casti_m512i( ctx->h, 3 );
}


#endif // VAES
