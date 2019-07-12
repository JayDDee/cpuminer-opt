#include "shavite-hash-2way.h"
#include "algo/sha/sph_types.h"

#include <stdio.h>

#if defined(__AVX2__)

static const uint32_t IV512[] =
{
        0x72FCCDD8, 0x79CA4727, 0x128A077B, 0x40D55AEC,
        0xD1901A06, 0x430AE307, 0xB29F5CD1, 0xDF07FBFC,
        0x8E45D73D, 0x681AB538, 0xBDE86578, 0xDD577E47,
        0xE275EADE, 0x502D9FCD, 0xB9357178, 0x022A4B9A
};

#define mm256_ror2x256hi_1x32( a, b ) \
   _mm256_blend_epi32( mm256_ror1x32_128( a ), \
                       mm256_ror1x32_128( b ), 0x88 )

static void
c512_2way( shavite512_2way_context *ctx, const void *msg )
{
   const __m128i zero = _mm_setzero_si128();
   __m256i p0, p1, p2, p3, x;
   __m256i k00, k01, k02, k03, k10, k11, k12, k13;
   __m256i *m = (__m256i*)msg;
   __m256i *h = (__m256i*)ctx->h;
   int r;

   p0 = h[0];
   p1 = h[1];
   p2 = h[2];
   p3 = h[3];

   // round
   k00 = m[0];
   x = mm256_aesenc_2x128( _mm256_xor_si256( p1, k00 ), zero );
   k01 = m[1];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
   k02 = m[2];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
   k03 = m[3];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

   p0 = _mm256_xor_si256( p0, x );

   k10 = m[4];
   x = mm256_aesenc_2x128( _mm256_xor_si256( p3, k10 ), zero );
   k11 = m[5];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );
   k12 = m[6];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
   k13 = m[7];
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );

   p2 = _mm256_xor_si256( p2, x );

   for ( r = 0; r < 3; r ++ )
   {
      // round 1, 5, 9

     k00 = _mm256_xor_si256( k13, mm256_ror1x32_128(
                                  mm256_aesenc_2x128( k00, zero ) ) );

     if ( r == 0 )
        k00 = _mm256_xor_si256( k00, _mm256_set_epi32( 
		      ~ctx->count3, ctx->count2, ctx->count1, ctx->count0,
                      ~ctx->count3, ctx->count2, ctx->count1, ctx->count0 ) );

     x = mm256_aesenc_2x128( _mm256_xor_si256( p0, k00 ), zero );
     k01 = _mm256_xor_si256( k00,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k01, zero ) ) );

     if ( r == 1 )
        k01 = _mm256_xor_si256( k01, _mm256_set_epi32(
	               ~ctx->count0, ctx->count1, ctx->count2, ctx->count3,
                       ~ctx->count0, ctx->count1, ctx->count2, ctx->count3 ) );

     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
     k02 = _mm256_xor_si256( k01,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k02, zero ) ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
     k03 = _mm256_xor_si256( k02,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k03, zero ) ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

     p3 = _mm256_xor_si256( p3, x );

     k10 = _mm256_xor_si256( k03,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k10, zero ) ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p2, k10 ), zero );
     k11 = _mm256_xor_si256( k10,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k11, zero ) ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );
     k12 = _mm256_xor_si256( k11,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k12, zero ) ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
     k13 = _mm256_xor_si256( k12,
		     mm256_ror1x32_128( mm256_aesenc_2x128( k13, zero ) ) );

     if ( r == 2 )
        k13 = _mm256_xor_si256( k13, _mm256_set_epi32(
                  ~ctx->count1, ctx->count0, ctx->count3, ctx->count2,
                  ~ctx->count1, ctx->count0, ctx->count3, ctx->count2 ) );
 
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );
     p1 = _mm256_xor_si256( p1, x );
     
     // round 2, 6, 10

     k00 = _mm256_xor_si256( k00, mm256_ror2x256hi_1x32( k12, k13 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p3, k00 ), zero );
     k01 = _mm256_xor_si256( k01, mm256_ror2x256hi_1x32( k13, k00 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
     k02 = _mm256_xor_si256( k02, mm256_ror2x256hi_1x32( k00, k01 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
     k03 = _mm256_xor_si256( k03, mm256_ror2x256hi_1x32( k01, k02 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

     p2 = _mm256_xor_si256( p2, x );

     k10 = _mm256_xor_si256( k10, mm256_ror2x256hi_1x32( k02, k03 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p1, k10 ), zero );
     k11 = _mm256_xor_si256( k11, mm256_ror2x256hi_1x32( k03, k10 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );
     k12 = _mm256_xor_si256( k12, mm256_ror2x256hi_1x32( k10, k11 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
     k13 = _mm256_xor_si256( k13, mm256_ror2x256hi_1x32( k11, k12 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );

     p0 = _mm256_xor_si256( p0, x );

     // round 3, 7, 11

     k00 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k00, zero ) ), k13 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p2, k00 ), zero );
     k01 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k01, zero ) ), k00 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
     k02 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k02, zero ) ), k01 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
     k03 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k03, zero ) ), k02 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

     p1 = _mm256_xor_si256( p1, x );

     k10 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k10, zero ) ), k03 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p0, k10 ), zero );
     k11 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k11, zero ) ), k10 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );
     k12 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k12, zero ) ), k11 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
     k13 = _mm256_xor_si256( mm256_ror1x32_128(
                                     mm256_aesenc_2x128( k13, zero ) ), k12 );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );

     p3 = _mm256_xor_si256( p3, x );

     // round 4, 8, 12

     k00 = _mm256_xor_si256( k00, mm256_ror2x256hi_1x32( k12, k13 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p1, k00 ), zero );
     k01 = _mm256_xor_si256( k01, mm256_ror2x256hi_1x32( k13, k00 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
     k02 = _mm256_xor_si256( k02, mm256_ror2x256hi_1x32( k00, k01 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
     k03 = _mm256_xor_si256( k03, mm256_ror2x256hi_1x32( k01, k02 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

     p0 = _mm256_xor_si256( p0, x );

     k10 = _mm256_xor_si256( k10, mm256_ror2x256hi_1x32( k02, k03 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( p3, k10 ), zero );
     k11 = _mm256_xor_si256( k11, mm256_ror2x256hi_1x32( k03, k10 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );
     k12 = _mm256_xor_si256( k12, mm256_ror2x256hi_1x32( k10, k11 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
     k13 = _mm256_xor_si256( k13, mm256_ror2x256hi_1x32( k11, k12 ) );
     x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );

     p2 = _mm256_xor_si256( p2, x );

   }

   // round 13

   k00 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k00, zero ) ), k13  );
   x = mm256_aesenc_2x128( _mm256_xor_si256( p0, k00 ), zero );
   k01 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k01, zero ) ), k00 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k01 ), zero );
   k02 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k02, zero ) ), k01 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k02 ), zero );
   k03 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k03, zero ) ), k02 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k03 ), zero );

   p3 = _mm256_xor_si256( p3, x );

   k10 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k10, zero ) ), k03 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( p2, k10 ), zero );
   k11 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k11, zero ) ), k10 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k11 ), zero );

   k12 = mm256_ror1x32_128( mm256_aesenc_2x128( k12, zero ) );
   k12 = _mm256_xor_si256( k12, _mm256_xor_si256( k11, _mm256_set_epi32(
	       ~ctx->count2, ctx->count3, ctx->count0, ctx->count1,
	       ~ctx->count2, ctx->count3, ctx->count0, ctx->count1 ) ) );

   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k12 ), zero );
   k13 = _mm256_xor_si256( mm256_ror1x32_128(
			             mm256_aesenc_2x128( k13, zero ) ), k12 );
   x = mm256_aesenc_2x128( _mm256_xor_si256( x, k13 ), zero );

   p1 = _mm256_xor_si256( p1, x );

   h[0] = _mm256_xor_si256( h[0], p2 );
   h[1] = _mm256_xor_si256( h[1], p3 );
   h[2] = _mm256_xor_si256( h[2], p0 );
   h[3] = _mm256_xor_si256( h[3], p1 );
}

void shavite512_2way_init( shavite512_2way_context *ctx )
{
   casti_m256i( ctx->h, 0 ) =
            _mm256_set_epi32( IV512[ 3], IV512[ 2], IV512[ 1], IV512[ 0],
                              IV512[ 3], IV512[ 2], IV512[ 1], IV512[ 0] );  
   casti_m256i( ctx->h, 1 ) =
            _mm256_set_epi32( IV512[ 7], IV512[ 6], IV512[ 5], IV512[ 4],
                              IV512[ 7], IV512[ 6], IV512[ 5], IV512[ 4] );
   casti_m256i( ctx->h, 2 ) =
            _mm256_set_epi32( IV512[11], IV512[10], IV512[ 9], IV512[ 8],
                              IV512[11], IV512[10], IV512[ 9], IV512[ 8] );
   casti_m256i( ctx->h, 3 ) =
            _mm256_set_epi32( IV512[15], IV512[14], IV512[13], IV512[12],
                              IV512[15], IV512[14], IV512[13], IV512[12] );
   ctx->ptr    = 0;
   ctx->count0 = 0;
   ctx->count1 = 0;
   ctx->count2 = 0;
   ctx->count3 = 0;
}

void shavite512_2way_update( shavite512_2way_context *ctx, const void *data,
                             size_t len )
{
   unsigned char *buf = ctx->buf;
   size_t         ptr = ctx->ptr;

   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof ctx->buf) - ptr;
      if ( clen > len << 1 )
         clen = len << 1;
      memcpy( buf + ptr, data, clen );
      data = (const unsigned char *)data + clen;
      ptr += clen;
      len -= clen >> 1;
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
         c512_2way( ctx, buf );
         ptr = 0;
      }
   }
   ctx->ptr = ptr;
}

void shavite512_2way_close( shavite512_2way_context *ctx, void *dst )
{
    unsigned char *buf;
    union 
    {
       uint32_t u32[4];
       uint16_t u16[8];
    } count;

    buf = ctx->buf;
    uint32_t vp = ctx->ptr>>5;

    // Terminating byte then zero pad
    casti_m256i( buf, vp++ ) = _mm256_set_epi32( 0,0,0,0x80, 0,0,0,0x80 );

    // Zero pad full vectors up to count
    for ( ; vp < 6; vp++ )      
        casti_m256i( buf, vp ) = m256_zero;

    // Count = { 0, 16, 64, 80 }. Outsize = 16 u32 = 512 bits = 0x0200
    // Count is misaligned to 16 bits and straddles a vector.
    // Use u32 overlay to stage then u16 to load buf.
    count.u32[0] = ctx->count0 += (ctx->ptr << 2);  // ptr/2 * 8
    count.u32[1] = ctx->count1;
    count.u32[2] = ctx->count2;
    count.u32[3] = ctx->count3;

    casti_m256i( buf, 6 ) = _mm256_set_epi16( count.u16[0], 0,0,0,0,0,0,0,
		                              count.u16[0], 0,0,0,0,0,0,0 );
    casti_m256i( buf, 7 ) = _mm256_set_epi16(
		    0x0200      , count.u16[7], count.u16[6], count.u16[5],
		    count.u16[4], count.u16[3], count.u16[2], count.u16[1],
                    0x0200      , count.u16[7], count.u16[6], count.u16[5],
                    count.u16[4], count.u16[3], count.u16[2], count.u16[1] );

    c512_2way( ctx, buf);

    casti_m256i( dst, 0 ) = casti_m256i( ctx->h, 0 );
    casti_m256i( dst, 1 ) = casti_m256i( ctx->h, 1 );
    casti_m256i( dst, 2 ) = casti_m256i( ctx->h, 2 );
    casti_m256i( dst, 3 ) = casti_m256i( ctx->h, 3 );
}

void shavite512_2way_update_close( shavite512_2way_context *ctx, void *dst,
                                   const void *data, size_t len )
{
   unsigned char *buf = ctx->buf;
   size_t         ptr = ctx->ptr;

   // process full blocks and load buf with remainder.
   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof ctx->buf) - ptr;
      if ( clen > len << 1 )
         clen = len << 1;
      memcpy( buf + ptr, data, clen );
      data = (const unsigned char *)data + clen;
      ptr += clen;
      len -= (clen >> 1);
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
         c512_2way( ctx, buf );
         ptr = 0;
      }
   }

   uint32_t vp = ptr>>5;
   // Count = { 0, 16, 64, 80 }. Outsize = 16 u32 = 512 bits = 0x0200
   // Count is misaligned to 16 bits and straddles 2 vectors.
   // Use u32 overlay to stage then u16 to load buf.
   union
   {
      uint32_t u32[4];
      uint16_t u16[8];
   } count;

   count.u32[0] = ctx->count0 += (ptr << 2);  // ptr/2 * 8
   count.u32[1] = ctx->count1;
   count.u32[2] = ctx->count2;
   count.u32[3] = ctx->count3;

   if ( vp == 0 )    // empty buf, xevan.
   { 
      casti_m256i( buf, 0 ) = _mm256_set_epi32( 0,0,0,0x80, 0,0,0,0x80 );
      memset_zero_256( (__m256i*)buf + 1, 5 );
      ctx->count0 = ctx->count1 = ctx->count2 = ctx->count3 = 0;
   }
   else     // half full buf, everyone else.
   {
      casti_m256i( buf, vp++ ) = _mm256_set_epi32( 0,0,0,0x80, 0,0,0,0x80 );
      memset_zero_256( (__m256i*)buf + vp, 6 - vp );
   }

   casti_m256i( buf, 6 ) = _mm256_set_epi16( count.u16[0], 0,0,0,0,0,0,0,
                                             count.u16[0], 0,0,0,0,0,0,0 );
   casti_m256i( buf, 7 ) = _mm256_set_epi16(
                   0x0200      , count.u16[7], count.u16[6], count.u16[5],
                   count.u16[4], count.u16[3], count.u16[2], count.u16[1],
                   0x0200      , count.u16[7], count.u16[6], count.u16[5],
                   count.u16[4], count.u16[3], count.u16[2], count.u16[1] );

   c512_2way( ctx, buf);

   casti_m256i( dst, 0 ) = casti_m256i( ctx->h, 0 );
   casti_m256i( dst, 1 ) = casti_m256i( ctx->h, 1 );
   casti_m256i( dst, 2 ) = casti_m256i( ctx->h, 2 );
   casti_m256i( dst, 3 ) = casti_m256i( ctx->h, 3 );
}

#endif // AVX2
