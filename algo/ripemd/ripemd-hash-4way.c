#include "ripemd-hash-4way.h"

#if defined(__SSE4_2__)

#include <stddef.h>
#include <string.h>

/*
static const uint32_t IV[5] =
{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
*/

/*
 * Round constants for RIPEMD-160.
 */

#define K11  0x0000000000000000
#define K12  0x5A8279995A827999
#define K13  0x6ED9EBA16ED9EBA1
#define K14  0x8F1BBCDC8F1BBCDC
#define K15  0xA953FD4EA953FD4E

#define K21  0x50A28BE650A28BE6
#define K22  0x5C4DD1245C4DD124
#define K23  0x6D703EF36D703EF3
#define K24  0x7A6D76E97A6D76E9
#define K25  0x0000000000000000

// RIPEMD-160 4 way

#define F1(x, y, z) \
   _mm_xor_si128( _mm_xor_si128( x, y ), z )

#define F2(x, y, z) \
   _mm_xor_si128( _mm_and_si128( _mm_xor_si128( y, z ), x ), z )

#define F3(x, y, z) \
   _mm_xor_si128( _mm_or_si128( x, mm128_not( y ) ), z )

#define F4(x, y, z) \
   _mm_xor_si128( _mm_and_si128( _mm_xor_si128( x, y ), z ), y )

#define F5(x, y, z) \
   _mm_xor_si128( x, _mm_or_si128( y, mm128_not( z ) ) )

#define RR(a, b, c, d, e, f, s, r, k) \
do{ \
   a = _mm_add_epi32( mm128_rol_32( _mm_add_epi32( _mm_add_epi32( \
                _mm_add_epi32( a, f( b ,c, d ) ), r ), \
                                 m128_const1_64( k ) ), s ), e ); \
   c = mm128_rol_32( c, 10 );\
} while (0)

#define ROUND1(a, b, c, d, e, f, s, r, k)  \
	RR(a ## 1, b ## 1, c ## 1, d ## 1, e ## 1, f, s, r, K1 ## k)

#define ROUND2(a, b, c, d, e, f, s, r, k)  \
	RR(a ## 2, b ## 2, c ## 2, d ## 2, e ## 2, f, s, r, K2 ## k)

static void ripemd160_4way_round( ripemd160_4way_context *sc )
{
   const __m128i *in = (__m128i*)sc->buf;
   __m128i *h  = (__m128i*)sc->val;
   register __m128i A1, B1, C1, D1, E1;
   register __m128i A2, B2, C2, D2, E2;
   __m128i tmp;

   A1 = A2 = h[0];
   B1 = B2 = h[1];
   C1 = C2 = h[2];
   D1 = D2 = h[3];
   E1 = E2 = h[4];

   ROUND1( A, B, C, D, E, F1, 11, in[ 0], 1 );
   ROUND1( E, A, B, C, D, F1, 14, in[ 1], 1 );
   ROUND1( D, E, A, B, C, F1, 15, in[ 2], 1 );
   ROUND1( C, D, E, A, B, F1, 12, in[ 3], 1 );
   ROUND1( B, C, D, E, A, F1,  5, in[ 4], 1 );
   ROUND1( A, B, C, D, E, F1,  8, in[ 5], 1 );
   ROUND1( E, A, B, C, D, F1,  7, in[ 6], 1 );
   ROUND1( D, E, A, B, C, F1,  9, in[ 7], 1 );
   ROUND1( C, D, E, A, B, F1, 11, in[ 8], 1 );
   ROUND1( B, C, D, E, A, F1, 13, in[ 9], 1 );
   ROUND1( A, B, C, D, E, F1, 14, in[10], 1 );
   ROUND1( E, A, B, C, D, F1, 15, in[11], 1 );
   ROUND1( D, E, A, B, C, F1,  6, in[12], 1 );
   ROUND1( C, D, E, A, B, F1,  7, in[13], 1 );
   ROUND1( B, C, D, E, A, F1,  9, in[14], 1 );
   ROUND1( A, B, C, D, E, F1,  8, in[15], 1 );

   ROUND1( E, A, B, C, D, F2,  7, in[ 7], 2 );
   ROUND1( D, E, A, B, C, F2,  6, in[ 4], 2 );
   ROUND1( C, D, E, A, B, F2,  8, in[13], 2 );
   ROUND1( B, C, D, E, A, F2, 13, in[ 1], 2 );
   ROUND1( A, B, C, D, E, F2, 11, in[10], 2 );
   ROUND1( E, A, B, C, D, F2,  9, in[ 6], 2 );
   ROUND1( D, E, A, B, C, F2,  7, in[15], 2 );
   ROUND1( C, D, E, A, B, F2, 15, in[ 3], 2 );
   ROUND1( B, C, D, E, A, F2,  7, in[12], 2 );
   ROUND1( A, B, C, D, E, F2, 12, in[ 0], 2 );
   ROUND1( E, A, B, C, D, F2, 15, in[ 9], 2 );
   ROUND1( D, E, A, B, C, F2,  9, in[ 5], 2 );
   ROUND1( C, D, E, A, B, F2, 11, in[ 2], 2 );
   ROUND1( B, C, D, E, A, F2,  7, in[14], 2 );
   ROUND1( A, B, C, D, E, F2, 13, in[11], 2 );
   ROUND1( E, A, B, C, D, F2, 12, in[ 8], 2 );

   ROUND1( D, E, A, B, C, F3, 11, in[ 3], 3 );
   ROUND1( C, D, E, A, B, F3, 13, in[10], 3 );
   ROUND1( B, C, D, E, A, F3,  6, in[14], 3 );
   ROUND1( A, B, C, D, E, F3,  7, in[ 4], 3 );
   ROUND1( E, A, B, C, D, F3, 14, in[ 9], 3 );
   ROUND1( D, E, A, B, C, F3,  9, in[15], 3 );
   ROUND1( C, D, E, A, B, F3, 13, in[ 8], 3 );
   ROUND1( B, C, D, E, A, F3, 15, in[ 1], 3 );
   ROUND1( A, B, C, D, E, F3, 14, in[ 2], 3 );
   ROUND1( E, A, B, C, D, F3,  8, in[ 7], 3 );
   ROUND1( D, E, A, B, C, F3, 13, in[ 0], 3 );
   ROUND1( C, D, E, A, B, F3,  6, in[ 6], 3 );
   ROUND1( B, C, D, E, A, F3,  5, in[13], 3 );
   ROUND1( A, B, C, D, E, F3, 12, in[11], 3 );
   ROUND1( E, A, B, C, D, F3,  7, in[ 5], 3 );
   ROUND1( D, E, A, B, C, F3,  5, in[12], 3 );

   ROUND1( C, D, E, A, B, F4, 11, in[ 1], 4 );
   ROUND1( B, C, D, E, A, F4, 12, in[ 9], 4 );
   ROUND1( A, B, C, D, E, F4, 14, in[11], 4 );
   ROUND1( E, A, B, C, D, F4, 15, in[10], 4 );
   ROUND1( D, E, A, B, C, F4, 14, in[ 0], 4 );
   ROUND1( C, D, E, A, B, F4, 15, in[ 8], 4 );
   ROUND1( B, C, D, E, A, F4,  9, in[12], 4 );
   ROUND1( A, B, C, D, E, F4,  8, in[ 4], 4 );
   ROUND1( E, A, B, C, D, F4,  9, in[13], 4 );
   ROUND1( D, E, A, B, C, F4, 14, in[ 3], 4 );
   ROUND1( C, D, E, A, B, F4,  5, in[ 7], 4 );
   ROUND1( B, C, D, E, A, F4,  6, in[15], 4 );
   ROUND1( A, B, C, D, E, F4,  8, in[14], 4 );
   ROUND1( E, A, B, C, D, F4,  6, in[ 5], 4 );
   ROUND1( D, E, A, B, C, F4,  5, in[ 6], 4 );
   ROUND1( C, D, E, A, B, F4, 12, in[ 2], 4 );

   ROUND1( B, C, D, E, A, F5,  9, in[ 4], 5 );
   ROUND1( A, B, C, D, E, F5, 15, in[ 0], 5 );
   ROUND1( E, A, B, C, D, F5,  5, in[ 5], 5 );
   ROUND1( D, E, A, B, C, F5, 11, in[ 9], 5 );
   ROUND1( C, D, E, A, B, F5,  6, in[ 7], 5 );
   ROUND1( B, C, D, E, A, F5,  8, in[12], 5 );
   ROUND1( A, B, C, D, E, F5, 13, in[ 2], 5 );
   ROUND1( E, A, B, C, D, F5, 12, in[10], 5 );
   ROUND1( D, E, A, B, C, F5,  5, in[14], 5 );
   ROUND1( C, D, E, A, B, F5, 12, in[ 1], 5 );
   ROUND1( B, C, D, E, A, F5, 13, in[ 3], 5 );
   ROUND1( A, B, C, D, E, F5, 14, in[ 8], 5 );
   ROUND1( E, A, B, C, D, F5, 11, in[11], 5 );
   ROUND1( D, E, A, B, C, F5,  8, in[ 6], 5 );
   ROUND1( C, D, E, A, B, F5,  5, in[15], 5 );
   ROUND1( B, C, D, E, A, F5,  6, in[13], 5 );

   ROUND2( A, B, C, D, E, F5,  8, in[ 5], 1 );
   ROUND2( E, A, B, C, D, F5,  9, in[14], 1 );
   ROUND2( D, E, A, B, C, F5,  9, in[ 7], 1 );
   ROUND2( C, D, E, A, B, F5, 11, in[ 0], 1 );
   ROUND2( B, C, D, E, A, F5, 13, in[ 9], 1 );
   ROUND2( A, B, C, D, E, F5, 15, in[ 2], 1 );
   ROUND2( E, A, B, C, D, F5, 15, in[11], 1 );
   ROUND2( D, E, A, B, C, F5,  5, in[ 4], 1 );
   ROUND2( C, D, E, A, B, F5,  7, in[13], 1 );
   ROUND2( B, C, D, E, A, F5,  7, in[ 6], 1 );
   ROUND2( A, B, C, D, E, F5,  8, in[15], 1 );
   ROUND2( E, A, B, C, D, F5, 11, in[ 8], 1 );
   ROUND2( D, E, A, B, C, F5, 14, in[ 1], 1 );
   ROUND2( C, D, E, A, B, F5, 14, in[10], 1 );
   ROUND2( B, C, D, E, A, F5, 12, in[ 3], 1 );
   ROUND2( A, B, C, D, E, F5,  6, in[12], 1 );

   ROUND2( E, A, B, C, D, F4,  9, in[ 6], 2 );
   ROUND2( D, E, A, B, C, F4, 13, in[11], 2 );
   ROUND2( C, D, E, A, B, F4, 15, in[ 3], 2 );
   ROUND2( B, C, D, E, A, F4,  7, in[ 7], 2 );
   ROUND2( A, B, C, D, E, F4, 12, in[ 0], 2 );
   ROUND2( E, A, B, C, D, F4,  8, in[13], 2 );
   ROUND2( D, E, A, B, C, F4,  9, in[ 5], 2 );
   ROUND2( C, D, E, A, B, F4, 11, in[10], 2 );
   ROUND2( B, C, D, E, A, F4,  7, in[14], 2 );
   ROUND2( A, B, C, D, E, F4,  7, in[15], 2 );
   ROUND2( E, A, B, C, D, F4, 12, in[ 8], 2 );
   ROUND2( D, E, A, B, C, F4,  7, in[12], 2 );
   ROUND2( C, D, E, A, B, F4,  6, in[ 4], 2 );
   ROUND2( B, C, D, E, A, F4, 15, in[ 9], 2 );
   ROUND2( A, B, C, D, E, F4, 13, in[ 1], 2 );
   ROUND2( E, A, B, C, D, F4, 11, in[ 2], 2 );

   ROUND2( D, E, A, B, C, F3,  9, in[15], 3 );
   ROUND2( C, D, E, A, B, F3,  7, in[ 5], 3 );
   ROUND2( B, C, D, E, A, F3, 15, in[ 1], 3 );
   ROUND2( A, B, C, D, E, F3, 11, in[ 3], 3 );
   ROUND2( E, A, B, C, D, F3,  8, in[ 7], 3 );
   ROUND2( D, E, A, B, C, F3,  6, in[14], 3 );
   ROUND2( C, D, E, A, B, F3,  6, in[ 6], 3 );
   ROUND2( B, C, D, E, A, F3, 14, in[ 9], 3 );
   ROUND2( A, B, C, D, E, F3, 12, in[11], 3 );
   ROUND2( E, A, B, C, D, F3, 13, in[ 8], 3 );
   ROUND2( D, E, A, B, C, F3,  5, in[12], 3 );
   ROUND2( C, D, E, A, B, F3, 14, in[ 2], 3 );
   ROUND2( B, C, D, E, A, F3, 13, in[10], 3 );
   ROUND2( A, B, C, D, E, F3, 13, in[ 0], 3 );
   ROUND2( E, A, B, C, D, F3,  7, in[ 4], 3 );
   ROUND2( D, E, A, B, C, F3,  5, in[13], 3 );

   ROUND2( C, D, E, A, B, F2, 15, in[ 8], 4 );
   ROUND2( B, C, D, E, A, F2,  5, in[ 6], 4 );
   ROUND2( A, B, C, D, E, F2,  8, in[ 4], 4 );
   ROUND2( E, A, B, C, D, F2, 11, in[ 1], 4 );
   ROUND2( D, E, A, B, C, F2, 14, in[ 3], 4 );
   ROUND2( C, D, E, A, B, F2, 14, in[11], 4 );
   ROUND2( B, C, D, E, A, F2,  6, in[15], 4 );
   ROUND2( A, B, C, D, E, F2, 14, in[ 0], 4 );
   ROUND2( E, A, B, C, D, F2,  6, in[ 5], 4 );
   ROUND2( D, E, A, B, C, F2,  9, in[12], 4 );
   ROUND2( C, D, E, A, B, F2, 12, in[ 2], 4 );
   ROUND2( B, C, D, E, A, F2,  9, in[13], 4 );
   ROUND2( A, B, C, D, E, F2, 12, in[ 9], 4 );
   ROUND2( E, A, B, C, D, F2,  5, in[ 7], 4 );
   ROUND2( D, E, A, B, C, F2, 15, in[10], 4 );
   ROUND2( C, D, E, A, B, F2,  8, in[14], 4 );

   ROUND2( B, C, D, E, A, F1,  8, in[12], 5 );
   ROUND2( A, B, C, D, E, F1,  5, in[15], 5 );
   ROUND2( E, A, B, C, D, F1, 12, in[10], 5 );
   ROUND2( D, E, A, B, C, F1,  9, in[ 4], 5 );
   ROUND2( C, D, E, A, B, F1, 12, in[ 1], 5 );
   ROUND2( B, C, D, E, A, F1,  5, in[ 5], 5 );
   ROUND2( A, B, C, D, E, F1, 14, in[ 8], 5 );
   ROUND2( E, A, B, C, D, F1,  6, in[ 7], 5 );
   ROUND2( D, E, A, B, C, F1,  8, in[ 6], 5 );
   ROUND2( C, D, E, A, B, F1, 13, in[ 2], 5 );
   ROUND2( B, C, D, E, A, F1,  6, in[13], 5 );
   ROUND2( A, B, C, D, E, F1,  5, in[14], 5 );
   ROUND2( E, A, B, C, D, F1, 15, in[ 0], 5 );
   ROUND2( D, E, A, B, C, F1, 13, in[ 3], 5 );
   ROUND2( C, D, E, A, B, F1, 11, in[ 9], 5 );
   ROUND2( B, C, D, E, A, F1, 11, in[11], 5 );

   tmp =  _mm_add_epi32( _mm_add_epi32( h[1], C1 ), D2 );
   h[1] = _mm_add_epi32( _mm_add_epi32( h[2], D1 ), E2 );
   h[2] = _mm_add_epi32( _mm_add_epi32( h[3], E1 ), A2 );
   h[3] = _mm_add_epi32( _mm_add_epi32( h[4], A1 ), B2 );
   h[4] = _mm_add_epi32( _mm_add_epi32( h[0], B1 ), C2 );
   h[0] = tmp;
}

void ripemd160_4way_init( ripemd160_4way_context *sc )
{
   sc->val[0] = m128_const1_64( 0x6745230167452301 );
   sc->val[1] = m128_const1_64( 0xEFCDAB89EFCDAB89 );
   sc->val[2] = m128_const1_64( 0x98BADCFE98BADCFE );
   sc->val[3] = m128_const1_64( 0x1032547610325476 );
   sc->val[4] = m128_const1_64( 0xC3D2E1F0C3D2E1F0 );
   sc->count_high = sc->count_low = 0;
}

void ripemd160_4way_update( ripemd160_4way_context *sc, const void *data,
                            size_t len )
{
   __m128i *vdata = (__m128i*)data;
   size_t ptr;
   const int block_size = 64;

   ptr = (unsigned)sc->count_low & (block_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = block_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_128( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == block_size )
      {
         ripemd160_4way_round( sc );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void ripemd160_4way_close( ripemd160_4way_context  *sc, void *dst )
{
   unsigned ptr, u;
   uint32_t low, high;
   const int block_size = 64;
   const int pad = block_size - 8;

   ptr = (unsigned)sc->count_low & ( block_size - 1U);
   sc->buf[ ptr>>2 ] = _mm_set1_epi32( 0x80 );
   ptr += 4;

   if ( ptr > pad )
   {
       memset_zero_128( sc->buf + (ptr>>2), (block_size - ptr) >> 2 );
       ripemd160_4way_round( sc );
       memset_zero_128( sc->buf, pad>>2 );
   }
   else
       memset_zero_128( sc->buf + (ptr>>2), (pad - ptr) >> 2 );
        
    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;
    sc->buf[  pad>>2      ] = _mm_set1_epi32( low  );
    sc->buf[ (pad>>2) + 1 ] = _mm_set1_epi32( high );
    ripemd160_4way_round( sc );
    for (u = 0; u < 5; u ++)
        casti_m128i( dst, u ) = sc->val[u];
}

#endif

#if defined(__AVX2__)

// Ripemd-160 8 way

#define F8W_1(x, y, z) \
   _mm256_xor_si256( _mm256_xor_si256( x, y ), z )

#define F8W_2(x, y, z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( y, z ), x ), z )

#define F8W_3(x, y, z) \
   _mm256_xor_si256( _mm256_or_si256( x, mm256_not( y ) ), z )

#define F8W_4(x, y, z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( x, y ), z ), y )

#define F8W_5(x, y, z) \
   _mm256_xor_si256( x, _mm256_or_si256( y, mm256_not( z ) ) )

#define RR_8W(a, b, c, d, e, f, s, r, k) \
do{ \
   a = _mm256_add_epi32( mm256_rol_32( _mm256_add_epi32( _mm256_add_epi32( \
                _mm256_add_epi32( a, f( b ,c, d ) ), r ), \
                                 m256_const1_64( k ) ), s ), e ); \
   c = mm256_rol_32( c, 10 );\
} while (0)
    
#define ROUND1_8W(a, b, c, d, e, f, s, r, k)  \
        RR_8W(a ## 1, b ## 1, c ## 1, d ## 1, e ## 1, f, s, r, K1 ## k)

#define ROUND2_8W(a, b, c, d, e, f, s, r, k)  \
        RR_8W(a ## 2, b ## 2, c ## 2, d ## 2, e ## 2, f, s, r, K2 ## k)

static void ripemd160_8way_round( ripemd160_8way_context *sc )
{
   const __m256i *in = (__m256i*)sc->buf;
   __m256i *h  = (__m256i*)sc->val;
   register __m256i A1, B1, C1, D1, E1;
   register __m256i A2, B2, C2, D2, E2;
   __m256i tmp;

   A1 = A2 = h[0];
   B1 = B2 = h[1];
   C1 = C2 = h[2];
   D1 = D2 = h[3];
   E1 = E2 = h[4];

   ROUND1_8W( A, B, C, D, E, F8W_1, 11, in[ 0], 1 );
   ROUND1_8W( E, A, B, C, D, F8W_1, 14, in[ 1], 1 );
   ROUND1_8W( D, E, A, B, C, F8W_1, 15, in[ 2], 1 );
   ROUND1_8W( C, D, E, A, B, F8W_1, 12, in[ 3], 1 );
   ROUND1_8W( B, C, D, E, A, F8W_1,  5, in[ 4], 1 );
   ROUND1_8W( A, B, C, D, E, F8W_1,  8, in[ 5], 1 );
   ROUND1_8W( E, A, B, C, D, F8W_1,  7, in[ 6], 1 );
   ROUND1_8W( D, E, A, B, C, F8W_1,  9, in[ 7], 1 );
   ROUND1_8W( C, D, E, A, B, F8W_1, 11, in[ 8], 1 );
   ROUND1_8W( B, C, D, E, A, F8W_1, 13, in[ 9], 1 );
   ROUND1_8W( A, B, C, D, E, F8W_1, 14, in[10], 1 );
   ROUND1_8W( E, A, B, C, D, F8W_1, 15, in[11], 1 );
   ROUND1_8W( D, E, A, B, C, F8W_1,  6, in[12], 1 );
   ROUND1_8W( C, D, E, A, B, F8W_1,  7, in[13], 1 );
   ROUND1_8W( B, C, D, E, A, F8W_1,  9, in[14], 1 );
   ROUND1_8W( A, B, C, D, E, F8W_1,  8, in[15], 1 );

   ROUND1_8W( E, A, B, C, D, F8W_2,  7, in[ 7], 2 );
   ROUND1_8W( D, E, A, B, C, F8W_2,  6, in[ 4], 2 );
   ROUND1_8W( C, D, E, A, B, F8W_2,  8, in[13], 2 );
   ROUND1_8W( B, C, D, E, A, F8W_2, 13, in[ 1], 2 );
   ROUND1_8W( A, B, C, D, E, F8W_2, 11, in[10], 2 );
   ROUND1_8W( E, A, B, C, D, F8W_2,  9, in[ 6], 2 );
   ROUND1_8W( D, E, A, B, C, F8W_2,  7, in[15], 2 );
   ROUND1_8W( C, D, E, A, B, F8W_2, 15, in[ 3], 2 );
   ROUND1_8W( B, C, D, E, A, F8W_2,  7, in[12], 2 );
   ROUND1_8W( A, B, C, D, E, F8W_2, 12, in[ 0], 2 );
   ROUND1_8W( E, A, B, C, D, F8W_2, 15, in[ 9], 2 );
   ROUND1_8W( D, E, A, B, C, F8W_2,  9, in[ 5], 2 );
   ROUND1_8W( C, D, E, A, B, F8W_2, 11, in[ 2], 2 );
   ROUND1_8W( B, C, D, E, A, F8W_2,  7, in[14], 2 );
   ROUND1_8W( A, B, C, D, E, F8W_2, 13, in[11], 2 );
   ROUND1_8W( E, A, B, C, D, F8W_2, 12, in[ 8], 2 );

   ROUND1_8W( D, E, A, B, C, F8W_3, 11, in[ 3], 3 );
   ROUND1_8W( C, D, E, A, B, F8W_3, 13, in[10], 3 );
   ROUND1_8W( B, C, D, E, A, F8W_3,  6, in[14], 3 );
   ROUND1_8W( A, B, C, D, E, F8W_3,  7, in[ 4], 3 );
   ROUND1_8W( E, A, B, C, D, F8W_3, 14, in[ 9], 3 );
   ROUND1_8W( D, E, A, B, C, F8W_3,  9, in[15], 3 );
   ROUND1_8W( C, D, E, A, B, F8W_3, 13, in[ 8], 3 );
   ROUND1_8W( B, C, D, E, A, F8W_3, 15, in[ 1], 3 );
   ROUND1_8W( A, B, C, D, E, F8W_3, 14, in[ 2], 3 );
   ROUND1_8W( E, A, B, C, D, F8W_3,  8, in[ 7], 3 );
   ROUND1_8W( D, E, A, B, C, F8W_3, 13, in[ 0], 3 );
   ROUND1_8W( C, D, E, A, B, F8W_3,  6, in[ 6], 3 );
   ROUND1_8W( B, C, D, E, A, F8W_3,  5, in[13], 3 );
   ROUND1_8W( A, B, C, D, E, F8W_3, 12, in[11], 3 );
   ROUND1_8W( E, A, B, C, D, F8W_3,  7, in[ 5], 3 );
   ROUND1_8W( D, E, A, B, C, F8W_3,  5, in[12], 3 );

   ROUND1_8W( C, D, E, A, B, F8W_4, 11, in[ 1], 4 );
   ROUND1_8W( B, C, D, E, A, F8W_4, 12, in[ 9], 4 );
   ROUND1_8W( A, B, C, D, E, F8W_4, 14, in[11], 4 );
   ROUND1_8W( E, A, B, C, D, F8W_4, 15, in[10], 4 );
   ROUND1_8W( D, E, A, B, C, F8W_4, 14, in[ 0], 4 );
   ROUND1_8W( C, D, E, A, B, F8W_4, 15, in[ 8], 4 );
   ROUND1_8W( B, C, D, E, A, F8W_4,  9, in[12], 4 );
   ROUND1_8W( A, B, C, D, E, F8W_4,  8, in[ 4], 4 );
   ROUND1_8W( E, A, B, C, D, F8W_4,  9, in[13], 4 );
   ROUND1_8W( D, E, A, B, C, F8W_4, 14, in[ 3], 4 );
   ROUND1_8W( C, D, E, A, B, F8W_4,  5, in[ 7], 4 );
   ROUND1_8W( B, C, D, E, A, F8W_4,  6, in[15], 4 );
   ROUND1_8W( A, B, C, D, E, F8W_4,  8, in[14], 4 );
   ROUND1_8W( E, A, B, C, D, F8W_4,  6, in[ 5], 4 );
   ROUND1_8W( D, E, A, B, C, F8W_4,  5, in[ 6], 4 );
   ROUND1_8W( C, D, E, A, B, F8W_4, 12, in[ 2], 4 );

   ROUND1_8W( B, C, D, E, A, F8W_5,  9, in[ 4], 5 );
   ROUND1_8W( A, B, C, D, E, F8W_5, 15, in[ 0], 5 );
   ROUND1_8W( E, A, B, C, D, F8W_5,  5, in[ 5], 5 );
   ROUND1_8W( D, E, A, B, C, F8W_5, 11, in[ 9], 5 );
   ROUND1_8W( C, D, E, A, B, F8W_5,  6, in[ 7], 5 );
   ROUND1_8W( B, C, D, E, A, F8W_5,  8, in[12], 5 );
   ROUND1_8W( A, B, C, D, E, F8W_5, 13, in[ 2], 5 );
   ROUND1_8W( E, A, B, C, D, F8W_5, 12, in[10], 5 );
   ROUND1_8W( D, E, A, B, C, F8W_5,  5, in[14], 5 );
   ROUND1_8W( C, D, E, A, B, F8W_5, 12, in[ 1], 5 );
   ROUND1_8W( B, C, D, E, A, F8W_5, 13, in[ 3], 5 );
   ROUND1_8W( A, B, C, D, E, F8W_5, 14, in[ 8], 5 );
   ROUND1_8W( E, A, B, C, D, F8W_5, 11, in[11], 5 );
   ROUND1_8W( D, E, A, B, C, F8W_5,  8, in[ 6], 5 );
   ROUND1_8W( C, D, E, A, B, F8W_5,  5, in[15], 5 );
   ROUND1_8W( B, C, D, E, A, F8W_5,  6, in[13], 5 );

   ROUND2_8W( A, B, C, D, E, F8W_5,  8, in[ 5], 1 );
   ROUND2_8W( E, A, B, C, D, F8W_5,  9, in[14], 1 );
   ROUND2_8W( D, E, A, B, C, F8W_5,  9, in[ 7], 1 );
   ROUND2_8W( C, D, E, A, B, F8W_5, 11, in[ 0], 1 );
   ROUND2_8W( B, C, D, E, A, F8W_5, 13, in[ 9], 1 );
   ROUND2_8W( A, B, C, D, E, F8W_5, 15, in[ 2], 1 );
   ROUND2_8W( E, A, B, C, D, F8W_5, 15, in[11], 1 );
   ROUND2_8W( D, E, A, B, C, F8W_5,  5, in[ 4], 1 );
   ROUND2_8W( C, D, E, A, B, F8W_5,  7, in[13], 1 );
   ROUND2_8W( B, C, D, E, A, F8W_5,  7, in[ 6], 1 );
   ROUND2_8W( A, B, C, D, E, F8W_5,  8, in[15], 1 );
   ROUND2_8W( E, A, B, C, D, F8W_5, 11, in[ 8], 1 );
   ROUND2_8W( D, E, A, B, C, F8W_5, 14, in[ 1], 1 );
   ROUND2_8W( C, D, E, A, B, F8W_5, 14, in[10], 1 );
   ROUND2_8W( B, C, D, E, A, F8W_5, 12, in[ 3], 1 );
   ROUND2_8W( A, B, C, D, E, F8W_5,  6, in[12], 1 );

   ROUND2_8W( E, A, B, C, D, F8W_4,  9, in[ 6], 2 );
   ROUND2_8W( D, E, A, B, C, F8W_4, 13, in[11], 2 );
   ROUND2_8W( C, D, E, A, B, F8W_4, 15, in[ 3], 2 );
   ROUND2_8W( B, C, D, E, A, F8W_4,  7, in[ 7], 2 );
   ROUND2_8W( A, B, C, D, E, F8W_4, 12, in[ 0], 2 );
   ROUND2_8W( E, A, B, C, D, F8W_4,  8, in[13], 2 );
   ROUND2_8W( D, E, A, B, C, F8W_4,  9, in[ 5], 2 );
   ROUND2_8W( C, D, E, A, B, F8W_4, 11, in[10], 2 );
   ROUND2_8W( B, C, D, E, A, F8W_4,  7, in[14], 2 );
   ROUND2_8W( A, B, C, D, E, F8W_4,  7, in[15], 2 );
   ROUND2_8W( E, A, B, C, D, F8W_4, 12, in[ 8], 2 );
   ROUND2_8W( D, E, A, B, C, F8W_4,  7, in[12], 2 );
   ROUND2_8W( C, D, E, A, B, F8W_4,  6, in[ 4], 2 );
   ROUND2_8W( B, C, D, E, A, F8W_4, 15, in[ 9], 2 );
   ROUND2_8W( A, B, C, D, E, F8W_4, 13, in[ 1], 2 );
   ROUND2_8W( E, A, B, C, D, F8W_4, 11, in[ 2], 2 );

   ROUND2_8W( D, E, A, B, C, F8W_3,  9, in[15], 3 );
   ROUND2_8W( C, D, E, A, B, F8W_3,  7, in[ 5], 3 );
   ROUND2_8W( B, C, D, E, A, F8W_3, 15, in[ 1], 3 );
   ROUND2_8W( A, B, C, D, E, F8W_3, 11, in[ 3], 3 );
   ROUND2_8W( E, A, B, C, D, F8W_3,  8, in[ 7], 3 );
   ROUND2_8W( D, E, A, B, C, F8W_3,  6, in[14], 3 );
   ROUND2_8W( C, D, E, A, B, F8W_3,  6, in[ 6], 3 );
   ROUND2_8W( B, C, D, E, A, F8W_3, 14, in[ 9], 3 );
   ROUND2_8W( A, B, C, D, E, F8W_3, 12, in[11], 3 );
   ROUND2_8W( E, A, B, C, D, F8W_3, 13, in[ 8], 3 );
   ROUND2_8W( D, E, A, B, C, F8W_3,  5, in[12], 3 );
   ROUND2_8W( C, D, E, A, B, F8W_3, 14, in[ 2], 3 );
   ROUND2_8W( B, C, D, E, A, F8W_3, 13, in[10], 3 );
   ROUND2_8W( A, B, C, D, E, F8W_3, 13, in[ 0], 3 );
   ROUND2_8W( E, A, B, C, D, F8W_3,  7, in[ 4], 3 );
   ROUND2_8W( D, E, A, B, C, F8W_3,  5, in[13], 3 );

   ROUND2_8W( C, D, E, A, B, F8W_2, 15, in[ 8], 4 );
   ROUND2_8W( B, C, D, E, A, F8W_2,  5, in[ 6], 4 );
   ROUND2_8W( A, B, C, D, E, F8W_2,  8, in[ 4], 4 );
   ROUND2_8W( E, A, B, C, D, F8W_2, 11, in[ 1], 4 );
   ROUND2_8W( D, E, A, B, C, F8W_2, 14, in[ 3], 4 );
   ROUND2_8W( C, D, E, A, B, F8W_2, 14, in[11], 4 );
   ROUND2_8W( B, C, D, E, A, F8W_2,  6, in[15], 4 );
   ROUND2_8W( A, B, C, D, E, F8W_2, 14, in[ 0], 4 );
   ROUND2_8W( E, A, B, C, D, F8W_2,  6, in[ 5], 4 );
   ROUND2_8W( D, E, A, B, C, F8W_2,  9, in[12], 4 );
   ROUND2_8W( C, D, E, A, B, F8W_2, 12, in[ 2], 4 );
   ROUND2_8W( B, C, D, E, A, F8W_2,  9, in[13], 4 );
   ROUND2_8W( A, B, C, D, E, F8W_2, 12, in[ 9], 4 );
   ROUND2_8W( E, A, B, C, D, F8W_2,  5, in[ 7], 4 );
   ROUND2_8W( D, E, A, B, C, F8W_2, 15, in[10], 4 );
   ROUND2_8W( C, D, E, A, B, F8W_2,  8, in[14], 4 );

   ROUND2_8W( B, C, D, E, A, F8W_1,  8, in[12], 5 );
   ROUND2_8W( A, B, C, D, E, F8W_1,  5, in[15], 5 );
   ROUND2_8W( E, A, B, C, D, F8W_1, 12, in[10], 5 );
   ROUND2_8W( D, E, A, B, C, F8W_1,  9, in[ 4], 5 );
   ROUND2_8W( C, D, E, A, B, F8W_1, 12, in[ 1], 5 );
   ROUND2_8W( B, C, D, E, A, F8W_1,  5, in[ 5], 5 );
   ROUND2_8W( A, B, C, D, E, F8W_1, 14, in[ 8], 5 );
   ROUND2_8W( E, A, B, C, D, F8W_1,  6, in[ 7], 5 );
   ROUND2_8W( D, E, A, B, C, F8W_1,  8, in[ 6], 5 );
   ROUND2_8W( C, D, E, A, B, F8W_1, 13, in[ 2], 5 );
   ROUND2_8W( B, C, D, E, A, F8W_1,  6, in[13], 5 );
   ROUND2_8W( A, B, C, D, E, F8W_1,  5, in[14], 5 );
   ROUND2_8W( E, A, B, C, D, F8W_1, 15, in[ 0], 5 );
   ROUND2_8W( D, E, A, B, C, F8W_1, 13, in[ 3], 5 );
   ROUND2_8W( C, D, E, A, B, F8W_1, 11, in[ 9], 5 );
   ROUND2_8W( B, C, D, E, A, F8W_1, 11, in[11], 5 );

   tmp =  _mm256_add_epi32( _mm256_add_epi32( h[1], C1 ), D2 );
   h[1] = _mm256_add_epi32( _mm256_add_epi32( h[2], D1 ), E2 );
   h[2] = _mm256_add_epi32( _mm256_add_epi32( h[3], E1 ), A2 );
   h[3] = _mm256_add_epi32( _mm256_add_epi32( h[4], A1 ), B2 );
   h[4] = _mm256_add_epi32( _mm256_add_epi32( h[0], B1 ), C2 );
   h[0] = tmp;
}


void ripemd160_8way_init( ripemd160_8way_context *sc )
{
   sc->val[0] = m256_const1_64( 0x6745230167452301 );
   sc->val[1] = m256_const1_64( 0xEFCDAB89EFCDAB89 );
   sc->val[2] = m256_const1_64( 0x98BADCFE98BADCFE );
   sc->val[3] = m256_const1_64( 0x1032547610325476 );
   sc->val[4] = m256_const1_64( 0xC3D2E1F0C3D2E1F0 );
   sc->count_high = sc->count_low = 0;
}

void ripemd160_8way_update( ripemd160_8way_context *sc, const void *data,
                            size_t len )
{
   __m256i *vdata = (__m256i*)data;
   size_t ptr;
   const int block_size = 64;

   ptr = (unsigned)sc->count_low & (block_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = block_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == block_size )
      {
         ripemd160_8way_round( sc );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void ripemd160_8way_close( ripemd160_8way_context  *sc, void *dst )
{
   unsigned ptr, u;
   uint32_t low, high;
   const int block_size = 64;
   const int pad = block_size - 8;

   ptr = (unsigned)sc->count_low & ( block_size - 1U);
   sc->buf[ ptr>>2 ] = _mm256_set1_epi32( 0x80 );
   ptr += 4;

   if ( ptr > pad )
   {
       memset_zero_256( sc->buf + (ptr>>2), (block_size - ptr) >> 2 );
       ripemd160_8way_round( sc );
       memset_zero_256( sc->buf, pad>>2 );
   }
   else
       memset_zero_256( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;
    sc->buf[  pad>>2      ] = _mm256_set1_epi32( low  );
    sc->buf[ (pad>>2) + 1 ] = _mm256_set1_epi32( high );
    ripemd160_8way_round( sc );
    for (u = 0; u < 5; u ++)
        casti_m256i( dst, u ) = sc->val[u];
}

#endif // __AVX2__

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

//  RIPEMD-160 16 way


#define F16W_1(x, y, z) \
   _mm512_xor_si512( _mm512_xor_si512( x, y ), z )

#define F16W_2(x, y, z) \
   _mm512_xor_si512( _mm512_and_si512( _mm512_xor_si512( y, z ), x ), z )

#define F16W_3(x, y, z) \
   _mm512_xor_si512( _mm512_or_si512( x, mm512_not( y ) ), z )

#define F16W_4(x, y, z) \
   _mm512_xor_si512( _mm512_and_si512( _mm512_xor_si512( x, y ), z ), y )

#define F16W_5(x, y, z) \
   _mm512_xor_si512( x, _mm512_or_si512( y, mm512_not( z ) ) )

#define RR_16W(a, b, c, d, e, f, s, r, k) \
do{ \
   a = _mm512_add_epi32( mm512_rol_32( _mm512_add_epi32( _mm512_add_epi32( \
                _mm512_add_epi32( a, f( b ,c, d ) ), r ), \
                                 m512_const1_64( k ) ), s ), e ); \
   c = mm512_rol_32( c, 10 );\
} while (0)

#define ROUND1_16W(a, b, c, d, e, f, s, r, k)  \
        RR_16W(a ## 1, b ## 1, c ## 1, d ## 1, e ## 1, f, s, r, K1 ## k)

#define ROUND2_16W(a, b, c, d, e, f, s, r, k)  \
        RR_16W(a ## 2, b ## 2, c ## 2, d ## 2, e ## 2, f, s, r, K2 ## k)

static void ripemd160_16way_round( ripemd160_16way_context *sc )
{
   const __m512i *in = (__m512i*)sc->buf;
   __m512i *h  = (__m512i*)sc->val;
   register __m512i A1, B1, C1, D1, E1;
   register __m512i A2, B2, C2, D2, E2;
   __m512i tmp;

   A1 = A2 = h[0];
   B1 = B2 = h[1];
   C1 = C2 = h[2];
   D1 = D2 = h[3];
   E1 = E2 = h[4];

   ROUND1_16W( A, B, C, D, E, F16W_1, 11, in[ 0], 1 );
   ROUND1_16W( E, A, B, C, D, F16W_1, 14, in[ 1], 1 );
   ROUND1_16W( D, E, A, B, C, F16W_1, 15, in[ 2], 1 );
   ROUND1_16W( C, D, E, A, B, F16W_1, 12, in[ 3], 1 );
   ROUND1_16W( B, C, D, E, A, F16W_1,  5, in[ 4], 1 );
   ROUND1_16W( A, B, C, D, E, F16W_1,  8, in[ 5], 1 );
   ROUND1_16W( E, A, B, C, D, F16W_1,  7, in[ 6], 1 );
   ROUND1_16W( D, E, A, B, C, F16W_1,  9, in[ 7], 1 );
   ROUND1_16W( C, D, E, A, B, F16W_1, 11, in[ 8], 1 );
   ROUND1_16W( B, C, D, E, A, F16W_1, 13, in[ 9], 1 );
   ROUND1_16W( A, B, C, D, E, F16W_1, 14, in[10], 1 );
   ROUND1_16W( E, A, B, C, D, F16W_1, 15, in[11], 1 );
   ROUND1_16W( D, E, A, B, C, F16W_1,  6, in[12], 1 );
   ROUND1_16W( C, D, E, A, B, F16W_1,  7, in[13], 1 );
   ROUND1_16W( B, C, D, E, A, F16W_1,  9, in[14], 1 );
   ROUND1_16W( A, B, C, D, E, F16W_1,  8, in[15], 1 );

   ROUND1_16W( E, A, B, C, D, F16W_2,  7, in[ 7], 2 );
   ROUND1_16W( D, E, A, B, C, F16W_2,  6, in[ 4], 2 );
   ROUND1_16W( C, D, E, A, B, F16W_2,  8, in[13], 2 );
   ROUND1_16W( B, C, D, E, A, F16W_2, 13, in[ 1], 2 );
   ROUND1_16W( A, B, C, D, E, F16W_2, 11, in[10], 2 );
   ROUND1_16W( E, A, B, C, D, F16W_2,  9, in[ 6], 2 );
   ROUND1_16W( D, E, A, B, C, F16W_2,  7, in[15], 2 );
   ROUND1_16W( C, D, E, A, B, F16W_2, 15, in[ 3], 2 );
   ROUND1_16W( B, C, D, E, A, F16W_2,  7, in[12], 2 );
   ROUND1_16W( A, B, C, D, E, F16W_2, 12, in[ 0], 2 );
   ROUND1_16W( E, A, B, C, D, F16W_2, 15, in[ 9], 2 );
   ROUND1_16W( D, E, A, B, C, F16W_2,  9, in[ 5], 2 );
   ROUND1_16W( C, D, E, A, B, F16W_2, 11, in[ 2], 2 );
   ROUND1_16W( B, C, D, E, A, F16W_2,  7, in[14], 2 );
   ROUND1_16W( A, B, C, D, E, F16W_2, 13, in[11], 2 );
   ROUND1_16W( E, A, B, C, D, F16W_2, 12, in[ 8], 2 );

   ROUND1_16W( D, E, A, B, C, F16W_3, 11, in[ 3], 3 );
   ROUND1_16W( C, D, E, A, B, F16W_3, 13, in[10], 3 );
   ROUND1_16W( B, C, D, E, A, F16W_3,  6, in[14], 3 );
   ROUND1_16W( A, B, C, D, E, F16W_3,  7, in[ 4], 3 );
   ROUND1_16W( E, A, B, C, D, F16W_3, 14, in[ 9], 3 );
   ROUND1_16W( D, E, A, B, C, F16W_3,  9, in[15], 3 );
   ROUND1_16W( C, D, E, A, B, F16W_3, 13, in[ 8], 3 );
   ROUND1_16W( B, C, D, E, A, F16W_3, 15, in[ 1], 3 );
   ROUND1_16W( A, B, C, D, E, F16W_3, 14, in[ 2], 3 );
   ROUND1_16W( E, A, B, C, D, F16W_3,  8, in[ 7], 3 );
   ROUND1_16W( D, E, A, B, C, F16W_3, 13, in[ 0], 3 );
   ROUND1_16W( C, D, E, A, B, F16W_3,  6, in[ 6], 3 );
   ROUND1_16W( B, C, D, E, A, F16W_3,  5, in[13], 3 );
   ROUND1_16W( A, B, C, D, E, F16W_3, 12, in[11], 3 );
   ROUND1_16W( E, A, B, C, D, F16W_3,  7, in[ 5], 3 );
   ROUND1_16W( D, E, A, B, C, F16W_3,  5, in[12], 3 );

   ROUND1_16W( C, D, E, A, B, F16W_4, 11, in[ 1], 4 );
   ROUND1_16W( B, C, D, E, A, F16W_4, 12, in[ 9], 4 );
   ROUND1_16W( A, B, C, D, E, F16W_4, 14, in[11], 4 );
   ROUND1_16W( E, A, B, C, D, F16W_4, 15, in[10], 4 );
   ROUND1_16W( D, E, A, B, C, F16W_4, 14, in[ 0], 4 );
   ROUND1_16W( C, D, E, A, B, F16W_4, 15, in[ 8], 4 );
   ROUND1_16W( B, C, D, E, A, F16W_4,  9, in[12], 4 );
   ROUND1_16W( A, B, C, D, E, F16W_4,  8, in[ 4], 4 );
   ROUND1_16W( E, A, B, C, D, F16W_4,  9, in[13], 4 );
   ROUND1_16W( D, E, A, B, C, F16W_4, 14, in[ 3], 4 );
   ROUND1_16W( C, D, E, A, B, F16W_4,  5, in[ 7], 4 );
   ROUND1_16W( B, C, D, E, A, F16W_4,  6, in[15], 4 );
   ROUND1_16W( A, B, C, D, E, F16W_4,  8, in[14], 4 );
   ROUND1_16W( E, A, B, C, D, F16W_4,  6, in[ 5], 4 );
   ROUND1_16W( D, E, A, B, C, F16W_4,  5, in[ 6], 4 );
   ROUND1_16W( C, D, E, A, B, F16W_4, 12, in[ 2], 4 );

   ROUND1_16W( B, C, D, E, A, F16W_5,  9, in[ 4], 5 );
   ROUND1_16W( A, B, C, D, E, F16W_5, 15, in[ 0], 5 );
   ROUND1_16W( E, A, B, C, D, F16W_5,  5, in[ 5], 5 );
   ROUND1_16W( D, E, A, B, C, F16W_5, 11, in[ 9], 5 );
   ROUND1_16W( C, D, E, A, B, F16W_5,  6, in[ 7], 5 );
   ROUND1_16W( B, C, D, E, A, F16W_5,  8, in[12], 5 );
   ROUND1_16W( A, B, C, D, E, F16W_5, 13, in[ 2], 5 );
   ROUND1_16W( E, A, B, C, D, F16W_5, 12, in[10], 5 );
   ROUND1_16W( D, E, A, B, C, F16W_5,  5, in[14], 5 );
   ROUND1_16W( C, D, E, A, B, F16W_5, 12, in[ 1], 5 );
   ROUND1_16W( B, C, D, E, A, F16W_5, 13, in[ 3], 5 );
   ROUND1_16W( A, B, C, D, E, F16W_5, 14, in[ 8], 5 );
   ROUND1_16W( E, A, B, C, D, F16W_5, 11, in[11], 5 );
   ROUND1_16W( D, E, A, B, C, F16W_5,  8, in[ 6], 5 );
   ROUND1_16W( C, D, E, A, B, F16W_5,  5, in[15], 5 );
   ROUND1_16W( B, C, D, E, A, F16W_5,  6, in[13], 5 );

   ROUND2_16W( A, B, C, D, E, F16W_5,  8, in[ 5], 1 );
   ROUND2_16W( E, A, B, C, D, F16W_5,  9, in[14], 1 );
   ROUND2_16W( D, E, A, B, C, F16W_5,  9, in[ 7], 1 );
   ROUND2_16W( C, D, E, A, B, F16W_5, 11, in[ 0], 1 );
   ROUND2_16W( B, C, D, E, A, F16W_5, 13, in[ 9], 1 );
   ROUND2_16W( A, B, C, D, E, F16W_5, 15, in[ 2], 1 );
   ROUND2_16W( E, A, B, C, D, F16W_5, 15, in[11], 1 );
   ROUND2_16W( D, E, A, B, C, F16W_5,  5, in[ 4], 1 );
   ROUND2_16W( C, D, E, A, B, F16W_5,  7, in[13], 1 );
   ROUND2_16W( B, C, D, E, A, F16W_5,  7, in[ 6], 1 );
   ROUND2_16W( A, B, C, D, E, F16W_5,  8, in[15], 1 );
   ROUND2_16W( E, A, B, C, D, F16W_5, 11, in[ 8], 1 );
   ROUND2_16W( D, E, A, B, C, F16W_5, 14, in[ 1], 1 );
   ROUND2_16W( C, D, E, A, B, F16W_5, 14, in[10], 1 );
   ROUND2_16W( B, C, D, E, A, F16W_5, 12, in[ 3], 1 );
   ROUND2_16W( A, B, C, D, E, F16W_5,  6, in[12], 1 );

   ROUND2_16W( E, A, B, C, D, F16W_4,  9, in[ 6], 2 );
   ROUND2_16W( D, E, A, B, C, F16W_4, 13, in[11], 2 );
   ROUND2_16W( C, D, E, A, B, F16W_4, 15, in[ 3], 2 );
   ROUND2_16W( B, C, D, E, A, F16W_4,  7, in[ 7], 2 );
   ROUND2_16W( A, B, C, D, E, F16W_4, 12, in[ 0], 2 );
   ROUND2_16W( E, A, B, C, D, F16W_4,  8, in[13], 2 );
   ROUND2_16W( D, E, A, B, C, F16W_4,  9, in[ 5], 2 );
   ROUND2_16W( C, D, E, A, B, F16W_4, 11, in[10], 2 );
   ROUND2_16W( B, C, D, E, A, F16W_4,  7, in[14], 2 );
   ROUND2_16W( A, B, C, D, E, F16W_4,  7, in[15], 2 );
   ROUND2_16W( E, A, B, C, D, F16W_4, 12, in[ 8], 2 );
   ROUND2_16W( D, E, A, B, C, F16W_4,  7, in[12], 2 );
   ROUND2_16W( C, D, E, A, B, F16W_4,  6, in[ 4], 2 );
   ROUND2_16W( B, C, D, E, A, F16W_4, 15, in[ 9], 2 );
   ROUND2_16W( A, B, C, D, E, F16W_4, 13, in[ 1], 2 );
   ROUND2_16W( E, A, B, C, D, F16W_4, 11, in[ 2], 2 );

   ROUND2_16W( D, E, A, B, C, F16W_3,  9, in[15], 3 );
   ROUND2_16W( C, D, E, A, B, F16W_3,  7, in[ 5], 3 );
   ROUND2_16W( B, C, D, E, A, F16W_3, 15, in[ 1], 3 );
   ROUND2_16W( A, B, C, D, E, F16W_3, 11, in[ 3], 3 );
   ROUND2_16W( E, A, B, C, D, F16W_3,  8, in[ 7], 3 );
   ROUND2_16W( D, E, A, B, C, F16W_3,  6, in[14], 3 );
   ROUND2_16W( C, D, E, A, B, F16W_3,  6, in[ 6], 3 );
   ROUND2_16W( B, C, D, E, A, F16W_3, 14, in[ 9], 3 );
   ROUND2_16W( A, B, C, D, E, F16W_3, 12, in[11], 3 );
   ROUND2_16W( E, A, B, C, D, F16W_3, 13, in[ 8], 3 );
   ROUND2_16W( D, E, A, B, C, F16W_3,  5, in[12], 3 );
   ROUND2_16W( C, D, E, A, B, F16W_3, 14, in[ 2], 3 );
   ROUND2_16W( B, C, D, E, A, F16W_3, 13, in[10], 3 );
   ROUND2_16W( A, B, C, D, E, F16W_3, 13, in[ 0], 3 );
   ROUND2_16W( E, A, B, C, D, F16W_3,  7, in[ 4], 3 );
   ROUND2_16W( D, E, A, B, C, F16W_3,  5, in[13], 3 );

   ROUND2_16W( C, D, E, A, B, F16W_2, 15, in[ 8], 4 );
   ROUND2_16W( B, C, D, E, A, F16W_2,  5, in[ 6], 4 );
   ROUND2_16W( A, B, C, D, E, F16W_2,  8, in[ 4], 4 );
   ROUND2_16W( E, A, B, C, D, F16W_2, 11, in[ 1], 4 );
   ROUND2_16W( D, E, A, B, C, F16W_2, 14, in[ 3], 4 );
   ROUND2_16W( C, D, E, A, B, F16W_2, 14, in[11], 4 );
   ROUND2_16W( B, C, D, E, A, F16W_2,  6, in[15], 4 );
   ROUND2_16W( A, B, C, D, E, F16W_2, 14, in[ 0], 4 );
   ROUND2_16W( E, A, B, C, D, F16W_2,  6, in[ 5], 4 );
   ROUND2_16W( D, E, A, B, C, F16W_2,  9, in[12], 4 );
   ROUND2_16W( C, D, E, A, B, F16W_2, 12, in[ 2], 4 );
   ROUND2_16W( B, C, D, E, A, F16W_2,  9, in[13], 4 );
   ROUND2_16W( A, B, C, D, E, F16W_2, 12, in[ 9], 4 );
   ROUND2_16W( E, A, B, C, D, F16W_2,  5, in[ 7], 4 );
   ROUND2_16W( D, E, A, B, C, F16W_2, 15, in[10], 4 );
   ROUND2_16W( C, D, E, A, B, F16W_2,  8, in[14], 4 );

   ROUND2_16W( B, C, D, E, A, F16W_1,  8, in[12], 5 );
   ROUND2_16W( A, B, C, D, E, F16W_1,  5, in[15], 5 );
   ROUND2_16W( E, A, B, C, D, F16W_1, 12, in[10], 5 );
   ROUND2_16W( D, E, A, B, C, F16W_1,  9, in[ 4], 5 );
   ROUND2_16W( C, D, E, A, B, F16W_1, 12, in[ 1], 5 );
   ROUND2_16W( B, C, D, E, A, F16W_1,  5, in[ 5], 5 );
   ROUND2_16W( A, B, C, D, E, F16W_1, 14, in[ 8], 5 );
   ROUND2_16W( E, A, B, C, D, F16W_1,  6, in[ 7], 5 );
   ROUND2_16W( D, E, A, B, C, F16W_1,  8, in[ 6], 5 );
   ROUND2_16W( C, D, E, A, B, F16W_1, 13, in[ 2], 5 );
   ROUND2_16W( B, C, D, E, A, F16W_1,  6, in[13], 5 );
   ROUND2_16W( A, B, C, D, E, F16W_1,  5, in[14], 5 );
   ROUND2_16W( E, A, B, C, D, F16W_1, 15, in[ 0], 5 );
   ROUND2_16W( D, E, A, B, C, F16W_1, 13, in[ 3], 5 );
   ROUND2_16W( C, D, E, A, B, F16W_1, 11, in[ 9], 5 );
   ROUND2_16W( B, C, D, E, A, F16W_1, 11, in[11], 5 );

   tmp =  _mm512_add_epi32( _mm512_add_epi32( h[1], C1 ), D2 );
   h[1] = _mm512_add_epi32( _mm512_add_epi32( h[2], D1 ), E2 );
   h[2] = _mm512_add_epi32( _mm512_add_epi32( h[3], E1 ), A2 );
   h[3] = _mm512_add_epi32( _mm512_add_epi32( h[4], A1 ), B2 );
   h[4] = _mm512_add_epi32( _mm512_add_epi32( h[0], B1 ), C2 );
   h[0] = tmp;
}

void ripemd160_16way_init( ripemd160_16way_context *sc )
{
   sc->val[0] = m512_const1_64( 0x6745230167452301 );
   sc->val[1] = m512_const1_64( 0xEFCDAB89EFCDAB89 );
   sc->val[2] = m512_const1_64( 0x98BADCFE98BADCFE );
   sc->val[3] = m512_const1_64( 0x1032547610325476 );
   sc->val[4] = m512_const1_64( 0xC3D2E1F0C3D2E1F0 );
   sc->count_high = sc->count_low = 0;
}

void ripemd160_16way_update( ripemd160_16way_context *sc, const void *data,
                      size_t len )
{
   __m512i *vdata = (__m512i*)data;
   size_t ptr;
   const int block_size = 64;

   ptr = (unsigned)sc->count_low & (block_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = block_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( sc->buf + (ptr>>2), vdata, clen>>2 );
      vdata = vdata + (clen>>2);
      ptr += clen;
      len -= clen;
      if ( ptr == block_size )
      {
         ripemd160_16way_round( sc );
         ptr = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high++;
   }
}

void ripemd160_16way_close( ripemd160_16way_context  *sc, void *dst )
{
   unsigned ptr, u;
   uint32_t low, high;
   const int block_size = 64;
   const int pad = block_size - 8;

   ptr = (unsigned)sc->count_low & ( block_size - 1U);
   sc->buf[ ptr>>2 ] = m512_const1_32( 0x80 );
   ptr += 4;

   if ( ptr > pad )
   {
       memset_zero_512( sc->buf + (ptr>>2), (block_size - ptr) >> 2 );
       ripemd160_16way_round( sc );
       memset_zero_512( sc->buf, pad>>2 );
   }
   else
       memset_zero_512( sc->buf + (ptr>>2), (pad - ptr) >> 2 );

    low = sc->count_low;
    high = (sc->count_high << 3) | (low >> 29);
    low = low << 3;
    sc->buf[  pad>>2      ] = _mm512_set1_epi32( low  );
    sc->buf[ (pad>>2) + 1 ] = _mm512_set1_epi32( high );
    ripemd160_16way_round( sc );
    for (u = 0; u < 5; u ++)
        casti_m512i( dst, u ) = sc->val[u];
}

#endif  // AVX512
