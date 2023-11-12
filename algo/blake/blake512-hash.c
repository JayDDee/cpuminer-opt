#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "blake512-hash.h"

// Blake-512 common

static const uint64_t BLAKE512_IV[8] __attribute__ ((aligned (32))) =
{
  0x6A09E667F3BCC908, 0xBB67AE8584CAA73B,
  0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
  0x510E527FADE682D1, 0x9B05688C2B3E6C1F,
  0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};

/*
static const uint64_t salt_zero_big[4] = { 0, 0, 0, 0 };

static const unsigned sigma[16][16] = {
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
	{ 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
	{ 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
	{  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
	{ 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
	{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
	{ 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
	{  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
	{  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
	{  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 }
};
*/
/*
static const uint64_t CB[16] __attribute__ ((aligned (32))) =
{
   0x243F6A8885A308D3, 0x13198A2E03707344,
   0xA4093822299F31D0, 0x082EFA98EC4E6C89,
   0x452821E638D01377, 0xBE5466CF34E90C6C,
   0xC0AC29B7C97C50DD, 0x3F84D5B5B5470917,
   0x9216D5D98979FB1B, 0xD1310BA698DFB5AC,
   0x2FFD72DBD01ADFB7, 0xB8E1AFED6A267E96,
   0xBA7C9045F12C7F99, 0x24A19947B3916CF7,
   0x0801F2E2858EFC16, 0x636920D871574E69
}
*/

#define Z00   0
#define Z01   1
#define Z02   2
#define Z03   3
#define Z04   4
#define Z05   5
#define Z06   6
#define Z07   7
#define Z08   8
#define Z09   9
#define Z0A   A
#define Z0B   B
#define Z0C   C
#define Z0D   D
#define Z0E   E
#define Z0F   F

#define Z10   E
#define Z11   A
#define Z12   4
#define Z13   8
#define Z14   9
#define Z15   F
#define Z16   D
#define Z17   6
#define Z18   1
#define Z19   C
#define Z1A   0
#define Z1B   2
#define Z1C   B
#define Z1D   7
#define Z1E   5
#define Z1F   3

#define Z20   B
#define Z21   8
#define Z22   C
#define Z23   0
#define Z24   5
#define Z25   2
#define Z26   F
#define Z27   D
#define Z28   A
#define Z29   E
#define Z2A   3
#define Z2B   6
#define Z2C   7
#define Z2D   1
#define Z2E   9
#define Z2F   4

#define Z30   7
#define Z31   9
#define Z32   3
#define Z33   1
#define Z34   D
#define Z35   C
#define Z36   B
#define Z37   E
#define Z38   2
#define Z39   6
#define Z3A   5
#define Z3B   A
#define Z3C   4
#define Z3D   0
#define Z3E   F
#define Z3F   8

#define Z40   9
#define Z41   0
#define Z42   5
#define Z43   7
#define Z44   2
#define Z45   4
#define Z46   A
#define Z47   F
#define Z48   E
#define Z49   1
#define Z4A   B
#define Z4B   C
#define Z4C   6
#define Z4D   8
#define Z4E   3
#define Z4F   D

#define Z50   2
#define Z51   C
#define Z52   6
#define Z53   A
#define Z54   0
#define Z55   B
#define Z56   8
#define Z57   3
#define Z58   4
#define Z59   D
#define Z5A   7
#define Z5B   5
#define Z5C   F
#define Z5D   E
#define Z5E   1
#define Z5F   9

#define Z60   C
#define Z61   5
#define Z62   1
#define Z63   F
#define Z64   E
#define Z65   D
#define Z66   4
#define Z67   A
#define Z68   0
#define Z69   7
#define Z6A   6
#define Z6B   3
#define Z6C   9
#define Z6D   2
#define Z6E   8
#define Z6F   B

#define Z70   D
#define Z71   B
#define Z72   7
#define Z73   E
#define Z74   C
#define Z75   1
#define Z76   3
#define Z77   9
#define Z78   5
#define Z79   0
#define Z7A   F
#define Z7B   4
#define Z7C   8
#define Z7D   6
#define Z7E   2
#define Z7F   A

#define Z80   6
#define Z81   F
#define Z82   E
#define Z83   9
#define Z84   B
#define Z85   3
#define Z86   0
#define Z87   8
#define Z88   C
#define Z89   2
#define Z8A   D
#define Z8B   7
#define Z8C   1
#define Z8D   4
#define Z8E   A
#define Z8F   5

#define Z90   A
#define Z91   2
#define Z92   8
#define Z93   4
#define Z94   7
#define Z95   6
#define Z96   1
#define Z97   5
#define Z98   F
#define Z99   B
#define Z9A   9
#define Z9B   E
#define Z9C   3
#define Z9D   C
#define Z9E   D
#define Z9F   0

#define Mx(r, i)    Mx_(Z ## r ## i)
#define Mx_(n)      Mx__(n)
#define Mx__(n)     M ## n

#define CBx(r, i)   CBx_(Z ## r ## i)
#define CBx_(n)     CBx__(n)
#define CBx__(n)    CB ## n

#define CB0   0x243F6A8885A308D3
#define CB1   0x13198A2E03707344
#define CB2   0xA4093822299F31D0
#define CB3   0x082EFA98EC4E6C89
#define CB4   0x452821E638D01377
#define CB5   0xBE5466CF34E90C6C
#define CB6   0xC0AC29B7C97C50DD
#define CB7   0x3F84D5B5B5470917
#define CB8   0x9216D5D98979FB1B
#define CB9   0xD1310BA698DFB5AC
#define CBA   0x2FFD72DBD01ADFB7
#define CBB   0xB8E1AFED6A267E96
#define CBC   0xBA7C9045F12C7F99
#define CBD   0x24A19947B3916CF7
#define CBE   0x0801F2E2858EFC16
#define CBF   0x636920D871574E69


///////////////////////////////////////////////////////
//
//          Blake-512 1 way SSE2, AVX2, NEON

#if defined(__AVX2__)

#define BLAKE512_ROUND( r ) \
{ \
   V0 = _mm256_add_epi64( V0, _mm256_add_epi64( V1, \
                           _mm256_set_epi64x( CBx( r, 7 ) ^ Mx( r, 6 ), \
                                              CBx( r, 5 ) ^ Mx( r, 4 ), \
                                              CBx( r, 3 ) ^ Mx( r, 2 ), \
                                              CBx( r, 1 ) ^ Mx( r, 0 ) ) ) ); \
   V3 = mm256_ror_64( _mm256_xor_si256( V3, V0 ), 32 ); \
   V2 = _mm256_add_epi64( V2, V3 ); \
   V1 = mm256_ror_64( _mm256_xor_si256( V1, V2 ), 25 ); \
   V0 = _mm256_add_epi64( V0, _mm256_add_epi64( V1, \
                           _mm256_set_epi64x( CBx( r, 6 ) ^ Mx( r, 7 ), \
                                              CBx( r, 4 ) ^ Mx( r, 5 ), \
                                              CBx( r, 2 ) ^ Mx( r, 3 ), \
                                              CBx( r, 0 ) ^ Mx( r, 1 ) ) ) ); \
   V3 = mm256_ror_64( _mm256_xor_si256( V3, V0 ), 16 ); \
   V2 = _mm256_add_epi64( V2, V3 ); \
   V1 = mm256_ror_64( _mm256_xor_si256( V1, V2 ), 11 ); \
   V0 = mm256_shufll_64( V0 ); \
   V3 = mm256_swap_128( V3 ); \
   V2 = mm256_shuflr_64( V2 ); \
   V0 = _mm256_add_epi64( V0, _mm256_add_epi64( V1, \
                           _mm256_set_epi64x( CBx( r, D ) ^ Mx( r, C ), \
                                              CBx( r, B ) ^ Mx( r, A ), \
                                              CBx( r, 9 ) ^ Mx( r, 8 ), \
                                              CBx( r, F ) ^ Mx( r, E ) ) ) ); \
   V3 = mm256_ror_64( _mm256_xor_si256( V3, V0 ), 32 ); \
   V2 = _mm256_add_epi64( V2, V3 ); \
   V1 = mm256_ror_64( _mm256_xor_si256( V1, V2 ), 25 ); \
   V0 = _mm256_add_epi64( V0, _mm256_add_epi64( V1, \
                           _mm256_set_epi64x( CBx( r, C ) ^ Mx( r, D ), \
                                              CBx( r, A ) ^ Mx( r, B ), \
                                              CBx( r, 8 ) ^ Mx( r, 9 ), \
                                              CBx( r, E ) ^ Mx( r, F ) ) ) ); \
   V3 = mm256_ror_64( _mm256_xor_si256( V3, V0 ), 16 ); \
   V2 = _mm256_add_epi64( V2, V3 ); \
   V1 = mm256_ror_64( _mm256_xor_si256( V1, V2 ), 11 ); \
   V0 = mm256_shuflr_64( V0 ); \
   V3 = mm256_swap_128( V3 ); \
   V2 = mm256_shufll_64( V2 ); \
}

void blake512_transform( uint64_t *H, const uint64_t *buf, const uint64_t T0,
                         const uint64_t T1 )
{
   __m256i V0, V1, V2, V3;
   uint64_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF;
   
   V0 = casti_m256i( H, 0 );
   V1 = casti_m256i( H, 1 );
   V2 = _mm256_set_epi64x( CB3, CB2, CB1, CB0 );
   V3 = _mm256_set_epi64x( CB7 ^ T1, CB6 ^ T1, CB5 ^ T0, CB4 ^ T0 );

   M0 = bswap_64( buf[ 0] );
   M1 = bswap_64( buf[ 1] );
   M2 = bswap_64( buf[ 2] );
   M3 = bswap_64( buf[ 3] );
   M4 = bswap_64( buf[ 4] );
   M5 = bswap_64( buf[ 5] );
   M6 = bswap_64( buf[ 6] );
   M7 = bswap_64( buf[ 7] );
   M8 = bswap_64( buf[ 8] );
   M9 = bswap_64( buf[ 9] );
   MA = bswap_64( buf[10] );
   MB = bswap_64( buf[11] );
   MC = bswap_64( buf[12] );
   MD = bswap_64( buf[13] );
   ME = bswap_64( buf[14] );
   MF = bswap_64( buf[15] );
   
   BLAKE512_ROUND( 0 );
   BLAKE512_ROUND( 1 );
   BLAKE512_ROUND( 2 );
   BLAKE512_ROUND( 3 );
   BLAKE512_ROUND( 4 );
   BLAKE512_ROUND( 5 );
   BLAKE512_ROUND( 6 );
   BLAKE512_ROUND( 7 );
   BLAKE512_ROUND( 8 );
   BLAKE512_ROUND( 9 );
   BLAKE512_ROUND( 0 );
   BLAKE512_ROUND( 1 );
   BLAKE512_ROUND( 2 );
   BLAKE512_ROUND( 3 );
   BLAKE512_ROUND( 4 );
   BLAKE512_ROUND( 5 );
   
   casti_m256i( H, 0 ) = mm256_xor3( casti_m256i( H, 0 ), V0, V2 );
   casti_m256i( H, 1 ) = mm256_xor3( casti_m256i( H, 1 ), V1, V3 );
}

#else

#define BLAKE512_G( r,  Va, Vb, Vc, Vd, Sa, Sb, Sc, Sd ) \
{ \
   Va = v128_add64( Va, v128_add64( Vb, \
                            v128_set64( CBx( r, Sd ) ^ Mx( r, Sc ), \
                                        CBx( r, Sb ) ^ Mx( r, Sa ) ) ) ); \
   Vd = v128_ror64( v128_xor( Vd, Va ), 32 ); \
   Vc = v128_add64( Vc, Vd ); \
   Vb = v128_ror64( v128_xor( Vb, Vc ), 25 ); \
\
   Va = v128_add64( Va, v128_add64( Vb, \
                            v128_set64( CBx( r, Sc ) ^ Mx( r, Sd ), \
                                        CBx( r, Sa ) ^ Mx( r, Sb ) ) ) ); \
   Vd = v128_ror64( v128_xor( Vd, Va ), 16 ); \
   Vc = v128_add64( Vc, Vd ); \
   Vb = v128_ror64( v128_xor( Vb, Vc ), 11 ); \
}

#define BLAKE512_ROUND( R ) \
{ \
   v128_t V32, V23, V67, V76; \
   BLAKE512_G( R, V[0], V[2], V[4], V[6], 0, 1, 2, 3 ); \
   BLAKE512_G( R, V[1], V[3], V[5], V[7], 4, 5, 6, 7 ); \
   V32 = v128_alignr64( V[3], V[2], 1 ); \
   V23 = v128_alignr64( V[2], V[3], 1 ); \
   V67 = v128_alignr64( V[6], V[7], 1 ); \
   V76 = v128_alignr64( V[7], V[6], 1 ); \
   BLAKE512_G( R, V[0], V32, V[5], V67, 8, 9, A, B ); \
   BLAKE512_G( R, V[1], V23, V[4], V76, C, D, E, F ); \
   V[2] = v128_alignr64( V32, V23, 1 ); \
   V[3] = v128_alignr64( V23, V32, 1 ); \
   V[6] = v128_alignr64( V76, V67, 1 ); \
   V[7] = v128_alignr64( V67, V76, 1 ); \
}

void blake512_transform( uint64_t *H, const uint64_t *buf,
                         const uint64_t T0, const uint64_t T1 )
{
   v128_t V[8];
   uint64_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF;

   V[0] = casti_v128u64( H, 0 );
   V[1] = casti_v128u64( H, 1 );
   V[2] = casti_v128u64( H, 2 );
   V[3] = casti_v128u64( H, 3 );
   V[4] = v128_set64( CB1, CB0 );
   V[5] = v128_set64( CB3, CB2 );
   V[6] = v128_set64( CB5 ^ T0, CB4 ^ T0 );
   V[7] = v128_set64( CB7 ^ T1, CB6 ^ T1 );

   M0 = bswap_64( buf[ 0] );
   M1 = bswap_64( buf[ 1] );
   M2 = bswap_64( buf[ 2] );
   M3 = bswap_64( buf[ 3] );
   M4 = bswap_64( buf[ 4] );
   M5 = bswap_64( buf[ 5] );
   M6 = bswap_64( buf[ 6] );
   M7 = bswap_64( buf[ 7] );
   M8 = bswap_64( buf[ 8] );
   M9 = bswap_64( buf[ 9] );
   MA = bswap_64( buf[10] );
   MB = bswap_64( buf[11] );
   MC = bswap_64( buf[12] );
   MD = bswap_64( buf[13] );
   ME = bswap_64( buf[14] );
   MF = bswap_64( buf[15] );
   
   BLAKE512_ROUND( 0 );
   BLAKE512_ROUND( 1 );
   BLAKE512_ROUND( 2 );
   BLAKE512_ROUND( 3 );
   BLAKE512_ROUND( 4 );
   BLAKE512_ROUND( 5 );
   BLAKE512_ROUND( 6 );
   BLAKE512_ROUND( 7 );
   BLAKE512_ROUND( 8 );
   BLAKE512_ROUND( 9 );
   BLAKE512_ROUND( 0 );
   BLAKE512_ROUND( 1 );
   BLAKE512_ROUND( 2 );
   BLAKE512_ROUND( 3 );
   BLAKE512_ROUND( 4 );
   BLAKE512_ROUND( 5 );

   casti_v128u64( H, 0 ) = v128_xor3( casti_v128u64( H, 0 ), V[0], V[4] );
   casti_v128u64( H, 1 ) = v128_xor3( casti_v128u64( H, 1 ), V[1], V[5] );
   casti_v128u64( H, 2 ) = v128_xor3( casti_v128u64( H, 2 ), V[2], V[6] );
   casti_v128u64( H, 3 ) = v128_xor3( casti_v128u64( H, 3 ), V[3], V[7] );
}

#endif

void blake512_init( blake512_context *sc )
{
   memcpy( sc->H, BLAKE512_IV, 8 * sizeof(uint64_t) );
   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

void blake512_update(blake512_context *sc, const void *data, size_t len)
{
   if ( len < (sizeof sc->buf) - sc->ptr )
   {
      memcpy( sc->buf + sc->ptr, data, len );
      sc->ptr += len;
      return;
   }

   while ( len > 0 )
   {
      size_t clen;

      clen = (sizeof sc->buf) - sc->ptr;
      if ( clen > len )  clen = len;
      memcpy( sc->buf + sc->ptr, data, clen );
      sc->ptr += clen;
      data = (const unsigned char *)data + clen;
      len -= clen;
      if ( sc->ptr == sizeof sc->buf )
      {
         if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
            sc->T1 += 1;

         blake512_transform( sc->H, (uint64_t*)sc->buf, sc->T0, sc->T1 );
         sc->ptr = 0;
      }
   }
}

void blake512_close( blake512_context *sc, void *dst )
{
   unsigned char buf[128] __attribute__((aligned(32)));
   size_t ptr, k;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   memcpy( buf, sc->buf, ptr );
   bit_len = ((unsigned)ptr << 3);
   buf[ptr] = 0x80;
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00;
      sc->T1 = 0xFFFFFFFFFFFFFFFF;
   }
   else if ( sc->T0 == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00 + bit_len;
      sc->T1 -= 1;
   }
   else
      sc->T0 -= 1024 - bit_len;

   if ( bit_len <= 894 )
   {
      memset( buf + ptr + 1, 0, 111 - ptr );
      buf[111] |= 1;
      *((uint64_t*)(buf + 112)) = bswap_64( th );
      *((uint64_t*)(buf + 120)) = bswap_64( tl );
      blake512_update( sc, buf + ptr, 128 - ptr );
   }
   else
   {
      memset( buf + ptr + 1, 0, 127 - ptr );
      blake512_update( sc, buf + ptr, 128 - ptr );
      sc->T0 = 0xFFFFFFFFFFFFFC00;
      sc->T1 = 0xFFFFFFFFFFFFFFFF;
      memset( buf, 0, 112 );
      buf[111] = 1;
      *(uint64_t*)(buf + 112) = bswap_64( th );
      *(uint64_t*)(buf + 120) = bswap_64( tl );
      blake512_update( sc, buf, 128 );
   }
   
   for ( k = 0; k < 8; k ++ )
      ((uint64_t*)dst)[k] = bswap_64( sc->H[k] );
}

void blake512_full( blake512_context *sc, void *dst, const void *data,
                    size_t len )
{
   blake512_init( sc );
   blake512_update( sc, data, len );
   blake512_close( sc, dst );
}

#define READ_STATE64( state ) \
   H0 = (state)->H[0]; \
   H1 = (state)->H[1]; \
   H2 = (state)->H[2]; \
   H3 = (state)->H[3]; \
   H4 = (state)->H[4]; \
   H5 = (state)->H[5]; \
   H6 = (state)->H[6]; \
   H7 = (state)->H[7]; \
   T0 = (state)->T0; \
   T1 = (state)->T1;


#define WRITE_STATE64( state ) \
   (state)->H[0] = H0; \
   (state)->H[1] = H1; \
   (state)->H[2] = H2; \
   (state)->H[3] = H3; \
   (state)->H[4] = H4; \
   (state)->H[5] = H5; \
   (state)->H[6] = H6; \
   (state)->H[7] = H7; \
   (state)->T0 = T0; \
   (state)->T1 = T1;

#if defined(__AVX2__)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

////////////////////////////////////
//
//      Blake-512 8 way AVX512

#define GB_8WAY( m0, m1, c0, c1, a, b, c, d ) \
{ \
   a = _mm512_add_epi64( _mm512_add_epi64( _mm512_xor_si512( \
                 v512_64( c1 ), m0 ), b ), a ); \
   d = mm512_swap64_32( _mm512_xor_si512( d, a ) ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 25 ); \
   a = _mm512_add_epi64( _mm512_add_epi64( _mm512_xor_si512( \
                 v512_64( c0 ), m1 ), b ), a ); \
   d = mm512_ror_64( _mm512_xor_si512( d, a ), 16 ); \
   c = _mm512_add_epi64( c, d ); \
   b = mm512_ror_64( _mm512_xor_si512( b, c ), 11 ); \
}

#define ROUND_B_8WAY( r ) \
{ \
   GB_8WAY(Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC); \
   GB_8WAY(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD); \
   GB_8WAY(Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE); \
   GB_8WAY(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF); \
   GB_8WAY(Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF); \
   GB_8WAY(Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC); \
   GB_8WAY(Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD); \
   GB_8WAY(Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE); \
}

#define DECL_STATE64_8WAY \
   __m512i H0, H1, H2, H3, H4, H5, H6, H7; \
   uint64_t T0, T1;

#define COMPRESS64_8WAY( buf ) \
{ \
  __m512i M0, M1, M2, M3, M4, M5, M6, M7; \
  __m512i M8, M9, MA, MB, MC, MD, ME, MF; \
  __m512i V0, V1, V2, V3, V4, V5, V6, V7; \
  __m512i V8, V9, VA, VB, VC, VD, VE, VF; \
  V0 = H0; \
  V1 = H1; \
  V2 = H2; \
  V3 = H3; \
  V4 = H4; \
  V5 = H5; \
  V6 = H6; \
  V7 = H7; \
  V8 = v512_64( CB0 );  \
  V9 = v512_64( CB1 );  \
  VA = v512_64( CB2 );  \
  VB = v512_64( CB3 );  \
  VC = v512_64( CB4 ^ T0 ); \
  VD = v512_64( CB5 ^ T0 ); \
  VE = v512_64( CB6 ^ T1 ); \
  VF = v512_64( CB7 ^ T1 ); \
  const __m512i shuf_bswap64 = mm512_bcast_m128( v128_set64( \
                                   0x08090a0b0c0d0e0f, 0x0001020304050607 ) ); \
  M0 = _mm512_shuffle_epi8( *(buf+ 0), shuf_bswap64 ); \
  M1 = _mm512_shuffle_epi8( *(buf+ 1), shuf_bswap64 ); \
  M2 = _mm512_shuffle_epi8( *(buf+ 2), shuf_bswap64 ); \
  M3 = _mm512_shuffle_epi8( *(buf+ 3), shuf_bswap64 ); \
  M4 = _mm512_shuffle_epi8( *(buf+ 4), shuf_bswap64 ); \
  M5 = _mm512_shuffle_epi8( *(buf+ 5), shuf_bswap64 ); \
  M6 = _mm512_shuffle_epi8( *(buf+ 6), shuf_bswap64 ); \
  M7 = _mm512_shuffle_epi8( *(buf+ 7), shuf_bswap64 ); \
  M8 = _mm512_shuffle_epi8( *(buf+ 8), shuf_bswap64 ); \
  M9 = _mm512_shuffle_epi8( *(buf+ 9), shuf_bswap64 ); \
  MA = _mm512_shuffle_epi8( *(buf+10), shuf_bswap64 ); \
  MB = _mm512_shuffle_epi8( *(buf+11), shuf_bswap64 ); \
  MC = _mm512_shuffle_epi8( *(buf+12), shuf_bswap64 ); \
  MD = _mm512_shuffle_epi8( *(buf+13), shuf_bswap64 ); \
  ME = _mm512_shuffle_epi8( *(buf+14), shuf_bswap64 ); \
  MF = _mm512_shuffle_epi8( *(buf+15), shuf_bswap64 ); \
  ROUND_B_8WAY(0); \
  ROUND_B_8WAY(1); \
  ROUND_B_8WAY(2); \
  ROUND_B_8WAY(3); \
  ROUND_B_8WAY(4); \
  ROUND_B_8WAY(5); \
  ROUND_B_8WAY(6); \
  ROUND_B_8WAY(7); \
  ROUND_B_8WAY(8); \
  ROUND_B_8WAY(9); \
  ROUND_B_8WAY(0); \
  ROUND_B_8WAY(1); \
  ROUND_B_8WAY(2); \
  ROUND_B_8WAY(3); \
  ROUND_B_8WAY(4); \
  ROUND_B_8WAY(5); \
  H0 = mm512_xor3( V8, V0, H0 ); \
  H1 = mm512_xor3( V9, V1, H1 ); \
  H2 = mm512_xor3( VA, V2, H2 ); \
  H3 = mm512_xor3( VB, V3, H3 ); \
  H4 = mm512_xor3( VC, V4, H4 ); \
  H5 = mm512_xor3( VD, V5, H5 ); \
  H6 = mm512_xor3( VE, V6, H6 ); \
  H7 = mm512_xor3( VF, V7, H7 ); \
}

void blake512_8way_compress( blake_8way_big_context *sc )
{ 
  __m512i M0, M1, M2, M3, M4, M5, M6, M7;
  __m512i M8, M9, MA, MB, MC, MD, ME, MF;
  __m512i V0, V1, V2, V3, V4, V5, V6, V7;
  __m512i V8, V9, VA, VB, VC, VD, VE, VF;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = v512_64( CB0 );
  V9 = v512_64( CB1 );
  VA = v512_64( CB2 );
  VB = v512_64( CB3 );
  VC = v512_64( CB4 ^ sc->T0 );
  VD = v512_64( CB5 ^ sc->T0 );
  VE = v512_64( CB6 ^ sc->T1 );
  VF = v512_64( CB7 ^ sc->T1 );

  const __m512i shuf_bswap64 = mm512_bcast_m128( v128_set64( 
                                   0x08090a0b0c0d0e0f, 0x0001020304050607 ) );

  M0 = _mm512_shuffle_epi8( sc->buf[ 0], shuf_bswap64 );
  M1 = _mm512_shuffle_epi8( sc->buf[ 1], shuf_bswap64 );
  M2 = _mm512_shuffle_epi8( sc->buf[ 2], shuf_bswap64 );
  M3 = _mm512_shuffle_epi8( sc->buf[ 3], shuf_bswap64 );
  M4 = _mm512_shuffle_epi8( sc->buf[ 4], shuf_bswap64 );
  M5 = _mm512_shuffle_epi8( sc->buf[ 5], shuf_bswap64 );
  M6 = _mm512_shuffle_epi8( sc->buf[ 6], shuf_bswap64 );
  M7 = _mm512_shuffle_epi8( sc->buf[ 7], shuf_bswap64 );
  M8 = _mm512_shuffle_epi8( sc->buf[ 8], shuf_bswap64 );
  M9 = _mm512_shuffle_epi8( sc->buf[ 9], shuf_bswap64 );
  MA = _mm512_shuffle_epi8( sc->buf[10], shuf_bswap64 );
  MB = _mm512_shuffle_epi8( sc->buf[11], shuf_bswap64 );
  MC = _mm512_shuffle_epi8( sc->buf[12], shuf_bswap64 );
  MD = _mm512_shuffle_epi8( sc->buf[13], shuf_bswap64 );
  ME = _mm512_shuffle_epi8( sc->buf[14], shuf_bswap64 );
  MF = _mm512_shuffle_epi8( sc->buf[15], shuf_bswap64 );

  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);
  ROUND_B_8WAY(6);
  ROUND_B_8WAY(7);
  ROUND_B_8WAY(8);
  ROUND_B_8WAY(9);
  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);

  sc->H[0] = mm512_xor3( V8, V0, sc->H[0] );
  sc->H[1] = mm512_xor3( V9, V1, sc->H[1] );
  sc->H[2] = mm512_xor3( VA, V2, sc->H[2] );
  sc->H[3] = mm512_xor3( VB, V3, sc->H[3] );
  sc->H[4] = mm512_xor3( VC, V4, sc->H[4] );
  sc->H[5] = mm512_xor3( VD, V5, sc->H[5] );
  sc->H[6] = mm512_xor3( VE, V6, sc->H[6] );
  sc->H[7] = mm512_xor3( VF, V7, sc->H[7] );
}

// won't be used after prehash implemented
void blake512_8way_compress_le( blake_8x64_big_context *sc )
{
  __m512i M0, M1, M2, M3, M4, M5, M6, M7;
  __m512i M8, M9, MA, MB, MC, MD, ME, MF;
  __m512i V0, V1, V2, V3, V4, V5, V6, V7;
  __m512i V8, V9, VA, VB, VC, VD, VE, VF;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = v512_64( CB0 );
  V9 = v512_64( CB1 );
  VA = v512_64( CB2 );
  VB = v512_64( CB3 );
  VC = v512_64( CB4 ^ sc->T0 );
  VD = v512_64( CB5 ^ sc->T0 );
  VE = v512_64( CB6 ^ sc->T1 );
  VF = v512_64( CB7 ^ sc->T1 );

  M0 = sc->buf[ 0];
  M1 = sc->buf[ 1];
  M2 = sc->buf[ 2];
  M3 = sc->buf[ 3];
  M4 = sc->buf[ 4];
  M5 = sc->buf[ 5];
  M6 = sc->buf[ 6];
  M7 = sc->buf[ 7];
  M8 = sc->buf[ 8];
  M9 = sc->buf[ 9];
  MA = sc->buf[10];
  MB = sc->buf[11];
  MC = sc->buf[12];
  MD = sc->buf[13];
  ME = sc->buf[14];
  MF = sc->buf[15];

  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);
  ROUND_B_8WAY(6);
  ROUND_B_8WAY(7);
  ROUND_B_8WAY(8);
  ROUND_B_8WAY(9);
  ROUND_B_8WAY(0);
  ROUND_B_8WAY(1);
  ROUND_B_8WAY(2);
  ROUND_B_8WAY(3);
  ROUND_B_8WAY(4);
  ROUND_B_8WAY(5);

  sc->H[0] = mm512_xor3( V8, V0, sc->H[0] );
  sc->H[1] = mm512_xor3( V9, V1, sc->H[1] );
  sc->H[2] = mm512_xor3( VA, V2, sc->H[2] );
  sc->H[3] = mm512_xor3( VB, V3, sc->H[3] );
  sc->H[4] = mm512_xor3( VC, V4, sc->H[4] );
  sc->H[5] = mm512_xor3( VD, V5, sc->H[5] );
  sc->H[6] = mm512_xor3( VE, V6, sc->H[6] );
  sc->H[7] = mm512_xor3( VF, V7, sc->H[7] );
}

// with final_le forms a full hash in 2 parts from little endian data.
// all variables hard coded for 80 bytes/lane.
void blake512_8x64_prehash_le( blake_8x64_big_context *sc, __m512i *midstate,
                               const void *data )
{
   __m512i V0, V1, V2, V3, V4, V5, V6, V7;
   __m512i V8, V9, VA, VB, VC, VD, VE, VF;

   // initial hash
   casti_m512i( sc->H, 0 ) = v512_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = v512_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = v512_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = v512_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = v512_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = v512_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = v512_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = v512_64( 0x5BE0CD19137E2179 );

   // fill buffer
   memcpy_512( sc->buf, (__m512i*)data, 80>>3 );
   sc->buf[10] = v512_64( 0x8000000000000000ULL );
   sc->buf[11] = 
   sc->buf[12] = m512_zero;
   sc->buf[13] = v512_64( 1 );
   sc->buf[14] = m512_zero;
   sc->buf[15] = v512_64( 80*8 );

   // build working variables
   V0 = sc->H[0];
   V1 = sc->H[1];
   V2 = sc->H[2];
   V3 = sc->H[3];
   V4 = sc->H[4];
   V5 = sc->H[5];
   V6 = sc->H[6];
   V7 = sc->H[7];
   V8 = v512_64( CB0 );
   V9 = v512_64( CB1 );
   VA = v512_64( CB2 );
   VB = v512_64( CB3 );
   VC = v512_64( CB4 ^ 0x280ULL );
   VD = v512_64( CB5 ^ 0x280ULL );
   VE = v512_64( CB6 );
   VF = v512_64( CB7 );

   // round 0
   GB_8WAY( sc->buf[ 0], sc->buf[ 1], CB0, CB1, V0, V4, V8, VC );
   GB_8WAY( sc->buf[ 2], sc->buf[ 3], CB2, CB3, V1, V5, V9, VD );
   GB_8WAY( sc->buf[ 4], sc->buf[ 5], CB4, CB5, V2, V6, VA, VE );
   GB_8WAY( sc->buf[ 6], sc->buf[ 7], CB6, CB7, V3, V7, VB, VF );

   // Do half of G4, skip the nonce
   // GB_8WAY( sc->buf[ 8], sc->buf[ 9], CBx(0, 8), CBx(0, 9), V0, V5, VA, VF );

   V0 = _mm512_add_epi64( _mm512_add_epi64( _mm512_xor_si512( 
                       v512_64( CB9 ), sc->buf[ 8] ), V5 ), V0 ); 
   VF = mm512_swap64_32( _mm512_xor_si512( VF, V0 ) ); 
   VA = _mm512_add_epi64( VA, VF ); 
   V5 = mm512_ror_64( _mm512_xor_si512( V5, VA ), 25 );
   V0 = _mm512_add_epi64( V0, V5 );
   
   GB_8WAY( sc->buf[10], sc->buf[11], CBA, CBB, V1, V6, VB, VC );
   GB_8WAY( sc->buf[12], sc->buf[13], CBC, CBD, V2, V7, V8, VD );
   GB_8WAY( sc->buf[14], sc->buf[15], CBE, CBF, V3, V4, V9, VE );
   
   // round 1
   // G1   
//   GB_8WAY(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD);
   V1 = _mm512_add_epi64( V1, _mm512_xor_si512( v512_64( CB8 ),
           sc->buf[ 4] ) );

   // G2
//   GB_8WAY(Mx(1, 4), Mx(1, 5), CBx(1, 4), CBx(1, 5), V2, V6, VA, VE);
   V2 = _mm512_add_epi64( V2, V6 ); 

   // G3
//   GB_8WAY(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF);
   V3 = _mm512_add_epi64( V3, _mm512_add_epi64( _mm512_xor_si512(
                 v512_64( CB6 ), sc->buf[13] ), V7 ) );

   // save midstate for second part
   midstate[ 0] = V0;
   midstate[ 1] = V1;
   midstate[ 2] = V2;
   midstate[ 3] = V3;
   midstate[ 4] = V4;
   midstate[ 5] = V5;
   midstate[ 6] = V6;
   midstate[ 7] = V7;
   midstate[ 8] = V8;
   midstate[ 9] = V9;
   midstate[10] = VA;
   midstate[11] = VB;
   midstate[12] = VC;
   midstate[13] = VD;
   midstate[14] = VE;
   midstate[15] = VF;
} 

// pick up where we left off, need the nonce now.
void blake512_8x64_final_le( blake_8x64_big_context *sc, void *hash,
                             const __m512i nonce, const __m512i *midstate )
{
   __m512i M0, M1, M2, M3, M4, M5, M6, M7;
   __m512i M8, M9, MA, MB, MC, MD, ME, MF;
   __m512i V0, V1, V2, V3, V4, V5, V6, V7;
   __m512i V8, V9, VA, VB, VC, VD, VE, VF;
   __m512i h[8] __attribute__ ((aligned (64)));

   // Load data with new nonce
   M0 = sc->buf[ 0];
   M1 = sc->buf[ 1];
   M2 = sc->buf[ 2];
   M3 = sc->buf[ 3];
   M4 = sc->buf[ 4];
   M5 = sc->buf[ 5];
   M6 = sc->buf[ 6];
   M7 = sc->buf[ 7];
   M8 = sc->buf[ 8];
   M9 = nonce;
   MA = sc->buf[10];
   MB = sc->buf[11];
   MC = sc->buf[12];
   MD = sc->buf[13];
   ME = sc->buf[14];
   MF = sc->buf[15];

   V0 = midstate[ 0];
   V1 = midstate[ 1];
   V2 = midstate[ 2];
   V3 = midstate[ 3];
   V4 = midstate[ 4];
   V5 = midstate[ 5];
   V6 = midstate[ 6];
   V7 = midstate[ 7];
   V8 = midstate[ 8];
   V9 = midstate[ 9];
   VA = midstate[10];
   VB = midstate[11];
   VC = midstate[12];
   VD = midstate[13];
   VE = midstate[14];
   VF = midstate[15];

   // finish round 0 with the nonce now available 
   V0 = _mm512_add_epi64( V0, _mm512_xor_si512(
                                       v512_64( CB8 ), M9 ) ); 
   VF = mm512_ror_64( _mm512_xor_si512( VF, V0 ), 16 );
   VA = _mm512_add_epi64( VA, VF );
   V5 = mm512_ror_64( _mm512_xor_si512( V5, VA ), 11 );
  
   // Round 1
   // G0
   GB_8WAY(Mx(1, 0), Mx(1, 1), CBx(1, 0), CBx(1, 1), V0, V4, V8, VC);

   // G1
//   GB_8WAY(Mx(1, 2), Mx(1, 3), CBx(1, 2), CBx(1, 3), V1, V5, V9, VD);
//   V1 = _mm512_add_epi64( V1, _mm512_xor_si512( v512_64( c1 ), m0 );

   V1 = _mm512_add_epi64( V1, V5 );   
   VD = mm512_swap64_32( _mm512_xor_si512( VD, V1 ) );
   V9 = _mm512_add_epi64( V9, VD );
   V5 = mm512_ror_64( _mm512_xor_si512( V5, V9 ), 25 );
   V1 = _mm512_add_epi64( V1, _mm512_add_epi64( _mm512_xor_si512(
                 v512_64( CBx(1,2) ), Mx(1,3) ), V5 ) );   
   VD = mm512_ror_64( _mm512_xor_si512( VD, V1 ), 16 );
   V9 = _mm512_add_epi64( V9, VD );
   V5 = mm512_ror_64( _mm512_xor_si512( V5, V9 ), 11 );

   // G2
//   GB_8WAY(Mx(1, 4), Mx(1, 5), CBx(1, 4), CBx(1, 5), V2, V6, VA, VE);
//   V2 = _mm512_add_epi64( V2, V6 );
   V2 = _mm512_add_epi64( V2, _mm512_xor_si512( 
                 v512_64( CBF ), M9 ) );
   VE = mm512_swap64_32( _mm512_xor_si512( VE, V2 ) );
   VA = _mm512_add_epi64( VA, VE );
   V6 = mm512_ror_64( _mm512_xor_si512( V6, VA ), 25 );
   V2 = _mm512_add_epi64( V2, _mm512_add_epi64( _mm512_xor_si512(
                 v512_64( CB9 ), MF ), V6 ) );
   VE = mm512_ror_64( _mm512_xor_si512( VE, V2 ), 16 );
   VA = _mm512_add_epi64( VA, VE );
   V6 = mm512_ror_64( _mm512_xor_si512( V6, VA ), 11 );

   // G3
//   GB_8WAY(Mx(1, 6), Mx(1, 7), CBx(1, 6), CBx(1, 7), V3, V7, VB, VF);
//   V3 = _mm512_add_epi64( V3, _mm512_add_epi64( _mm512_xor_si512( 
//                 v512_64( CBx(1, 7) ), Mx(1, 6) ), V7 ) ); 

   VF = mm512_swap64_32( _mm512_xor_si512( VF, V3 ) ); 
   VB = _mm512_add_epi64( VB, VF ); 
   V7 = mm512_ror_64( _mm512_xor_si512( V7, VB ), 25 );
   V3 = _mm512_add_epi64( V3, _mm512_add_epi64( _mm512_xor_si512(
                 v512_64( CBx(1, 6) ), Mx(1, 7) ), V7 ) ); 
   VF = mm512_ror_64( _mm512_xor_si512( VF, V3 ), 16 ); 
   VB = _mm512_add_epi64( VB, VF ); 
   V7 = mm512_ror_64( _mm512_xor_si512( V7, VB ), 11 );

   // G4, G5, G6, G7
   GB_8WAY(Mx(1, 8), Mx(1, 9), CBx(1, 8), CBx(1, 9), V0, V5, VA, VF);
   GB_8WAY(Mx(1, A), Mx(1, B), CBx(1, A), CBx(1, B), V1, V6, VB, VC);
   GB_8WAY(Mx(1, C), Mx(1, D), CBx(1, C), CBx(1, D), V2, V7, V8, VD);
   GB_8WAY(Mx(1, E), Mx(1, F), CBx(1, E), CBx(1, F), V3, V4, V9, VE);

   // remaining rounds  
   ROUND_B_8WAY(2);
   ROUND_B_8WAY(3);
   ROUND_B_8WAY(4);
   ROUND_B_8WAY(5);
   ROUND_B_8WAY(6);
   ROUND_B_8WAY(7);
   ROUND_B_8WAY(8);
   ROUND_B_8WAY(9);
   ROUND_B_8WAY(0);
   ROUND_B_8WAY(1);
   ROUND_B_8WAY(2);
   ROUND_B_8WAY(3);
   ROUND_B_8WAY(4);
   ROUND_B_8WAY(5);

   h[0] = mm512_xor3( V8, V0, sc->H[0] );
   h[1] = mm512_xor3( V9, V1, sc->H[1] );
   h[2] = mm512_xor3( VA, V2, sc->H[2] );
   h[3] = mm512_xor3( VB, V3, sc->H[3] );
   h[4] = mm512_xor3( VC, V4, sc->H[4] );
   h[5] = mm512_xor3( VD, V5, sc->H[5] );
   h[6] = mm512_xor3( VE, V6, sc->H[6] );
   h[7] = mm512_xor3( VF, V7, sc->H[7] );

   // bswap final hash
   mm512_block_bswap_64( (__m512i*)hash, h );
}

void blake512_8x64_init( blake_8x64_big_context *sc )
{
   casti_m512i( sc->H, 0 ) = v512_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = v512_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = v512_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = v512_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = v512_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = v512_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = v512_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = v512_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

static void
blake64_8way( blake_8x64_big_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   __m512i *buf;
   size_t ptr;
   DECL_STATE64_8WAY

   const int buf_size = 128;  //  sizeof/8

// 64, 80 bytes: 1st pass copy data. 2nd pass copy padding and compress.   
// 128 bytes: 1st pass copy data, compress. 2nd pass copy padding, compress.
   
   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < (buf_size - ptr) )
   {
      memcpy_512( buf + (ptr>>3), vdata, len>>3 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }

   READ_STATE64(sc);
   while ( len > 0 )
   {
      size_t clen;

      clen = buf_size - ptr;
      if ( clen > len )
      clen = len;
      memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
      ptr += clen;
      vdata = vdata + (clen>>3);
      len -= clen;
      if ( ptr == buf_size )
      {
         if ( ( T0 = T0 + 1024 ) < 1024 )
            T1 = T1 + 1;
         COMPRESS64_8WAY( buf );
         ptr = 0;
      }
   }
   WRITE_STATE64(sc);
   sc->ptr = ptr;

   }

static void
blake64_8x64_close( blake_8x64_big_context *sc, void *dst )
{
   __m512i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>3] = v512_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
   sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
   sc->T1 = sc->T1 - 1;
   }
   else
   {
        sc->T0 -= 1024 - bit_len;
   }
   if ( ptr <= 104 )
   {
       memset_zero_512( buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       buf[104>>3] = _mm512_or_si512( buf[104>>3],
                                 v512_64( 0x0100000000000000ULL ) );
       buf[112>>3] = v512_64( bswap_64( th ) );
       buf[120>>3] = v512_64( bswap_64( tl ) );

       blake64_8way( sc, buf + (ptr>>3), 128 - ptr );
   }
   else
  {
       memset_zero_512( buf + (ptr>>3) + 1, (120 - ptr) >> 3 );

       blake64_8way( sc, buf + (ptr>>3), 128 - ptr );
       sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
       sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
       memset_zero_512( buf, 112>>3 );
       buf[104>>3] = v512_64( 0x0100000000000000ULL );
       buf[112>>3] = v512_64( bswap_64( th ) );
       buf[120>>3] = v512_64( bswap_64( tl ) );

       blake64_8way( sc, buf, 128 );
   }
   mm512_block_bswap_64( (__m512i*)dst, sc->H );
}

// init, update & close
void blake512_8x64_full( blake_8x64_big_context *sc, void * dst, 
                        const void *data, size_t len )
{
   
// init

   casti_m512i( sc->H, 0 ) = v512_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = v512_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = v512_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = v512_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = v512_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = v512_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = v512_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = v512_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   memcpy_512( sc->buf, (__m512i*)data, len>>3 );
   sc->ptr = len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
            sc->T1 = sc->T1 + 1;
      blake512_8way_compress( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = v512_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr64 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
   sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
   sc->T1 = sc->T1 - 1;
   }
   else
      sc->T0 -= 1024 - bit_len;

   memset_zero_512( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = v512_64( 0x0100000000000000ULL );
   sc->buf[14] = v512_64( bswap_64( th ) );
   sc->buf[15] = v512_64( bswap_64( tl ) );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_8way_compress( sc );
   
   mm512_block_bswap_64( (__m512i*)dst, sc->H );
}
   
void blake512_8x64_full_le( blake_8x64_big_context *sc, void * dst,
                        const void *data, size_t len )
{

// init

   casti_m512i( sc->H, 0 ) = v512_64( 0x6A09E667F3BCC908 );
   casti_m512i( sc->H, 1 ) = v512_64( 0xBB67AE8584CAA73B );
   casti_m512i( sc->H, 2 ) = v512_64( 0x3C6EF372FE94F82B );
   casti_m512i( sc->H, 3 ) = v512_64( 0xA54FF53A5F1D36F1 );
   casti_m512i( sc->H, 4 ) = v512_64( 0x510E527FADE682D1 );
   casti_m512i( sc->H, 5 ) = v512_64( 0x9B05688C2B3E6C1F );
   casti_m512i( sc->H, 6 ) = v512_64( 0x1F83D9ABFB41BD6B );
   casti_m512i( sc->H, 7 ) = v512_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   memcpy_512( sc->buf, (__m512i*)data, len>>3 );
   sc->ptr = len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
            sc->T1 = sc->T1 + 1;
      blake512_8way_compress_le( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = v512_64( 0x8000000000000000ULL );
   tl = sc->T0 + bit_len;
   th = sc->T1;

   if ( ptr64 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
   sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
   sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
   sc->T1 = sc->T1 - 1;
   }
   else
      sc->T0 -= 1024 - bit_len;

   memset_zero_512( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = v512_64( 1 );
   sc->buf[14] = v512_64( th );
   sc->buf[15] = v512_64( tl );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_8way_compress_le( sc );

   mm512_block_bswap_64( (__m512i*)dst, sc->H );
}

void
blake512_8x64_update(void *cc, const void *data, size_t len)
{
   blake64_8way(cc, data, len);
}

void
blake512_8x64_close(void *cc, void *dst)
{
   blake64_8x64_close(cc, dst);
}

#endif  // AVX512

/////////////////////////////////
//
//        Blake-512 4 way

#define GB_4WAY(m0, m1, c0, c1, a, b, c, d) \
{ \
   a = _mm256_add_epi64( _mm256_add_epi64( _mm256_xor_si256( \
                 v256_64( c1 ), m0 ), b ), a ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 32 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 25 ); \
   a = _mm256_add_epi64( _mm256_add_epi64( _mm256_xor_si256( \
                 v256_64( c0 ), m1 ), b ), a ); \
   d = mm256_ror_64( _mm256_xor_si256( d, a ), 16 ); \
   c = _mm256_add_epi64( c, d ); \
   b = mm256_ror_64( _mm256_xor_si256( b, c ), 11 ); \
}

#define ROUND_B_4WAY(r) \
{ \
	GB_4WAY(Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC); \
	GB_4WAY(Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD); \
	GB_4WAY(Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE); \
	GB_4WAY(Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF); \
	GB_4WAY(Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF); \
	GB_4WAY(Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC); \
	GB_4WAY(Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD); \
	GB_4WAY(Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE); \
}

#define DECL_STATE64_4WAY \
	__m256i H0, H1, H2, H3, H4, H5, H6, H7; \
	uint64_t T0, T1;

#define COMPRESS64_4WAY \
{ \
  __m256i M0, M1, M2, M3, M4, M5, M6, M7; \
  __m256i M8, M9, MA, MB, MC, MD, ME, MF; \
  __m256i V0, V1, V2, V3, V4, V5, V6, V7; \
  __m256i V8, V9, VA, VB, VC, VD, VE, VF; \
  V0 = H0; \
  V1 = H1; \
  V2 = H2; \
  V3 = H3; \
  V4 = H4; \
  V5 = H5; \
  V6 = H6; \
  V7 = H7; \
  V8 = v256_64( CB0 );  \
  V9 = v256_64( CB1 );  \
  VA = v256_64( CB2 );  \
  VB = v256_64( CB3 );  \
  VC = v256_64( CB4 ^ T0 ); \
  VD = v256_64( CB5 ^ T0 ); \
  VE = v256_64( CB6 ^ T1 ); \
  VF = v256_64( CB7 ^ T1 ); \
  const __m256i shuf_bswap64 = mm256_bcast_m128( v128_set64( \
                             0x08090a0b0c0d0e0f, 0x0001020304050607 ) ); \
  M0 = _mm256_shuffle_epi8( *(buf+ 0), shuf_bswap64 ); \
  M1 = _mm256_shuffle_epi8( *(buf+ 1), shuf_bswap64 ); \
  M2 = _mm256_shuffle_epi8( *(buf+ 2), shuf_bswap64 ); \
  M3 = _mm256_shuffle_epi8( *(buf+ 3), shuf_bswap64 ); \
  M4 = _mm256_shuffle_epi8( *(buf+ 4), shuf_bswap64 ); \
  M5 = _mm256_shuffle_epi8( *(buf+ 5), shuf_bswap64 ); \
  M6 = _mm256_shuffle_epi8( *(buf+ 6), shuf_bswap64 ); \
  M7 = _mm256_shuffle_epi8( *(buf+ 7), shuf_bswap64 ); \
  M8 = _mm256_shuffle_epi8( *(buf+ 8), shuf_bswap64 ); \
  M9 = _mm256_shuffle_epi8( *(buf+ 9), shuf_bswap64 ); \
  MA = _mm256_shuffle_epi8( *(buf+10), shuf_bswap64 ); \
  MB = _mm256_shuffle_epi8( *(buf+11), shuf_bswap64 ); \
  MC = _mm256_shuffle_epi8( *(buf+12), shuf_bswap64 ); \
  MD = _mm256_shuffle_epi8( *(buf+13), shuf_bswap64 ); \
  ME = _mm256_shuffle_epi8( *(buf+14), shuf_bswap64 ); \
  MF = _mm256_shuffle_epi8( *(buf+15), shuf_bswap64 ); \
  ROUND_B_4WAY(0); \
  ROUND_B_4WAY(1); \
  ROUND_B_4WAY(2); \
  ROUND_B_4WAY(3); \
  ROUND_B_4WAY(4); \
  ROUND_B_4WAY(5); \
  ROUND_B_4WAY(6); \
  ROUND_B_4WAY(7); \
  ROUND_B_4WAY(8); \
  ROUND_B_4WAY(9); \
  ROUND_B_4WAY(0); \
  ROUND_B_4WAY(1); \
  ROUND_B_4WAY(2); \
  ROUND_B_4WAY(3); \
  ROUND_B_4WAY(4); \
  ROUND_B_4WAY(5); \
  H0 = mm256_xor3( V8, V0, H0 ); \
  H1 = mm256_xor3( V9, V1, H1 ); \
  H2 = mm256_xor3( VA, V2, H2 ); \
  H3 = mm256_xor3( VB, V3, H3 ); \
  H4 = mm256_xor3( VC, V4, H4 ); \
  H5 = mm256_xor3( VD, V5, H5 ); \
  H6 = mm256_xor3( VE, V6, H6 ); \
  H7 = mm256_xor3( VF, V7, H7 ); \
}


void blake512_4way_compress( blake_4x64_big_context *sc )
{
  __m256i M0, M1, M2, M3, M4, M5, M6, M7;
  __m256i M8, M9, MA, MB, MC, MD, ME, MF;
  __m256i V0, V1, V2, V3, V4, V5, V6, V7;
  __m256i V8, V9, VA, VB, VC, VD, VE, VF;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = v256_64( CB0 );
  V9 = v256_64( CB1 );
  VA = v256_64( CB2 );
  VB = v256_64( CB3 );
  VC = v256_64( CB4 ^ sc->T0 );
  VD = v256_64( CB5 ^ sc->T0 );
  VE = v256_64( CB6 ^ sc->T1 );
  VF = v256_64( CB7 ^ sc->T1 );
  const __m256i shuf_bswap64 = mm256_bcast_m128( v128_set64(
                                    0x08090a0b0c0d0e0f, 0x0001020304050607 ) );

  M0 = _mm256_shuffle_epi8( sc->buf[ 0], shuf_bswap64 );
  M1 = _mm256_shuffle_epi8( sc->buf[ 1], shuf_bswap64 );
  M2 = _mm256_shuffle_epi8( sc->buf[ 2], shuf_bswap64 );
  M3 = _mm256_shuffle_epi8( sc->buf[ 3], shuf_bswap64 );
  M4 = _mm256_shuffle_epi8( sc->buf[ 4], shuf_bswap64 );
  M5 = _mm256_shuffle_epi8( sc->buf[ 5], shuf_bswap64 );
  M6 = _mm256_shuffle_epi8( sc->buf[ 6], shuf_bswap64 );
  M7 = _mm256_shuffle_epi8( sc->buf[ 7], shuf_bswap64 );
  M8 = _mm256_shuffle_epi8( sc->buf[ 8], shuf_bswap64 );
  M9 = _mm256_shuffle_epi8( sc->buf[ 9], shuf_bswap64 );
  MA = _mm256_shuffle_epi8( sc->buf[10], shuf_bswap64 );
  MB = _mm256_shuffle_epi8( sc->buf[11], shuf_bswap64 );
  MC = _mm256_shuffle_epi8( sc->buf[12], shuf_bswap64 );
  MD = _mm256_shuffle_epi8( sc->buf[13], shuf_bswap64 );
  ME = _mm256_shuffle_epi8( sc->buf[14], shuf_bswap64 );
  MF = _mm256_shuffle_epi8( sc->buf[15], shuf_bswap64 );

  ROUND_B_4WAY(0);
  ROUND_B_4WAY(1);
  ROUND_B_4WAY(2);
  ROUND_B_4WAY(3);
  ROUND_B_4WAY(4);
  ROUND_B_4WAY(5);
  ROUND_B_4WAY(6);
  ROUND_B_4WAY(7);
  ROUND_B_4WAY(8);
  ROUND_B_4WAY(9);
  ROUND_B_4WAY(0);
  ROUND_B_4WAY(1);
  ROUND_B_4WAY(2);
  ROUND_B_4WAY(3);
  ROUND_B_4WAY(4);
  ROUND_B_4WAY(5);

  sc->H[0] = mm256_xor3( V8, V0, sc->H[0] );
  sc->H[1] = mm256_xor3( V9, V1, sc->H[1] );
  sc->H[2] = mm256_xor3( VA, V2, sc->H[2] );
  sc->H[3] = mm256_xor3( VB, V3, sc->H[3] );
  sc->H[4] = mm256_xor3( VC, V4, sc->H[4] );
  sc->H[5] = mm256_xor3( VD, V5, sc->H[5] );
  sc->H[6] = mm256_xor3( VE, V6, sc->H[6] );
  sc->H[7] = mm256_xor3( VF, V7, sc->H[7] );
}

void blake512_4x64_prehash_le( blake_4x64_big_context *sc, __m256i *midstate,
                               const void *data )
{
   __m256i V0, V1, V2, V3, V4, V5, V6, V7;
   __m256i V8, V9, VA, VB, VC, VD, VE, VF;

   // initial hash
   casti_m256i( sc->H, 0 ) = v256_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = v256_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = v256_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = v256_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = v256_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = v256_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = v256_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = v256_64( 0x5BE0CD19137E2179 );
   
   // fill buffer
   memcpy_256( sc->buf, (__m256i*)data, 80>>3 );
   sc->buf[10] = v256_64( 0x8000000000000000ULL );
   sc->buf[11] = m256_zero;
   sc->buf[12] = m256_zero;
   sc->buf[13] = v256_64( 1 );
   sc->buf[14] = m256_zero;
   sc->buf[15] = v256_64( 80*8 );

   // build working variables
   V0 = sc->H[0];
   V1 = sc->H[1];
   V2 = sc->H[2];
   V3 = sc->H[3];
   V4 = sc->H[4];
   V5 = sc->H[5];
   V6 = sc->H[6];
   V7 = sc->H[7];
   V8 = v256_64( CB0 );
   V9 = v256_64( CB1 );
   VA = v256_64( CB2 );
   VB = v256_64( CB3 );
   VC = v256_64( CB4 ^ 0x280ULL );
   VD = v256_64( CB5 ^ 0x280ULL );
   VE = v256_64( CB6 );
   VF = v256_64( CB7 );

   // round 0
   GB_4WAY( sc->buf[ 0], sc->buf[ 1], CB0, CB1, V0, V4, V8, VC );
   GB_4WAY( sc->buf[ 2], sc->buf[ 3], CB2, CB3, V1, V5, V9, VD );
   GB_4WAY( sc->buf[ 4], sc->buf[ 5], CB4, CB5, V2, V6, VA, VE );
   GB_4WAY( sc->buf[ 6], sc->buf[ 7], CB6, CB7, V3, V7, VB, VF );

   // G4 skip nonce
   V0 = _mm256_add_epi64( _mm256_add_epi64( _mm256_xor_si256(
                       v256_64( CB9 ), sc->buf[ 8] ), V5 ), V0 );
   VF = mm256_ror_64( _mm256_xor_si256( VF, V0 ), 32 );
   VA = _mm256_add_epi64( VA, VF );
   V5 = mm256_ror_64( _mm256_xor_si256( V5, VA ), 25 );
   V0 = _mm256_add_epi64( V0, V5 );

   GB_4WAY( sc->buf[10], sc->buf[11], CBA, CBB, V1, V6, VB, VC );
   GB_4WAY( sc->buf[12], sc->buf[13], CBC, CBD, V2, V7, V8, VD );
   GB_4WAY( sc->buf[14], sc->buf[15], CBE, CBF, V3, V4, V9, VE );

   // round 1
   // G1   
   V1 = _mm256_add_epi64( V1, _mm256_xor_si256( v256_64( CB8 ),
           sc->buf[ 4] ) );

   // G2
   V2 = _mm256_add_epi64( V2, V6 );

   // G3
   V3 = _mm256_add_epi64( V3, _mm256_add_epi64( _mm256_xor_si256(
                 v256_64( CB6 ), sc->buf[13] ), V7 ) );

   // save midstate for second part
   midstate[ 0] = V0;
   midstate[ 1] = V1;
   midstate[ 2] = V2;
   midstate[ 3] = V3;
   midstate[ 4] = V4;
   midstate[ 5] = V5;
   midstate[ 6] = V6;
   midstate[ 7] = V7;
   midstate[ 8] = V8;
   midstate[ 9] = V9;
   midstate[10] = VA;
   midstate[11] = VB;
   midstate[12] = VC;
   midstate[13] = VD;
   midstate[14] = VE;
   midstate[15] = VF;
}

void blake512_4x64_final_le( blake_4x64_big_context *sc, void *hash,
                             const __m256i nonce, const __m256i *midstate )
{
   __m256i M0, M1, M2, M3, M4, M5, M6, M7;
   __m256i M8, M9, MA, MB, MC, MD, ME, MF;
   __m256i V0, V1, V2, V3, V4, V5, V6, V7;
   __m256i V8, V9, VA, VB, VC, VD, VE, VF;
   __m256i h[8] __attribute__ ((aligned (64)));

   // Load data with new nonce
   M0 = sc->buf[ 0];
   M1 = sc->buf[ 1];
   M2 = sc->buf[ 2];
   M3 = sc->buf[ 3];
   M4 = sc->buf[ 4];
   M5 = sc->buf[ 5];
   M6 = sc->buf[ 6];
   M7 = sc->buf[ 7];
   M8 = sc->buf[ 8];
   M9 = nonce;
   MA = sc->buf[10];
   MB = sc->buf[11];
   MC = sc->buf[12];
   MD = sc->buf[13];
   ME = sc->buf[14];
   MF = sc->buf[15];

   V0 = midstate[ 0];
   V1 = midstate[ 1];
   V2 = midstate[ 2];
   V3 = midstate[ 3];
   V4 = midstate[ 4];
   V5 = midstate[ 5];
   V6 = midstate[ 6];
   V7 = midstate[ 7];
   V8 = midstate[ 8];
   V9 = midstate[ 9];
   VA = midstate[10];
   VB = midstate[11];
   VC = midstate[12];
   VD = midstate[13];
   VE = midstate[14];
   VF = midstate[15];

   // finish round 0, with the nonce now available 
   V0 = _mm256_add_epi64( V0, _mm256_xor_si256(
                                       v256_64( CB8 ), M9 ) );
   VF = mm256_ror_64( _mm256_xor_si256( VF, V0 ), 16 );
   VA = _mm256_add_epi64( VA, VF );
   V5 = mm256_ror_64( _mm256_xor_si256( V5, VA ), 11 );

   // Round 1
   // G0
   GB_4WAY(Mx(1, 0), Mx(1, 1), CBx(1, 0), CBx(1, 1), V0, V4, V8, VC);

   // G1
   V1 = _mm256_add_epi64( V1, V5 );
   VD = mm256_ror_64( _mm256_xor_si256( VD, V1 ), 32 );
   V9 = _mm256_add_epi64( V9, VD );
   V5 = mm256_ror_64( _mm256_xor_si256( V5, V9 ), 25 );
   V1 = _mm256_add_epi64( V1, _mm256_add_epi64( _mm256_xor_si256(
                 v256_64( CBx(1,2) ), Mx(1,3) ), V5 ) );
   VD = mm256_ror_64( _mm256_xor_si256( VD, V1 ), 16 );
   V9 = _mm256_add_epi64( V9, VD );
   V5 = mm256_ror_64( _mm256_xor_si256( V5, V9 ), 11 );

   // G2
   V2 = _mm256_add_epi64( V2, _mm256_xor_si256(
                 v256_64( CBF ), M9 ) );
   VE = mm256_ror_64( _mm256_xor_si256( VE, V2 ), 32 );
   VA = _mm256_add_epi64( VA, VE );
   V6 = mm256_ror_64( _mm256_xor_si256( V6, VA ), 25 );
   V2 = _mm256_add_epi64( V2, _mm256_add_epi64( _mm256_xor_si256(
                 v256_64( CB9 ), MF ), V6 ) );
   VE = mm256_ror_64( _mm256_xor_si256( VE, V2 ), 16 );
   VA = _mm256_add_epi64( VA, VE );
   V6 = mm256_ror_64( _mm256_xor_si256( V6, VA ), 11 );

   // G3
   VF = mm256_ror_64( _mm256_xor_si256( VF, V3 ), 32 );
   VB = _mm256_add_epi64( VB, VF );
   V7 = mm256_ror_64( _mm256_xor_si256( V7, VB ), 25 );
   V3 = _mm256_add_epi64( V3, _mm256_add_epi64( _mm256_xor_si256(
                 v256_64( CBx(1, 6) ), Mx(1, 7) ), V7 ) );
   VF = mm256_ror_64( _mm256_xor_si256( VF, V3 ), 16 );
   VB = _mm256_add_epi64( VB, VF );
   V7 = mm256_ror_64( _mm256_xor_si256( V7, VB ), 11 );

   // G4, G5, G6, G7
   GB_4WAY(Mx(1, 8), Mx(1, 9), CBx(1, 8), CBx(1, 9), V0, V5, VA, VF);
   GB_4WAY(Mx(1, A), Mx(1, B), CBx(1, A), CBx(1, B), V1, V6, VB, VC);
   GB_4WAY(Mx(1, C), Mx(1, D), CBx(1, C), CBx(1, D), V2, V7, V8, VD);
   GB_4WAY(Mx(1, E), Mx(1, F), CBx(1, E), CBx(1, F), V3, V4, V9, VE);

   ROUND_B_4WAY(2);
   ROUND_B_4WAY(3);
   ROUND_B_4WAY(4);
   ROUND_B_4WAY(5);
   ROUND_B_4WAY(6);
   ROUND_B_4WAY(7);
   ROUND_B_4WAY(8);
   ROUND_B_4WAY(9);
   ROUND_B_4WAY(0);
   ROUND_B_4WAY(1);
   ROUND_B_4WAY(2);
   ROUND_B_4WAY(3);
   ROUND_B_4WAY(4);
   ROUND_B_4WAY(5);

   h[0] = mm256_xor3( V8, V0, sc->H[0] );
   h[1] = mm256_xor3( V9, V1, sc->H[1] );
   h[2] = mm256_xor3( VA, V2, sc->H[2] );
   h[3] = mm256_xor3( VB, V3, sc->H[3] );
   h[4] = mm256_xor3( VC, V4, sc->H[4] );
   h[5] = mm256_xor3( VD, V5, sc->H[5] );
   h[6] = mm256_xor3( VE, V6, sc->H[6] );
   h[7] = mm256_xor3( VF, V7, sc->H[7] );

   // bswap final hash
   mm256_block_bswap_64( (__m256i*)hash, h );
}


void blake512_4x64_init( blake_4x64_big_context *sc )
{
   casti_m256i( sc->H, 0 ) = v256_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = v256_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = v256_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = v256_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = v256_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = v256_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = v256_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = v256_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

static void
blake64_4way( blake_4x64_big_context *sc, const void *data, size_t len)
{
   __m256i *vdata = (__m256i*)data;
   __m256i *buf;
   size_t ptr;
   DECL_STATE64_4WAY

   const int buf_size = 128;  //  sizeof/8 

   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < (buf_size - ptr) )
   {
   	memcpy_256( buf + (ptr>>3), vdata, len>>3 );
	   ptr += len;
	   sc->ptr = ptr;
	   return;
   }

   READ_STATE64(sc);
   while ( len > 0 )
   {
   	size_t clen;

	   clen = buf_size - ptr;
	   if ( clen > len )
		   clen = len;
   	memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
	   ptr += clen;
	   vdata = vdata + (clen>>3);
	   len -= clen;
	   if ( ptr == buf_size )
      {
		   if ( (T0 = T0 + 1024 ) < 1024 )
			   T1 = T1 + 1;
	   	COMPRESS64_4WAY;
		   ptr = 0;
	   }
   }
   WRITE_STATE64(sc);
   sc->ptr = ptr;
}

static void
blake64_4way_close( blake_4x64_big_context *sc, void *dst )
{
   __m256i buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   buf[ptr>>3] = v256_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
	sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
	sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
	sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
	sc->T1 = sc->T1 - 1;
   } 
   else
   {
        sc->T0 -= 1024 - bit_len;
   }

   if ( ptr <= 104 )
   {
       memset_zero_256( buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       buf[104>>3] = _mm256_or_si256( buf[104>>3],
                                 v256_64( 0x0100000000000000ULL ) );
       buf[112>>3] = v256_64( bswap_64( th ) );
       buf[120>>3] = v256_64( bswap_64( tl ) );
       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
   }
   else
   {
       memset_zero_256( buf + (ptr>>3) + 1, (120 - ptr) >> 3 );
       blake64_4way( sc, buf + (ptr>>3), 128 - ptr );
       sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
       sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
       memset_zero_256( buf, 112>>3 ); 
       buf[104>>3] = v256_64( 0x0100000000000000ULL );
       buf[112>>3] = v256_64( bswap_64( th ) );
       buf[120>>3] = v256_64( bswap_64( tl ) );
       blake64_4way( sc, buf, 128 );
   }

   mm256_block_bswap_64( (__m256i*)dst, sc->H );
}

// init, update & close
void blake512_4x64_full( blake_4x64_big_context *sc, void * dst,
                         const void *data, size_t len )
{

// init

   casti_m256i( sc->H, 0 ) = v256_64( 0x6A09E667F3BCC908 );
   casti_m256i( sc->H, 1 ) = v256_64( 0xBB67AE8584CAA73B );
   casti_m256i( sc->H, 2 ) = v256_64( 0x3C6EF372FE94F82B );
   casti_m256i( sc->H, 3 ) = v256_64( 0xA54FF53A5F1D36F1 );
   casti_m256i( sc->H, 4 ) = v256_64( 0x510E527FADE682D1 );
   casti_m256i( sc->H, 5 ) = v256_64( 0x9B05688C2B3E6C1F );
   casti_m256i( sc->H, 6 ) = v256_64( 0x1F83D9ABFB41BD6B );
   casti_m256i( sc->H, 7 ) = v256_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   memcpy_256( sc->buf, (__m256i*)data, len>>3 );
   sc->ptr += len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
         sc->T1 =  sc->T1 + 1;
      blake512_4way_compress( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = v256_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if ( sc->ptr == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
      sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
      sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 1024 - bit_len;

   memset_zero_256( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = v256_64( 0x0100000000000000ULL );
   sc->buf[14] = v256_64( bswap_64( th ) );
   sc->buf[15] = v256_64( bswap_64( tl ) );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_4way_compress( sc );

   mm256_block_bswap_64( (__m256i*)dst, sc->H );
}

void
blake512_4x64_update(void *cc, const void *data, size_t len)
{
	blake64_4way(cc, data, len);
}

void
blake512_4x64_close(void *cc, void *dst)
{
   blake64_4way_close( cc, dst );
}

#endif   // AVX2
        
///////////////////////////////////////
//
//        Blake-512 2 way

#if defined(__SSE2__) || defined(__ARM_NEON)

#define GB_2X64( m0, m1, c0, c1, a, b, c, d ) \
{ \
   a = v128_add64( v128_add64( v128_xor( v128_64( c1 ), m0 ), b ), a ); \
   d = v128_ror64( v128_xor( d, a ), 32 ); \
   c = v128_add64( c, d ); \
   b = v128_ror64( v128_xor( b, c ), 25 ); \
   a = v128_add64( v128_add64( v128_xor( v128_64( c0 ), m1 ), b ), a ); \
   d = v128_ror64( v128_xor( d, a ), 16 ); \
   c = v128_add64( c, d ); \
   b = v128_ror64( v128_xor( b, c ), 11 ); \
}

#define ROUND_B_2X64(r) \
{ \
   GB_2X64( Mx(r, 0), Mx(r, 1), CBx(r, 0), CBx(r, 1), V0, V4, V8, VC ); \
   GB_2X64( Mx(r, 2), Mx(r, 3), CBx(r, 2), CBx(r, 3), V1, V5, V9, VD ); \
   GB_2X64( Mx(r, 4), Mx(r, 5), CBx(r, 4), CBx(r, 5), V2, V6, VA, VE ); \
   GB_2X64( Mx(r, 6), Mx(r, 7), CBx(r, 6), CBx(r, 7), V3, V7, VB, VF ); \
   GB_2X64( Mx(r, 8), Mx(r, 9), CBx(r, 8), CBx(r, 9), V0, V5, VA, VF ); \
   GB_2X64( Mx(r, A), Mx(r, B), CBx(r, A), CBx(r, B), V1, V6, VB, VC ); \
   GB_2X64( Mx(r, C), Mx(r, D), CBx(r, C), CBx(r, D), V2, V7, V8, VD ); \
   GB_2X64( Mx(r, E), Mx(r, F), CBx(r, E), CBx(r, F), V3, V4, V9, VE ); \
}

#define DECL_STATE_2X64 \
   v128u64_t H0, H1, H2, H3, H4, H5, H6, H7; \
   uint64_t T0, T1;

void blake512_2x64_compress( blake_2x64_big_context *sc )
{
  v128u64_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF;
  v128u64_t V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, VA, VB, VC, VD, VE, VF;

  V0 = sc->H[0];
  V1 = sc->H[1];
  V2 = sc->H[2];
  V3 = sc->H[3];
  V4 = sc->H[4];
  V5 = sc->H[5];
  V6 = sc->H[6];
  V7 = sc->H[7];
  V8 = v128_64( CB0 );
  V9 = v128_64( CB1 );
  VA = v128_64( CB2 );
  VB = v128_64( CB3 );
  VC = v128_64( CB4 ^ sc->T0 );
  VD = v128_64( CB5 ^ sc->T0 );
  VE = v128_64( CB6 ^ sc->T1 );
  VF = v128_64( CB7 ^ sc->T1 );

#if defined(__SSSE3__)

  const v128u64_t shuf_bswap64 = v128_set64(
                                 0x08090a0b0c0d0e0f, 0x0001020304050607 );
  M0 = v128_shuffle8( sc->buf[ 0], shuf_bswap64 );
  M1 = v128_shuffle8( sc->buf[ 1], shuf_bswap64 );
  M2 = v128_shuffle8( sc->buf[ 2], shuf_bswap64 );
  M3 = v128_shuffle8( sc->buf[ 3], shuf_bswap64 );
  M4 = v128_shuffle8( sc->buf[ 4], shuf_bswap64 );
  M5 = v128_shuffle8( sc->buf[ 5], shuf_bswap64 );
  M6 = v128_shuffle8( sc->buf[ 6], shuf_bswap64 );
  M7 = v128_shuffle8( sc->buf[ 7], shuf_bswap64 );
  M8 = v128_shuffle8( sc->buf[ 8], shuf_bswap64 );
  M9 = v128_shuffle8( sc->buf[ 9], shuf_bswap64 );
  MA = v128_shuffle8( sc->buf[10], shuf_bswap64 );
  MB = v128_shuffle8( sc->buf[11], shuf_bswap64 );
  MC = v128_shuffle8( sc->buf[12], shuf_bswap64 );
  MD = v128_shuffle8( sc->buf[13], shuf_bswap64 );
  ME = v128_shuffle8( sc->buf[14], shuf_bswap64 );
  MF = v128_shuffle8( sc->buf[15], shuf_bswap64 );

#else  // SSE2 & NEON

  M0 = v128_bswap64( sc->buf[ 0] );
  M1 = v128_bswap64( sc->buf[ 1] );
  M2 = v128_bswap64( sc->buf[ 2] );
  M3 = v128_bswap64( sc->buf[ 3] );
  M4 = v128_bswap64( sc->buf[ 4] );
  M5 = v128_bswap64( sc->buf[ 5] );
  M6 = v128_bswap64( sc->buf[ 6] );
  M7 = v128_bswap64( sc->buf[ 7] );
  M8 = v128_bswap64( sc->buf[ 8] );
  M9 = v128_bswap64( sc->buf[ 9] );
  MA = v128_bswap64( sc->buf[10] );
  MB = v128_bswap64( sc->buf[11] );
  MC = v128_bswap64( sc->buf[12] );
  MD = v128_bswap64( sc->buf[13] );
  ME = v128_bswap64( sc->buf[14] );
  MF = v128_bswap64( sc->buf[15] );
  
#endif

  ROUND_B_2X64(0);
  ROUND_B_2X64(1);
  ROUND_B_2X64(2);
  ROUND_B_2X64(3);
  ROUND_B_2X64(4);
  ROUND_B_2X64(5);
  ROUND_B_2X64(6);
  ROUND_B_2X64(7);
  ROUND_B_2X64(8);
  ROUND_B_2X64(9);
  ROUND_B_2X64(0);
  ROUND_B_2X64(1);
  ROUND_B_2X64(2);
  ROUND_B_2X64(3);
  ROUND_B_2X64(4);
  ROUND_B_2X64(5);

  sc->H[0] = v128_xor3( V8, V0, sc->H[0] );
  sc->H[1] = v128_xor3( V9, V1, sc->H[1] );
  sc->H[2] = v128_xor3( VA, V2, sc->H[2] );
  sc->H[3] = v128_xor3( VB, V3, sc->H[3] );
  sc->H[4] = v128_xor3( VC, V4, sc->H[4] );
  sc->H[5] = v128_xor3( VD, V5, sc->H[5] );
  sc->H[6] = v128_xor3( VE, V6, sc->H[6] );
  sc->H[7] = v128_xor3( VF, V7, sc->H[7] );
}

void blake512_2x64_prehash_part1_le( blake_2x64_big_context *sc,
                                     v128u64_t *midstate, const void *data )
{
   v128u64_t V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, VA, VB, VC, VD, VE, VF;

   // initial hash
   casti_v128( sc->H, 0 ) = v128_64( 0x6A09E667F3BCC908 );
   casti_v128( sc->H, 1 ) = v128_64( 0xBB67AE8584CAA73B );
   casti_v128( sc->H, 2 ) = v128_64( 0x3C6EF372FE94F82B );
   casti_v128( sc->H, 3 ) = v128_64( 0xA54FF53A5F1D36F1 );
   casti_v128( sc->H, 4 ) = v128_64( 0x510E527FADE682D1 );
   casti_v128( sc->H, 5 ) = v128_64( 0x9B05688C2B3E6C1F );
   casti_v128( sc->H, 6 ) = v128_64( 0x1F83D9ABFB41BD6B );
   casti_v128( sc->H, 7 ) = v128_64( 0x5BE0CD19137E2179 );

   // fill buffer
   v128_memcpy( sc->buf, (v128u64_t*)data, 80>>3 );
   sc->buf[10] = v128_64( 0x8000000000000000ULL );
   sc->buf[11] = v128_zero;
   sc->buf[12] = v128_zero;
   sc->buf[13] = v128_64( 1 );
   sc->buf[14] = v128_zero;
   sc->buf[15] = v128_64( 80*8 );

   // build working variables
   V0 = sc->H[0];
   V1 = sc->H[1];
   V2 = sc->H[2];
   V3 = sc->H[3];
   V4 = sc->H[4];
   V5 = sc->H[5];
   V6 = sc->H[6];
   V7 = sc->H[7];
   V8 = v128_64( CB0 );
   V9 = v128_64( CB1 );
   VA = v128_64( CB2 );
   VB = v128_64( CB3 );
   VC = v128_64( CB4 ^ 0x280ULL );
   VD = v128_64( CB5 ^ 0x280ULL );
   VE = v128_64( CB6 );
   VF = v128_64( CB7 );

   // round 0
   GB_2X64( sc->buf[ 0], sc->buf[ 1], CB0, CB1, V0, V4, V8, VC );
   GB_2X64( sc->buf[ 2], sc->buf[ 3], CB2, CB3, V1, V5, V9, VD );
   GB_2X64( sc->buf[ 4], sc->buf[ 5], CB4, CB5, V2, V6, VA, VE );
   GB_2X64( sc->buf[ 6], sc->buf[ 7], CB6, CB7, V3, V7, VB, VF );

   // G4 skip nonce
   V0 = v128_add64( v128_add64( v128_xor( v128_64( CB9 ), sc->buf[ 8] ), V5 ),
                                          V0 );
   VF = v128_ror64( v128_xor( VF, V0 ), 32 );
   VA = v128_add64( VA, VF );
   V5 = v128_ror64( v128_xor( V5, VA ), 25 );
   V0 = v128_add64( V0, V5 );

   GB_2X64( sc->buf[10], sc->buf[11], CBA, CBB, V1, V6, VB, VC );
   GB_2X64( sc->buf[12], sc->buf[13], CBC, CBD, V2, V7, V8, VD );
   GB_2X64( sc->buf[14], sc->buf[15], CBE, CBF, V3, V4, V9, VE );

   // round 1
   // G1   
   V1 = v128_add64( V1, v128_xor( v128_64( CB8 ), sc->buf[ 4] ) );

   // G2
   V2 = v128_add64( V2, V6 );

   // G3
   V3 = v128_add64( V3, v128_add64( v128_xor( v128_64( CB6 ), sc->buf[13] ),
                                    V7 ) );

   // save midstate for second part
   midstate[ 0] = V0;
   midstate[ 1] = V1;
   midstate[ 2] = V2;
   midstate[ 3] = V3;
   midstate[ 4] = V4;
   midstate[ 5] = V5;
   midstate[ 6] = V6;
   midstate[ 7] = V7;
   midstate[ 8] = V8;
   midstate[ 9] = V9;
   midstate[10] = VA;
   midstate[11] = VB;
   midstate[12] = VC;
   midstate[13] = VD;
   midstate[14] = VE;
   midstate[15] = VF;
}

void blake512_2x64_prehash_part2_le( blake_2x64_big_context *sc, void *hash,
                           const v128u64_t nonce, const v128u64_t *midstate )
{
   v128u64_t M0, M1, M2, M3, M4, M5, M6, M7, M8, M9, MA, MB, MC, MD, ME, MF;
   v128u64_t V0, V1, V2, V3, V4, V5, V6, V7, V8, V9, VA, VB, VC, VD, VE, VF;
   v128u64_t h[8] __attribute__ ((aligned (32)));

   // Load data with new nonce
   M0 = sc->buf[ 0];
   M1 = sc->buf[ 1];
   M2 = sc->buf[ 2];
   M3 = sc->buf[ 3];
   M4 = sc->buf[ 4];
   M5 = sc->buf[ 5];
   M6 = sc->buf[ 6];
   M7 = sc->buf[ 7];
   M8 = sc->buf[ 8];
   M9 = nonce;
   MA = sc->buf[10];
   MB = sc->buf[11];
   MC = sc->buf[12];
   MD = sc->buf[13];
   ME = sc->buf[14];
   MF = sc->buf[15];

   V0 = midstate[ 0];
   V1 = midstate[ 1];
   V2 = midstate[ 2];
   V3 = midstate[ 3];
   V4 = midstate[ 4];
   V5 = midstate[ 5];
   V6 = midstate[ 6];
   V7 = midstate[ 7];
   V8 = midstate[ 8];
   V9 = midstate[ 9];
   VA = midstate[10];
   VB = midstate[11];
   VC = midstate[12];
   VD = midstate[13];
   VE = midstate[14];
   VF = midstate[15];

   // finish round 0, with the nonce now available 
   V0 = v128_add64( V0, v128_xor( v128_64( CB8 ), M9 ) );
   VF = v128_ror64( v128_xor( VF, V0 ), 16 );
   VA = v128_add64( VA, VF );
   V5 = v128_ror64( v128_xor( V5, VA ), 11 );

   // Round 1
   // G0
   GB_2X64(Mx(1, 0), Mx(1, 1), CBx(1, 0), CBx(1, 1), V0, V4, V8, VC);

   // G1
   V1 = v128_add64( V1, V5 );
   VD = v128_ror64( v128_xor( VD, V1 ), 32 );
   V9 = v128_add64( V9, VD );
   V5 = v128_ror64( v128_xor( V5, V9 ), 25 );
   V1 = v128_add64( V1, v128_add64( v128_xor( v128_64( CBx(1,2) ), Mx(1,3) ),
                                              V5 ) );
   VD = v128_ror64( v128_xor( VD, V1 ), 16 );
   V9 = v128_add64( V9, VD );
   V5 = v128_ror64( v128_xor( V5, V9 ), 11 );

   // G2
   V2 = v128_add64( V2, v128_xor( v128_64( CBF ), M9 ) );
   VE = v128_ror64( v128_xor( VE, V2 ), 32 );
   VA = v128_add64( VA, VE );
   V6 = v128_ror64( v128_xor( V6, VA ), 25 );
   V2 = v128_add64( V2, v128_add64( v128_xor( v128_64( CB9 ), MF ), V6 ) );
   VE = v128_ror64( v128_xor( VE, V2 ), 16 );
   VA = v128_add64( VA, VE );
   V6 = v128_ror64( v128_xor( V6, VA ), 11 );

   // G3
   VF = v128_ror64( v128_xor( VF, V3 ), 32 );
   VB = v128_add64( VB, VF );
   V7 = v128_ror64( v128_xor( V7, VB ), 25 );
   V3 = v128_add64( V3, v128_add64( v128_xor( v128_64( CBx(1, 6) ), Mx(1, 7) ),
                                              V7 ) );
   VF = v128_ror64( v128_xor( VF, V3 ), 16 );
   VB = v128_add64( VB, VF );
   V7 = v128_ror64( v128_xor( V7, VB ), 11 );

   // G4, G5, G6, G7
   GB_2X64(Mx(1, 8), Mx(1, 9), CBx(1, 8), CBx(1, 9), V0, V5, VA, VF);
   GB_2X64(Mx(1, A), Mx(1, B), CBx(1, A), CBx(1, B), V1, V6, VB, VC);
   GB_2X64(Mx(1, C), Mx(1, D), CBx(1, C), CBx(1, D), V2, V7, V8, VD);
   GB_2X64(Mx(1, E), Mx(1, F), CBx(1, E), CBx(1, F), V3, V4, V9, VE);

   ROUND_B_2X64(2);
   ROUND_B_2X64(3);
   ROUND_B_2X64(4);
   ROUND_B_2X64(5);
   ROUND_B_2X64(6);
   ROUND_B_2X64(7);
   ROUND_B_2X64(8);
   ROUND_B_2X64(9);
   ROUND_B_2X64(0);
   ROUND_B_2X64(1);
   ROUND_B_2X64(2);
   ROUND_B_2X64(3);
   ROUND_B_2X64(4);
   ROUND_B_2X64(5);

   h[0] = v128_xor3( V8, V0, sc->H[0] );
   h[1] = v128_xor3( V9, V1, sc->H[1] );
   h[2] = v128_xor3( VA, V2, sc->H[2] );
   h[3] = v128_xor3( VB, V3, sc->H[3] );
   h[4] = v128_xor3( VC, V4, sc->H[4] );
   h[5] = v128_xor3( VD, V5, sc->H[5] );
   h[6] = v128_xor3( VE, V6, sc->H[6] );
   h[7] = v128_xor3( VF, V7, sc->H[7] );

   // bswap final hash
   v128_block_bswap64( (v128u64_t*)hash, h );
}


void blake512_2x64_init( blake_2x64_big_context *sc )
{
   casti_v128( sc->H, 0 ) = v128_64( 0x6A09E667F3BCC908 );
   casti_v128( sc->H, 1 ) = v128_64( 0xBB67AE8584CAA73B );
   casti_v128( sc->H, 2 ) = v128_64( 0x3C6EF372FE94F82B );
   casti_v128( sc->H, 3 ) = v128_64( 0xA54FF53A5F1D36F1 );
   casti_v128( sc->H, 4 ) = v128_64( 0x510E527FADE682D1 );
   casti_v128( sc->H, 5 ) = v128_64( 0x9B05688C2B3E6C1F );
   casti_v128( sc->H, 6 ) = v128_64( 0x1F83D9ABFB41BD6B );
   casti_v128( sc->H, 7 ) = v128_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;
}

static void
blake64_2x64( blake_2x64_big_context *sc, const void *data, size_t len)
{
   v128u64_t *vdata = (v128u64_t*)data;
   v128u64_t *buf;
   size_t ptr;
   const int buf_size = 128;  //  sizeof/8 

   buf = sc->buf;
   ptr = sc->ptr;
   if ( len < (buf_size - ptr) )
   {
      v128_memcpy( buf + (ptr>>3), vdata, len>>3 );
      ptr += len;
      sc->ptr = ptr;
      return;
   }

   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      v128_memcpy( buf + (ptr>>3), vdata, clen>>3 );
      ptr += clen;
      vdata = vdata + (clen>>3);
      len -= clen;
      if ( ptr == buf_size )
      {
         if ( (sc->T0 = sc->T0 + 1024 ) < 1024 )
            sc->T1 = sc->T1 + 1;
         blake512_2x64_compress( sc );
         ptr = 0;
      }
   }
   sc->ptr = ptr;
}

static void
blake64_2x64_close( blake_2x64_big_context *sc, void *dst )
{
   v128u64_t buf[16];
   size_t ptr;
   unsigned bit_len;
   uint64_t th, tl;

   ptr = sc->ptr;
   bit_len = ((unsigned)ptr << 3);
   sc->buf[ptr>>3] = v128_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if (ptr == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
      sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
      sc->T1 = sc->T1 - 1;
   }
   else
      sc->T0 -= 1024 - bit_len;
   
   if ( ptr <= 104 )
   {
       v128_memset_zero( sc->buf + (ptr>>3) + 1, (104-ptr) >> 3 );
       sc->buf[104>>3] = v128_or( sc->buf[104>>3],
                                  v128_64( 0x0100000000000000ULL ) );
       sc->buf[112>>3] = v128_64( bswap_64( th ) );
       sc->buf[120>>3] = v128_64( bswap_64( tl ) );
       blake64_2x64( sc, sc->buf + (ptr>>3), 128 - ptr );
   }
   else
   {
       v128_memset_zero( sc->buf + (ptr>>3) + 1, (120 - ptr) >> 3 );
       blake64_2x64( sc, sc->buf + (ptr>>3), 128 - ptr );
       sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
       sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
       v128_memset_zero( buf, 112>>3 );
       buf[104>>3] = v128_64( 0x0100000000000000ULL );
       buf[112>>3] = v128_64( bswap_64( th ) );
       buf[120>>3] = v128_64( bswap_64( tl ) );
       blake64_2x64( sc, buf, 128 );
   }

   v128_block_bswap64( (v128u64_t*)dst, sc->H );
}

// init, update & close
void blake512_2x64_full( blake_2x64_big_context *sc, void * dst,
                         const void *data, size_t len )
{
// init

   casti_v128u64( sc->H, 0 ) = v128_64( 0x6A09E667F3BCC908 );
   casti_v128u64( sc->H, 1 ) = v128_64( 0xBB67AE8584CAA73B );
   casti_v128u64( sc->H, 2 ) = v128_64( 0x3C6EF372FE94F82B );
   casti_v128u64( sc->H, 3 ) = v128_64( 0xA54FF53A5F1D36F1 );
   casti_v128u64( sc->H, 4 ) = v128_64( 0x510E527FADE682D1 );
   casti_v128u64( sc->H, 5 ) = v128_64( 0x9B05688C2B3E6C1F );
   casti_v128u64( sc->H, 6 ) = v128_64( 0x1F83D9ABFB41BD6B );
   casti_v128u64( sc->H, 7 ) = v128_64( 0x5BE0CD19137E2179 );

   sc->T0 = sc->T1 = 0;
   sc->ptr = 0;

// update

   v128_memcpy( sc->buf, (v128u64_t*)data, len>>3 );
   sc->ptr += len;
   if ( len == 128 )
   {
      if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
         sc->T1 =  sc->T1 + 1;
      blake512_2x64_compress( sc );
      sc->ptr = 0;
   }

// close

   size_t ptr64 = sc->ptr >> 3;
   unsigned bit_len;
   uint64_t th, tl;

   bit_len = sc->ptr << 3;
   sc->buf[ptr64] = v128_64( 0x80 );
   tl = sc->T0 + bit_len;
   th = sc->T1;
   if ( sc->ptr == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL;
      sc->T1 = 0xFFFFFFFFFFFFFFFFULL;
   }
   else if ( sc->T0 == 0 )
   {
      sc->T0 = 0xFFFFFFFFFFFFFC00ULL + bit_len;
      sc->T1 = sc->T1 - 1;
   }
   else
        sc->T0 -= 1024 - bit_len;

   v128_memset_zero( sc->buf + ptr64 + 1, 13 - ptr64 );
   sc->buf[13] = v128_64( 0x0100000000000000ULL );
   sc->buf[14] = v128_64( bswap_64( th ) );
   sc->buf[15] = v128_64( bswap_64( tl ) );

   if ( ( sc->T0 = sc->T0 + 1024 ) < 1024 )
       sc->T1 = sc->T1 + 1;

   blake512_2x64_compress( sc );

   v128_block_bswap64( (v128u64_t*)dst, sc->H );
}

void
blake512_2x64_update(void *cc, const void *data, size_t len)
{
   blake64_2x64(cc, data, len);
}

void
blake512_2x64_close(void *cc, void *dst)
{
   blake64_2x64_close( cc, dst );
}

#endif  // SSE2 or NEON
         

