#include <stddef.h>
#include <string.h>
#include "panama-hash-4way.h"

//  Common macros

#define M17( macro ) \
do { \
      macro(  0,  1,  2,  4 ); \
      macro(  1,  2,  3,  5 ); \
      macro(  2,  3,  4,  6 ); \
      macro(  3,  4,  5,  7 ); \
      macro(  4,  5,  6,  8 ); \
      macro(  5,  6,  7,  9 ); \
      macro(  6,  7,  8, 10 ); \
      macro(  7,  8,  9, 11 ); \
      macro(  8,  9, 10, 12 ); \
      macro(  9, 10, 11, 13 ); \
      macro( 10, 11, 12, 14 ); \
      macro( 11, 12, 13, 15 ); \
      macro( 12, 13, 14, 16 ); \
      macro( 13, 14, 15,  0 ); \
      macro( 14, 15, 16,  1 ); \
      macro( 15, 16,  0,  2 ); \
      macro( 16,  0,  1,  3 ); \
} while (0)

#define RSTATE(n0, n1, n2, n4)    (a ## n0 = sc->state[n0])

#define WSTATE(n0, n1, n2, n4)    (sc->state[n0] = a ## n0)

#define INC0     1
#define INC1     2
#define INC2     3
#define INC3     4
#define INC4     5
#define INC5     6
#define INC6     7
#define INC7     8

//////////////////////////////////
//
//    Panama-256 4 way SSE2

#define LVAR17_4W(b)  __m128i \
	b ## 0, b ## 1, b ## 2, b ## 3, b ## 4, b ## 5, \
	b ## 6, b ## 7, b ## 8, b ## 9, b ## 10, b ## 11, \
	b ## 12, b ## 13, b ## 14, b ## 15, b ## 16;

#define LVARS_4W   \
	LVAR17_4W(a) \
	LVAR17_4W(g)

#define BUPDATE1_4W( n0, n2 ) \
do { \
   sc->buffer[ptr24][n0] = _mm_xor_si128( sc->buffer[ptr24][n0], \
                                          sc->buffer[ptr31][n2] ); \
   sc->buffer[ptr31][n2] = _mm_xor_si128( sc->buffer[ptr31][n2], INW1(n2) ); \
} while (0)

#define BUPDATE_4W \
do { \
		BUPDATE1_4W( 0, 2 ); \
		BUPDATE1_4W( 1, 3 ); \
		BUPDATE1_4W( 2, 4 ); \
		BUPDATE1_4W( 3, 5 ); \
		BUPDATE1_4W( 4, 6 ); \
		BUPDATE1_4W( 5, 7 ); \
		BUPDATE1_4W( 6, 0 ); \
		BUPDATE1_4W( 7, 1 ); \
} while (0)

#define GAMMA_4W(n0, n1, n2, n4)   \
   (g ## n0 = _mm_xor_si128( a ## n0, \
                             _mm_or_si128( a ## n1, mm128_not( a ## n2 ) ) ) )

#define PI_ALL_4W   do { \
      a0  = g0; \
      a1  = mm128_rol_32( g7,   1 ); \
      a2  = mm128_rol_32( g14,  3 ); \
      a3  = mm128_rol_32( g4,   6 ); \
      a4  = mm128_rol_32( g11, 10 ); \
      a5  = mm128_rol_32( g1,  15 ); \
      a6  = mm128_rol_32( g8,  21 ); \
      a7  = mm128_rol_32( g15, 28 ); \
      a8  = mm128_rol_32( g5,   4 ); \
      a9  = mm128_rol_32( g12, 13 ); \
      a10 = mm128_rol_32( g2,  23 ); \
      a11 = mm128_rol_32( g9,   2 ); \
      a12 = mm128_rol_32( g16, 14 ); \
      a13 = mm128_rol_32( g6,  27 ); \
      a14 = mm128_rol_32( g13,  9 ); \
      a15 = mm128_rol_32( g3,  24 ); \
      a16 = mm128_rol_32( g10,  8 ); \
   } while (0)

#define THETA_4W(n0, n1, n2, n4)   \
   ( g ## n0 = _mm_xor_si128( a ## n0, _mm_xor_si128( a ## n1, a ## n4 ) ) )

#define SIGMA_ALL_4W   do { \
		a0 = _mm_xor_si128( g0, m128_one_32 ); \
		a1 = _mm_xor_si128( g1, INW2( 0 ) ); \
		a2 = _mm_xor_si128( g2, INW2( 1 ) ); \
		a3 = _mm_xor_si128( g3, INW2( 2 ) ); \
		a4 = _mm_xor_si128( g4, INW2( 3 ) ); \
		a5 = _mm_xor_si128( g5, INW2( 4 ) ); \
		a6 = _mm_xor_si128( g6, INW2( 5 ) ); \
		a7 = _mm_xor_si128( g7, INW2( 6 ) ); \
		a8 = _mm_xor_si128( g8, INW2( 7 ) ); \
		a9  = _mm_xor_si128( g9,  sc->buffer[ ptr16 ][0] ); \
		a10 = _mm_xor_si128( g10, sc->buffer[ ptr16 ][1] ); \
		a11 = _mm_xor_si128( g11, sc->buffer[ ptr16 ][2] ); \
		a12 = _mm_xor_si128( g12, sc->buffer[ ptr16 ][3] ); \
		a13 = _mm_xor_si128( g13, sc->buffer[ ptr16 ][4] ); \
		a14 = _mm_xor_si128( g14, sc->buffer[ ptr16 ][5] ); \
		a15 = _mm_xor_si128( g15, sc->buffer[ ptr16 ][6] ); \
		a16 = _mm_xor_si128( g16, sc->buffer[ ptr16 ][7] ); \
	} while (0)

#define PANAMA_STEP_4W   do { \
		unsigned ptr16, ptr24, ptr31; \
 \
		ptr24 = (ptr0 - 8) & 31; \
		ptr31 = (ptr0 - 1) & 31; \
		BUPDATE_4W; \
		M17( GAMMA_4W ); \
		PI_ALL_4W; \
		M17( THETA_4W ); \
		ptr16 = ptr0 ^ 16; \
		SIGMA_ALL_4W; \
		ptr0 = ptr31; \
	} while (0)

static void
panama_4way_push( panama_4way_context *sc, const unsigned char *pbuf,
                  size_t num )
{
	LVARS_4W
	unsigned ptr0;

#define INW1(i)   casti_m128i( pbuf, i )
#define INW2(i)   INW1(i)

	M17( RSTATE );
   ptr0 = sc->buffer_ptr;
	while ( num-- > 0 )
   {
		PANAMA_STEP_4W;
		pbuf = (const unsigned char *)pbuf + 32*4;
	}
	M17( WSTATE );
	sc->buffer_ptr = ptr0;

#undef INW1
#undef INW2
}

/*
 * Perform the "pull" operation repeatedly ("num" times). The hash output
 * will be extracted from the state afterwards.
 */
static void
panama_4way_pull( panama_4way_context *sc, unsigned num )
{
	LVARS_4W
	unsigned ptr0;
#define INW1(i)     INW_H1(INC ## i)
#define INW_H1(i)   INW_H2(i)
#define INW_H2(i)   a ## i
#define INW2(i)     casti_m128i( sc->buffer[ptr4], i )

	M17( RSTATE );
   ptr0 = sc->buffer_ptr;
   while ( num-- > 0 )
   {
		unsigned ptr4;
		ptr4 = ( (ptr0 + 4) & 31 );
      PANAMA_STEP_4W;
	}
	M17( WSTATE );

#undef INW1
#undef INW_H1
#undef INW_H2
#undef INW2
}

void
panama_4way_init( void *cc )
{
	panama_4way_context *sc;

	sc = cc;
	sc->data_ptr = 0;
	memset( sc->buffer, 0, sizeof sc->buffer );
	sc->buffer_ptr = 0;
	memset( sc->state, 0, sizeof sc->state );
}

static void
panama_4way_short( void *cc, const void *data, size_t len )
{
	panama_4way_context *sc;
	unsigned current;
	sc = cc;
	current = sc->data_ptr;
	while ( len > 0 )
   {
		unsigned clen;

		clen = ( (sizeof sc->data ) >> 2 ) - current;
		if (clen > len)
			clen = len;

      memcpy( sc->data + (current << 2), data, clen << 2 );
		data = (const unsigned char *)data + ( clen << 2 );
		len -= clen;
		current += clen;
		if (current == ( (sizeof sc->data) >> 2 ) )
      {
			current = 0;
			panama_4way_push( sc, sc->data, 1 );
		}
	}

   sc->data_ptr = current;
}

void
panama_4way_update( void *cc, const void *data, size_t len )
{
	panama_4way_context *sc;
	unsigned current;
	size_t rlen;

	if ( len < ( 2 * ( (sizeof sc->data ) >> 2 ) ) )
   {
		panama_4way_short( cc, data, len );
		return;
	}
	sc = cc;
	current = sc->data_ptr;
	if ( current > 0 )
   {
		unsigned t;

		t = ( (sizeof sc->data) >> 2 ) -  current;
		panama_4way_short(sc, data, t);
		data = (const unsigned char *)data + ( t << 2 );
		len -= t;
	}

   panama_4way_push( sc, data, len >> 5 );

   rlen = len & 31;
	if ( rlen > 0 )
      memcpy_128( (__m128i*)sc->data, (__m128i*)data  + len - rlen, rlen );

	sc->data_ptr = rlen;
}

void
panama_4way_close( void *cc, void *dst )
{
	panama_4way_context *sc;
	unsigned current;
	int i;

	sc = cc;
	current = sc->data_ptr;
	*(__m128i*)( sc->data + current ) = m128_one_32;
   current++;
   memset_zero_128( (__m128i*)sc->data + current, 32 - current );
   panama_4way_push( sc, sc->data, 1 );
   panama_4way_pull( sc, 32 );
   for ( i = 0; i < 8; i ++ )
      casti_m128i( dst, i ) = sc->state[i + 9];
}


#if defined(__AVX2__)

///////////////////////
//
//    Panama-256 8 way AVX2

#define LVAR17_8W(b)  __m256i \
   b ## 0, b ## 1, b ## 2, b ## 3, b ## 4, b ## 5, \
   b ## 6, b ## 7, b ## 8, b ## 9, b ## 10, b ## 11, \
   b ## 12, b ## 13, b ## 14, b ## 15, b ## 16;

#define LVARS_8W   \
   LVAR17_8W(a) \
   LVAR17_8W(g)

#define BUPDATE1_8W( n0, n2 ) \
do { \
   sc->buffer[ptr24][n0] = _mm256_xor_si256( sc->buffer[ptr24][n0], \
                                             sc->buffer[ptr31][n2] ); \
   sc->buffer[ptr31][n2] = _mm256_xor_si256( sc->buffer[ptr31][n2], INW1(n2) ); \
} while (0)

#define BUPDATE_8W \
do { \
      BUPDATE1_8W( 0, 2 ); \
      BUPDATE1_8W( 1, 3 ); \
      BUPDATE1_8W( 2, 4 ); \
      BUPDATE1_8W( 3, 5 ); \
      BUPDATE1_8W( 4, 6 ); \
      BUPDATE1_8W( 5, 7 ); \
      BUPDATE1_8W( 6, 0 ); \
      BUPDATE1_8W( 7, 1 ); \
} while (0)

#if defined(__AVX512VL__)

#define GAMMA_8W(n0, n1, n2, n4)   \
   ( g ## n0 = _mm256_ternarylogic_epi32( a ## n0, a ## n2, a ## n1, 0x4b ) )  

#define THETA_8W(n0, n1, n2, n4)   \
   ( g ## n0 = mm256_xor3( a ## n0, a ## n1, a ## n4 ) )   

#else

#define GAMMA_8W(n0, n1, n2, n4)   \
   (g ## n0 = _mm256_xor_si256( a ## n0, \
                         _mm256_or_si256( a ## n1, mm256_not( a ## n2 ) ) ) )

#define THETA_8W(n0, n1, n2, n4)   \
   ( g ## n0 = _mm256_xor_si256( a ## n0, _mm256_xor_si256( a ## n1, \
                                                            a ## n4 ) ) )

#endif

#define PI_ALL_8W   do { \
      a0  = g0; \
      a1  = mm256_rol_32( g7,   1 ); \
      a2  = mm256_rol_32( g14,  3 ); \
      a3  = mm256_rol_32( g4,   6 ); \
      a4  = mm256_rol_32( g11, 10 ); \
      a5  = mm256_rol_32( g1,  15 ); \
      a6  = mm256_rol_32( g8,  21 ); \
      a7  = mm256_rol_32( g15, 28 ); \
      a8  = mm256_rol_32( g5,   4 ); \
      a9  = mm256_rol_32( g12, 13 ); \
      a10 = mm256_rol_32( g2,  23 ); \
      a11 = mm256_rol_32( g9,   2 ); \
      a12 = mm256_rol_32( g16, 14 ); \
      a13 = mm256_rol_32( g6,  27 ); \
      a14 = mm256_rol_32( g13,  9 ); \
      a15 = mm256_rol_32( g3,  24 ); \
      a16 = mm256_rol_32( g10,  8 ); \
   } while (0)


#define SIGMA_ALL_8W   do { \
      a0  = _mm256_xor_si256( g0, m256_one_32 ); \
      a1  = _mm256_xor_si256( g1, INW2( 0 ) ); \
      a2  = _mm256_xor_si256( g2, INW2( 1 ) ); \
      a3  = _mm256_xor_si256( g3, INW2( 2 ) ); \
      a4  = _mm256_xor_si256( g4, INW2( 3 ) ); \
      a5  = _mm256_xor_si256( g5, INW2( 4 ) ); \
      a6  = _mm256_xor_si256( g6, INW2( 5 ) ); \
      a7  = _mm256_xor_si256( g7, INW2( 6 ) ); \
      a8  = _mm256_xor_si256( g8, INW2( 7 ) ); \
      a9  = _mm256_xor_si256( g9,  sc->buffer[ ptr16 ][0] ); \
      a10 = _mm256_xor_si256( g10, sc->buffer[ ptr16 ][1] ); \
      a11 = _mm256_xor_si256( g11, sc->buffer[ ptr16 ][2] ); \
      a12 = _mm256_xor_si256( g12, sc->buffer[ ptr16 ][3] ); \
      a13 = _mm256_xor_si256( g13, sc->buffer[ ptr16 ][4] ); \
      a14 = _mm256_xor_si256( g14, sc->buffer[ ptr16 ][5] ); \
      a15 = _mm256_xor_si256( g15, sc->buffer[ ptr16 ][6] ); \
      a16 = _mm256_xor_si256( g16, sc->buffer[ ptr16 ][7] ); \
   } while (0)

#define PANAMA_STEP_8W   do { \
      unsigned ptr16, ptr24, ptr31; \
 \
      ptr24 = (ptr0 - 8) & 31; \
      ptr31 = (ptr0 - 1) & 31; \
      BUPDATE_8W; \
      M17( GAMMA_8W ); \
      PI_ALL_8W; \
      M17( THETA_8W ); \
      ptr16 = ptr0 ^ 16; \
      SIGMA_ALL_8W; \
      ptr0 = ptr31; \
   } while (0)

static void
panama_8way_push( panama_8way_context *sc, const unsigned char *pbuf,
                  size_t num )
{
   LVARS_8W
   unsigned ptr0;

#define INW1(i)   casti_m256i( pbuf, i )
#define INW2(i)   INW1(i)

   M17( RSTATE );
   ptr0 = sc->buffer_ptr;
   while ( num-- > 0 )
   {
      PANAMA_STEP_8W;
      pbuf = (const unsigned char *)pbuf + 32*8;
   }
   M17( WSTATE );
   sc->buffer_ptr = ptr0;

#undef INW1
#undef INW2
}

static void
panama_8way_pull( panama_8way_context *sc, unsigned num )
{
   LVARS_8W
   unsigned ptr0;
#define INW1(i)     INW_H1(INC ## i)
#define INW_H1(i)   INW_H2(i)
#define INW_H2(i)   a ## i
#define INW2(i)     casti_m256i( sc->buffer[ptr4], i )

   M17( RSTATE );

   ptr0 = sc->buffer_ptr;

   while ( num-- > 0 )
   {
      unsigned ptr4;
      ptr4 = ( (ptr0 + 4) & 31 );
      PANAMA_STEP_8W;
   }
   M17( WSTATE );

#undef INW1
#undef INW_H1
#undef INW_H2
#undef INW2
}

void
panama_8way_init( void *cc )
{
   panama_8way_context *sc;

   sc = cc;
   sc->data_ptr = 0;
   memset( sc->buffer, 0, sizeof sc->buffer );
   sc->buffer_ptr = 0;
   memset( sc->state, 0, sizeof sc->state );
}

static void
panama_8way_short( void *cc, const void *data, size_t len )
{
   panama_8way_context *sc;
   unsigned current;
   sc = cc;
   current = sc->data_ptr;
   while ( len > 0 )
   {
      unsigned clen;

      clen = ( (sizeof sc->data ) >> 3 ) - current;
      if (clen > len)
         clen = len;

      memcpy( sc->data + (current << 3), data, clen << 3 );
      data = (const unsigned char *)data + ( clen << 3 );
      len -= clen;
      current += clen;
      if (current == ( (sizeof sc->data) >> 3 ) )
      {
         current = 0;
         panama_8way_push( sc, sc->data, 1 );
      }
   }
   sc->data_ptr = current;
}

void
panama_8way_update( void *cc, const void *data, size_t len )
{
   panama_8way_context *sc;
   unsigned current;
   size_t rlen;

   if ( len < ( 2 * ( (sizeof sc->data ) >> 3 ) ) )
   {
      panama_8way_short( cc, data, len );
      return;
   }
   sc = cc;
   current = sc->data_ptr;
   if ( current > 0 )
   {
      unsigned t;

      t = ( (sizeof sc->data) >> 3 ) -  current;
      panama_8way_short(sc, data, t);
      data = (const unsigned char *)data + ( t << 3 );
      len -= t;
   }

   panama_8way_push( sc, data, len >> 5 );

   rlen = len & 31;
   if ( rlen > 0 )
      memcpy_256( (__m256i*)sc->data, (__m256i*)data  + len - rlen, rlen );

   sc->data_ptr = rlen;
}

void
panama_8way_close( void *cc, void *dst )
{
   panama_8way_context *sc;
   unsigned current;
   int i;

   sc = cc;
   current = sc->data_ptr;
   *(__m256i*)( sc->data + current ) = m256_one_32;
   current++;
   memset_zero_256( (__m256i*)sc->data + current, 32 - current );
   panama_8way_push( sc, sc->data, 1 );
   panama_8way_pull( sc, 32 );

   for ( i = 0; i < 8; i ++ )
      casti_m256i( dst, i ) = sc->state[i + 9];
}

#endif
