#if !defined(INTRLV_SSE2_H__)
#define INTRLV_SSE2_H__ 1

// Don't call __mm_extract_epi32 directly, it needs SSE4.1.
// Use mm128_extr_32 wrapper instead, it has both SSE4.1 & SSE2 covered.

#if  defined(__SSE2__)

///////////////////////////////////////////////////////////////
//
//           SSE2 128 bit vectors


// Macros to abstract typecasting

// Interleave lanes 
#define mm128_put_64( s0, s1) \
  _mm_set_epi64x( *((const uint64_t*)(s1)), *((const uint64_t*)(s0)) )

#define mm128_put_32( s0, s1, s2, s3 ) \
  _mm_set_epi32( *((const uint32_t*)(s3)), *((const uint32_t*)(s2)), \
                 *((const uint32_t*)(s1)), *((const uint32_t*)(s0)) )

// Deinterleave lanes
#define mm128_get_64( s, i0, i1 ) \
  _mm_set_epi64x( ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm128_get_32( s, i0, i1, i2, i3 ) \
  _mm_set_epi32( ((const uint32_t*)(s))[i3], ((const uint32_t*)(s))[i2], \
                 ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

// blend 2 vectors while interleaving: { hi[n], lo[n-1], ... hi[1], lo[0] }
#define mm128_intrlv_blend_64( hi, lo ) \
                _mm256_blend_epi16( hi, lo, 0x0f )
#define mm128_intrlv_blend_32( hi, lo ) \
                _mm6_blend_epi16( hi, lo, 0x33 )

// 1 sse2 block, 16 x 16 bytes

#define mm128_intrlv_4x32_128( d, s0, s1, s2, s3 )\
do { \
   casti_m128i( d,0 ) = _mm_set_epi32( \
                            mm128_extr_32( s3, 0 ), mm128_extr_32( s2, 0 ), \
                            mm128_extr_32( s1, 0 ), mm128_extr_32( s0, 0 ) ); \
   casti_m128i( d,1 ) = _mm_set_epi32( \
                            mm128_extr_32( s3, 1 ), mm128_extr_32( s2, 1 ), \
                            mm128_extr_32( s1, 1 ), mm128_extr_32( s0, 1 ) ); \
   casti_m128i( d,2 ) = _mm_set_epi32( \
                            mm128_extr_32( s3, 2 ), mm128_extr_32( s2, 2 ), \
                            mm128_extr_32( s1, 2 ), mm128_extr_32( s0, 2 ) ); \
   casti_m128i( d,3 ) = _mm_set_epi32( \
                            mm128_extr_32( s3, 3 ), mm128_extr_32( s2, 3 ), \
                            mm128_extr_32( s1, 3 ), mm128_extr_32( s0, 3 ) ); \
} while(0)

static inline void mm128_dintrlv_4x32_128( void *d0, void *d1, void *d2,
                                           void *d3, const void *src )
{
   __m128i s0 = *(__m128i*) src;
   __m128i s1 = *(__m128i*)(src+16);
   __m128i s2 = *(__m128i*)(src+32);
   __m128i s3 = *(__m128i*)(src+48);

   *(__m128i*)d0 = _mm_set_epi32(
                     mm128_extr_32( s3,0 ), mm128_extr_32( s2,0 ),
                     mm128_extr_32( s1,0 ), mm128_extr_32( s0,0 ) );
   *(__m128i*)d1 = _mm_set_epi32(
                     mm128_extr_32( s3,1 ), mm128_extr_32( s2,1 ),
                     mm128_extr_32( s1,1 ), mm128_extr_32( s0,1 ) );
   *(__m128i*)d2 = _mm_set_epi32(
                     mm128_extr_32( s3,2 ), mm128_extr_32( s2,2 ),
                     mm128_extr_32( s1,2 ), mm128_extr_32( s0,2 ) );
   *(__m128i*)d3 = _mm_set_epi32(
                     mm128_extr_32( s3,3 ), mm128_extr_32( s2,3 ),
                     mm128_extr_32( s1,3 ), mm128_extr_32( s0,3 ) );
}

static inline void mm128_intrlv_2x64x128( void *d, const void *s0,
                       const void *s1 )
{
  casti_m128i( d,0 ) = mm128_put_64( s0,    s1    );
  casti_m128i( d,1 ) = mm128_put_64( s0+ 8, s1+ 8 );
  casti_m128i( d,2 ) = mm128_put_64( s0+16, s1+16 );
  casti_m128i( d,3 ) = mm128_put_64( s0+24, s1+24 );
}

#define mm128_bswap_intrlv_4x32_128( d, src ) \
do { \
  __m128i ss = mm128_bswap_32( src );\
  casti_m128i( d,0 ) = _mm_set1_epi32( mm128_extr_32( ss, 0 ) ); \
  casti_m128i( d,1 ) = _mm_set1_epi32( mm128_extr_32( ss, 1 ) ); \
  casti_m128i( d,2 ) = _mm_set1_epi32( mm128_extr_32( ss, 2 ) ); \
  casti_m128i( d,3 ) = _mm_set1_epi32( mm128_extr_32( ss, 3 ) ); \
} while(0)


//
// User functions.

// interleave 4 arrays of 32 bit elements for 128 bit processing
// bit_len must be 256, 512 or 640 bits.
static inline void mm128_intrlv_4x32( void *d, const void *s0,
               const void *s1, const void *s2, const void *s3, int bit_len )
{
   mm128_intrlv_4x32_128( d    , casti_m128i(s0,0), casti_m128i(s1,0),
                                 casti_m128i(s2,0), casti_m128i(s3,0) );
   mm128_intrlv_4x32_128( d+ 64, casti_m128i(s0,1), casti_m128i(s1,1),   
                                 casti_m128i(s2,1), casti_m128i(s3,1) );   
   if ( bit_len <= 256 ) return;
   mm128_intrlv_4x32_128( d+128, casti_m128i(s0,2), casti_m128i(s1,2),
                                 casti_m128i(s2,2), casti_m128i(s3,2) );
   mm128_intrlv_4x32_128( d+192, casti_m128i(s0,3), casti_m128i(s1,3),
                                 casti_m128i(s2,3), casti_m128i(s3,3) );
   if ( bit_len <= 512 ) return;
   mm128_intrlv_4x32_128( d+256, casti_m128i(s0,4), casti_m128i(s1,4),
                                 casti_m128i(s2,4), casti_m128i(s3,4) );
   if ( bit_len <= 640 ) return;
   mm128_intrlv_4x32_128( d+320, casti_m128i(s0,5), casti_m128i(s1,5),
                                 casti_m128i(s2,5), casti_m128i(s3,5) );
   mm128_intrlv_4x32_128( d+384, casti_m128i(s0,6), casti_m128i(s1,6),
                                 casti_m128i(s2,6), casti_m128i(s3,6) );
   mm128_intrlv_4x32_128( d+448, casti_m128i(s0,7), casti_m128i(s1,7),
                                 casti_m128i(s2,7), casti_m128i(s3,7) );
   // bit_len == 1024
}

// Still used by decred due to odd data size: 180 bytes
// bit_len must be multiple of 32
static inline void mm128_intrlv_4x32x( void *dst, void *src0, void  *src1,
                                        void *src2, void *src3, int bit_len )
{
   uint32_t *d  = (uint32_t*)dst;
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;

   for ( int i = 0; i < bit_len >> 5; i++, d += 4 )
   {
      *d     = *(s0+i);
      *(d+1) = *(s1+i);
      *(d+2) = *(s2+i);
      *(d+3) = *(s3+i);
   }
}

static inline void mm128_dintrlv_4x32( void *d0, void *d1, void *d2,
                                       void *d3, const void *s, int bit_len )
{
   mm128_dintrlv_4x32_128( d0    , d1    , d2    , d3    , s     );
   mm128_dintrlv_4x32_128( d0+ 16, d1+ 16, d2+ 16, d3+ 16, s+ 64 );
   if ( bit_len <= 256 ) return;
   mm128_dintrlv_4x32_128( d0+ 32, d1+ 32, d2+ 32, d3+ 32, s+128 );
   mm128_dintrlv_4x32_128( d0+ 48, d1+ 48, d2+ 48, d3+ 48, s+192 );
   if ( bit_len <= 512 ) return;
   mm128_dintrlv_4x32_128( d0+ 64, d1+ 64, d2+ 64, d3+ 64, s+256 );
   if ( bit_len <= 640 ) return;
   mm128_dintrlv_4x32_128( d0+ 80, d1+ 80, d2+ 80, d3+ 80, s+320 );
   mm128_dintrlv_4x32_128( d0+ 96, d1+ 96, d2+ 96, d3+ 96, s+384 );
   mm128_dintrlv_4x32_128( d0+112, d1+112, d2+112, d3+112, s+448 );
   // bit_len == 1024
}

// extract and deinterleave specified lane.
static inline void mm128_extr_lane_4x32( void *d, const void *s,
                                         const int lane, const int bit_len )
{
  casti_m128i( d, 0 ) =
             mm128_get_32( s, lane   , lane+ 4, lane+ 8, lane+12 );
  casti_m128i( d, 1 ) =
             mm128_get_32( s, lane+16, lane+20, lane+24, lane+28 );
  if ( bit_len <= 256 ) return;
  casti_m128i( d, 2 ) =
             mm128_get_32( s, lane+32, lane+36, lane+40, lane+44 );
  casti_m128i( d, 3 ) =
             mm128_get_32( s, lane+48, lane+52, lane+56, lane+60 );
  // bit_len == 512
}

// Interleave 80 bytes of 32 bit data for 4 lanes.
static inline void mm128_bswap_intrlv80_4x32( void *d, const void *s )
{
   mm128_bswap_intrlv_4x32_128( d    , casti_m128i( s, 0 ) );
   mm128_bswap_intrlv_4x32_128( d+ 64, casti_m128i( s, 1 ) );
   mm128_bswap_intrlv_4x32_128( d+128, casti_m128i( s, 2 ) );
   mm128_bswap_intrlv_4x32_128( d+192, casti_m128i( s, 3 ) );
   mm128_bswap_intrlv_4x32_128( d+256, casti_m128i( s, 4 ) );
}

#endif // SSE2
#endif // INTRLV_SSE2_H__

