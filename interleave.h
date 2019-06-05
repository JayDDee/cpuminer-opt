#ifndef INTERLEAVE_H__
#define INTERLEAVE_H__ 1

#include "avxdefs.h"

// Paired functions for interleaving and deinterleaving data for vector
// processing. 
// Size is specfied in bits regardless of vector size to avoid pointer
// arithmetic confusion with different size vectors and be consistent with
// the function's name. 
//
// Each function has 2 implementations, an optimized version that uses
// vector indexing and a slower version that uses pointers. The optimized
// version can only be used with 64 bit elements and only supports sizes
// of 256, 512 or 640 bits, 32, 64, and 80 bytes respectively.
//
// All data must be aligned to 256 bits for AVX2, or 128 bits for SSE2.
// Interleave source args and deinterleave destination args are not required
// to be contiguous in memory but it's more efficient if they are.
// Interleave source agrs may be the same actual arg repeated.
// 640 bit deinterleaving 4x64 using 256 bit AVX2 requires the
// destination buffers be defined with padding up to 768 bits for overrun
// space. Although overrun space use is non destructive it should not overlay
// useful data and should be ignored by the caller.

// These utilities support converting multiple streams of scalar data into
// interleaved parallel vectors for SIMD processing.
//
// There are three key variables: data width, data length and vector width.
//
// Data width: 32, 64 or 128 bits.
//
// Data length: 256, 512, 640, or 1024 bits (32, 64, 80, 128 bytes).
// 
// Vector width: 128 bits SSE2, 256 bits AVX2, 512 bits AVX512.
//
// Interleaving and deinterleaving is supported for the following sizes
// depending on the available technology (nlanes x datawidth):
//
// SSE2: 2x64 or 4x32
//
// AVX2: 2x128, 4x64, 8x32
//
// AVX512: 4x128, 8x64, 16x32
//
// Interleaving and deinterleaving is done in blocks of 8*8, 16*16, 32*32,
// or 64*64 bytes for MMX, SSE2, AVX2 and AVX512 vectors respectively.

//////////////////////////////////////////////////////
// 
//          MMX 64 bit vectors

#define mm64_put_32( s0, s1 ) \
  _mm_set_pi32( *((const uint32_t*)(s1)), *((const uint32_t*)(s0)) )

#define mm64_get_32( s, i0, i1 ) \
  _mm_set_pi32( ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

// 1 MMX block, 8 bytes * 2 lanes
static inline void mm64_interleave_2x32( void *d, const void *s0,
                                         const void *s1, int len )
{
  casti_m64( d, 0 ) = mm64_put_32( s0    , s1     );
  casti_m64( d, 1 ) = mm64_put_32( s0+  4, s1+  4 );
  casti_m64( d, 2 ) = mm64_put_32( s0+  8, s1+  8 );
  casti_m64( d, 3 ) = mm64_put_32( s0+ 12, s1+ 12 );
  casti_m64( d, 4 ) = mm64_put_32( s0+ 16, s1+ 16 );
  casti_m64( d, 5 ) = mm64_put_32( s0+ 20, s1+ 20 );
  casti_m64( d, 6 ) = mm64_put_32( s0+ 24, s1+ 24 );
  casti_m64( d, 7 ) = mm64_put_32( s0+ 28, s1+ 28 );

  if ( len <= 256 ) return;

  casti_m64( d, 8 ) = mm64_put_32( s0+ 32, s1+ 32 );
  casti_m64( d, 9 ) = mm64_put_32( s0+ 36, s1+ 36 );
  casti_m64( d,10 ) = mm64_put_32( s0+ 40, s1+ 40 );
  casti_m64( d,11 ) = mm64_put_32( s0+ 44, s1+ 44 );
  casti_m64( d,12 ) = mm64_put_32( s0+ 48, s1+ 48 );
  casti_m64( d,13 ) = mm64_put_32( s0+ 52, s1+ 52 );
  casti_m64( d,14 ) = mm64_put_32( s0+ 56, s1+ 56 );
  casti_m64( d,15 ) = mm64_put_32( s0+ 60, s1+ 60 );

  if ( len <= 512 ) return;

  casti_m64( d,16 ) = mm64_put_32( s0+ 64, s1+ 64 );
  casti_m64( d,17 ) = mm64_put_32( s0+ 68, s1+ 68 );
  casti_m64( d,18 ) = mm64_put_32( s0+ 72, s1+ 72 );
  casti_m64( d,19 ) = mm64_put_32( s0+ 76, s1+ 76 );

  if ( len <= 640 ) return;

  casti_m64( d,20 ) = mm64_put_32( s0+ 80, s1+ 80 );
  casti_m64( d,21 ) = mm64_put_32( s0+ 84, s1+ 84 );
  casti_m64( d,22 ) = mm64_put_32( s0+ 88, s1+ 88 );
  casti_m64( d,23 ) = mm64_put_32( s0+ 92, s1+ 92 );
  casti_m64( d,24 ) = mm64_put_32( s0+ 96, s1+ 96 );
  casti_m64( d,25 ) = mm64_put_32( s0+100, s1+100 );
  casti_m64( d,26 ) = mm64_put_32( s0+104, s1+104 );
  casti_m64( d,27 ) = mm64_put_32( s0+108, s1+108 );
  casti_m64( d,28 ) = mm64_put_32( s0+112, s1+112 );
  casti_m64( d,29 ) = mm64_put_32( s0+116, s1+116 );
  casti_m64( d,30 ) = mm64_put_32( s0+120, s1+120 );
  casti_m64( d,31 ) = mm64_put_32( s0+124, s1+124 );
}

static inline void mm64_deinterleave_2x32( void *d00, void *d01,
                                    const int n, const void *s, int len )
{
   casti_m64( d00,0 ) = mm64_get_32( s,  0,  2 );
   casti_m64( d01,0 ) = mm64_get_32( s,  1,  3 );
   casti_m64( d00,1 ) = mm64_get_32( s,  4,  6 );
   casti_m64( d01,1 ) = mm64_get_32( s,  5,  7 );
   casti_m64( d00,2 ) = mm64_get_32( s,  8, 10 );
   casti_m64( d01,2 ) = mm64_get_32( s,  9, 11 );
   casti_m64( d00,3 ) = mm64_get_32( s, 12, 14 );
   casti_m64( d01,3 ) = mm64_get_32( s, 13, 15 );

   if ( len <= 256 ) return;

   casti_m64( d00,4 ) = mm64_get_32( s, 16, 18 );
   casti_m64( d01,4 ) = mm64_get_32( s, 17, 19 );
   casti_m64( d00,5 ) = mm64_get_32( s, 20, 22 );
   casti_m64( d01,5 ) = mm64_get_32( s, 21, 23 );
   casti_m64( d00,6 ) = mm64_get_32( s, 24, 26 );
   casti_m64( d01,6 ) = mm64_get_32( s, 25, 27 );
   casti_m64( d00,7 ) = mm64_get_32( s, 28, 30 );
   casti_m64( d01,7 ) = mm64_get_32( s, 29, 31 );

   if ( len <= 512 ) return;

   casti_m64( d00,8 ) = mm64_get_32( s, 32, 34 );
   casti_m64( d01,8 ) = mm64_get_32( s, 33, 35 );
   casti_m64( d00,9 ) = mm64_get_32( s, 36, 38 );
   casti_m64( d01,9 ) = mm64_get_32( s, 37, 39 );

   if ( len <= 640 ) return;

   casti_m64( d00,10 ) = mm64_get_32( s, 40, 42 );
   casti_m64( d01,10 ) = mm64_get_32( s, 41, 43 );
   casti_m64( d00,11 ) = mm64_get_32( s, 44, 46 );
   casti_m64( d01,11 ) = mm64_get_32( s, 45, 47 );
   casti_m64( d00,12 ) = mm64_get_32( s, 48, 50 );
   casti_m64( d01,12 ) = mm64_get_32( s, 49, 51 );
   casti_m64( d00,13 ) = mm64_get_32( s, 52, 54 );
   casti_m64( d01,13 ) = mm64_get_32( s, 53, 55 );
   casti_m64( d00,14 ) = mm64_get_32( s, 56, 58 );
   casti_m64( d01,14 ) = mm64_get_32( s, 57, 59 );
   casti_m64( d00,15 ) = mm64_get_32( s, 60, 62 );
   casti_m64( d01,15 ) = mm64_get_32( s, 61, 63 );
}

static inline void mm64_extract_lane_2x32( void *d, const void *s,
                                         const int lane, const int bit_len )
{
  casti_m64( d, 0 ) = mm64_get_32( s, lane   , lane+ 4 );
  casti_m64( d, 1 ) = mm64_get_32( s, lane+ 8, lane+12 );
  casti_m64( d, 2 ) = mm64_get_32( s, lane+16, lane+20 );
  casti_m64( d, 3 ) = mm64_get_32( s, lane+24, lane+28 );

  if ( bit_len <= 256 ) return;
  casti_m64( d, 4 ) = mm64_get_32( s, lane+32, lane+36 );
  casti_m64( d, 5 ) = mm64_get_32( s, lane+40, lane+44 );
  casti_m64( d, 6 ) = mm64_get_32( s, lane+48, lane+52 );
  casti_m64( d, 7 ) = mm64_get_32( s, lane+56, lane+60 );
  // bit_len == 512
}


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
#define mm128_interleave_blend_64( hi, lo ) \
                _mm256_blend_epi16( hi, lo, 0x0f )
#define mm128_interleave_blend_32( hi, lo ) \
                _mm6_blend_epi16( hi, lo, 0x33 )


// 1 sse2 block, 16 bytes * 4 lanes
static inline void mm128_interleave_4x32x128( void *d, const void *s0,
                       const void *s1, const void *s2, const void *s3 )
{
  casti_m128i( d,0 ) = mm128_put_32( s0,    s1,    s2,    s3    );
  casti_m128i( d,1 ) = mm128_put_32( s0+ 4, s1+ 4, s2+ 4, s3+ 4 );
  casti_m128i( d,2 ) = mm128_put_32( s0+ 8, s1+ 8, s2+ 8, s3+ 8 );
  casti_m128i( d,3 ) = mm128_put_32( s0+12, s1+12, s2+12, s3+12 );
}

static inline void mm128_deinterleave_4x32x128( void *d00, void *d01,
        void *d02, void *d03, const int n, const void *s )
{
   casti_m128i( d00,n ) = mm128_get_32( s, 0, 4,  8, 12 );
   casti_m128i( d01,n ) = mm128_get_32( s, 1, 5,  9, 13 );
   casti_m128i( d02,n ) = mm128_get_32( s, 2, 6, 10, 14 );
   casti_m128i( d03,n ) = mm128_get_32( s, 3, 7, 11, 15 );
}

static inline void mm128_interleave_2x64xi128( void *d, const void *s0,
                       const void *s1 )
{
  casti_m128i( d,0 ) = mm128_put_64( s0,    s1    );
  casti_m128i( d,1 ) = mm128_put_64( s0+ 8, s1+ 8 );
  casti_m128i( d,2 ) = mm128_put_64( s0+16, s1+16 );
  casti_m128i( d,3 ) = mm128_put_64( s0+24, s1+24 );
}

// Used for AVX2 interleaving

// AVX2 block is 32 * 32 bytes

// half avx2 block, 16 bytes * 8 lanes
static inline void mm128_deinterleave_8x32x128( void *d00, void *d01,
               void *d02, void *d03, void *d04, void *d05, void *d06,
	       void *d07, const int n, const void *s )
{
   casti_m128i( d00, n ) = mm128_get_32( s, 0,  8, 16, 24 );
   casti_m128i( d01, n ) = mm128_get_32( s, 1,  9, 17, 25 );
   casti_m128i( d02, n ) = mm128_get_32( s, 2, 10, 18, 26 );
   casti_m128i( d03, n ) = mm128_get_32( s, 3, 11, 19, 27 );
   casti_m128i( d04, n ) = mm128_get_32( s, 4, 12, 20, 28 );
   casti_m128i( d05, n ) = mm128_get_32( s, 5, 13, 21, 29 );
   casti_m128i( d06, n ) = mm128_get_32( s, 6, 14, 22, 30 );
   casti_m128i( d07, n ) = mm128_get_32( s, 7, 15, 23, 31 );
}

// quarter avx2 block, 16 bytes * 4 lanes
// 4 lanes of 128 bits using 64 bit interleaving
// Used for last 16 bytes of 80 byte input, only used for testing.
static inline void mm128_deinterleave_4x64x128( void *d0, void *d1, void *d2,
                                        void *d3, const int n, const void *s )
{
   casti_m128i( d0,n ) = mm128_get_64( s, 0, 4 );
   casti_m128i( d1,n ) = mm128_get_64( s, 1, 5 );
   casti_m128i( d2,n ) = mm128_get_64( s, 2, 6 );
   casti_m128i( d3,n ) = mm128_get_64( s, 3, 7 );
}

static inline void mm128_deinterleave_2x128x128( void *d0, void *d1,
                                                const int n, const void *s )
{
   casti_m128i( d0,n ) = mm128_get_64( s, 0, 1 );
   casti_m128i( d1,n ) = mm128_get_64( s, 2, 3 );
}


// Used for AVX512 interleaving

// AVX512 block is 64 * 64 bytes

// quarter avx512 block, 16 bytes * 16 lanes 
static inline void mm128_deinterleave_16x32x128( void *d00, void *d01,
        void *d02, void *d03, void *d04, void *d05, void *d06, void *d07,
        void *d08, void *d09, void *d10, void *d11, void *d12, void *d13,
        void *d14, void *d15, const int n, const void *s )
{
   cast_m128i( d00 ) = mm128_get_32( s, 0,  16, 32, 48 );
   cast_m128i( d01 ) = mm128_get_32( s, 1,  17, 33, 49 );
   cast_m128i( d02 ) = mm128_get_32( s, 2,  18, 34, 50 );
   cast_m128i( d03 ) = mm128_get_32( s, 3,  19, 35, 51 );
   cast_m128i( d04 ) = mm128_get_32( s, 4,  20, 36, 52 );
   cast_m128i( d05 ) = mm128_get_32( s, 5,  21, 37, 53 );
   cast_m128i( d06 ) = mm128_get_32( s, 6,  22, 38, 54 );
   cast_m128i( d07 ) = mm128_get_32( s, 7,  23, 39, 55 );
   cast_m128i( d08 ) = mm128_get_32( s, 8,  24, 40, 56 );
   cast_m128i( d09 ) = mm128_get_32( s, 9,  25, 41, 57 );
   cast_m128i( d10 ) = mm128_get_32( s, 10, 26, 42, 58 );
   cast_m128i( d11 ) = mm128_get_32( s, 11, 27, 43, 59 );
   cast_m128i( d12 ) = mm128_get_32( s, 12, 28, 44, 60 );
   cast_m128i( d13 ) = mm128_get_32( s, 13, 29, 45, 61 );
   cast_m128i( d14 ) = mm128_get_32( s, 14, 30, 46, 62 );
   cast_m128i( d15 ) = mm128_get_32( s, 15, 31, 47, 63 );
}

// quarter avx512 block, 32 bytes * 8 lanes
// 8 lanes of 128 bits using 64 bit interleaving
// Used for last 16 bytes of 80 byte input, only used for testing.
static inline void mm128_deinterleave_8x64x128( void *d0, void *d1, void *d2,
                         void *d3, void *d4, void *d5, void *d6, void *d7,
                         const int n, const void *s )
{
   casti_m128i( d0,n ) = mm128_get_64( s, 0,  8 );
   casti_m128i( d1,n ) = mm128_get_64( s, 1,  9 );
   casti_m128i( d2,n ) = mm128_get_64( s, 2, 10 );
   casti_m128i( d3,n ) = mm128_get_64( s, 3, 11 );
   casti_m128i( d4,n ) = mm128_get_64( s, 4, 12 );
   casti_m128i( d5,n ) = mm128_get_64( s, 5, 13 );
   casti_m128i( d6,n ) = mm128_get_64( s, 6, 14 );
   casti_m128i( d7,n ) = mm128_get_64( s, 7, 15 );
}

static inline void mm128_deinterleave_4x128x128( void *d0, void *d1, void *d2,
                                void *d3, const int n, const void *s )
{
   casti_m128i( d0,n ) = mm128_get_64( s, 0, 1 );
   casti_m128i( d1,n ) = mm128_get_64( s, 2, 3 );
   casti_m128i( d2,n ) = mm128_get_64( s, 4, 5 );
   casti_m128i( d3,n ) = mm128_get_64( s, 5, 7 );
}

//

// interleave 4 arrays of 32 bit elements for 128 bit processing
// bit_len must be 256, 512 or 640 bits.
static inline void mm128_interleave_4x32( void *d, const void *s0,
           const void *s1, const void *s2, const void *s3, int bit_len )
{
   mm128_interleave_4x32x128( d   , s0   , s1   , s2   , s3    );
   mm128_interleave_4x32x128( d+64, s0+16, s1+16, s2+16, s3+16 );
   if ( bit_len <= 256 ) return;
   mm128_interleave_4x32x128( d+128, s0+32, s1+32, s2+32, s3+32 );
   mm128_interleave_4x32x128( d+192, s0+48, s1+48, s2+48, s3+48 );
   if ( bit_len <= 512 ) return;
   mm128_interleave_4x32x128( d+256, s0+64, s1+64, s2+64, s3+64 );
   if ( bit_len <= 640 ) return;
   mm128_interleave_4x32x128( d+320, s0+ 80, s1+ 80, s2+ 80, s3+ 80 );
   mm128_interleave_4x32x128( d+384, s0+ 96, s1+ 96, s2+ 96, s3+ 96 );
   mm128_interleave_4x32x128( d+448, s0+112, s1+112, s2+112, s3+112 );
   // bit_len == 1024
}

// Still used by decred due to odd data size: 180 bytes
// bit_len must be multiple of 32
static inline void mm128_interleave_4x32x( void *dst, void *src0, void  *src1,
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

static inline void mm128_deinterleave_4x32( void *d0, void *d1, void *d2,
                                     void *d3, const void *s, int bit_len )
{
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 0, s     );
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 1, s+64 );
   if ( bit_len <= 256 ) return;
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 2, s+128 );
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 3, s+192 );
   if ( bit_len <= 512 ) return;
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 4, s+256 );
   if ( bit_len <= 640 ) return;
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 5, s+320 );
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 6, s+384 );
   mm128_deinterleave_4x32x128( d0, d1, d2, d3, 7, s+448 );
   // bit_len == 1024
}

// extract and deinterleave specified lane.
static inline void mm128_extract_lane_4x32( void *d, const void *s,
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

/*
// deinterleave 4 arrays into individual buffers for scalarm processing
// bit_len must be multiple of 32
static inline void mm128_deinterleave_4x32x( void *dst0, void *dst1, void *dst2,
                                    void *dst3, const void *src, int bit_len )
{
  uint32_t *s  = (uint32_t*)src;
  uint32_t *d0 = (uint32_t*)dst0;
  uint32_t *d1 = (uint32_t*)dst1;
  uint32_t *d2 = (uint32_t*)dst2;
  uint32_t *d3 = (uint32_t*)dst3;

  for ( int i = 0; i < bit_len >> 5; i++, s += 4 )
  {
     *(d0+i) = *s;
     *(d1+i) = *(s+1);
     *(d2+i) = *(s+2);
     *(d3+i) = *(s+3);
  }
}
*/

///////////////////////////////////////////////////////////
//
//          AVX2 256 Bit Vectors
//
#if defined (__AVX2__)

#define mm256_put_64( s0, s1, s2, s3) \
  _mm256_set_epi64x( *((const uint64_t*)(s3)), *((const uint64_t*)(s2)), \
                     *((const uint64_t*)(s1)), *((const uint64_t*)(s0)) )

#define mm256_put_32( s00, s01, s02, s03, s04, s05, s06, s07 ) \
  _mm256_set_epi32( *((const uint32_t*)(s07)), *((const uint32_t*)(s06)), \
                    *((const uint32_t*)(s05)), *((const uint32_t*)(s04)), \
                    *((const uint32_t*)(s03)), *((const uint32_t*)(s02)), \
                    *((const uint32_t*)(s01)), *((const uint32_t*)(s00)) )

#define mm256_get_64( s, i0, i1, i2, i3 ) \
  _mm256_set_epi64x( ((const uint64_t*)(s))[i3], ((const uint64_t*)(s))[i2], \
                     ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm256_get_32( s, i0, i1, i2, i3, i4, i5, i6, i7 ) \
  _mm256_set_epi32( ((const uint32_t*)(s))[i7], ((const uint32_t*)(s))[i6], \
                    ((const uint32_t*)(s))[i5], ((const uint32_t*)(s))[i4], \
                    ((const uint32_t*)(s))[i3], ((const uint32_t*)(s))[i2], \
                    ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )


// Blend 2 vectors alternating hi & lo: { hi[n], lo[n-1], ... hi[1], lo[0] }
#define mm256_interleave_blend_128( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x0f )

#define mm256_interleave_blend_64( hi, lo ) \
                _mm256_blend_epi32( hi, lo, 0x33 )

#define mm256_interleave_blend_32( hi, lo ) \
	        _mm256_blend_epi32( hi, lo, 0x55 )


// Used for AVX2 interleaving

static inline void mm256_interleave_8x32x256( void *d, const void *s00,
     const void *s01, const void *s02, const void *s03, const void *s04,
     const void *s05, const void *s06, const void *s07 )
{
   casti_m256i( d, 0 ) = mm256_put_32( s00,    s01,    s02,    s03,
                                       s04,    s05,    s06,    s07    );
   casti_m256i( d, 1 ) = mm256_put_32( s00+ 4, s01+ 4, s02+ 4, s03+ 4,
                                       s04+ 4, s05+ 4, s06+ 4, s07+ 4 );
   casti_m256i( d, 2 ) = mm256_put_32( s00+ 8, s01+ 8, s02+ 8, s03+ 8,
                                       s04+ 8, s05+ 8, s06+ 8, s07+ 8 );
   casti_m256i( d, 3 ) = mm256_put_32( s00+12, s01+12, s02+12, s03+12,
                                       s04+12, s05+12, s06+12, s07+12 );
   casti_m256i( d, 4 ) = mm256_put_32( s00+16, s01+16, s02+16, s03+16,
                                       s04+16, s05+16, s06+16, s07+16 );
   casti_m256i( d, 5 ) = mm256_put_32( s00+20, s01+20, s02+20, s03+20,
                                       s04+20, s05+20, s06+20, s07+20 );
   casti_m256i( d, 6 ) = mm256_put_32( s00+24, s01+24, s02+24, s03+24,
                                       s04+24, s05+24, s06+24, s07+24 );
   casti_m256i( d, 7 ) = mm256_put_32( s00+28, s01+28, s02+28, s03+28,
                                       s04+28, s05+28, s06+28, s07+28 );
}

static inline void mm256_be_interleave_8x32x256( void *d, const void *s00,
       const void *s01, const void *s02, const void *s03, const void *s04,
       const void *s05, const void *s06, const void *s07 )
{
   casti_m256i( d, 0 ) = mm256_bswap_32( 
		            mm256_put_32( s00,    s01,    s02,    s03,
                                          s04,    s05,    s06,    s07    ) );
   casti_m256i( d, 1 ) = mm256_bswap_32(
		            mm256_put_32( s00+ 4, s01+ 4, s02+ 4, s03+ 4,
                                          s04+ 4, s05+ 4, s06+ 4, s07+ 4 ) );
   casti_m256i( d, 2 ) = mm256_bswap_32(
	                    mm256_put_32( s00+ 8, s01+ 8, s02+ 8, s03+ 8,
                                          s04+ 8, s05+ 8, s06+ 8, s07+ 8 ) );
   casti_m256i( d, 3 ) = mm256_bswap_32(
	                    mm256_put_32( s00+12, s01+12, s02+12, s03+12,
                                          s04+12, s05+12, s06+12, s07+12 ) );
   casti_m256i( d, 4 ) = mm256_bswap_32(
	                    mm256_put_32( s00+16, s01+16, s02+16, s03+16,
                                          s04+16, s05+16, s06+16, s07+16 ) );
   casti_m256i( d, 5 ) = mm256_bswap_32(
	                    mm256_put_32( s00+20, s01+20, s02+20, s03+20,
                                          s04+20, s05+20, s06+20, s07+20 ) );
   casti_m256i( d, 6 ) = mm256_bswap_32(
	                    mm256_put_32( s00+24, s01+24, s02+24, s03+24,
                                          s04+24, s05+24, s06+24, s07+24 ) );
   casti_m256i( d, 7 ) = mm256_bswap_32(
	                    mm256_put_32( s00+28, s01+28, s02+28, s03+28,
                                          s04+28, s05+28, s06+28, s07+28 ) );
}

static inline void mm256_interleave_8x32x128( void *d, const void *s00,
     const void *s01, const void *s02, const void *s03, const void *s04,
     const void *s05, const void *s06, const void *s07 )
{
   casti_m256i( d, 0 ) = mm256_put_32( s00,    s01,    s02,    s03,
                                       s04,    s05,    s06,    s07    );
   casti_m256i( d, 1 ) = mm256_put_32( s00+ 4, s01+ 4, s02+ 4, s03+ 4,
                                       s04+ 4, s05+ 4, s06+ 4, s07+ 4 );
   casti_m256i( d, 2 ) = mm256_put_32( s00+ 8, s01+ 8, s02+ 8, s03+ 8,
                                       s04+ 8, s05+ 8, s06+ 8, s07+ 8 );
   casti_m256i( d, 3 ) = mm256_put_32( s00+12, s01+12, s02+12, s03+12,
                                       s04+12, s05+12, s06+12, s07+12 );
}

static inline void mm256_be_interleave_8x32x128( void *d, const void *s00,
       const void *s01, const void *s02, const void *s03, const void *s04,
       const void *s05, const void *s06, const void *s07 )
{
   casti_m256i( d, 0 ) = mm256_bswap_32( 
		            mm256_put_32( s00,    s01,    s02,    s03,
                                          s04,    s05,    s06,    s07    ) );
   casti_m256i( d, 1 ) = mm256_bswap_32(
	                    mm256_put_32( s00+ 4, s01+ 4, s02+ 4, s03+ 4,
                                          s04+ 4, s05+ 4, s06+ 4, s07+ 4 ) );
   casti_m256i( d, 2 ) = mm256_bswap_32(
	                    mm256_put_32( s00+ 8, s01+ 8, s02+ 8, s03+ 8,
                                          s04+ 8, s05+ 8, s06+ 8, s07+ 8 ) );
   casti_m256i( d, 3 ) = mm256_bswap_32(
	                    mm256_put_32( s00+12, s01+12, s02+12, s03+12,
                                          s04+12, s05+12, s06+12, s07+12 ) );
}

// can be called directly for 32 byte hash using AVX2
static inline void mm256_deinterleave_8x32x256( void *d00, void *d01,
	       void *d02, void *d03, void *d04, void *d05, void *d06,
	       void *d07, const int n, const void *s )
{
   casti_m256i( d00, n ) = mm256_get_32( s, 0,  8, 16, 24, 32, 40, 48, 56 );
   casti_m256i( d01, n ) = mm256_get_32( s, 1,  9, 17, 25, 33, 41, 49, 57 );
   casti_m256i( d02, n ) = mm256_get_32( s, 2, 10, 18, 26, 34, 42, 50, 58 );
   casti_m256i( d03, n ) = mm256_get_32( s, 3, 11, 19, 27, 35, 43, 51, 59 );
   casti_m256i( d04, n ) = mm256_get_32( s, 4, 12, 20, 28, 36, 44, 52, 60 );
   casti_m256i( d05, n ) = mm256_get_32( s, 5, 13, 21, 29, 37, 45, 53, 61 );
   casti_m256i( d06, n ) = mm256_get_32( s, 6, 14, 22, 30, 38, 46, 54, 62 );
   casti_m256i( d07, n ) = mm256_get_32( s, 7, 15, 23, 31, 39, 47, 55, 63 );
}

static inline void mm256_interleave_4x64x256( void *d, const void *s0,
                       const void *s1, const void *s2, const void *s3 )
{
  casti_m256i( d,0 ) = mm256_put_64( s0,    s1,    s2,    s3    );
  casti_m256i( d,1 ) = mm256_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8 );
  casti_m256i( d,2 ) = mm256_put_64( s0+16, s1+16, s2+16, s3+16 );
  casti_m256i( d,3 ) = mm256_put_64( s0+24, s1+24, s2+24, s3+24 );
}

// bswap the data as it's interleaved.
// A bit of a missnomer, but be is nice and short.
static inline void mm256_be_interleave_4x64x256( void *d, const void *s0,
                       const void *s1, const void *s2, const void *s3 )
{
  casti_m256i( d,0 ) = mm256_bswap_32( 
		             mm256_put_64( s0,    s1,    s2,    s3    ) );
  casti_m256i( d,1 ) = mm256_bswap_32(
	                     mm256_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8 ) );
  casti_m256i( d,2 ) = mm256_bswap_32( 
		             mm256_put_64( s0+16, s1+16, s2+16, s3+16 ) );
  casti_m256i( d,3 ) = mm256_bswap_32( 
		             mm256_put_64( s0+24, s1+24, s2+24, s3+24 ) );
}

static inline void mm256_interleave_4x64x128( void *d, const void *s0,
                       const void *s1, const void *s2, const void *s3 )
{
  casti_m256i( d,0 ) = mm256_put_64( s0,    s1,    s2,    s3    );
  casti_m256i( d,1 ) = mm256_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8 );
}

static inline void mm256_be_interleave_4x64x128( void *d, const void *s0,
                       const void *s1, const void *s2, const void *s3 )
{
  casti_m256i( d,0 ) = mm256_bswap_32( 
		           mm256_put_64( s0,    s1,    s2,    s3    ) );
  casti_m256i( d,1 ) = mm256_bswap_32( 
		           mm256_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8 ) );
}

// 4 lanes of 256 bits using 64 bit interleaving (standard final hash size)
static inline void mm256_deinterleave_4x64x256( void *d0, void *d1, void *d2,
                            void *d3, const int n, const void *s )
{
   casti_m256i( d0,n ) = mm256_get_64( s, 0, 4,  8, 12 );
   casti_m256i( d1,n ) = mm256_get_64( s, 1, 5,  9, 13 );
   casti_m256i( d2,n ) = mm256_get_64( s, 2, 6, 10, 14 );
   casti_m256i( d3,n ) = mm256_get_64( s, 3, 7, 11, 15 );
}


static inline void mm256_deinterleave_2x128x256( void *d0, void *d1, 
                                                 const int n, const void *s )
{
   casti_m256i( d0,n ) = mm256_get_64( s, 0, 1, 4, 5 );
   casti_m256i( d1,n ) = mm256_get_64( s, 2, 3, 6, 7 );
}

// Used for AVX512 interleaving

static inline void mm256_deinterleave_16x32x256( void *d00, void *d01, 
		           void *d02, void *d03, void *d04, void *d05,
			   void *d06, void *d07, void *d08, void *d09,
			   void *d10, void *d11, void *d12, void *d13,
			   void *d14, void *d15, const int n, const void *s )
{
   casti_m256i( d00,n ) = mm256_get_32( s,  0, 16, 32, 48, 64, 80, 96,112 );
   casti_m256i( d01,n ) = mm256_get_32( s,  1, 17, 33, 49, 65, 81, 97,113 );
   casti_m256i( d02,n ) = mm256_get_32( s,  2, 18, 34, 50, 66, 82, 98,114 );
   casti_m256i( d03,n ) = mm256_get_32( s,  3, 19, 35, 51, 67, 83, 99,115 );
   casti_m256i( d04,n ) = mm256_get_32( s,  4, 20, 36, 52, 68, 84,100,116 );
   casti_m256i( d05,n ) = mm256_get_32( s,  5, 21, 37, 53, 69, 85,101,117 );
   casti_m256i( d06,n ) = mm256_get_32( s,  6, 22, 38, 54, 70, 86,102,118 );
   casti_m256i( d07,n ) = mm256_get_32( s,  7, 23, 39, 55, 71, 87,103,119 );
   casti_m256i( d08,n ) = mm256_get_32( s,  8, 24, 40, 56, 72, 88,104,120 );
   casti_m256i( d09,n ) = mm256_get_32( s,  9, 25, 41, 57, 73, 89,105,121 );
   casti_m256i( d10,n ) = mm256_get_32( s, 10, 26, 42, 58, 74, 90,106,122 );
   casti_m256i( d11,n ) = mm256_get_32( s, 11, 27, 43, 59, 75, 91,107,123 );
   casti_m256i( d12,n ) = mm256_get_32( s, 12, 28, 44, 60, 76, 92,108,124 );
   casti_m256i( d13,n ) = mm256_get_32( s, 13, 29, 45, 61, 77, 93,109,125 );
   casti_m256i( d14,n ) = mm256_get_32( s, 14, 30, 46, 62, 78, 94,110,126 );
   casti_m256i( d15,n ) = mm256_get_32( s, 15, 31, 47, 63, 79, 95,111,127 );
}

// 8 lanes of 256 bits using 64 bit interleaving (standard final hash size)
static inline void mm256_deinterleave_8x64x256( void *d0, void *d1, void *d2,
                            void *d3, void *d4, void *d5, void *d6, void *d7,
                            const int n, const void *s )
{
   casti_m256i( d0,n ) = mm256_get_64( s,  0,  8, 16, 24 );
   casti_m256i( d1,n ) = mm256_get_64( s,  1,  9, 17, 25 );
   casti_m256i( d2,n ) = mm256_get_64( s,  2, 10, 18, 26 );
   casti_m256i( d3,n ) = mm256_get_64( s,  3, 11, 19, 27 );
   casti_m256i( d4,n ) = mm256_get_64( s,  4, 12, 20, 28 );
   casti_m256i( d5,n ) = mm256_get_64( s,  5, 13, 21, 29 );
   casti_m256i( d6,n ) = mm256_get_64( s,  6, 14, 22, 30 );
   casti_m256i( d7,n ) = mm256_get_64( s,  7, 15, 23, 31 );
}

static inline void mm256_deinterleave_4x128x256( void *d0, void *d1, void *d2,
                                void *d3, const int n, const void *s )
{
   casti_m256i( d0,n ) = mm256_get_64( s,  0,  1,  8,  9 );
   casti_m256i( d1,n ) = mm256_get_64( s,  2,  3, 10, 11 );
   casti_m256i( d2,n ) = mm256_get_64( s,  4,  5, 12, 13 );
   casti_m256i( d3,n ) = mm256_get_64( s,  6,  7, 14, 15 );
}

//

// Interleave 8 source buffers containing 32 bit data into the destination
// vector
static inline void mm256_interleave_8x32( void *d, const void *s0,
        const void *s1, const void *s2, const void *s3, const void *s4,
        const void *s5, const void *s6, const void *s7, int bit_len )
{
   mm256_interleave_8x32x256( d, s0, s1, s2, s3, s4, s5, s6, s7 );
   if ( bit_len <= 256 ) return;
   mm256_interleave_8x32x256( d+256, s0+32, s1+32, s2+32, s3+32,
		                     s4+32, s5+32, s6+32, s7+32 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm256_interleave_8x32x128( d+512, s0+64, s1+64, s2+64, s3+64,
                                        s4+64, s5+64, s6+64, s7+64 );
      return;
   }
   mm256_interleave_8x32x256( d+512, s0+64, s1+64, s2+64, s3+64,
                                     s4+64, s5+64, s6+64, s7+64 );
   mm256_interleave_8x32x256( d+768, s0+96, s1+96, s2+96, s3+96,
                                     s4+96, s5+96, s6+96, s7+96 );
   // bit_len == 1024
}

static inline void mm256_be_interleave_8x32( void *d, const void *s0,
        const void *s1, const void *s2, const void *s3, const void *s4,
        const void *s5, const void *s6, const void *s7, int bit_len )
{
   mm256_be_interleave_8x32x256( d, s0, s1, s2, s3, s4, s5, s6, s7 );
   if ( bit_len <= 256 ) return;
   mm256_be_interleave_8x32x256( d+256, s0+32, s1+32, s2+32, s3+32,
                                     s4+32, s5+32, s6+32, s7+32 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm256_be_interleave_8x32x128( d+512, s0+64, s1+64, s2+64, s3+64,
                                        s4+64, s5+64, s6+64, s7+64 );
      return;
   }
   mm256_be_interleave_8x32x256( d+512, s0+64, s1+64, s2+64, s3+64,
                                     s4+64, s5+64, s6+64, s7+64 );
   mm256_be_interleave_8x32x256( d+768, s0+96, s1+96, s2+96, s3+96,
                                     s4+96, s5+96, s6+96, s7+96 );
   // bit_len == 1024
}

/*
// Slower but it works with 32 bit data
// bit_len must be multiple of 32
static inline void mm256_interleave_8x32x( uint32_t *dst, uint32_t *src0,
          uint32_t *src1, uint32_t *src2, uint32_t *src3, uint32_t *src4,
          uint32_t *src5, uint32_t *src6, uint32_t *src7, int bit_len )
{
   uint32_t *d = dst;;
   for ( int i = 0; i < bit_len>>5; i++, d += 8 )
   {
      *d     = *(src0+i);
      *(d+1) = *(src1+i);
      *(d+2) = *(src2+i);
      *(d+3) = *(src3+i);
      *(d+4) = *(src4+i);
      *(d+5) = *(src5+i);
      *(d+6) = *(src6+i);
      *(d+7) = *(src7+i);
  }
}
*/

// Deinterleave 8 buffers of 32 bit data from the source buffer.
// Sub-function can be called directly for 32 byte final hash.
static inline void mm256_deinterleave_8x32( void *d0, void *d1, void *d2,
                        void *d3, void *d4, void *d5, void *d6, void *d7,
                        const void *s, int bit_len )
{
   mm256_deinterleave_8x32x256( d0, d1, d2, d3, d4, d5, d6, d7, 0, s );
   if ( bit_len <= 256 ) return;
   mm256_deinterleave_8x32x256( d0, d1, d2, d3, d4, d5, d6, d7, 1, s+256 );
   if ( bit_len <= 512 ) return;
   // short block, final 16 bytes of input data
   if ( bit_len <= 640 )
   {
      mm128_deinterleave_8x32x128( d0, d1, d2, d3, d4, d5, d6, d7, 2, s+512 );
      return;
   }
   // bitlen == 1024
   mm256_deinterleave_8x32x256( d0, d1, d2, d3, d4, d5, d6, d7, 2, s+512 );
   mm256_deinterleave_8x32x256( d0, d1, d2, d3, d4, d5, d6, d7, 3, s+768 );
}

/*
// Deinterleave 8 arrays into indivdual buffers for scalar processing
// bit_len must be multiple of 32
static inline void mm256_deinterleave_8x32x( uint32_t *dst0, uint32_t *dst1,
                uint32_t *dst2,uint32_t *dst3, uint32_t *dst4, uint32_t *dst5,
                uint32_t *dst6,uint32_t *dst7,uint32_t *src, int bit_len )
{
  uint32_t *s = src;
  for ( int i = 0; i < bit_len>>5; i++, s += 8 )
  {
     *(dst0+i) = *( s     );
     *(dst1+i) = *( s + 1 );
     *(dst2+i) = *( s + 2 );
     *(dst3+i) = *( s + 3 );
     *(dst4+i) = *( s + 4 );
     *(dst5+i) = *( s + 5 );
     *(dst6+i) = *( s + 6 );
     *(dst7+i) = *( s + 7 );
  }
}
*/

static inline void mm256_extract_lane_8x32( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  casti_m256i( d, 0 ) =
	     mm256_get_32( s, lane   , lane+ 8, lane+16, lane+24,
		              lane+32, lane+40, lane+48, lane+56 );
  if ( bit_len <= 256 ) return;
  casti_m256i( d, 1 ) =
	     mm256_get_32( s, lane+64, lane+ 72, lane+ 80, lane+ 88,
                              lane+96, lane+104, lane+112, lane+120 );
  // bit_len == 512
}

//

// Interleave 4 source buffers containing 64 bit data into the destination
// buffer. Only bit_len 256, 512, 640 & 1024 are supported.
static inline void mm256_interleave_4x64( void *d, const void *s0,
            const void *s1, const void *s2, const void *s3, int bit_len )
{
  mm256_interleave_4x64x256( d, s0, s1, s2, s3 );
  if ( bit_len <= 256 ) return;
  mm256_interleave_4x64x256( d+128, s0+32, s1+32, s2+32, s3+32 );
  if ( bit_len <= 512 ) return;
  if ( bit_len <= 640 )
  {
    mm256_interleave_4x64x128( d+256, s0+64, s1+64, s2+64, s3+64 );
    return;
  }
  // bit_len == 1024
  mm256_interleave_4x64x256( d+256, s0+64, s1+64, s2+64, s3+64 );
  mm256_interleave_4x64x256( d+384, s0+96, s1+96, s2+96, s3+96 );
}

static inline void mm256_be_interleave_4x64( void *d, const void *s0,
            const void *s1, const void *s2, const void *s3, int bit_len )
{
  mm256_be_interleave_4x64x256( d, s0, s1, s2, s3 );
  if ( bit_len <= 256 ) return;
  mm256_be_interleave_4x64x256( d+128, s0+32, s1+32, s2+32, s3+32 );
  if ( bit_len <= 512 ) return;
  if ( bit_len <= 640 )
  {
    mm256_be_interleave_4x64x128( d+256, s0+64, s1+64, s2+64, s3+64 );
    return;
  }
  // bit_len == 1024
  mm256_be_interleave_4x64x256( d+256, s0+64, s1+64, s2+64, s3+64 );
  mm256_be_interleave_4x64x256( d+384, s0+96, s1+96, s2+96, s3+96 );
}

/*
// Slower version
// bit_len must be multiple of 64
static inline void mm256_interleave_4x64x( void *dst, void *src0, void *src1,
                                    void *src2, void *src3, int bit_len )
{
   uint64_t *d = (uint64_t*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;
   uint64_t *s2 = (uint64_t*)src2;
   uint64_t *s3 = (uint64_t*)src3;

   for ( int i = 0; i < bit_len>>6; i++, d += 4 )
   {
      *d     = *(s0+i);
      *(d+1) = *(s1+i);
      *(d+2) = *(s2+i);
      *(d+3) = *(s3+i);
  }
}
*/

// Deinterleave 4 buffers of 64 bit data from the source buffer.
// bit_len must be 256, 512, 640 or 1024 bits.
// Requires overrun padding for 640 bit len.
static inline void mm256_deinterleave_4x64( void *d0, void *d1, void *d2,
                                    void *d3, const void *s, int bit_len )
{
   mm256_deinterleave_4x64x256( d0, d1, d2, d3, 0, s );
   if ( bit_len <= 256 ) return;
   mm256_deinterleave_4x64x256( d0, d1, d2, d3, 1, s+128 );
   if ( bit_len <= 512 ) return;
   // short block, final 16 bytes of input data
   if ( bit_len <= 640 )
   {
      mm128_deinterleave_4x64x128( d0, d1, d2, d3, 2, s+256 );
      return;
   }
   // bit_len == 1024
   mm256_deinterleave_4x64x256( d0, d1, d2, d3, 2, s+256 );
   mm256_deinterleave_4x64x256( d0, d1, d2, d3, 3, s+384 );
}

/*
// Slower version
// bit_len must be multiple 0f 64
static inline void mm256_deinterleave_4x64x( void *dst0, void *dst1,
                             void *dst2, void *dst3, void *src, int bit_len )
{
  uint64_t *s = (uint64_t*)src;
  uint64_t *d0 = (uint64_t*)dst0;
  uint64_t *d1 = (uint64_t*)dst1;
  uint64_t *d2 = (uint64_t*)dst2;
  uint64_t *d3 = (uint64_t*)dst3;

  for ( int i = 0; i < bit_len>>6; i++, s += 4 )
  {
     *(d0+i) = *s;
     *(d1+i) = *(s+1);
     *(d2+i) = *(s+2);
     *(d3+i) = *(s+3);
  }
}
*/

// extract and deinterleave specified lane.
static inline void mm256_extract_lane_4x64( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  casti_m256i( d, 0 ) =
             mm256_get_64( s, lane, lane+4, lane+8, lane+12 );

  if ( bit_len <= 256 ) return;
  casti_m256i( d, 1 ) =
             mm256_get_64( s, lane+16, lane+20, lane+24, lane+28 );
  return;
}


// Convert from 4x32 SSE2 interleaving to 4x64 AVX2.
// Can't do it in place
#define mm256_reinterleave_4x64 mm256_reinterleave_4x32_4x64
static inline void mm256_reinterleave_4x32_4x64( void *dst, void *src,
	                                         int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[ 7],s[ 3],s[ 6],s[ 2],s[ 5],s[ 1],s[ 4],s[ 0] );
   d[1] = _mm256_set_epi32( s[15],s[11],s[14],s[10],s[13],s[ 9],s[12],s[ 8] );
   d[2] = _mm256_set_epi32( s[23],s[19],s[22],s[18],s[21],s[17],s[20],s[16] );
   d[3] = _mm256_set_epi32( s[31],s[27],s[30],s[26],s[29],s[25],s[28],s[24] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi32( s[39],s[35],s[38],s[34],s[37],s[33],s[36],s[32] );
   d[5] = _mm256_set_epi32( s[47],s[43],s[46],s[42],s[45],s[41],s[44],s[40] );
   d[6] = _mm256_set_epi32( s[55],s[51],s[54],s[50],s[53],s[49],s[52],s[48] );
   d[7] = _mm256_set_epi32( s[63],s[59],s[62],s[58],s[61],s[57],s[60],s[56] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi32( s[71],s[67],s[70],s[66],s[69],s[65],s[68],s[64] );
   d[9] = _mm256_set_epi32( s[79],s[75],s[78],s[74],s[77],s[73],s[76],s[72] );

   if ( bit_len <= 640 ) return;

  d[10] = _mm256_set_epi32(s[87],s[83],s[86],s[82],s[85],s[81],s[84],s[80]);
  d[11] = _mm256_set_epi32(s[95],s[91],s[94],s[90],s[93],s[89],s[92],s[88]);

  d[12] = _mm256_set_epi32(s[103],s[99],s[102],s[98],s[101],s[97],s[100],s[96]);
  d[13] = _mm256_set_epi32(s[111],s[107],s[110],s[106],s[109],s[105],s[108],s[104]);
  d[14] = _mm256_set_epi32(s[119],s[115],s[118],s[114],s[117],s[113],s[116],s[112]);
  d[15] = _mm256_set_epi32(s[127],s[123],s[126],s[122],s[125],s[121],s[124],s[120]);
   // bit_len == 1024
}

/*
// likely of no use.
// convert 4x32 byte (128 bit) vectors to 4x64 (256 bit) vectors for AVX2
// bit_len must be multiple of 64
// broken
static inline void mm256_reinterleave_4x64x( uint64_t *dst, uint32_t *src,
                                             int  bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   uint32_t *s = (uint32_t*)src;
   for ( int i = 0; i < bit_len >> 5; i += 8 )
   {
      *( d + i     ) = *( s + i     );      // 0 <- 0    8 <- 8
      *( d + i + 1 ) = *( s + i + 4 );      // 1 <- 4    9 <- 12
      *( d + i + 2 ) = *( s + i + 1 );      // 2 <- 1    10 <- 9
      *( d + i + 3 ) = *( s + i + 5 );      // 3 <- 5    11 <- 13
      *( d + i + 4 ) = *( s + i + 2 );      // 4 <- 2    12 <- 10
      *( d + i + 5 ) = *( s + i + 6 );      // 5 <- 6    13 <- 14
      *( d + i + 6 ) = *( s + i + 3 );      // 6 <- 3    14 <- 11
      *( d + i + 7 ) = *( s + i + 7 );      // 7 <- 7    15 <- 15
     }
}
*/

// Convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
#define mm256_reinterleave_4x32 mm256_reinterleave_4x64_4x32
static inline void mm256_reinterleave_4x64_4x32( void *dst, void *src,
	                                         int  bit_len )
{
   __m256i  *d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[ 7],s[ 5],s[ 3],s[ 1],s[ 6],s[ 4],s[ 2],s[ 0] );
   d[1] = _mm256_set_epi32( s[15],s[13],s[11],s[ 9],s[14],s[12],s[10],s[ 8] );
   d[2] = _mm256_set_epi32( s[23],s[21],s[19],s[17],s[22],s[20],s[18],s[16] );
   d[3] = _mm256_set_epi32( s[31],s[29],s[27],s[25],s[30],s[28],s[26],s[24] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi32( s[39],s[37],s[35],s[33],s[38],s[36],s[34],s[32] );
   d[5] = _mm256_set_epi32( s[47],s[45],s[43],s[41],s[46],s[44],s[42],s[40] );
   d[6] = _mm256_set_epi32( s[55],s[53],s[51],s[49],s[54],s[52],s[50],s[48] );
   d[7] = _mm256_set_epi32( s[63],s[61],s[59],s[57],s[62],s[60],s[58],s[56] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi32( s[71],s[69],s[67],s[65],s[70],s[68],s[66],s[64] );
   d[9] = _mm256_set_epi32( s[79],s[77],s[75],s[73],s[78],s[76],s[74],s[72] );

   if ( bit_len <= 640 ) return;

   d[10] = _mm256_set_epi32( s[87],s[85],s[83],s[81],s[86],s[84],s[82],s[80] );
   d[11] = _mm256_set_epi32( s[95],s[93],s[91],s[89],s[94],s[92],s[90],s[88] );

   d[12] = _mm256_set_epi32( s[103],s[101],s[99],s[97],s[102],s[100],s[98],s[96] );
   d[13] = _mm256_set_epi32( s[111],s[109],s[107],s[105],s[110],s[108],s[106],s[104] );
   d[14] = _mm256_set_epi32( s[119],s[117],s[115],s[113],s[118],s[116],s[114],s[112] );
   d[15] = _mm256_set_epi32( s[127],s[125],s[123],s[121],s[126],s[124],s[122],s[120] );
   // bit_len == 1024
}

static inline void mm256_reinterleave_4x64_2x128( void *dst0, void *dst1,
                                              const void *src, int  bit_len )
{
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   uint64_t *s = (uint64_t*)src;

   d0[0] = _mm256_set_epi64x( s[ 5], s[ 1], s[ 4], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[ 7], s[ 3], s[ 6], s[ 2] );

   d0[1] = _mm256_set_epi64x( s[13], s[ 9], s[12], s[ 8] );
   d1[1] = _mm256_set_epi64x( s[15], s[11], s[14], s[10] );

   if ( bit_len <= 256 ) return;

   d0[2] = _mm256_set_epi64x( s[21], s[17], s[20], s[16] );
   d1[2] = _mm256_set_epi64x( s[23], s[19], s[22], s[18] );

   d0[3] = _mm256_set_epi64x( s[29], s[25], s[28], s[24] );
   d1[3] = _mm256_set_epi64x( s[31], s[27], s[30], s[26] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm256_set_epi64x( s[37], s[33], s[36], s[32] );
   d1[4] = _mm256_set_epi64x( s[39], s[35], s[38], s[34] );

   d0[5] = _mm256_set_epi64x( s[45], s[41], s[44], s[40] );
   d1[5] = _mm256_set_epi64x( s[47], s[43], s[46], s[42] );

   d0[6] = _mm256_set_epi64x( s[53], s[49], s[52], s[48] );
   d1[6] = _mm256_set_epi64x( s[55], s[51], s[54], s[50] );

   d0[7] = _mm256_set_epi64x( s[61], s[57], s[60], s[56] );
   d1[7] = _mm256_set_epi64x( s[63], s[59], s[62], s[58] );
}


static inline void mm256_reinterleave_2x128_4x64( void *dst, const void *src0,
	                                      const void *src1, int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;

   d[ 0] = _mm256_set_epi64x( s1[2], s1[0], s0[2], s0[0] );
   d[ 1] = _mm256_set_epi64x( s1[3], s1[1], s0[3], s0[1] );
   d[ 2] = _mm256_set_epi64x( s1[6], s1[4], s0[6], s0[4] );
   d[ 3] = _mm256_set_epi64x( s1[7], s1[5], s0[7], s0[5] );

   if ( bit_len <= 256 ) return;

   d[ 4] = _mm256_set_epi64x( s1[10], s1[ 8], s0[10], s0[ 8] );
   d[ 5] = _mm256_set_epi64x( s1[11], s1[ 9], s0[11], s0[ 9] );
   d[ 6] = _mm256_set_epi64x( s1[14], s1[12], s0[14], s0[12] );
   d[ 7] = _mm256_set_epi64x( s1[15], s1[13], s0[15], s0[13] );

   if ( bit_len <= 512 ) return;

   d[ 8] = _mm256_set_epi64x( s1[18], s1[16], s0[18], s0[16] );
   d[ 9] = _mm256_set_epi64x( s1[19], s1[17], s0[19], s0[17] );
   d[10] = _mm256_set_epi64x( s1[22], s1[20], s0[22], s0[20] );
   d[11] = _mm256_set_epi64x( s1[23], s1[21], s0[23], s0[21] );

   d[12] = _mm256_set_epi64x( s1[26], s1[24], s0[26], s0[24] );
   d[13] = _mm256_set_epi64x( s1[27], s1[25], s0[27], s0[25] );
   d[14] = _mm256_set_epi64x( s1[30], s1[28], s0[30], s0[28] );
   d[15] = _mm256_set_epi64x( s1[31], s1[29], s0[31], s0[29] );
}




/*
// not used
static inline void mm_reinterleave_4x32( void *dst, void *src, int  bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   uint32_t *s = (uint32_t*)src;
   for ( int i = 0; i < bit_len >> 5; i +=8 )
   {
      *( d + i     ) = *( s + i     );
      *( d + i + 1 ) = *( s + i + 2 );
      *( d + i + 2 ) = *( s + i + 4 );
      *( d + i + 3 ) = *( s + i + 6 );
      *( d + i + 4 ) = *( s + i + 1 );
      *( d + i + 5 ) = *( s + i + 3 );
      *( d + i + 6 ) = *( s + i + 5 );
      *( d + i + 7 ) = *( s + i + 7 );
   }
}
*/

#define mm256_interleave_2x128 mm256_interleave_1x128
static inline void mm256_interleave_1x128( const void *d, const void *s0,
	                                   void *s1, const int bit_len )
{
  casti_m256i( d, 0 ) = mm256_put_64( s0   , s0+ 8, s1   , s1+ 8 );
  casti_m256i( d, 1 ) = mm256_put_64( s0+16, s0+24, s1+16, s1+24 );
  if ( bit_len <= 256 ) return;
  casti_m256i( d, 2 ) = mm256_put_64( s0+32, s0+40, s1+32, s1+40 );
  casti_m256i( d, 3 ) = mm256_put_64( s0+48, s0+56, s1+48, s1+56 );
  if ( bit_len <= 512 ) return;
  casti_m256i( d, 4 ) = mm256_put_64( s0+64, s0+72, s1+64, s1+72 );
  if ( bit_len <= 640 ) return;
  casti_m256i( d, 5 ) = mm256_put_64( s0+ 80, s0+ 88, s1+ 80, s1+ 88 );
  casti_m256i( d, 6 ) = mm256_put_64( s0+ 96, s0+104, s1+ 96, s1+104 );
  casti_m256i( d, 7 ) = mm256_put_64( s0+112, s0+120, s1+112, s1+120 );
  // bit_len == 1024
}

#define mm256_deinterleave_2x128 mm256_deinterleave_1x128
static inline void mm256_deinterleave_1x128( void *d0, void *d1, void *s,
                                             int bit_len )
{
   mm256_deinterleave_2x128x256( d0, d1, 0, s );
   if ( bit_len <= 256 ) return;
   mm256_deinterleave_2x128x256( d0, d1, 1, s+64 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm128_deinterleave_2x128x128( d0, d1, 2, s+128 );
      return;
   }
   mm256_deinterleave_2x128x256( d0, d1, 2, s+128 );
   mm256_deinterleave_2x128x256( d0, d1, 3, s+192 );
   // bit_len == 1024
}

#endif // __AVX2__

///////////////////////////////////////////

#if defined(__AVX512F__)
//#if 0

// Macro functions returning vector.
// Abstracted typecasting, avoid temp pointers.
// Source arguments may be any 64 or 32 byte aligned pointer as appropriate.

#define mm512_put_64( s0, s1, s2, s3, s4, s5, s6, s7 ) \
  _mm512_set_epi64( *((const uint64_t*)(s7)), *((const uint64_t*)(s6)), \
                    *((const uint64_t*)(s5)), *((const uint64_t*)(s4)), \
                    *((const uint64_t*)(s3)), *((const uint64_t*)(s2)), \
                    *((const uint64_t*)(s1)), *((const uint64_t*)(s0)) ) 

#define mm512_put_32( s00, s01, s02, s03, s04, s05, s06, s07, \
                      s08, s09, s10, s11, s12, s13, s14, s15 ) \
  _mm512_set_epi32( *((const uint32_t*)(s15)), *((const uint32_t*)(s14)), \
                    *((const uint32_t*)(s13)), *((const uint32_t*)(s12)), \
                    *((const uint32_t*)(s11)), *((const uint32_t*)(s10)), \
                    *((const uint32_t*)(s09)), *((const uint32_t*)(s08)), \
                    *((const uint32_t*)(s07)), *((const uint32_t*)(s06)), \
                    *((const uint32_t*)(s05)), *((const uint32_t*)(s04)), \
                    *((const uint32_t*)(s03)), *((const uint32_t*)(s02)), \
                    *((const uint32_t*)(s01)), *((const uint32_t*)(s00)) ) 

#define mm512_get_64( s, i0, i1, i2, i3, i4, i5, i6, i7 ) \
  _mm512_set_epi64( ((const uint64_t*)(s))[i7], ((const uint64_t*)(s))[i6], \
                    ((const uint64_t*)(s))[i5], ((const uint64_t*)(s))[i4], \
                    ((const uint64_t*)(s))[i3], ((const uint64_t*)(s))[i2], \
                    ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm512_get_32( s, i00, i01, i02, i03, i04, i05, i06, i07, \
                         i08, i09, i10, i11, i12, i13, i14, i15 ) \
  _mm512_set_epi32( ((const uint32_t*)(s))[i15], ((const uint32_t*)(s))[i14], \
                    ((const uint32_t*)(s))[i13], ((const uint32_t*)(s))[i12], \
                    ((const uint32_t*)(s))[i11], ((const uint32_t*)(s))[i10], \
                    ((const uint32_t*)(s))[i09], ((const uint32_t*)(s))[i08], \
                    ((const uint32_t*)(s))[i07], ((const uint32_t*)(s))[i06], \
                    ((const uint32_t*)(s))[i05], ((const uint32_t*)(s))[i04], \
                    ((const uint32_t*)(s))[i03], ((const uint32_t*)(s))[i02], \
                    ((const uint32_t*)(s))[i01], ((const uint32_t*)(s))[i00] )

// AVX512 has no blend, can be done with permute2xvar but at what cost?
// Can also be done with shifting and mask-or'ing for 3 instructins with
// 1 dependency. Finally it can be done with 1 _mm512_set but with 8 64 bit
// array index calculations and 8 pointer reads.

// Blend 2 vectors alternating hi & lo: { hi[n], lo[n-1], ... hi[1]. lo[0] }
#define mm512_interleave_blend_128( hi, lo ) \
  _mm256_permute2xvar_epi64( hi, lo, _mm512_set_epi64( \
                            0x7, 0x6, 0x5, 0x4, 0xb, 0xa, 0x9, 0x8 )

#define mm512_interleave_blend_64( hi, lo ) \
  _mm256_permute2xvar_epi64( hi, lo, _mm512_set_epi64( \
                            0x7, 0x6, 0xd, 0xc, 0x3, 0x2, 0x9, 0x8 )

#define mm512_interleave_blend_32( hi, lo ) \
  _mm256_permute2xvar_epi32( hi, lo, _mm512_set_epi32( \
		            0x0f, 0x1e, 0x0d, 0x1c, 0x0b, 0x1a, 0x09, 0x18, \
                            0x07, 0x16, 0x05, 0x14, 0x03, 0x12, 0x01, 0x10 )
//

static inline void mm512_interleave_16x32x512( void *d, const void *s00,
     const void *s01, const void *s02, const void *s03, const void *s04,
     const void *s05, const void *s06, const void *s07, const void *s08,
     const void *s09, const void *s10, const void *s11, const void *s12,
     const void *s13, const void *s14, const void *s15 )
{
   casti_m512i( d, 0 ) = mm512_put_32(
	      s00,    s01,    s02,    s03,    s04,    s05,    s06,    s07,
              s08,    s09,    s10,    s11,    s12,    s13,    s14,    s15 );
   casti_m512i( d, 1 ) = mm512_put_32(
	      s00+ 4, s01+ 4, s02+ 4, s03+ 4, s04+ 4, s05+ 4, s06+ 4, s07+ 4,
              s08+ 4, s09+ 4, s10+ 4, s11+ 4, s12+ 4, s13+ 4, s14+ 4, s15+ 4 );
   casti_m512i( d, 2 ) = mm512_put_32(
              s00+ 8, s01+ 8, s02+ 8, s03+ 8, s04+ 8, s05+ 8, s06+ 8, s07+ 8,
              s08+ 8, s09+ 8, s10+ 8, s11+ 8, s12+ 8, s13+ 8, s14+ 8, s15+ 8 );
   casti_m512i( d, 3 ) = mm512_put_32(
	      s00+12, s01+12, s02+12, s03+12, s04+12, s05+12, s06+12, s07+12,
              s08+12, s09+12, s10+12, s11+12, s12+12, s13+12, s14+12, s15+12 );
   casti_m512i( d, 4 ) = mm512_put_32(
	      s00+16, s01+16, s02+16, s03+16, s04+16, s05+16, s06+16, s07+16,
              s08+16, s09+16, s10+16, s11+16, s12+16, s13+16, s14+16, s15+16 );
   casti_m512i( d, 5 ) = mm512_put_32(
	      s00+20, s01+20, s02+20, s03+20, s04+20, s05+20, s06+20, s07+20,
              s08+20, s09+20, s10+20, s11+20, s12+20, s13+20, s14+20, s15+20 );
   casti_m512i( d, 6 ) = mm512_put_32(
	      s00+24, s01+24, s02+24, s03+24, s04+24, s05+24, s06+24, s07+24,
              s08+24, s09+24, s10+24, s11+24, s12+24, s13+24, s14+24, s15+24 );
   casti_m512i( d, 7 ) = mm512_put_32(
	      s00+28, s01+28, s02+28, s03+28, s04+28, s05+28, s06+28, s07+28,
              s08+28, s09+28, s10+28, s11+28, s12+28, s13+28, s14+28, s15+28 );
   casti_m512i( d, 8 ) = mm512_put_32(
	      s00+32, s01+28, s02+28, s03+28, s04+32, s05+28, s06+28, s07+28,
              s08+32, s09+28, s10+28, s11+28, s12+32, s13+28, s14+28, s15+28 );
   casti_m512i( d, 9 ) = mm512_put_32(
	      s00+36, s01+28, s02+28, s03+28, s04+36, s05+28, s06+28, s07+28,
              s08+36, s09+28, s10+28, s11+28, s12+36, s13+28, s14+28, s15+28 );
   casti_m512i( d,10 ) = mm512_put_32(
	      s00+40, s01+28, s02+28, s03+28, s04+40, s05+28, s06+28, s07+28,
              s08+40, s09+28, s10+28, s11+28, s12+40, s13+28, s14+28, s15+28 );
   casti_m512i( d,11 ) = mm512_put_32(
	      s00+44, s01+28, s02+28, s03+28, s04+44, s05+28, s06+28, s07+28,
              s08+44, s09+28, s10+28, s11+28, s12+44, s13+28, s14+28, s15+28 );
   casti_m512i( d,12 ) = mm512_put_32(
	      s00+48, s01+28, s02+28, s03+28, s04+48, s05+28, s06+28, s07+28,
              s08+48, s09+28, s10+28, s11+28, s12+48, s13+28, s14+28, s15+28 );
   casti_m512i( d,13 ) = mm512_put_32(
	      s00+52, s01+28, s02+28, s03+28, s04+52, s05+28, s06+28, s07+28,
              s08+52, s09+28, s10+28, s11+28, s12+52, s13+28, s14+28, s15+28 );
   casti_m512i( d,14 ) = mm512_put_32(
	      s00+56, s01+28, s02+28, s03+28, s04+56, s05+28, s06+28, s07+28,
              s08+56, s09+28, s10+28, s11+28, s12+56, s13+28, s14+28, s15+28 );
   casti_m512i( d,15 ) = mm512_put_32(
	      s00+60, s01+28, s02+28, s03+28, s04+60, s05+28, s06+28, s07+28,
              s08+60, s09+28, s10+28, s11+28, s12+60, s13+28, s14+28, s15+28 );
}


static inline void mm512_interleave_16x32x256( void *d, const void *s00,
     const void *s01, const void *s02, const void *s03, const void *s04,
     const void *s05, const void *s06, const void *s07, const void *s08,
     const void *s09, const void *s10, const void *s11, const void *s12,
     const void *s13, const void *s14, const void *s15 )
{
   casti_m512i( d, 0 ) = mm512_put_32(
             s00,    s01,    s02,    s03,    s04,    s05,    s06,    s07,
             s08,    s09,    s10,    s11,    s12,    s13,    s14,    s15 );
   casti_m512i( d, 1 ) = mm512_put_32(
	     s00+ 4, s01+ 4, s02+ 4, s03+ 4, s04+ 4, s05+ 4, s06+ 4, s07+ 4,
             s08+ 4, s09+ 4, s10+ 4, s11+ 4, s12+ 4, s13+ 4, s14+ 4, s15+ 4 );
   casti_m512i( d, 2 ) = mm512_put_32(
	     s00+ 8, s01+ 8, s02+ 8, s03+ 8, s04+ 8, s05+ 8, s06+ 8, s07+ 8,
             s08+ 8, s09+ 8, s10+ 8, s11+ 8, s12+ 8, s13+ 8, s14+ 8, s15+ 8 );
   casti_m512i( d, 3 ) = mm512_put_32(
	     s00+12, s01+12, s02+12, s03+12, s04+12, s05+12, s06+12, s07+12,
             s08+12, s09+12, s10+12, s11+12, s12+12, s13+12, s14+12, s15+12 );
   casti_m512i( d, 4 ) = mm512_put_32(
             s00+16, s01+16, s02+16, s03+16, s04+16, s05+16, s06+16, s07+16,
             s08+16, s09+16, s10+16, s11+16, s12+16, s13+16, s14+16, s15+16 );
   casti_m512i( d, 5 ) = mm512_put_32(
	     s00+20, s01+20, s02+20, s03+20, s04+20, s05+20, s06+20, s07+20,
             s08+20, s09+20, s10+20, s11+20, s12+20, s13+20, s14+20, s15+20 );
   casti_m512i( d, 6 ) = mm512_put_32(
	     s00+24, s01+24, s02+24, s03+24, s04+24, s05+24, s06+24, s07+24,
             s08+24, s09+24, s10+24, s11+24, s12+24, s13+24, s14+24, s15+24 );
   casti_m512i( d, 7 ) = mm512_put_32(
	     s00+28, s01+28, s02+28, s03+28, s04+28, s05+28, s06+28, s07+28,
             s08+28, s09+28, s10+28, s11+28, s12+28, s13+28, s14+28, s15+28 );
}

// Last 16 bytes of input
static inline void mm512_interleave_16x32x128( void *d, const void *s00,
     const void *s01, const void *s02, const void *s03, const void *s04,
     const void *s05, const void *s06, const void *s07, const void *s08,
     const void *s09, const void *s10, const void *s11, const void *s12,
     const void *s13, const void *s14, const void *s15 )
{
   casti_m512i( d, 0 ) = mm512_put_32(
	     s00,    s01,    s02,    s03,    s04,    s05,    s06,    s07,
	     s08,    s09,    s10,    s11,    s12,    s13,    s14,    s15 );
   casti_m512i( d, 1 ) = mm512_put_32(
	     s00+ 4, s01+ 4, s02+ 4, s03+ 4, s04+ 4, s05+ 4, s06+ 4, s07+ 4,
             s08+ 4, s09+ 4, s10+ 4, s11+ 4, s12+ 4, s13+ 4, s14+ 4, s15+ 4 );
   casti_m512i( d, 2 ) = mm512_put_32(
	     s00+ 8, s01+ 8, s02+ 8, s03+ 8, s04+ 8, s05+ 8, s06+ 8, s07+ 8,
             s08+ 8, s09+ 8, s10+ 8, s11+ 8, s12+ 8, s13+ 8, s14+ 8, s15+ 8 );
   casti_m512i( d, 3 ) = mm512_put_32(
	     s00+12, s01+12, s02+12, s03+12, s04+12, s05+12, s06+12, s07+12,
             s08+12, s09+12, s10+12, s11+12, s12+12, s13+12, s14+12, s15+12 );
}

// can be called directly for 64 byte hash.
static inline void mm512_deinterleave_16x32x512( void *d00, void *d01,
                void *d02, void *d03, void *d04, void *d05, void *d06,
                void *d07, void *d08, void *d09, void *d10, void *d11,
                void *d12, void *d13, void *d14, void *d15, const int n,
		const void *s )
{
   casti_m512i(d00,n) = mm512_get_32( s,  0, 16, 32, 48, 64, 80, 96,112,
  		                        128,144,160,176,192,208,224,240 );
   casti_m512i(d01,n) = mm512_get_32( s,  1, 17, 33, 49, 65, 81, 97,113,
  		                        129,145,161,177,193,209,225,241 );
   casti_m512i(d02,n) = mm512_get_32( s,  2, 18, 34, 50, 66, 82, 98,114,
  				        130,146,162,178,194,210,226,242 );
   casti_m512i(d03,n) = mm512_get_32( s,  3, 19, 35, 51, 67, 83, 99,115,
                                        131,147,163,179,195,211,227,243 );
   casti_m512i(d04,n) = mm512_get_32( s,  4, 20, 36, 52, 68, 84,100,116,
		                        132,148,164,180,196,212,228,244 );
   casti_m512i(d05,n) = mm512_get_32( s,  5, 21, 37, 53, 69, 85,101,117,
                                        133,149,165,181,197,213,229,245 );
   casti_m512i(d06,n) = mm512_get_32( s,  6, 22, 38, 54, 70, 86,102,118,
                                        134,150,166,182,198,214,230,246 );
   casti_m512i(d07,n) = mm512_get_32( s,  7, 23, 39, 55, 71, 87,103,119,
		                        135,151,167,183,199,215,231,247 );
   casti_m512i(d08,n) = mm512_get_32( s,  8, 24, 40, 56, 72, 88,104,120,
		                        136,152,168,184,200,216,232,248 );
   casti_m512i(d09,n) = mm512_get_32( s,  9, 25, 41, 57, 73, 89,105,121,
		                        137,153,169,185,201,217,233,249 );
   casti_m512i(d10,n) = mm512_get_32( s, 10, 26, 42, 58, 74, 90,106,122,
		                        138,154,170,186,202,218,234,250 );
   casti_m512i(d11,n) = mm512_get_32( s, 11, 27, 43, 59, 75, 91,107,123,
		                        139,155,171,187,203,219,235,251 );
   casti_m512i(d12,n) = mm512_get_32( s, 12, 28, 44, 60, 76, 92,108,124,
		                        140,156,172,188,204,220,236,252 );
   casti_m512i(d13,n) = mm512_get_32( s, 13, 29, 45, 61, 77, 93,109,125,
		                        141,157,173,189,205,221,237,253 );
   casti_m512i(d14,n) = mm512_get_32( s, 14, 30, 46, 62, 78, 94,110,126,
	                                142,158,174,190,206,222,238,254 );
   casti_m512i(d15,n) = mm512_get_32( s, 15, 31, 47, 63, 79, 95,111,127,
           	                        143,159,175,191,207,223,239,255 );
}

static inline void mm512_interleave_8x64x512( void *d, const void *s0,
                   const void *s1, const void *s2, const void *s3,
                   const void *s4, const void *s5, const void *s6,
                   const void *s7 )
{
  casti_m512i( d,0 ) = mm512_put_64( s0,    s1,    s2,    s3,
                                     s4,    s5,    s6,    s7 );
  casti_m512i( d,1 ) = mm512_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8,
                                     s4+ 8, s5+ 8, s6+ 8, s7+ 8 );
  casti_m512i( d,2 ) = mm512_put_64( s0+16, s1+16, s2+16, s3+16,
                                     s4+16, s5+16, s6+16, s7+16 );
  casti_m512i( d,3 ) = mm512_put_64( s0+24, s1+24, s2+24, s3+24,
                                     s4+24, s5+24, s6+24, s7+24 );
  casti_m512i( d,4 ) = mm512_put_64( s0+32, s1+32, s2+32, s3+32,
                                     s4+32, s5+32, s6+32, s7+32 );
  casti_m512i( d,5 ) = mm512_put_64( s0+40, s1+40, s2+40, s3+40,
                                     s4+40, s5+40, s6+40, s7+40 );
  casti_m512i( d,6 ) = mm512_put_64( s0+48, s1+48, s2+48, s3+48,
                                     s4+48, s5+48, s6+48, s7+48 );
  casti_m512i( d,7 ) = mm512_put_64( s0+56, s1+56, s2+56, s3+56,
                                     s4+56, s5+56, s6+56, s7+56 );
}

static inline void mm512_interleave_8x64x256( void *d, const void *s0,
                   const void *s1, const void *s2, const void *s3,
                   const void *s4, const void *s5, const void *s6,
                   const void *s7 )
{
  casti_m512i( d,0 ) = mm512_put_64( s0,    s1,    s2,    s3,
                                     s4,    s5,    s6,    s7 );
  casti_m512i( d,1 ) = mm512_put_64( s0+ 8, s1+ 8, s2+ 8, s3+ 8,
                                     s4+ 8, s5+ 8, s6+ 8, s7+ 8 );
  casti_m512i( d,2 ) = mm512_put_64( s0+16, s1+16, s2+16, s3+16,
                                     s4+16, s5+16, s6+16, s7+16 );
  casti_m512i( d,3 ) = mm512_put_64( s0+24, s1+24, s2+24, s3+24,
                                     s4+24, s5+24, s6+24, s7+24 );
}


// 8 lanes of 512 bits using 64 bit interleaving (typical intermediate hash) 
static inline void mm512_deinterleave_8x64x512( void *d0, void *d1, void *d2,
                            void *d3, void *d4, void *d5, void *d6, void *d7,
			    const int n, const void *s )
{
   casti_m512i( d0,n ) = mm512_get_64( s, 0,  8, 16, 24, 32, 40, 48, 56 );
   casti_m512i( d1,n ) = mm512_get_64( s, 1,  9, 17, 25, 33, 41, 49, 57 );
   casti_m512i( d2,n ) = mm512_get_64( s, 2, 10, 18, 26, 34, 42, 50, 58 );
   casti_m512i( d3,n ) = mm512_get_64( s, 3, 11, 19, 27, 35, 43, 51, 59 );
   casti_m512i( d4,n ) = mm512_get_64( s, 4, 12, 20, 28, 36, 44, 52, 60 );
   casti_m512i( d5,n ) = mm512_get_64( s, 5, 13, 21, 29, 37, 45, 53, 61 );
   casti_m512i( d6,n ) = mm512_get_64( s, 6, 14, 22, 30, 38, 46, 54, 62 );
   casti_m512i( d7,n ) = mm512_get_64( s, 7, 15, 23, 31, 39, 47, 55, 63 );
}

static inline void mm512_deinterleave_4x128x512( void *d0, void *d1, void *d2,
                                void *d3, const int n, const void *s )
{
   casti_m512i( d0,n ) = mm512_get_64( s, 0, 1,  8,  9, 16, 17, 24, 25 );
   casti_m512i( d1,n ) = mm512_get_64( s, 2, 3, 10, 11, 18, 19, 16, 27 );
   casti_m512i( d2,n ) = mm512_get_64( s, 4, 5, 12, 13, 20, 21, 28, 29 );
   casti_m512i( d3,n ) = mm512_get_64( s, 6, 7, 14, 15, 22, 23, 30, 31 );
}

//

static inline void mm512_interleave_16x32( void *d, const void *s00,
    const void *s01, const void *s02, const void *s03, const void *s04,
    const void *s05, const void *s06, const void *s07, const void *s08,
    const void *s09, const void *s10, const void *s11, const void *s12,
    const void *s13, const void *s14, const void *s15, int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm512_interleave_16x32x256( d, s00, s01, s02, s03, s04, s05, s06, s07,
                                     s08, s09, s10, s11, s12, s13, s14, s15 );
      return;
   }
   mm512_interleave_16x32x512( d, s00, s01, s02, s03, s04, s05, s06, s07,
		                  s08, s09, s10, s11, s12, s13, s14, s15 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {

      mm512_interleave_16x32x128( d+1024, s00+64, s01+64, s02+64, s03+64,
		          s04+64, s05+64, s06+64, s07+64, s08+64, s09+64,
			  s10+64, s11+64, s12+64, s13+64, s14+64, s15+64 );
      return;
   }
   mm512_interleave_16x32x512( d+1024, s00+64, s01+64, s02+64, s03+64,  
                       s04+64, s05+64, s06+64, s07+64, s08+64, s09+64, 
                       s10+64, s11+64, s12+64, s13+64, s14+64, s15+64 );
   // bit_len == 1024
}

// sub-functions can be called directly for 32 & 64 byte hash.
static inline void mm512_deinterleave_16x32( void *d00, void *d01, void *d02,
            void *d03, void *d04, void *d05, void *d06, void *d07, void *d08,
            void *d09, void *d10, void *d11, void *d12, void *d13, void *d14,
            void *d15, const void *src, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_16x32x256( d00, d01, d02, d03, d04, d05, d06, d07,
                                    d08, d09, d10, d11, d12, d13, d14, d15,
                                    0,src );
      return;
   }
   mm512_deinterleave_16x32x512( d00, d01, d02, d03, d04, d05, d06, d07,
                                 d08, d09, d10, d11, d12, d13, d14, d15,
                                 0, src );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      // short block, final 16 bytes of input data.
      mm128_deinterleave_16x32x128( d00, d01, d02, d03, d04, d05, d06, d07,
		                    d08, d09, d10, d11, d12, d13, d14, d15,
				    1, src+1024 );
      return;
   }
   // bit_len == 1024
   mm512_deinterleave_16x32x512( d00, d01, d02, d03, d04, d05, d06, d07,
		                 d08, d09, d10, d11, d12, d13, d14, d15,
				 1, src+1024 );
}

static inline void mm512_extract_lane_16x32( void *dst, const void *src,
                                            const int lane, const int bit_len )
{
  if ( bit_len <= 256 )
  {
     cast_m256i( dst ) = mm256_get_32( src, lane, lane+16, lane+32, lane+48,
		                         lane+64, lane+80, lane+96, lane+112 );
     return;
  }
  cast_m512i( dst ) = mm512_get_32( src, lane, lane+ 16, lane+ 32, lane+ 48,
                 lane+ 64, lane+ 80, lane+ 96, lane+112, lane+128, lane+144,
	         lane+160, lane+176, lane+192, lane+208, lane+224, lane+248 );
}

//

static inline void mm512_interleave_8x64( void *d, const void *s0,
                   const void *s1, const void *s2, const void *s3,
                   const void *s4, const void *s5, const void *s6,
                   const void *s7, int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm512_interleave_8x64x256( d, s0, s1, s2, s3, s4, s5, s6, s7 );
      return;
   }
   mm512_interleave_8x64x512( d, s0, s1, s2, s3, s4, s5, s6, s7 );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      casti_m512i( d, 8 ) = mm512_put_64( s7+64, s6+64, s5+64, s4+64,
                                          s3+64, s2+64, s1+64, s0+64 );
      casti_m512i( d, 9 ) = mm512_put_64( s7+72, s6+72, s5+72, s4+72,
                                          s3+72, s2+72, s1+72, s0+72 );
      return;
   }
   // bitlen == 1024
   mm512_interleave_8x64x512( d+512, s0+64, s1+64, s2+64, s3+64,
		                     s4+64, s5+64, s6+64, s7+64 );
}


static inline void mm512_deinterleave_8x64( void *d0, void *d1, void *d2,
                        void *d3, void *d4, void *d5, void *d6, void *d7,
                        const void *s, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_8x64x256( d0, d1, d2, d3, d4, d5, d6, d7, 0, s );
      return;
   }
   mm512_deinterleave_8x64x512( d0, d1, d2, d3, d4, d5, d6, d7, 0, s );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      // short block, final 16 bytes of input data.
      mm128_deinterleave_8x64x128( d0, d1, d2, d3, d4, d5, d6, d7, 1, s+512 );
      return;
   }
   // bit_len == 1024
   mm512_deinterleave_8x64x512( d0, d1, d2, d3, d4, d5, d6, d7, 1, s+512 );
}

// Extract one lane from 64 bit interleaved data
static inline void mm512_extract_lane_8x64( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  if ( bit_len <= 256 )
  {
     cast_m256i( d ) = mm256_get_64( s, lane, lane+8, lane+16, lane+24 );
     return;
  }
  // else bit_len == 512
  cast_m512i( d ) = mm512_get_64( s, lane   , lane+ 8, lane+16, lane+24,
		                         lane+32, lane+40, lane+48, lane+56 );
}

//

static inline void mm512_interleave_4x128( void *d, const void *s0,
            const void *s1, const void *s2, const void *s3, const int bit_len )
{
  casti_m512i( d, 0 ) = mm512_put_64( s0,    s0+8,  s1,    s1+8,
                                      s2,    s2+8,  s3,    s3+8 ); 
  casti_m512i( d, 1 ) = mm512_put_64( s0+16, s0+24, s1+16, s1+24,
                                      s2+16, s2+24, s3+16, s3+24 );
  if ( bit_len <= 256 ) return;

  casti_m512i( d, 2 ) = mm512_put_64( s0+32, s0+40, s1+32, s1+40, 
                                      s2+32, s2+40, s3+32, s3+40 );
  casti_m512i( d, 3 ) = mm512_put_64( s0+48, s0+56, s1+48, s1+56, 
                                      s2+48, s2+56, s3+48, s3+56 );
  if ( bit_len <= 512 ) return;

  casti_m512i( d, 4 ) = mm512_put_64( s0+64, s0+72, s1+64, s1+72,  
                                      s2+64, s2+72, s3+64, s3+72 );
  if ( bit_len <= 640 ) return;

  casti_m512i( d, 5 ) = mm512_put_64( s0+ 80, s0+ 88, s1+ 80, s1+ 88,  
                                      s2+ 80, s2+ 88, s3+ 80, s3+ 88 );
  casti_m512i( d, 6 ) = mm512_put_64( s0+ 96, s0+104, s1+ 96, s1+104,  
                                      s2+ 96, s2+104, s3+ 96, s3+104 );
  casti_m512i( d, 7 ) = mm512_put_64( s0+112, s0+120, s1+112, s1+120,  
                                      s2+112, s2+120, s3+112, s3+120 );
   // bit_len == 1024
}

static inline void mm512_deinterleave_4x128( void *d0, void *d1, void *d2,
              void *d3, const void *s, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_4x128x256( d0, d1, d2, d3, 0, s );
      return;
   }
   mm512_deinterleave_4x128x512( d0, d1, d2, d3, 0, s );
   if ( bit_len <= 512 ) return;
   if ( bit_len <= 640 )
   {
      mm128_deinterleave_4x128x128( d0, d1, d2, d3, 1, s+256 );
      return;
   }
   // bit_len == 1024
   mm512_deinterleave_4x128x512( d0, d1, d2, d3, 1, s+256 );
}

// input one 8x64 buffer and return 2*4*128
static inline void mm512_reinterleave_8x64_4x128( void *dst0, void *dst1,
                                              const void *src, int  bit_len )
{
   __m512i* d0 = (__m512i*)dst0;
   __m512i* d1 = (__m512i*)dst1;
   uint64_t *s = (uint64_t*)src;

   d0[0] = _mm512_set_epi64( s[ 11], s[  3], s[ 10], s[  2],
                             s[  9], s[  1], s[  8], s[  0] );
   d0[1] = _mm512_set_epi64( s[ 27], s[ 19], s[ 26], s[ 18],
 		             s[ 25], s[ 17], s[ 24], s[ 16] );
   d0[2] = _mm512_set_epi64( s[ 15], s[  7], s[ 14], s[  6],
                             s[ 13], s[  5], s[ 12], s[  4] );
   d0[3] = _mm512_set_epi64( s[ 31], s[ 23], s[ 30], s[ 22],
                             s[ 29], s[ 21], s[ 28], s[ 20] );
   d1[0] = _mm512_set_epi64( s[ 43], s[ 35], s[ 42], s[ 34],
                             s[ 41], s[ 33], s[ 40], s[ 32] );
   d1[1] = _mm512_set_epi64( s[ 59], s[ 51], s[ 58], s[ 50],
                             s[ 57], s[ 49], s[ 56], s[ 48] );
   d1[2] = _mm512_set_epi64( s[ 47], s[ 39], s[ 46], s[ 38],
                             s[ 45], s[ 37], s[ 44], s[ 36] );
   d1[3] = _mm512_set_epi64( s[ 63], s[ 55], s[ 62], s[ 54],
                              s[ 61], s[ 53], s[ 60], s[ 52] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm512_set_epi64( s[ 75], s[ 67], s[ 74], s[ 66],
                             s[ 73], s[ 65], s[ 72], s[ 64] );
   d0[5] = _mm512_set_epi64( s[ 91], s[ 83], s[ 90], s[ 82],
                             s[ 89], s[ 81], s[ 88], s[ 80] );
   d0[6] = _mm512_set_epi64( s[ 79], s[ 71], s[ 78], s[ 70],
                             s[ 77], s[ 69], s[ 76], s[ 68] );
   d0[7] = _mm512_set_epi64( s[ 95], s[ 87], s[ 94], s[ 86],
                             s[ 93], s[ 85], s[ 92], s[ 84] );
   d1[4] = _mm512_set_epi64( s[107], s[ 99], s[106], s[ 98],
                             s[105], s[ 97], s[104], s[ 96] );
   d1[5] = _mm512_set_epi64( s[123], s[115], s[122], s[114],
                             s[121], s[113], s[120], s[112] );
   d1[6] = _mm512_set_epi64( s[111], s[103], s[110], s[102],
                             s[109], s[101], s[108], s[100] );
   d1[7] = _mm512_set_epi64( s[127], s[119], s[126], s[118],
                             s[125], s[117], s[124], s[116] );

}

// input 2 4x128  return 8x64
static inline void mm512_reinterleave_4x128_8x64( void *dst, const void *src0,
                                              const void *src1, int  bit_len )
{
   __m512i* d = (__m512i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;

   d[0] = _mm512_set_epi64( s1[ 6], s1[ 4], s1[ 2], s1[ 0],
                            s0[ 6], s0[ 4], s0[ 2], s0[ 0] );
   d[1] = _mm512_set_epi64( s1[ 7], s1[ 5], s1[ 3], s1[ 1],
                            s0[ 7], s0[ 5], s0[ 3], s0[ 1] );
   d[2] = _mm512_set_epi64( s1[14], s1[12], s1[10], s1[ 8],
                            s0[14], s0[12], s0[10], s0[ 8] );
   d[3] = _mm512_set_epi64( s1[15], s1[13], s1[11], s1[ 9],
                            s0[15], s0[13], s0[11], s0[ 9] );
   d[4] = _mm512_set_epi64( s1[22], s1[20], s1[18], s1[16],
                            s0[22], s0[20], s0[18], s0[16] );
   d[5] = _mm512_set_epi64( s1[23], s1[21], s1[19], s1[17],
                            s0[24], s0[21], s0[19], s0[17] );
   d[6] = _mm512_set_epi64( s1[22], s1[28], s1[26], s1[24],
                            s0[22], s0[28], s0[26], s0[24] );
   d[7] = _mm512_set_epi64( s1[31], s1[29], s1[27], s1[25],
                            s0[31], s0[29], s0[27], s0[25] );

   if ( bit_len <= 512 ) return;

   d[0] = _mm512_set_epi64( s1[38], s1[36], s1[34], s1[32],
                            s0[38], s0[36], s0[34], s0[32] );
   d[1] = _mm512_set_epi64( s1[39], s1[37], s1[35], s1[33],
                            s0[39], s0[37], s0[35], s0[33] );
   d[2] = _mm512_set_epi64( s1[46], s1[44], s1[42], s1[40],
                            s0[46], s0[44], s0[42], s0[40] );
   d[3] = _mm512_set_epi64( s1[47], s1[45], s1[43], s1[41],
                            s0[47], s0[45], s0[43], s0[41] );
   d[4] = _mm512_set_epi64( s1[54], s1[52], s1[50], s1[48],
                            s0[54], s0[52], s0[50], s0[48] );
   d[5] = _mm512_set_epi64( s1[55], s1[53], s1[51], s1[49],
                            s0[55], s0[53], s0[51], s0[49] );

   d[6] = _mm512_set_epi64( s1[62], s1[60], s1[58], s1[56],
                            s0[62], s0[60], s0[58], s0[56] );
   d[7] = _mm512_set_epi64( s1[63], s1[61], s1[59], s1[57],
                            s0[63], s0[61], s0[59], s0[57] );

}

static inline void mm512_extract_lane_4x128( void *d, const void *s,
                                            const int lane, const int bit_len )
{
  int l = lane<<1;
  if ( bit_len <= 256 )
  {
     cast_m256i( d ) = mm256_get_64( s, l, l+1, l+8, l+9 );
     return;
  }
  // else bit_len == 512
  cast_m512i( d ) = mm512_get_64( s, l   , l+ 1, l+ 8, l+ 9,
	                             l+16, l+17, l+24, l+25 );
}

#endif // __AVX512F__
#endif // INTERLEAVE_H__
