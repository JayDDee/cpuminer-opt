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

// SSE2

// interleave 4 arrays of 32 bit elements for 128 bit processing
// bit_len must be 256, 512 or 640 bits.
static inline void mm_interleave_4x32( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3, int bit_len )
{
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;
   __m128i* d = (__m128i*)dst;

   d[0] = _mm_set_epi32( s3[ 0], s2[ 0], s1[ 0], s0[ 0] );
   d[1] = _mm_set_epi32( s3[ 1], s2[ 1], s1[ 1], s0[ 1] );
   d[2] = _mm_set_epi32( s3[ 2], s2[ 2], s1[ 2], s0[ 2] );
   d[3] = _mm_set_epi32( s3[ 3], s2[ 3], s1[ 3], s0[ 3] );
   d[4] = _mm_set_epi32( s3[ 4], s2[ 4], s1[ 4], s0[ 4] );
   d[5] = _mm_set_epi32( s3[ 5], s2[ 5], s1[ 5], s0[ 5] );
   d[6] = _mm_set_epi32( s3[ 6], s2[ 6], s1[ 6], s0[ 6] );
   d[7] = _mm_set_epi32( s3[ 7], s2[ 7], s1[ 7], s0[ 7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = _mm_set_epi32( s3[ 8], s2[ 8], s1[ 8], s0[ 8] );
   d[ 9] = _mm_set_epi32( s3[ 9], s2[ 9], s1[ 9], s0[ 9] );
   d[10] = _mm_set_epi32( s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm_set_epi32( s3[11], s2[11], s1[11], s0[11] );
   d[12] = _mm_set_epi32( s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm_set_epi32( s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm_set_epi32( s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm_set_epi32( s3[15], s2[15], s1[15], s0[15] );

   if ( bit_len <= 512 ) return;

   d[16] = _mm_set_epi32( s3[16], s2[16], s1[16], s0[16] );
   d[17] = _mm_set_epi32( s3[17], s2[17], s1[17], s0[17] );
   d[18] = _mm_set_epi32( s3[18], s2[18], s1[18], s0[18] );
   d[19] = _mm_set_epi32( s3[19], s2[19], s1[19], s0[19] );

   if ( bit_len <= 640 ) return;

   d[20] = _mm_set_epi32( s3[20], s2[20], s1[20], s0[20] );
   d[21] = _mm_set_epi32( s3[21], s2[21], s1[21], s0[21] );
   d[22] = _mm_set_epi32( s3[22], s2[22], s1[22], s0[22] );
   d[23] = _mm_set_epi32( s3[23], s2[23], s1[23], s0[23] );

   d[24] = _mm_set_epi32( s3[24], s2[24], s1[24], s0[24] );
   d[25] = _mm_set_epi32( s3[25], s2[25], s1[25], s0[25] );
   d[26] = _mm_set_epi32( s3[26], s2[26], s1[26], s0[26] );
   d[27] = _mm_set_epi32( s3[27], s2[27], s1[27], s0[27] );
   d[28] = _mm_set_epi32( s3[28], s2[28], s1[28], s0[28] );
   d[29] = _mm_set_epi32( s3[29], s2[29], s1[29], s0[29] );
   d[30] = _mm_set_epi32( s3[30], s2[30], s1[30], s0[30] );
   d[31] = _mm_set_epi32( s3[31], s2[31], s1[31], s0[31] );
   // bit_len == 1024
}

// bit_len must be multiple of 32
static inline void mm_interleave_4x32x( void *dst, void *src0, void  *src1,
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

static inline void mm_deinterleave_4x32( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src, int bit_len )
{
   uint32_t *s = (uint32_t*)src;
   __m128i* d0 = (__m128i*)dst0;
   __m128i* d1 = (__m128i*)dst1;
   __m128i* d2 = (__m128i*)dst2;
   __m128i* d3 = (__m128i*)dst3;

   d0[0] = _mm_set_epi32( s[12], s[ 8], s[ 4], s[ 0] );
   d1[0] = _mm_set_epi32( s[13], s[ 9], s[ 5], s[ 1] );
   d2[0] = _mm_set_epi32( s[14], s[10], s[ 6], s[ 2] );
   d3[0] = _mm_set_epi32( s[15], s[11], s[ 7], s[ 3] );

   d0[1] = _mm_set_epi32( s[28], s[24], s[20], s[16] );
   d1[1] = _mm_set_epi32( s[29], s[25], s[21], s[17] );
   d2[1] = _mm_set_epi32( s[30], s[26], s[22], s[18] );
   d3[1] = _mm_set_epi32( s[31], s[27], s[23], s[19] );

   if ( bit_len <= 256 ) return;

   d0[2] = _mm_set_epi32( s[44], s[40], s[36], s[32] );
   d1[2] = _mm_set_epi32( s[45], s[41], s[37], s[33] );
   d2[2] = _mm_set_epi32( s[46], s[42], s[38], s[34] );
   d3[2] = _mm_set_epi32( s[47], s[43], s[39], s[35] );

   d0[3] = _mm_set_epi32( s[60], s[56], s[52], s[48] );
   d1[3] = _mm_set_epi32( s[61], s[57], s[53], s[49] );
   d2[3] = _mm_set_epi32( s[62], s[58], s[54], s[50] );
   d3[3] = _mm_set_epi32( s[63], s[59], s[55], s[51] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm_set_epi32( s[76], s[72], s[68], s[64] );
   d1[4] = _mm_set_epi32( s[77], s[73], s[69], s[65] );
   d2[4] = _mm_set_epi32( s[78], s[74], s[70], s[66] );
   d3[4] = _mm_set_epi32( s[79], s[75], s[71], s[67] );

   if ( bit_len <= 640 ) return;

   d0[5] = _mm_set_epi32( s[92], s[88], s[84], s[80] );
   d1[5] = _mm_set_epi32( s[93], s[89], s[85], s[81] );
   d2[5] = _mm_set_epi32( s[94], s[90], s[86], s[82] );
   d3[5] = _mm_set_epi32( s[95], s[91], s[87], s[83] );

   d0[6] = _mm_set_epi32( s[108], s[104], s[100], s[ 96] );
   d1[6] = _mm_set_epi32( s[109], s[105], s[101], s[ 97] );
   d2[6] = _mm_set_epi32( s[110], s[106], s[102], s[ 98] );
   d3[6] = _mm_set_epi32( s[111], s[107], s[103], s[ 99] );

   d0[7] = _mm_set_epi32( s[124], s[120], s[116], s[112] );
   d1[7] = _mm_set_epi32( s[125], s[121], s[117], s[113] );
   d2[7] = _mm_set_epi32( s[126], s[122], s[118], s[114] );
   d3[7] = _mm_set_epi32( s[127], s[123], s[119], s[115] );
   // bit_len == 1024
}

// extract and deinterleave specified lane.
static inline void mm_extract_lane_4x32( void *dst, const void *src,
                                         const  int lane, const int bit_len )
{
   uint32_t *s = (uint32_t*)src;
   __m128i* d = (__m128i*)dst;

   d[0] = _mm_set_epi32( s[lane+12], s[lane+ 8], s[lane+ 4], s[lane+ 0] );
   d[1] = _mm_set_epi32( s[lane+28], s[lane+24], s[lane+20], s[lane+16] );

   if ( bit_len <= 256 ) return;

   d[2] = _mm_set_epi32( s[lane+44], s[lane+40], s[lane+36], s[lane+32] );
   d[3] = _mm_set_epi32( s[lane+60], s[lane+56], s[lane+52], s[lane+48] );
   // bit_len == 512
}

// deinterleave 4 arrays into individual buffers for scalarm processing
// bit_len must be multiple of 32
static inline void mm_deinterleave_4x32x( void *dst0, void *dst1, void *dst2,
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

#if defined (__AVX2__)

// Interleave 4 source buffers containing 64 bit data into the destination
// buffer. Only bit_len 256, 512, 640 & 1024 are supported.
static inline void mm256_interleave_4x64( void *dst, const void *src0,
            const void *src1, const void *src2, const void *src3, int bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;
   uint64_t *s2 = (uint64_t*)src2;
   uint64_t *s3 = (uint64_t*)src3;

   d[0] = _mm256_set_epi64x( s3[0], s2[0], s1[0], s0[0] );
   d[1] = _mm256_set_epi64x( s3[1], s2[1], s1[1], s0[1] );
   d[2] = _mm256_set_epi64x( s3[2], s2[2], s1[2], s0[2] );
   d[3] = _mm256_set_epi64x( s3[3], s2[3], s1[3], s0[3] );

   if ( bit_len <= 256 ) return;

   d[4] = _mm256_set_epi64x( s3[4], s2[4], s1[4], s0[4] );
   d[5] = _mm256_set_epi64x( s3[5], s2[5], s1[5], s0[5] );
   d[6] = _mm256_set_epi64x( s3[6], s2[6], s1[6], s0[6] );
   d[7] = _mm256_set_epi64x( s3[7], s2[7], s1[7], s0[7] );

   if ( bit_len <= 512 ) return;

   d[8] = _mm256_set_epi64x( s3[8], s2[8], s1[8], s0[8] );
   d[9] = _mm256_set_epi64x( s3[9], s2[9], s1[9], s0[9] );

   if ( bit_len <= 640 ) return;

   d[10] = _mm256_set_epi64x( s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm256_set_epi64x( s3[11], s2[11], s1[11], s0[11] );

   d[12] = _mm256_set_epi64x( s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm256_set_epi64x( s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm256_set_epi64x( s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm256_set_epi64x( s3[15], s2[15], s1[15], s0[15] );
   // bit_len == 1024
}

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

// Deinterleave 4 buffers of 64 bit data from the source buffer.
// bit_len must be 256, 512, 640 or 1024 bits.
// Requires overrun padding for 640 bit len.
static inline void mm256_deinterleave_4x64( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src, int bit_len )
{
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   __m256i* d2 = (__m256i*)dst2;
   __m256i* d3 = (__m256i*)dst3;
   uint64_t* s = (uint64_t*)src;

   d0[0] = _mm256_set_epi64x( s[12], s[ 8], s[ 4], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[13], s[ 9], s[ 5], s[ 1] );
   d2[0] = _mm256_set_epi64x( s[14], s[10], s[ 6], s[ 2] );
   d3[0] = _mm256_set_epi64x( s[15], s[11], s[ 7], s[ 3] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi64x( s[28], s[24], s[20], s[16] );
   d1[1] = _mm256_set_epi64x( s[29], s[25], s[21], s[17] );
   d2[1] = _mm256_set_epi64x( s[30], s[26], s[22], s[18] );
   d3[1] = _mm256_set_epi64x( s[31], s[27], s[23], s[19] );

   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      // null change to overrun area
      d0[2] = _mm256_set_epi64x( d0[2][3], d0[2][2], s[36], s[32] );
      d1[2] = _mm256_set_epi64x( d1[2][3], d1[2][2], s[37], s[33] );
      d2[2] = _mm256_set_epi64x( d2[2][3], d2[2][2], s[38], s[34] );
      d3[2] = _mm256_set_epi64x( d3[2][3], d3[2][2], s[39], s[35] );
      return;
   }

   d0[2] = _mm256_set_epi64x( s[44], s[40], s[36], s[32] );
   d1[2] = _mm256_set_epi64x( s[45], s[41], s[37], s[33] );
   d2[2] = _mm256_set_epi64x( s[46], s[42], s[38], s[34] );
   d3[2] = _mm256_set_epi64x( s[47], s[43], s[39], s[35] );

   d0[3] = _mm256_set_epi64x( s[60], s[56], s[52], s[48] );
   d1[3] = _mm256_set_epi64x( s[61], s[57], s[53], s[49] );
   d2[3] = _mm256_set_epi64x( s[62], s[58], s[54], s[50] );
   d3[3] = _mm256_set_epi64x( s[63], s[59], s[55], s[51] );
   // bit_len == 1024
}

// extract and deinterleave specified lane.
static inline void mm256_extract_lane_4x64( void *dst, const void *src,
                                            const int lane, const int bit_len )
{
   uint64_t *s = (uint64_t*)src;
   __m256i* d = (__m256i*)dst;

   d[0] = _mm256_set_epi64x( s[12+lane], s[ 8+lane], s[ 4+lane], s[   lane] );

   if ( bit_len <= 256 ) return;

   d[1] = _mm256_set_epi64x( s[28+lane], s[24+lane], s[20+lane], s[16+lane] );
   // bit_len == 512
}

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

// Interleave 8 source buffers containing 32 bit data into the destination
// vector
static inline void mm256_interleave_8x32( void *dst, const void *src0,
        const void *src1, const void *src2, const void *src3, const void *src4,
        const void *src5, const void *src6, const void *src7, int bit_len )
{
   uint32_t *s0 = (uint32_t*)src0;
   uint32_t *s1 = (uint32_t*)src1;
   uint32_t *s2 = (uint32_t*)src2;
   uint32_t *s3 = (uint32_t*)src3;
   uint32_t *s4 = (uint32_t*)src4;
   uint32_t *s5 = (uint32_t*)src5;
   uint32_t *s6 = (uint32_t*)src6;
   uint32_t *s7 = (uint32_t*)src7;
   __m256i *d = (__m256i*)dst;

   d[ 0] = _mm256_set_epi32( s7[0], s6[0], s5[0], s4[0],
                             s3[0], s2[0], s1[0], s0[0] );
   d[ 1] = _mm256_set_epi32( s7[1], s6[1], s5[1], s4[1],
                             s3[1], s2[1], s1[1], s0[1] );
   d[ 2] = _mm256_set_epi32( s7[2], s6[2], s5[2], s4[2],
                             s3[2], s2[2], s1[2], s0[2] );
   d[ 3] = _mm256_set_epi32( s7[3], s6[3], s5[3], s4[3],
                             s3[3], s2[3], s1[3], s0[3] );
   d[ 4] = _mm256_set_epi32( s7[4], s6[4], s5[4], s4[4],
                             s3[4], s2[4], s1[4], s0[4] );
   d[ 5] = _mm256_set_epi32( s7[5], s6[5], s5[5], s4[5],
                             s3[5], s2[5], s1[5], s0[5] );
   d[ 6] = _mm256_set_epi32( s7[6], s6[6], s5[6], s4[6],
                             s3[6], s2[6], s1[6], s0[6] );
   d[ 7] = _mm256_set_epi32( s7[7], s6[7], s5[7], s4[7],
                             s3[7], s2[7], s1[7], s0[7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = _mm256_set_epi32( s7[ 8], s6[ 8], s5[ 8], s4[ 8],
                             s3[ 8], s2[ 8], s1[ 8], s0[ 8] );
   d[ 9] = _mm256_set_epi32( s7[ 9], s6[ 9], s5[ 9], s4[ 9],
                             s3[ 9], s2[ 9], s1[ 9], s0[ 9] );
   d[10] = _mm256_set_epi32( s7[10], s6[10], s5[10], s4[10],
                             s3[10], s2[10], s1[10], s0[10] );
   d[11] = _mm256_set_epi32( s7[11], s6[11], s5[11], s4[11],
                             s3[11], s2[11], s1[11], s0[11] );
   d[12] = _mm256_set_epi32( s7[12], s6[12], s5[12], s4[12],
                             s3[12], s2[12], s1[12], s0[12] );
   d[13] = _mm256_set_epi32( s7[13], s6[13], s5[13], s4[13],
                             s3[13], s2[13], s1[13], s0[13] );
   d[14] = _mm256_set_epi32( s7[14], s6[14], s5[14], s4[14],
                             s3[14], s2[14], s1[14], s0[14] );
   d[15] = _mm256_set_epi32( s7[15], s6[15], s5[15], s4[15],
                             s3[15], s2[15], s1[15], s0[15] );

   if ( bit_len <= 512 ) return;

   d[16] = _mm256_set_epi32( s7[16], s6[16], s5[16], s4[16],
                             s3[16], s2[16], s1[16], s0[16] );
   d[17] = _mm256_set_epi32( s7[17], s6[17], s5[17], s4[17],
                             s3[17], s2[17], s1[17], s0[17] );
   d[18] = _mm256_set_epi32( s7[18], s6[18], s5[18], s4[18],
                             s3[18], s2[18], s1[18], s0[18] );
   d[19] = _mm256_set_epi32( s7[19], s6[19], s5[19], s4[19],
                             s3[19], s2[19], s1[19], s0[19] );

   if ( bit_len <= 640 ) return;

   d[20] = _mm256_set_epi32( s7[20], s6[20], s5[20], s4[20],
                             s3[20], s2[20], s1[20], s0[20] );
   d[21] = _mm256_set_epi32( s7[21], s6[21], s5[21], s4[21],
                             s3[21], s2[21], s1[21], s0[21] );
   d[22] = _mm256_set_epi32( s7[22], s6[22], s5[22], s4[22],
                             s3[22], s2[22], s1[22], s0[22] );
   d[23] = _mm256_set_epi32( s7[23], s6[23], s5[23], s4[23],
                             s3[23], s2[23], s1[23], s0[23] );

   if ( bit_len <= 768 ) return;

   d[24] = _mm256_set_epi32( s7[24], s6[24], s5[24], s4[24],
                             s3[24], s2[24], s1[24], s0[24] );
   d[25] = _mm256_set_epi32( s7[25], s6[25], s5[25], s4[25],
                             s3[25], s2[25], s1[25], s0[25] );
   d[26] = _mm256_set_epi32( s7[26], s6[26], s5[26], s4[26],
                             s3[26], s2[26], s1[26], s0[26] );
   d[27] = _mm256_set_epi32( s7[27], s6[27], s5[27], s4[27],
                             s3[27], s2[27], s1[27], s0[27] );
   d[28] = _mm256_set_epi32( s7[28], s6[28], s5[28], s4[28],
                             s3[28], s2[28], s1[28], s0[28] );
   d[29] = _mm256_set_epi32( s7[29], s6[29], s5[29], s4[29],
                             s3[29], s2[29], s1[29], s0[29] );
   d[30] = _mm256_set_epi32( s7[30], s6[30], s5[30], s4[30],
                             s3[30], s2[30], s1[30], s0[30] );
   d[31] = _mm256_set_epi32( s7[31], s6[31], s5[31], s4[31],
                             s3[31], s2[31], s1[31], s0[31] );

   // bit_len == 1024
}

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

// Deinterleave 8 buffers of 32 bit data from the source buffer.
static inline void mm256_deinterleave_8x32( void *dst0, void *dst1, void *dst2,
              void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
              const void *src, int bit_len )
{
   uint32_t *s = (uint32_t*)src;
   __m256i* d0 = (__m256i*)dst0;
   __m256i* d1 = (__m256i*)dst1;
   __m256i* d2 = (__m256i*)dst2;
   __m256i* d3 = (__m256i*)dst3;
   __m256i* d4 = (__m256i*)dst4;
   __m256i* d5 = (__m256i*)dst5;
   __m256i* d6 = (__m256i*)dst6;
   __m256i* d7 = (__m256i*)dst7;

   d0[0] = _mm256_set_epi32( s[ 56], s[ 48], s[ 40], s[ 32],
                             s[ 24], s[ 16], s[  8], s[  0] );
   d1[0] = _mm256_set_epi32( s[ 57], s[ 49], s[ 41], s[ 33],
                             s[ 25], s[ 17], s[  9], s[  1] );
   d2[0] = _mm256_set_epi32( s[ 58], s[ 50], s[ 42], s[ 34],
                             s[ 26], s[ 18], s[ 10], s[  2] );
   d3[0] = _mm256_set_epi32( s[ 59], s[ 51], s[ 43], s[ 35],
                             s[ 27], s[ 19], s[ 11], s[  3] );
   d4[0] = _mm256_set_epi32( s[ 60], s[ 52], s[ 44], s[ 36],
                             s[ 28], s[ 20], s[ 12], s[  4] );
   d5[0] = _mm256_set_epi32( s[ 61], s[ 53], s[ 45], s[ 37],
                             s[ 29], s[ 21], s[ 13], s[  5] );
   d6[0] = _mm256_set_epi32( s[ 62], s[ 54], s[ 46], s[ 38],
                             s[ 30], s[ 22], s[ 14], s[  6] );
   d7[0] = _mm256_set_epi32( s[ 63], s[ 55], s[ 47], s[ 39],
                             s[ 31], s[ 23], s[ 15], s[  7] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi32( s[120], s[112], s[104], s[ 96],
                             s[ 88], s[ 80], s[ 72], s[ 64] );
   d1[1] = _mm256_set_epi32( s[121], s[113], s[105], s[ 97],
                             s[ 89], s[ 81], s[ 73], s[ 65] );
   d2[1] = _mm256_set_epi32( s[122], s[114], s[106], s[ 98],
                             s[ 90], s[ 82], s[ 74], s[ 66]);
   d3[1] = _mm256_set_epi32( s[123], s[115], s[107], s[ 99],
                             s[ 91], s[ 83], s[ 75], s[ 67] );
   d4[1] = _mm256_set_epi32( s[124], s[116], s[108], s[100],
                             s[ 92], s[ 84], s[ 76], s[ 68] );
   d5[1] = _mm256_set_epi32( s[125], s[117], s[109], s[101],
                             s[ 93], s[ 85], s[ 77], s[ 69] );
   d6[1] = _mm256_set_epi32( s[126], s[118], s[110], s[102],
                             s[ 94], s[ 86], s[ 78], s[ 70] );
   d7[1] = _mm256_set_epi32( s[127], s[119], s[111], s[103],
                             s[ 95], s[ 87], s[ 79], s[ 71] );

   if ( bit_len <= 512 ) return;

   // null change for overrun space, vector indexing doesn't work for
   // 32 bit data
   if ( bit_len <= 640 )
   {
      uint32_t *d = ((uint32_t*)d0) + 8;
      d0[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[152], s[144], s[136], s[128] );
      d = ((uint32_t*)d1) + 8;
      d1[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[153], s[145], s[137], s[129] );
      d = ((uint32_t*)d2) + 8;
      d2[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[154], s[146], s[138], s[130]);
      d = ((uint32_t*)d3) + 8;
      d3[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[155], s[147], s[139], s[131] );
      d = ((uint32_t*)d4) + 8;
      d4[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[156], s[148], s[140], s[132] );
      d = ((uint32_t*)d5) + 8;
      d5[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[157], s[149], s[141], s[133] );
      d = ((uint32_t*)d6) + 8;
      d6[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[158], s[150], s[142], s[134] );
      d = ((uint32_t*)d7) + 8;
      d7[2] = _mm256_set_epi32( *(d+7), *(d+6), *(d+5), *(d+4),
                                  s[159], s[151], s[143], s[135] );
      return;
   }

   d0[2] = _mm256_set_epi32( s[184], s[176], s[168], s[160],
                             s[152], s[144], s[136], s[128] );
   d1[2] = _mm256_set_epi32( s[185], s[177], s[169], s[161],
                             s[153], s[145], s[137], s[129] );
   d2[2] = _mm256_set_epi32( s[186], s[178], s[170], s[162],
                             s[154], s[146], s[138], s[130] );
   d3[2] = _mm256_set_epi32( s[187], s[179], s[171], s[163],
                             s[155], s[147], s[139], s[131] );
   d4[2] = _mm256_set_epi32( s[188], s[180], s[172], s[164],
                             s[156], s[148], s[140], s[132] );
   d5[2] = _mm256_set_epi32( s[189], s[181], s[173], s[165],
                             s[157], s[149], s[141], s[133] );
   d6[2] = _mm256_set_epi32( s[190], s[182], s[174], s[166],
                             s[158], s[150], s[142], s[134] );
   d7[2] = _mm256_set_epi32( s[191], s[183], s[175], s[167],
                             s[159], s[151], s[143], s[135] );

   if ( bit_len <= 768 ) return;

   d0[3] = _mm256_set_epi32( s[248], s[240], s[232], s[224],
                             s[216], s[208], s[200], s[192] );
   d1[3] = _mm256_set_epi32( s[249], s[241], s[233], s[225],
                             s[217], s[209], s[201], s[193] );
   d2[3] = _mm256_set_epi32( s[250], s[242], s[234], s[226],
                             s[218], s[210], s[202], s[194] );
   d3[3] = _mm256_set_epi32( s[251], s[243], s[235], s[227],
                             s[219], s[211], s[203], s[195] );
   d4[3] = _mm256_set_epi32( s[252], s[244], s[236], s[228],
                             s[220], s[212], s[204], s[196] );
   d5[3] = _mm256_set_epi32( s[253], s[245], s[237], s[229],
                             s[221], s[213], s[205], s[197] );
   d6[3] = _mm256_set_epi32( s[254], s[246], s[238], s[230],
                             s[222], s[214], s[206], s[198] );
   d7[3] = _mm256_set_epi32( s[255], s[247], s[239], s[231],
                             s[223], s[215], s[207], s[199] );
// bit_len == 1024
}

static inline void mm256_extract_lane_8x32( void *dst, const void *src,
                                            const int lane, const int bit_len )
{
  uint32_t *s = (uint32_t*)src;
  __m256i* d = (__m256i*)dst;

  d[0] = _mm256_set_epi32( s[56+lane], s[48+lane], s[40+lane], s[32+lane],
                           s[24+lane], s[24+lane], s[ 8+lane], s[   lane] );

  if ( bit_len <= 256 ) return;

  d[1] = _mm256_set_epi32( s[120+lane], s[112+lane], s[104+lane], s[96+lane],
                           s[ 88+lane], s[ 80+lane], s[ 72+lane], s[64+lane] );
  // bit_len == 512
}

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

// Convert from 4x32 AVX interleaving to 4x64 AVX2.
// Can't do it in place
static inline void mm256_reinterleave_4x64( void *dst, void *src, int  bit_len )
{
   __m256i* d = (__m256i*)dst;
   uint32_t *s = (uint32_t*)src;

   d[0] = _mm256_set_epi32( s[7], s[3], s[6], s[2], s[5], s[1], s[4], s[0] );
   d[1] = _mm256_set_epi32( s[15],s[11],s[14],s[10],s[13],s[9],s[12], s[8] );
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

// Convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
static inline void mm256_reinterleave_4x32( void *dst, void *src, int  bit_len )
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

static inline void mm256_interleave_2x128( void *dst, void *src0, void *src1,
                                           int bit_len )
{
   __m256i  *d = (__m256i*)dst;
   uint64_t *s0 = (uint64_t*)src0;
   uint64_t *s1 = (uint64_t*)src1;   

   d[0] = _mm256_set_epi64x( s1[ 1], s1[ 0], s0[ 1], s0[ 0] );
   d[1] = _mm256_set_epi64x( s1[ 3], s1[ 2], s0[ 3], s0[ 2] );

   if ( bit_len <= 256 ) return;

   d[2] = _mm256_set_epi64x( s1[ 5], s1[ 4], s0[ 5], s0[ 4] );
   d[3] = _mm256_set_epi64x( s1[ 7], s1[ 6], s0[ 7], s0[ 6] );

   if ( bit_len <= 512 ) return;

   d[4] = _mm256_set_epi64x( s1[ 9], s1[ 8], s0[ 9], s0[ 8] );
   
   if ( bit_len <= 640 ) return;

   d[5] = _mm256_set_epi64x( s1[11], s1[10], s0[11], s0[10] );

   d[6] = _mm256_set_epi64x( s1[13], s1[12], s0[13], s0[12] );
   d[7] = _mm256_set_epi64x( s1[15], s1[14], s0[15], s0[14] );

   // bit_len == 1024
}

static inline void mm256_deinterleave_2x128( void *dst0, void *dst1, void *src,
                                             int bit_len )
{
   uint64_t *s = (uint64_t*)src;
   __m256i  *d0 = (__m256i*)dst0;
   __m256i  *d1 = (__m256i*)dst1;

   d0[0] = _mm256_set_epi64x( s[ 5], s[4], s[ 1], s[ 0] );
   d1[0] = _mm256_set_epi64x( s[ 7], s[6], s[ 3], s[ 2] );

   if ( bit_len <= 256 ) return;

   d0[1] = _mm256_set_epi64x( s[13], s[12], s[ 9], s[ 8] );
   d1[1] = _mm256_set_epi64x( s[15], s[14], s[11], s[10] );

   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      d0[2] = _mm256_set_epi64x( d0[2][3], d0[2][2], s[17], s[16] );
      d1[2] = _mm256_set_epi64x( d1[2][3], d1[2][2], s[19], s[18] );
      return;
   }

   d0[2] = _mm256_set_epi64x( s[21], s[20], s[17], s[16] );
   d1[2] = _mm256_set_epi64x( s[23], s[22], s[19], s[18] );

   d0[3] = _mm256_set_epi64x( s[29], s[28], s[25], s[24] );
   d1[3] = _mm256_set_epi64x( s[31], s[30], s[27], s[26] );

   // bit_len == 1024
}

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

#endif // __AVX2__

//#if defined(__AVX512F__)
#if 0

// Macro functions returning vector.
// Abstracted typecasting, avoid temp pointers.
// Source arguments may be any 64 or 32 bit aligned pointer as appropriate.

#define mm512_put_64( s0, s1, s2, s3, s4, s5, s6, s7 ) \
  _mm512_set_epi64( *((const uint64_t*)(s7)), *((const uint64_t*)(s6)), \
                    *((const uint64_t*)(s5)), *((const uint64_t*)(s4)), \
                    *((const uint64_t*)(s3)), *((const uint64_t*)(s2)), \
                    *((const uint64_t*)(s1)), *((const uint64_t*)(s0)) ) 

#define mm512_put_32( s00, s01, s02, s03, s04, s05, s06, s07, \
                      s08, s09, s10, s11, s12, s13, s14, s15 ) \
  _mm512_set_epi64( *((const uint32_t*)(s15)), *((const uint32_t*)(s14)), \
                    *((const uint32_t*)(s13)), *((const uint32_t*)(s12)), \
                    *((const uint32_t*)(s11)), *((const uint32_t*)(s10)), \
                    *((const uint32_t*)(s09)), *((const uint32_t*)(s08)), \
                    *((const uint32_t*)(s07)), *((const uint32_t*)(s06)), \
                    *((const uint32_t*)(s05)), *((const uint32_t*)(s04)), \
                    *((const uint32_t*)(s03)), *((const uint32_t*)(s02)), \
                    *((const uint32_t*)(s01)), *((const uint32_t*)(s00)) ) 

// Inconsistent pointer arithmetic, interleave always uses bytes, deinterleave
// uses scaled.

#define mm_get_64( s, i0, i1 ) \
  _mm_set_epi64x( ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm256_get_64( s, i0, i1, i2, i3 ) \
  _mm256_set_epi64x( ((const uint64_t*)(s))[i3], ((const uint64_t*)(s))[i2], \
                     ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm512_get_64( s, i0, i1, i2, i3, i4, i5, i6, i7 ) \
  _mm512_set_epi64( ((const uint64_t*)(s))[i7], ((const uint64_t*)(s))[i6], \
                    ((const uint64_t*)(s))[i5], ((const uint64_t*)(s))[i4], \
                    ((const uint64_t*)(s))[i3], ((const uint64_t*)(s))[i2], \
                    ((const uint64_t*)(s))[i1], ((const uint64_t*)(s))[i0] )

#define mm_get_32( s, i0, i1, i2, i3 ) \
  _mm_set_epi32( ((const uint32_t*)(s))[i3], ((const uint32_t*)(s))[i2], \
                 ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

#define mm256_get_32( s, i0, i1, i2, i3, i4, i5, i6, i7 ) \
  _mm256_set_epi32( ((const uint32_t*)(s))[i7], ((const uint32_t*)(s))[i6], \
                    ((const uint32_t*)(s))[i5], ((const uint32_t*)(s))[i4], \
                    ((const uint32_t*)(s))[i3], ((const uint32_t*)(s))[i2], \
                    ((const uint32_t*)(s))[i1], ((const uint32_t*)(s))[i0] )

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



static inline void mm512_interleave_8x64( void *d, const void *s0,
                   const void *s1, const void *s2, const void *s3,
                   const void *s4, const void *s5, const void *s6,
                   const void *s7, int bit_len )
{
  casti_m512i( d, 0 ) = mm512_put_64( s7,    s6,    s5,    s4,
                                      s3,    s2,    s1,    s0 );
  casti_m512i( d, 1 ) = mm512_put_64( s7+ 8, s6+ 8, s5+ 8, s4+ 8,
                                      s3+ 8, s2+ 8, s1+ 8, s0+ 8 );
  casti_m512i( d, 2 ) = mm512_put_64( s7+16, s6+16, s5+16, s4+16,
                                      s3+16, s2+16, s1+16, s0+16 );
  casti_m512i( d, 3 ) = mm512_put_64( s7+24, s6+24, s5+24, s4+24,
                                      s3+24, s2+24, s1+24, s0+24 );
  if ( bit_len <= 256 ) return;

  casti_m512i( d, 4 ) = mm512_put_64( s7+32, s6+32, s5+32, s4+32,
                                      s3+32, s2+32, s1+32, s0+32 );
  casti_m512i( d, 5 ) = mm512_put_64( s7+40, s6+40, s5+40, s4+40,
                                      s3+40, s2+40, s1+40, s0+40 );
  casti_m512i( d, 6 ) = mm512_put_64( s7+48, s6+48, s5+48, s4+48,
                                      s3+48, s2+48, s1+48, s0+48 );
  casti_m512i( d, 7 ) = mm512_put_64( s7+56, s6+56, s5+56, s4+56,
                                      s3+56, s2+56, s1+56, s0+56 );
  if ( bit_len <= 512 ) return;

  casti_m512i( d, 8 ) = mm512_put_64( s7+64, s6+64, s5+64, s4+64,
                                      s3+64, s2+64, s1+64, s0+64 );
  casti_m512i( d, 9 ) = mm512_put_64( s7+72, s6+72, s5+72, s4+72,
                                      s3+72, s2+72, s1+72, s0+72 );

  if ( bit_len <= 640 ) return;

  casti_m512i( d, 10 ) = mm512_put_64( s7+ 80, s6+ 80, s5+ 80, s4+ 80,
                                       s3+ 80, s2+ 80, s1+ 80, s0+ 80 );
  casti_m512i( d, 11 ) = mm512_put_64( s7+ 88, s6+ 88, s5+ 88, s4+ 88,
                                       s3+ 88, s2+ 88, s1+ 88, s0+ 88 );
  casti_m512i( d, 12 ) = mm512_put_64( s7+ 96, s6+ 96, s5+ 96, s4+ 96,
                                       s3+ 96, s2+ 96, s1+ 96, s0+ 96 );
  casti_m512i( d, 13 ) = mm512_put_64( s7+104, s6+104, s5+104, s4+104,
                                       s3+104, s2+104, s1+104, s0+104 );
  casti_m512i( d, 14 ) = mm512_put_64( s7+112, s6+112, s5+112, s4+112,
                                       s3+112, s2+112, s1+112, s0+112 );
  casti_m512i( d, 15 ) = mm512_put_64( s7+120, s6+120, s5+120, s4+120,
                                       s3+120, s2+120, s1+120, s0+120 );
  // bit_len == 1024
}

// 8 lanes of 128 bits using 64 bit interleaving
// Used for last 16 bytes of 80 byte input, only used for testing.
static inline void mm_deinterleave_8x64x128( void *d0, void *d1, void *d2,
                         void *d3, void *d4, void *d5, void *d6, void *d7,
                         const void *s )
{
   cast_m128i( d0 ) = mm_get_64( s,  8, 0 );
   cast_m128i( d1 ) = mm_get_64( s,  9, 1 );
   cast_m128i( d2 ) = mm_get_64( s, 10, 2 );
   cast_m128i( d3 ) = mm_get_64( s, 11, 3 );
   cast_m128i( d4 ) = mm_get_64( s, 12, 4 );
   cast_m128i( d5 ) = mm_get_64( s, 13, 5 );
   cast_m128i( d6 ) = mm_get_64( s, 14, 6 );
   cast_m128i( d7 ) = mm_get_64( s, 15, 7 );
}

// 8 lanes of 256 bits using 64 bit interleaving (standard final hash size)
static inline void mm256_deinterleave_8x64x256( void *d0, void *d1, void *d2,
                            void *d3, void *d4, void *d5, void *d6, void *d7,
                            const void *s )
{
   cast_m256i( d0 ) = mm256_get_64( s, 24, 16,  8,  0 );
   cast_m256i( d1 ) = mm256_get_64( s, 25, 17,  9,  1 );
   cast_m256i( d2 ) = mm256_get_64( s, 26, 18, 10,  2 );
   cast_m256i( d3 ) = mm256_get_64( s, 27, 19, 11,  3 );
   cast_m256i( d4 ) = mm256_get_64( s, 28, 20, 12,  4 );
   cast_m256i( d5 ) = mm256_get_64( s, 29, 21, 13,  5 );
   cast_m256i( d6 ) = mm256_get_64( s, 30, 22, 14,  6 );
   cast_m256i( d6 ) = mm256_get_64( s, 31, 23, 15,  7 );
}

// 8 lanes of 512 bits using 64 bit interleaving (typical intermediate hash) 
static inline void mm512_deinterleave_8x64x512( void *d00, void *d01,
               void *d02, void *d03, void *d04, void *d05, void *d06,
               void *d07, const void *s )
{
   cast_m512i( d0 ) = mm512_get_64( s, 56, 48, 40, 32, 24, 16,  8,  0 );
   cast_m512i( d1 ) = mm512_get_64( s, 57, 49, 41, 33, 25, 17,  9,  1 );
   cast_m512i( d2 ) = mm512_get_64( s, 58, 50, 42, 34, 26, 18, 10,  2 );
   cast_m512i( d3 ) = mm512_get_64( s, 59, 51, 43, 35, 27, 19, 11,  3 );
   cast_m512i( d4 ) = mm512_get_64( s, 60, 52, 44, 36, 28, 20, 12,  4 );
   cast_m512i( d5 ) = mm512_get_64( s, 61, 53, 45, 37, 29, 21, 13,  5 );
   cast_m512i( d7 ) = mm512_get_64( s, 62, 54, 46, 38, 30, 22, 14,  6 );
   cast_m512i( d7 ) = mm512_get_64( s, 63, 55, 47, 39, 31, 23, 15,  7 );
}

static inline void mm512_deinterleave_8x64( void *dst0, void *dst1, void *dst2,
              void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
              const void *src, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_8x64x256( dst0, dst1, dst2, dst3,
                                   dst4, dst5, dst6, dst7, src );
      return
   }

   mm512_deinterleave_8x64x512( dst0, dst1, dst2, dst3,
                                dst4, dst5, dst6, dst7, src );
   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      mm_deinterleave_8x64x128( dst0+64, dst1+64, dst2+64, dst3+64,
                                dst4+64, dst5+64, dst6+64, dst7+64, src+512 );
      return;
   }

   // bit_len == 1024
   mm512_deinterleave_8x64x512( dst0+64, dst1+64, dst2+64, dst3+64,
                                dst4+64, dst5+64, dst6+64, dst7+64, src+512 );
}

// Extract one lane from 64 bit interleaved data
static inline void mm512_extract_lane_8x64( void *dst, const void *src,
                                            const int lane, const int bit_len )
{
  const uint64_t *s = (const uint64_t*)src;

  if ( bit_len <= 256 )
  {
     cast_m256i( dst ) = mm256_get_64( src, 24+lane, 16+lane,
                                             8+lane,    lane );
     return;
  }
  // else bit_len == 512
  cast_m512i( dst ) = mm512_get_64( src, 56+lane, 48+lane,
                                         40+lane, 32+lane,
                                         24+lane, 16+lane,
                                          8+lane,    lane );
}


static inline void mm512_interleave_16x32( void *dst, const void *s00,
    const void *s01, const void *s02, const void *s03, const void *s04,
    const void *s05, const void *s06, const void *s07, const void *s08,
    const void *s09, const void *s10, const void *s11, const void *s12,
    const void *s13, const void *s14, const void *s15, int bit_len )
{
   casti_m512i( d, 0 ) = mm512_put_32( s15,    s14,    s13,    s12,
                                       s11,    s10,    s09,    s08,
                                       s07,    s06,    s05,    s04,
                                       s03,    s02,    s01,    s00 );
   casti_m512i( d, 1 ) = mm512_put_32( s15+ 4, s14+ 4, s13+ 4, s12+ 4,
                                       s11+ 4, s10+ 4, s09+ 4, s08+ 4,
                                       s07+ 4, s06+ 4, s05+ 4, s04+ 4,
                                       s03+ 4, s02+ 4, s01+ 4, s00+ 4 );
   casti_m512i( d, 2 ) = mm512_put_32( s15+ 8, s14+ 8, s13+ 8, s12+ 8,
                                       s11+ 8, s10+ 8, s09+ 8, s08+ 8,
                                       s07+ 8, s06+ 8, s05+ 8, s04+ 8,
                                       s03+ 8, s02+ 8, s01+ 8, s00+ 8 );
   casti_m512i( d, 3 ) = mm512_put_32( s15+12, s14+12, s13+12, s12+12,
                                       s11+12, s10+12, s09+12, s08+12,
                                       s07+12, s06+12, s05+12, s04+12,
                                       s03+12, s02+12, s01+12, s00+12 );
   casti_m512i( d, 4 ) = mm512_put_32( s15+16, s14+16, s13+16, s12+16,
                                       s11+16, s10+16, s09+16, s08+16,
                                       s07+16, s06+16, s05+16, s04+16,
                                       s03+16, s02+16, s01+16, s00+16 );
   casti_m512i( d, 5 ) = mm512_put_32( s15+20, s14+20, s13+20, s12+20,
                                       s11+20, s10+20, s09+20, s08+20,
                                       s07+20, s06+20, s05+20, s04+20,
                                       s03+20, s02+20, s01+20, s00+20 );
   casti_m512i( d, 6 ) = mm512_put_32( s15+24, s14+24, s13+24, s12+24,
                                       s11+24, s10+24, s09+24, s08+24,
                                       s07+24, s06+24, s05+24, s04+24,
                                       s03+24, s02+24, s01+24, s00+24 );
   casti_m512i( d, 7 ) = mm512_put_32( s15+28, s14+28, s13+28, s12+28,
                                       s11+28, s10+28, s09+28, s08+28,
                                       s07+28, s06+28, s05+28, s04+28,
                                       s03+28, s02+28, s01+28, s00+28 );
   if ( bit_len <= 256 ) return;

   casti_m512i( d,  8 ) = mm512_put_32( s15+32, s14+32, s13+32, s12+32,
                                        s11+32, s10+32, s09+32, s08+32,
                                        s07+32, s06+32, s05+32, s04+32,
                                        s03+32, s02+32, s01+32, s00+32 );
   casti_m512i( d,  9 ) = mm512_put_32( s15+36, s14+36, s13+36, s12+36,
                                        s11+36, s10+36, s09+36, s08+36,
                                        s07+36, s06+36, s05+36, s04+36,
                                        s03+36, s02+36, s01+36, s00+36 );
   casti_m512i( d, 10 ) = mm512_put_32( s15+40, s14+40, s13+40, s12+40,
                                        s11+40, s10+40, s09+40, s08+40,
                                        s07+40, s06+40, s05+40, s04+40,
                                        s03+40, s02+40, s01+40, s00+40 );
   casti_m512i( d, 11 ) = mm512_put_32( s15+44, s14+44, s13+44, s12+44,
                                        s11+44, s10+44, s09+44, s08+44,
                                        s07+44, s06+44, s05+44, s04+44,
                                        s03+44, s02+44, s01+44, s00+44 );
   casti_m512i( d, 12 ) = mm512_put_32( s15+48, s14+48, s13+48, s12+48,
                                        s11+48, s10+48, s09+48, s08+48,
                                        s07+48, s06+48, s05+48, s04+48,
                                        s03+48, s02+48, s01+48, s00+48 );
   casti_m512i( d, 13 ) = mm512_put_32( s15+52, s14+52, s13+52, s12+52,
                                        s11+52, s10+52, s09+52, s08+52,
                                        s07+52, s06+52, s05+52, s04+52,
                                        s03+52, s02+52, s01+52, s00+52 );
   casti_m512i( d, 14 ) = mm512_put_32( s15+56, s14+56, s13+56, s12+56,
                                        s11+56, s10+56, s09+56, s08+56,
                                        s07+56, s06+56, s05+56, s04+56,
                                        s03+56, s02+56, s01+56, s00+56 );
   casti_m512i( d, 15 ) = mm512_put_32( s15+60, s14+60, s13+60, s12+60,
                                        s11+60, s10+60, s09+60, s08+60,
                                        s07+60, s06+60, s05+60, s04+60,
                                        s03+60, s02+60, s01+60, s00+60 );
   if ( bit_len <= 512 ) return;

   casti_m512i( d, 16 ) = mm512_put_32( s15+64, s14+64, s13+64, s12+64,
                                        s11+64, s10+64, s09+64, s08+64,
                                        s07+64, s06+64, s05+64, s04+64,
                                        s03+64, s02+64, s01+64, s00+64 );
   casti_m512i( d, 17 ) = mm512_put_32( s15+68, s14+68, s13+68, s12+68,
                                        s11+68, s10+68, s09+68, s08+68,
                                        s07+68, s06+68, s05+68, s04+68,
                                        s03+68, s02+68, s01+68, s00+68 );
   casti_m512i( d, 18 ) = mm512_put_32( s15+72, s14+72, s13+72, s12+72,
                                        s11+72, s10+72, s09+72, s08+72,
                                        s07+72, s06+72, s05+72, s04+72,
                                        s03+72, s02+72, s01+72, s00+72 );
   casti_m512i( d, 19 ) = mm512_put_32( s15+76, s14+76, s13+76, s12+76,
                                        s11+76, s10+76, s09+76, s08+76,
                                        s07+76, s06+76, s05+76, s04+76,
                                        s03+76, s02+76, s01+76, s00+76 );
   if ( bit_len <= 640 ) return;

   casti_m512i( d, 20 ) = mm512_put_32( s15+80, s14+80, s13+80, s12+80,
                                        s11+80, s10+80, s09+80, s08+80,
                                        s07+80, s06+80, s05+80, s04+80,
                                        s03+80, s02+80, s01+80, s00+80 );
   casti_m512i( d, 21 ) = mm512_put_32( s15+84, s14+84, s13+84, s12+84,
                                        s11+84, s10+84, s09+84, s08+84,
                                        s07+84, s06+84, s05+84, s04+84,
                                        s03+84, s02+84, s01+84, s00+84 );
   casti_m512i( d, 22 ) = mm512_put_32( s15+88, s14+88, s13+88, s12+88,
                                        s11+88, s10+88, s09+88, s08+88,
                                        s07+88, s06+88, s05+88, s04+88,
                                        s03+88, s02+88, s01+88, s00+88 );
   casti_m512i( d, 23 ) = mm512_put_32( s15+92, s14+92, s13+92, s12+92,
                                        s11+92, s10+92, s09+92, s08+92,
                                        s07+92, s06+92, s05+92, s04+92,
                                        s03+92, s02+92, s01+92, s00+92 );
   if ( bit_len <= 768 ) return;

   casti_m512i( d, 24 ) = mm512_put_32( s15+ 96, s14+ 96, s13+ 96, s12+ 96,
                                        s11+ 96, s10+ 96, s09+ 96, s08+ 96,
                                        s07+ 96, s06+ 96, s05+ 96, s04+ 96,
                                        s03+ 96, s02+ 96, s01+ 96, s00+ 96 );
   casti_m512i( d, 25 ) = mm512_put_32( s15+100, s14+100, s13+100, s12+100,
                                        s11+100, s10+100, s09+100, s08+100,
                                        s07+100, s06+100, s05+100, s04+100,
                                        s03+100, s02+100, s01+100, s00+100 );
   casti_m512i( d, 26 ) = mm512_put_32( s15+104, s14+104, s13+104, s12+104,
                                        s11+104, s10+104, s09+104, s08+104,
                                        s07+104, s06+104, s05+104, s04+104,
                                        s03+104, s02+104, s01+104, s00+104 );
   casti_m512i( d, 27 ) = mm512_put_32( s15+108, s14+108, s13+108, s12+108,
                                        s11+108, s10+108, s09+108, s08+108,
                                        s07+108, s06+108, s05+108, s04+108,
                                        s03+108, s02+108, s01+108, s00+108 );
   casti_m512i( d, 28 ) = mm512_put_32( s15+112, s14+112, s13+112, s12+112,
                                        s11+112, s10+112, s09+112, s08+112,
                                        s07+112, s06+112, s05+112, s04+112,
                                        s03+112, s02+112, s01+112, s00+112 );
   casti_m512i( d, 29 ) = mm512_put_32( s15+116, s14+116, s13+116, s12+116,
                                        s11+116, s10+116, s09+116, s08+116,
                                        s07+116, s06+116, s05+116, s04+116,
                                        s03+116, s02+116, s01+116, s00+116 );
   casti_m512i( d, 30 ) = mm512_put_32( s15+120, s14+120, s13+120, s12+120,
                                        s11+120, s10+120, s09+120, s08+120,
                                        s07+120, s06+120, s05+120, s04+120,
                                        s03+120, s02+120, s01+120, s00+120 );
   casti_m512i( d, 31 ) = mm512_put_32( s15+124, s14+124, s13+124, s12+124,
                                        s11+124, s10+124, s09+124, s08+124,
                                        s07+124, s06+124, s05+124, s04+124,
                                        s03+124, s02+124, s01+124, s00+124 );
   // bit_len == 1024
}

static inline void mm_deinterleave_16x32x128( void *d00, void *d01, void *d02,
             void *d03, void *d04, void *d05, void *d06, void *d07, void *d08,
             void *d09, void *d10, void *d11, void *d12, void *d13, void *d14,
             void *d15, const void *s )
{
   cast_m128i( d00 ) = mm_get_32( s, 48, 32, 16,  0 );
   cast_m128i( d01 ) = mm_get_32( s, 49, 33, 17,  1 );
   cast_m128i( d02 ) = mm_get_32( s, 50, 34, 18,  2 );
   cast_m128i( d03 ) = mm_get_32( s, 51, 35, 19,  3 );
   cast_m128i( d04 ) = mm_get_32( s, 52, 36, 20,  4 );
   cast_m128i( d05 ) = mm_get_32( s, 53, 37, 21,  5 );
   cast_m128i( d06 ) = mm_get_32( s, 54, 38, 22,  6 );
   cast_m128i( d07 ) = mm_get_32( s, 55, 39, 23,  7 );
   cast_m128i( d08 ) = mm_get_32( s, 56, 40, 24,  8 );
   cast_m128i( d09 ) = mm_get_32( s, 57, 41, 25,  9 );
   cast_m128i( d10 ) = mm_get_32( s, 58, 42, 26, 10 );
   cast_m128i( d11 ) = mm_get_32( s, 59, 43, 27, 11 );
   cast_m128i( d12 ) = mm_get_32( s, 60, 44, 28, 12 );
   cast_m128i( d13 ) = mm_get_32( s, 61, 45, 29, 13 );
   cast_m128i( d14 ) = mm_get_32( s, 62, 46, 30, 14 );
   cast_m128i( d15 ) = mm_get_32( s, 63, 47, 31, 15 );
}

static inline void mm256_deinterleave_16x32x256( void *d00, void *d01,
                void *d02, void *d03, void *d04, void *d05, void *d06,
                void *d07, void *d08, void *d09, void *d10, void *d11,
                void *d12, void *d13, void *d14, void *d15, const void *s )
{
   cast_m256i( d00 ) = mm256_get_32( s, 112,  96, 80, 64, 48, 32, 16,  0 );
   cast_m256i( d01 ) = mm256_get_32( s, 113,  97, 81, 65, 49, 33, 17,  1 );
   cast_m256i( d02 ) = mm256_get_32( s, 114,  98, 82, 66, 50, 34, 18,  2 );
   cast_m256i( d03 ) = mm256_get_32( s, 115,  99, 83, 67, 51, 35, 19,  3 );
   cast_m256i( d04 ) = mm256_get_32( s, 116, 100, 84, 68, 52, 36, 20,  4 );
   cast_m256i( d05 ) = mm256_get_32( s, 117, 101, 85, 69, 53, 37, 21,  5 );
   cast_m256i( d06 ) = mm256_get_32( s, 118, 102, 86, 70, 54, 38, 22,  6 );
   cast_m256i( d07 ) = mm256_get_32( s, 119, 103, 87, 71, 55, 39, 23,  7 );
   cast_m256i( d08 ) = mm256_get_32( s, 120, 104, 88, 72, 56, 40, 24,  8 );
   cast_m256i( d09 ) = mm256_get_32( s, 121, 105, 89, 73, 57, 41, 25,  9 );
   cast_m256i( d10 ) = mm256_get_32( s, 122, 106, 90, 64, 58, 42, 26, 10 );
   cast_m256i( d11 ) = mm256_get_32( s, 123, 107, 91, 75, 59, 43, 27, 11 );
   cast_m256i( d12 ) = mm256_get_32( s, 124, 108, 92, 76, 60, 44, 28, 12 );
   cast_m256i( d13 ) = mm256_get_32( s, 125, 109, 93, 77, 61, 45, 29, 13 );
   cast_m256i( d14 ) = mm256_get_32( s, 126, 110, 94, 78, 62, 46, 30, 14 );
   cast_m256i( d15 ) = mm256_get_32( s, 127, 111, 95, 79, 63, 47, 31, 15 );
}

static inline void mm512_deinterleave_16x32x512( void *d00, void *d01, 
                void *d02, void *d03, void *d04, void *d05, void *d06, 
                void *d07, void *d08, void *d09, void *d10, void *d11, 
                void *d12, void *d13, void *d14, void *d15, const void *s )
{
 cast_m512i( d00 ) = mm512_get_32( s, 240, 224, 208, 192, 176, 160, 144, 128,
                                      112,  96,  80,  64,  48,  32,  16,   0 );
 cast_m512i( d01 ) = mm512_get_32( s, 241, 225, 209, 193, 177, 161, 145, 129,  
                                      113,  97,  81,  65,  49,  33,  17,   1 );
 cast_m512i( d02 ) = mm512_get_32( s, 242, 226, 210, 194, 178, 162, 146, 130,  
                                      113,  98,  82,  66,  50,  34,  18,   2 );
 cast_m512i( d03 ) = mm512_get_32( s, 243, 227, 211, 195, 179, 163, 147, 131, 
                                      115,  99,  83,  67,  51,  35,  19,   3 );
 cast_m512i( d04 ) = mm512_get_32( s, 244, 228, 212, 196, 180, 164, 148, 132,  
                                      116, 100,  84,  68,  52,  36,  20,   4 );
 cast_m512i( d05 ) = mm512_get_32( s, 245, 229, 213, 197, 181, 165, 149, 133,  
                                      117, 101,  85,  69,  53,  37,  21,   5 );
 cast_m512i( d06 ) = mm512_get_32( s, 246, 230, 214, 198, 182, 166, 150, 134,  
                                      118, 102,  86,  70,  54,  38,  22,   6 );
 cast_m512i( d07 ) = mm512_get_32( s, 247, 231, 215, 199, 183, 167, 151, 135,  
                                      119, 103,  87,  71,  55,  39,  23,   7 );
 cast_m512i( d08 ) = mm512_get_32( s, 248, 232, 216, 200, 184, 168, 152, 136,  
                                      120, 104,  88,  72,  56,  40,  24,   8 );
 cast_m512i( d09 ) = mm512_get_32( s, 249, 233, 217, 201, 185, 169, 153, 137,  
                                      121, 105,  89,  73,  57,  41,  25,   9 );
 cast_m512i( d10 ) = mm512_get_32( s, 250, 234, 218, 202, 186, 170, 154, 138,  
                                      122, 106,  90,  74,  58,  42,  26,  10 );
 cast_m512i( d11 ) = mm512_get_32( s, 251, 235, 219, 203, 187, 171, 155, 139,  
                                      123, 107,  91,  75,  59,  43,  27,  11 );
 cast_m512i( d12 ) = mm512_get_32( s, 252, 236, 220, 204, 188, 172, 156, 140,  
                                      124, 108,  92,  76,  60,  44,  28,  12 );
 cast_m512i( d13 ) = mm512_get_32( s, 253, 237, 221, 205, 189, 173, 157, 141,  
                                      125, 109,  93,  77,  61,  45,  29,  13 );
 cast_m512i( d14 ) = mm512_get_32( s, 254, 238, 222, 206, 190, 174, 158, 142,  
                                      126, 110,  94,  78,  62,  46,  30,  14 );
 cast_m512i( d15 ) = mm512_get_32( s, 255, 239, 223, 207, 191, 175, 159, 143,  
                                      127, 111,  95,  79,  63,  47,  31,  15 );

}

static inline void mm512_deinterleave_16x32( void *d00, void *d01, void *d02,
            void *d03, void *d04, void *d05, void *d06, void *d07, void *d08,
            void *d09, void *d10, void *d11, void *d12, void *d13, void *d14,
            void *d15, const void *src, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_16x32x256( d00, d01, d02, d03, d04, d05, d06, d07,
                                    d08, d09, d10, d11, d12, d13, d14, d15,
                                    src );
      return
   }
   mm512_deinterleave_16x32x512( d00, d01, d02, d03, d04, d05, d06, d07,
                                 d08, d09, d10, d11, d12, d13, d14, d15, 
                                 src );
   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      mm_deinterleave_16x32x128( d00+64, d01+64, d02+64, d03+64, d04+64,
                 d05+64, d06+64, d07+64, d08+64, d09+64, d10+64, d11+64,
                 d12+64, d13+64, d14+64, d15+64, src );
      return;
   }
   // bit_len == 1024
   mm512_deinterleave_16x32x512( d00+64, d01+64, d02+64, d03+64, d04+64, 
                 d05+64, d06+64, d07+64, d08+64, d09+64, d10+64, d11+64, 
                 d12+64, d13+64, d14+64, d15+64, src );
}

static inline void mm512_extract_lane_16x32( void *dst, const void *src,
                                            const int lane, const int bit_len )
{

  if ( bit_len <= 256 )
  {
     cast_m256i( dst ) = mm256_get_32( src, 112+lane, 96+lane, 80+lane,
                                64+lane, 48+lane, 32+lane, 16+lane, lane );
     return;
  }
  cast_m512i( dst ) = mm512_get_32( src, 240+lane, 224+lane, 208+lane,
           192+lane, 176+lane, 160+lane, 144+lane, 128+lane, 112+lane,
           96+lane, 80+lane, 64+lane, 48+lane, 32+lane, 16+lane, lane );
  if ( bit_len <= 512 ) return;

  // bit_len == 1024
  cast_m512i( dst+64 ) = mm512_get_32( src+256, 240+lane, 224+lane, 208+lane,
           192+lane, 176+lane, 160+lane, 144+lane, 128+lane, 112+lane,
           96+lane, 80+lane, 64+lane, 48+lane, 32+lane, 16+lane, lane );
}

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

static inline void mm512_deinterleave_4x128x128( void *d0, void *d1, void *d2,
                                void *d3, const void *src, const int bit_len )
{
   cast_m128i( d0 ) = mm_get_64( s, 1, 0 );
   cast_m128i( d1 ) = mm_get_64( s, 3, 2 );
   cast_m128i( d2 ) = mm_get_64( s, 5, 4 );
   cast_m128i( d3 ) = mm_get_64( s, 7, 6 );
}

static inline void mm512_deinterleave_4x128x256( void *d0, void *d1, void *d2,
                                void *d3, const void *src, const int bit_len )
{
   cast_m256i( d0 ) = mm256_get_64( s,  9,  8, 1, 0 );
   cast_m256i( d1 ) = mm256_get_64( s, 11, 10, 3, 2 );
   cast_m256i( d2 ) = mm256_get_64( s, 13, 12, 5, 4 );
   cast_m256i( d3 ) = mm256_get_64( s, 15, 14, 7, 6 );
}

static inline void mm512_deinterleave_4x128x512( void *d0, void *d1, void *d2,
                                void *d3, const void *src, const int bit_len )
{
   cast_m512i( d0 ) = mm512_get_64( s, 25, 24, 17, 16,  9,  8, 1, 0 );
   cast_m512i( d1 ) = mm512_get_64( s, 27, 26, 19, 18, 11, 10, 3, 2 );
   cast_m512i( d2 ) = mm512_get_64( s, 29, 28, 21, 20, 13, 12, 5, 4 );
   cast_m512i( d3 ) = mm512_get_64( s, 31, 30, 23, 22, 15, 14, 7, 6 );
}

static inline void mm512_deinterleave_4x128( void *dst0, void *dst1, void *dst2,
              void *dst3, const void *src, const int bit_len )
{
   if ( bit_len <= 256 )
   {
      mm256_deinterleave_4x128x256( dst0, dst1, dst2, dst3, src );
      return
   }

   mm512_deinterleave_4x128x512( dst0, dst1, dst2, dst3, src );
   if ( bit_len <= 512 ) return;

   if ( bit_len <= 640 )
   {
      mm_deinterleave_4x128x128( dst0+128, dst1+128, dst2+128, dst3+128,
                                 src+512 );
      return;
   }

   // bit_len == 1024
   mm512_deinterleave_4x128x512( dst0+128, dst1+128, dst2+128, dst3+128,
                                 src+512 );
}

static inline void mm512_extract_lane_4x128( void *dst, const void *src,
                                            const int lane, const int bit_len )
{
  int l = lane<<1;
  if ( bit_len <= 256 )
  {
     cast_m256i( dst ) = mm256_get_64( src, 9+l, 8+l, 1+l, l );
     return;
  }
  // else bit_len == 512
  cast_m512i( dst ) = mm512_get_64( src, 25+l, 24+l,  17+l, 16+l,
                                          9+l,  8+l,   1+l,    l );
}


#endif // __AVX512F__
#endif // INTERLEAVE_H__
