#if !defined(INTERLEAVE_H__)
#define INTERLEAVE_H__ 1

//////////////////////////////////////////////////////////////////////////
//
//   Utilities to interleave and deinterleave multiple data for parallel
//   processing using SIMD. Utilities are grouped by data size.
//   

////////////////////////////////
//
//          32 bit data

// 2x32

static inline void intrlv_2x32( void *dst, const void *src0,
                                const void *src1, const int bit_len )
{
   uint32_t *d = (uint32_t*)dst;;
   const uint32_t *s0 = (const uint32_t*)src0;
   const uint32_t *s1 = (const uint32_t*)src1;
   d[ 0] = s0[ 0];    d[ 1] = s1[ 0];   d[ 2] = s0[ 1];    d[ 3] = s1[ 1];
   d[ 4] = s0[ 2];    d[ 5] = s1[ 2];   d[ 6] = s0[ 3];    d[ 7] = s1[ 3];
   d[ 8] = s0[ 4];    d[ 9] = s1[ 4];   d[10] = s0[ 5];    d[11] = s1[ 5];
   d[12] = s0[ 6];    d[13] = s1[ 6];   d[14] = s0[ 7];    d[15] = s1[ 7];
   if ( bit_len <= 256 ) return;
   d[16] = s0[ 8];    d[17] = s1[ 8];   d[18] = s0[ 9];    d[19] = s1[ 9];
   d[20] = s0[10];    d[21] = s1[10];   d[22] = s0[11];    d[23] = s1[11];
   d[24] = s0[12];    d[25] = s1[12];   d[26] = s0[13];    d[27] = s1[13];
   d[28] = s0[14];    d[29] = s1[14];   d[30] = s0[15];    d[31] = s1[15];
   if ( bit_len <= 512 ) return;
   d[32] = s0[16];    d[33] = s1[16];   d[34] = s0[17];    d[35] = s1[17];
   d[36] = s0[18];    d[37] = s1[18];   d[38] = s0[19];    d[39] = s1[19];
   if ( bit_len <= 640 ) return;
   d[40] = s0[20];    d[41] = s1[20];   d[42] = s0[21];    d[43] = s1[21];
   d[44] = s0[22];    d[45] = s1[22];   d[46] = s0[23];    d[47] = s1[23];
   d[48] = s0[24];    d[49] = s1[24];   d[50] = s0[25];    d[51] = s1[25];
   d[52] = s0[26];    d[53] = s1[26];   d[54] = s0[27];    d[55] = s1[27];
   d[56] = s0[28];    d[57] = s1[28];   d[58] = s0[29];    d[59] = s1[29];
   d[60] = s0[30];    d[61] = s1[30];   d[62] = s0[31];    d[63] = s1[31];
}

static inline void dintrlv_2x32( void *dst0, void *dst1,
                                 const void *src, const int bit_len )
{
   uint32_t *d0 = (uint32_t*)dst0;
   uint32_t *d1 = (uint32_t*)dst1;
   const uint32_t *s = (const uint32_t*)src;

   d0[ 0] = s[ 0];   d1[ 0] = s[ 1];   d0[ 1] = s[ 2];   d1[ 1] = s[ 3];
   d0[ 2] = s[ 4];   d1[ 2] = s[ 5];   d0[ 3] = s[ 6];   d1[ 3] = s[ 7];
   d0[ 4] = s[ 8];   d1[ 4] = s[ 9];   d0[ 5] = s[10];   d1[ 5] = s[11];
   d0[ 6] = s[12];   d1[ 6] = s[13];   d0[ 7] = s[14];   d1[ 7] = s[15];
   if ( bit_len <= 256 ) return;
   d0[ 8] = s[16];   d1[ 8] = s[17];   d0[ 9] = s[18];   d1[ 9] = s[19];
   d0[10] = s[20];   d1[10] = s[21];   d0[11] = s[22];   d1[11] = s[23];
   d0[12] = s[24];   d1[12] = s[25];   d0[13] = s[26];   d1[13] = s[27];
   d0[14] = s[28];   d1[14] = s[29];   d0[15] = s[30];   d1[15] = s[31];
   if ( bit_len <= 512 ) return;
   d0[16] = s[32];   d1[16] = s[33];   d0[17] = s[34];   d1[17] = s[35];
   d0[18] = s[36];   d1[18] = s[37];   d0[19] = s[38];   d1[19] = s[39];
   if ( bit_len <= 640 ) return;
   d0[20] = s[40];   d1[20] = s[41];   d0[21] = s[42];   d1[21] = s[43];
   d0[22] = s[44];   d1[22] = s[45];   d0[23] = s[46];   d1[23] = s[47];
   d0[24] = s[48];   d1[24] = s[49];   d0[25] = s[50];   d1[25] = s[51];
   d0[26] = s[52];   d1[26] = s[53];   d0[27] = s[54];   d1[27] = s[55];
   d0[28] = s[56];   d1[28] = s[57];   d0[29] = s[58];   d1[29] = s[59];
   d0[30] = s[60];   d1[30] = s[61];   d0[31] = s[62];   d1[31] = s[63];
}

static inline void extr_lane_2x32( void *dst, const void *src,
                                   const int lane, const int bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   const uint32_t *s = (const uint32_t*)src;
   d[ 0] = s[ lane    ];   d[ 1] = s[ lane+ 2 ];
   d[ 2] = s[ lane+ 4 ];   d[ 3] = s[ lane+ 6 ];
   d[ 4] = s[ lane+ 8 ];   d[ 5] = s[ lane+10 ];
   d[ 6] = s[ lane+12 ];   d[ 7] = s[ lane+14 ];
   if ( bit_len <= 256 ) return;
   d[ 8] = s[ lane+16 ];   d[ 9] = s[ lane+18 ];
   d[10] = s[ lane+20 ];   d[11] = s[ lane+22 ];
   d[12] = s[ lane+24 ];   d[13] = s[ lane+26 ];
   d[14] = s[ lane+28 ];   d[15] = s[ lane+30 ];
}

// 4x32
/*
static inline void intrlv_4x32( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3, int bit_len )
{
   __m64 *d = (__m64*)dst;
   const __m64 *s0 = (const __m64*)src0;
   const __m64 *s1 = (const __m64*)src1;
   const __m64 *s2 = (const __m64*)src2;
   const __m64 *s3 = (const __m64*)src3;

   d[ 0] = _mm_unpacklo_pi32( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_pi32( s2[0], s3[0] );
   d[ 2] = _mm_unpackhi_pi32( s0[0], s1[0] );
   d[ 3] = _mm_unpackhi_pi32( s2[0], s3[0] );

   d[ 4] = _mm_unpacklo_pi32( s0[1], s1[1] );
   d[ 5] = _mm_unpacklo_pi32( s2[1], s3[1] );
   d[ 6] = _mm_unpackhi_pi32( s0[1], s1[1] );
   d[ 7] = _mm_unpackhi_pi32( s2[1], s3[1] );

   d[ 8] = _mm_unpacklo_pi32( s0[2], s1[2] );
   d[ 9] = _mm_unpacklo_pi32( s2[2], s3[2] );
   d[10] = _mm_unpackhi_pi32( s0[2], s1[2] );
   d[11] = _mm_unpackhi_pi32( s2[2], s3[2] );

   d[12] = _mm_unpacklo_pi32( s0[3], s1[3] );
   d[13] = _mm_unpacklo_pi32( s2[3], s3[3] );
   d[14] = _mm_unpackhi_pi32( s0[3], s1[3] );
   d[15] = _mm_unpackhi_pi32( s2[3], s3[3] );

   if ( bit_len <= 256 ) return;

   d[16] = _mm_unpacklo_pi32( s0[4], s1[4] );
   d[17] = _mm_unpacklo_pi32( s2[4], s3[4] );
   d[18] = _mm_unpackhi_pi32( s0[4], s1[4] );
   d[19] = _mm_unpackhi_pi32( s2[4], s3[4] );

   d[20] = _mm_unpacklo_pi32( s0[5], s1[5] );
   d[21] = _mm_unpacklo_pi32( s2[5], s3[5] );
   d[22] = _mm_unpackhi_pi32( s0[5], s1[5] );
   d[23] = _mm_unpackhi_pi32( s2[5], s3[5] );

   d[24] = _mm_unpacklo_pi32( s0[6], s1[6] );
   d[25] = _mm_unpacklo_pi32( s2[6], s3[6] );
   d[26] = _mm_unpackhi_pi32( s0[6], s1[6] );
   d[27] = _mm_unpackhi_pi32( s2[6], s3[6] );

   d[28] = _mm_unpacklo_pi32( s0[7], s1[7] );
   d[29] = _mm_unpacklo_pi32( s2[7], s3[7] );
   d[30] = _mm_unpackhi_pi32( s0[7], s1[7] );
   d[31] = _mm_unpackhi_pi32( s2[7], s3[7] );

   if ( bit_len <= 512 ) return;

   d[32] = _mm_unpacklo_pi32( s0[8], s1[8] );
   d[33] = _mm_unpacklo_pi32( s2[8], s3[8] );
   d[34] = _mm_unpackhi_pi32( s0[8], s1[8] );
   d[35] = _mm_unpackhi_pi32( s2[8], s3[8] );

   d[36] = _mm_unpacklo_pi32( s0[9], s1[9] );
   d[37] = _mm_unpacklo_pi32( s2[9], s3[9] );
   d[38] = _mm_unpackhi_pi32( s0[9], s1[9] );
   d[39] = _mm_unpackhi_pi32( s2[9], s3[9] );
   
   if ( bit_len <= 640 ) return;

   d[40] = _mm_unpacklo_pi32( s0[10], s1[10] );
   d[41] = _mm_unpacklo_pi32( s2[10], s3[10] );
   d[42] = _mm_unpackhi_pi32( s0[10], s1[10] );
   d[43] = _mm_unpackhi_pi32( s2[10], s3[10] );

   d[44] = _mm_unpacklo_pi32( s0[11], s1[11] );
   d[45] = _mm_unpacklo_pi32( s2[11], s3[11] );
   d[46] = _mm_unpackhi_pi32( s0[11], s1[11] );
   d[47] = _mm_unpackhi_pi32( s2[11], s3[11] );

   d[48] = _mm_unpacklo_pi32( s0[12], s1[12] );
   d[49] = _mm_unpacklo_pi32( s2[12], s3[12] );
   d[50] = _mm_unpackhi_pi32( s0[12], s1[12] );
   d[51] = _mm_unpackhi_pi32( s2[12], s3[12] );

   d[52] = _mm_unpacklo_pi32( s0[13], s1[13] );
   d[53] = _mm_unpacklo_pi32( s2[13], s3[13] );
   d[54] = _mm_unpackhi_pi32( s0[13], s1[13] );
   d[55] = _mm_unpackhi_pi32( s2[13], s3[13] );

   d[56] = _mm_unpacklo_pi32( s0[14], s1[14] );
   d[57] = _mm_unpacklo_pi32( s2[14], s3[14] );
   d[58] = _mm_unpackhi_pi32( s0[14], s1[14] );
   d[59] = _mm_unpackhi_pi32( s2[14], s3[14] );

   d[60] = _mm_unpacklo_pi32( s0[15], s1[15] );
   d[61] = _mm_unpacklo_pi32( s2[15], s3[15] );
   d[62] = _mm_unpackhi_pi32( s0[15], s1[15] );
   d[63] = _mm_unpackhi_pi32( s2[15], s3[15] );
}  
*/

static inline void intrlv_4x32( void *dst, const void *src0, const void *src1,
                      const void *src2, const void *src3, const int bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   const uint32_t *s0 = (const uint32_t*)src0;
   const uint32_t *s1 = (const uint32_t*)src1;
   const uint32_t *s2 = (const uint32_t*)src2;
   const uint32_t *s3 = (const uint32_t*)src3;
   d[  0] = s0[ 0];   d[  1] = s1[ 0];   d[  2] = s2[ 0];   d[  3] = s3[ 0];
   d[  4] = s0[ 1];   d[  5] = s1[ 1];   d[  6] = s2[ 1];   d[  7] = s3[ 1];
   d[  8] = s0[ 2];   d[  9] = s1[ 2];   d[ 10] = s2[ 2];   d[ 11] = s3[ 2];
   d[ 12] = s0[ 3];   d[ 13] = s1[ 3];   d[ 14] = s2[ 3];   d[ 15] = s3[ 3];
   d[ 16] = s0[ 4];   d[ 17] = s1[ 4];   d[ 18] = s2[ 4];   d[ 19] = s3[ 4];
   d[ 20] = s0[ 5];   d[ 21] = s1[ 5];   d[ 22] = s2[ 5];   d[ 23] = s3[ 5];
   d[ 24] = s0[ 6];   d[ 25] = s1[ 6];   d[ 26] = s2[ 6];   d[ 27] = s3[ 6];
   d[ 28] = s0[ 7];   d[ 29] = s1[ 7];   d[ 30] = s2[ 7];   d[ 31] = s3[ 7];
   if ( bit_len <= 256 ) return;
   d[ 32] = s0[ 8];   d[ 33] = s1[ 8];   d[ 34] = s2[ 8];   d[ 35] = s3[ 8];
   d[ 36] = s0[ 9];   d[ 37] = s1[ 9];   d[ 38] = s2[ 9];   d[ 39] = s3[ 9];
   d[ 40] = s0[10];   d[ 41] = s1[10];   d[ 42] = s2[10];   d[ 43] = s3[10];
   d[ 44] = s0[11];   d[ 45] = s1[11];   d[ 46] = s2[11];   d[ 47] = s3[11];
   d[ 48] = s0[12];   d[ 49] = s1[12];   d[ 50] = s2[12];   d[ 51] = s3[12];
   d[ 52] = s0[13];   d[ 53] = s1[13];   d[ 54] = s2[13];   d[ 55] = s3[13];
   d[ 56] = s0[14];   d[ 57] = s1[14];   d[ 58] = s2[14];   d[ 59] = s3[14];
   d[ 60] = s0[15];   d[ 61] = s1[15];   d[ 62] = s2[15];   d[ 63] = s3[15];
   if ( bit_len <= 512 ) return;
   d[ 64] = s0[16];   d[ 65] = s1[16];   d[ 66] = s2[16];   d[ 67] = s3[16];
   d[ 68] = s0[17];   d[ 69] = s1[17];   d[ 70] = s2[17];   d[ 71] = s3[17];
   d[ 72] = s0[18];   d[ 73] = s1[18];   d[ 74] = s2[18];   d[ 75] = s3[18];
   d[ 76] = s0[19];   d[ 77] = s1[19];   d[ 78] = s2[19];   d[ 79] = s3[19];
   if ( bit_len <= 640 ) return;
   d[ 80] = s0[20];   d[ 81] = s1[20];   d[ 82] = s2[20];   d[ 83] = s3[20];
   d[ 84] = s0[21];   d[ 85] = s1[21];   d[ 86] = s2[21];   d[ 87] = s3[21];
   d[ 88] = s0[22];   d[ 89] = s1[22];   d[ 90] = s2[22];   d[ 91] = s3[22];
   d[ 92] = s0[23];   d[ 93] = s1[23];   d[ 94] = s2[23];   d[ 95] = s3[23];
   d[ 96] = s0[24];   d[ 97] = s1[24];   d[ 98] = s2[24];   d[ 99] = s3[24];
   d[100] = s0[25];   d[101] = s1[25];   d[102] = s2[25];   d[103] = s3[25];
   d[104] = s0[26];   d[105] = s1[26];   d[106] = s2[26];   d[107] = s3[26];
   d[108] = s0[27];   d[109] = s1[27];   d[110] = s2[27];   d[111] = s3[27];
   d[112] = s0[28];   d[113] = s1[28];   d[114] = s2[28];   d[115] = s3[28];
   d[116] = s0[29];   d[117] = s1[29];   d[118] = s2[29];   d[119] = s3[29];
   d[120] = s0[30];   d[121] = s1[30];   d[122] = s2[30];   d[123] = s3[30];
   d[124] = s0[31];   d[125] = s1[31];   d[126] = s2[31];   d[127] = s3[31];
}

/*
static inline void intrlv_4x32_512( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3 )
{
   __m64 *d = (__m64*)dst;
   const __m64 *s0 = (const __m64*)src0;
   const __m64 *s1 = (const __m64*)src1;
   const __m64 *s2 = (const __m64*)src2;
   const __m64 *s3 = (const __m64*)src3;

   d[ 0] = _mm_unpacklo_pi32( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_pi32( s2[0], s3[0] );
   d[ 2] = _mm_unpackhi_pi32( s0[0], s1[0] );
   d[ 3] = _mm_unpackhi_pi32( s2[0], s3[0] );

   d[ 4] = _mm_unpacklo_pi32( s0[1], s1[1] );
   d[ 5] = _mm_unpacklo_pi32( s2[1], s3[1] );
   d[ 6] = _mm_unpackhi_pi32( s0[1], s1[1] );
   d[ 7] = _mm_unpackhi_pi32( s2[1], s3[1] );

   d[ 8] = _mm_unpacklo_pi32( s0[2], s1[2] );
   d[ 9] = _mm_unpacklo_pi32( s2[2], s3[2] );
   d[10] = _mm_unpackhi_pi32( s0[2], s1[2] );
   d[11] = _mm_unpackhi_pi32( s2[2], s3[2] );

   d[12] = _mm_unpacklo_pi32( s0[3], s1[3] );
   d[13] = _mm_unpacklo_pi32( s2[3], s3[3] );
   d[14] = _mm_unpackhi_pi32( s0[3], s1[3] );
   d[15] = _mm_unpackhi_pi32( s2[3], s3[3] );

   d[16] = _mm_unpacklo_pi32( s0[4], s1[4] );
   d[17] = _mm_unpacklo_pi32( s2[4], s3[4] );
   d[18] = _mm_unpackhi_pi32( s0[4], s1[4] );
   d[19] = _mm_unpackhi_pi32( s2[4], s3[4] );

   d[20] = _mm_unpacklo_pi32( s0[5], s1[5] );
   d[21] = _mm_unpacklo_pi32( s2[5], s3[5] );
   d[22] = _mm_unpackhi_pi32( s0[5], s1[5] );
   d[23] = _mm_unpackhi_pi32( s2[5], s3[5] );

   d[24] = _mm_unpacklo_pi32( s0[6], s1[6] );
   d[25] = _mm_unpacklo_pi32( s2[6], s3[6] );
   d[26] = _mm_unpackhi_pi32( s0[6], s1[6] );
   d[27] = _mm_unpackhi_pi32( s2[6], s3[6] );

   d[28] = _mm_unpacklo_pi32( s0[7], s1[7] );
   d[29] = _mm_unpacklo_pi32( s2[7], s3[7] );
   d[30] = _mm_unpackhi_pi32( s0[7], s1[7] );
   d[31] = _mm_unpackhi_pi32( s2[7], s3[7] );
}
*/

static inline void intrlv_4x32_512( void *dst, const void *src0,
                     const void *src1, const void *src2, const void *src3 )
{
   uint32_t *d = (uint32_t*)dst;
   const uint32_t *s0 = (const uint32_t*)src0;
   const uint32_t *s1 = (const uint32_t*)src1;
   const uint32_t *s2 = (const uint32_t*)src2;
   const uint32_t *s3 = (const uint32_t*)src3;
   d[  0] = s0[ 0];   d[  1] = s1[ 0];   d[  2] = s2[ 0];   d[  3] = s3[ 0];
   d[  4] = s0[ 1];   d[  5] = s1[ 1];   d[  6] = s2[ 1];   d[  7] = s3[ 1];
   d[  8] = s0[ 2];   d[  9] = s1[ 2];   d[ 10] = s2[ 2];   d[ 11] = s3[ 2];
   d[ 12] = s0[ 3];   d[ 13] = s1[ 3];   d[ 14] = s2[ 3];   d[ 15] = s3[ 3];
   d[ 16] = s0[ 4];   d[ 17] = s1[ 4];   d[ 18] = s2[ 4];   d[ 19] = s3[ 4];
   d[ 20] = s0[ 5];   d[ 21] = s1[ 5];   d[ 22] = s2[ 5];   d[ 23] = s3[ 5];
   d[ 24] = s0[ 6];   d[ 25] = s1[ 6];   d[ 26] = s2[ 6];   d[ 27] = s3[ 6];
   d[ 28] = s0[ 7];   d[ 29] = s1[ 7];   d[ 30] = s2[ 7];   d[ 31] = s3[ 7];
   d[ 32] = s0[ 8];   d[ 33] = s1[ 8];   d[ 34] = s2[ 8];   d[ 35] = s3[ 8];
   d[ 36] = s0[ 9];   d[ 37] = s1[ 9];   d[ 38] = s2[ 9];   d[ 39] = s3[ 9];
   d[ 40] = s0[10];   d[ 41] = s1[10];   d[ 42] = s2[10];   d[ 43] = s3[10];
   d[ 44] = s0[11];   d[ 45] = s1[11];   d[ 46] = s2[11];   d[ 47] = s3[11];
   d[ 48] = s0[12];   d[ 49] = s1[12];   d[ 50] = s2[12];   d[ 51] = s3[12];
   d[ 52] = s0[13];   d[ 53] = s1[13];   d[ 54] = s2[13];   d[ 55] = s3[13];
   d[ 56] = s0[14];   d[ 57] = s1[14];   d[ 58] = s2[14];   d[ 59] = s3[14];
   d[ 60] = s0[15];   d[ 61] = s1[15];   d[ 62] = s2[15];   d[ 63] = s3[15];
}

/*
static inline void dintrlv_4x32( void *dst0, void *dst1, void *dst2,
                                 void *dst3, const void *src, int bit_len )
{
   __m64 *d0 = (__m64*)dst0;
   __m64 *d1 = (__m64*)dst1;
   __m64 *d2 = (__m64*)dst2;
   __m64 *d3 = (__m64*)dst3;
   const __m64 *s = (const __m64*)src;
   d0[0] = _mm_unpacklo_pi32( s[ 0], s[ 2] );
   d1[0] = _mm_unpackhi_pi32( s[ 0], s[ 2] );
   d2[0] = _mm_unpacklo_pi32( s[ 1], s[ 3] );
   d3[0] = _mm_unpackhi_pi32( s[ 1], s[ 3] );

   d0[1] = _mm_unpacklo_pi32( s[ 4], s[ 6] );
   d1[1] = _mm_unpackhi_pi32( s[ 4], s[ 6] );
   d2[1] = _mm_unpacklo_pi32( s[ 5], s[ 7] );
   d3[1] = _mm_unpackhi_pi32( s[ 5], s[ 7] );

   d0[2] = _mm_unpacklo_pi32( s[ 8], s[10] );
   d1[2] = _mm_unpackhi_pi32( s[ 8], s[10] );
   d2[2] = _mm_unpacklo_pi32( s[ 9], s[11] );
   d3[2] = _mm_unpackhi_pi32( s[ 9], s[11] );

   d0[3] = _mm_unpacklo_pi32( s[12], s[14] );
   d1[3] = _mm_unpackhi_pi32( s[12], s[14] );
   d2[3] = _mm_unpacklo_pi32( s[13], s[15] );
   d3[3] = _mm_unpackhi_pi32( s[13], s[15] );

   if ( bit_len <= 256 ) return;

   d0[4] = _mm_unpacklo_pi32( s[16], s[18] );
   d1[4] = _mm_unpackhi_pi32( s[16], s[18] );
   d2[4] = _mm_unpacklo_pi32( s[17], s[19] );
   d3[4] = _mm_unpackhi_pi32( s[17], s[19] );

   d0[5] = _mm_unpacklo_pi32( s[20], s[22] );
   d1[5] = _mm_unpackhi_pi32( s[20], s[22] );
   d2[5] = _mm_unpacklo_pi32( s[21], s[23] );
   d3[5] = _mm_unpackhi_pi32( s[21], s[23] );

   d0[6] = _mm_unpacklo_pi32( s[24], s[26] );
   d1[6] = _mm_unpackhi_pi32( s[24], s[26] );
   d2[6] = _mm_unpacklo_pi32( s[25], s[27] );
   d3[6] = _mm_unpackhi_pi32( s[25], s[27] );

   d0[7] = _mm_unpacklo_pi32( s[28], s[30] );
   d1[7] = _mm_unpackhi_pi32( s[28], s[30] );
   d2[7] = _mm_unpacklo_pi32( s[29], s[31] );
   d3[7] = _mm_unpackhi_pi32( s[29], s[31] );

   if ( bit_len <= 512 ) return;

   d0[8] = _mm_unpacklo_pi32( s[32], s[34] );
   d1[8] = _mm_unpackhi_pi32( s[32], s[34] );
   d2[8] = _mm_unpacklo_pi32( s[33], s[35] );
   d3[8] = _mm_unpackhi_pi32( s[33], s[35] );

   d0[9] = _mm_unpacklo_pi32( s[36], s[38] );
   d1[9] = _mm_unpackhi_pi32( s[36], s[38] );
   d2[9] = _mm_unpacklo_pi32( s[37], s[39] );
   d3[9] = _mm_unpackhi_pi32( s[37], s[39] );

   if ( bit_len <= 640 ) return;

   d0[10] = _mm_unpacklo_pi32( s[40], s[42] );
   d1[10] = _mm_unpackhi_pi32( s[40], s[42] );
   d2[10] = _mm_unpacklo_pi32( s[41], s[43] );
   d3[10] = _mm_unpackhi_pi32( s[41], s[43] );

   d0[11] = _mm_unpacklo_pi32( s[44], s[46] );
   d1[11] = _mm_unpackhi_pi32( s[44], s[46] );
   d2[11] = _mm_unpacklo_pi32( s[45], s[47] );
   d3[11] = _mm_unpackhi_pi32( s[45], s[47] );

   d0[12] = _mm_unpacklo_pi32( s[48], s[50] );
   d1[12] = _mm_unpackhi_pi32( s[48], s[50] );
   d2[12] = _mm_unpacklo_pi32( s[49], s[51] );
   d3[12] = _mm_unpackhi_pi32( s[49], s[51] );

   d0[13] = _mm_unpacklo_pi32( s[52], s[54] );
   d1[13] = _mm_unpackhi_pi32( s[52], s[54] );
   d2[13] = _mm_unpacklo_pi32( s[53], s[55] );
   d3[13] = _mm_unpackhi_pi32( s[53], s[55] );

   d0[14] = _mm_unpacklo_pi32( s[56], s[58] );
   d1[14] = _mm_unpackhi_pi32( s[56], s[58] );
   d2[14] = _mm_unpacklo_pi32( s[57], s[59] );
   d3[14] = _mm_unpackhi_pi32( s[57], s[59] );

   d0[15] = _mm_unpacklo_pi32( s[60], s[62] );
   d1[15] = _mm_unpackhi_pi32( s[60], s[62] );
   d2[15] = _mm_unpacklo_pi32( s[61], s[62] );
   d3[15] = _mm_unpackhi_pi32( s[61], s[62] );
}
*/

static inline void dintrlv_4x32( void *dst0, void *dst1, void *dst2,
                           void *dst3, const void *src, const int bit_len )
{
   uint32_t *d0 = (uint32_t*)dst0;
   uint32_t *d1 = (uint32_t*)dst1;
   uint32_t *d2 = (uint32_t*)dst2;
   uint32_t *d3 = (uint32_t*)dst3;
   const uint32_t *s = (const uint32_t*)src;
   d0[ 0] = s[  0];   d1[ 0] = s[  1];    d2[ 0] = s[  2];   d3[ 0] = s[  3];
   d0[ 1] = s[  4];   d1[ 1] = s[  5];    d2[ 1] = s[  6];   d3[ 1] = s[  7];
   d0[ 2] = s[  8];   d1[ 2] = s[  9];    d2[ 2] = s[ 10];   d3[ 2] = s[ 11];
   d0[ 3] = s[ 12];   d1[ 3] = s[ 13];    d2[ 3] = s[ 14];   d3[ 3] = s[ 15];
   d0[ 4] = s[ 16];   d1[ 4] = s[ 17];    d2[ 4] = s[ 18];   d3[ 4] = s[ 19];
   d0[ 5] = s[ 20];   d1[ 5] = s[ 21];    d2[ 5] = s[ 22];   d3[ 5] = s[ 23];
   d0[ 6] = s[ 24];   d1[ 6] = s[ 25];    d2[ 6] = s[ 26];   d3[ 6] = s[ 27];
   d0[ 7] = s[ 28];   d1[ 7] = s[ 29];    d2[ 7] = s[ 30];   d3[ 7] = s[ 31];
   if ( bit_len <= 256 ) return;
   d0[ 8] = s[ 32];   d1[ 8] = s[ 33];    d2[ 8] = s[ 34];   d3[ 8] = s[ 35];
   d0[ 9] = s[ 36];   d1[ 9] = s[ 37];    d2[ 9] = s[ 38];   d3[ 9] = s[ 39];
   d0[10] = s[ 40];   d1[10] = s[ 41];    d2[10] = s[ 42];   d3[10] = s[ 43];
   d0[11] = s[ 44];   d1[11] = s[ 45];    d2[11] = s[ 46];   d3[11] = s[ 47];
   d0[12] = s[ 48];   d1[12] = s[ 49];    d2[12] = s[ 50];   d3[12] = s[ 51];
   d0[13] = s[ 52];   d1[13] = s[ 53];    d2[13] = s[ 54];   d3[13] = s[ 55];
   d0[14] = s[ 56];   d1[14] = s[ 57];    d2[14] = s[ 58];   d3[14] = s[ 59];
   d0[15] = s[ 60];   d1[15] = s[ 61];    d2[15] = s[ 62];   d3[15] = s[ 63];
   if ( bit_len <= 512 ) return;
   d0[16] = s[ 64];   d1[16] = s[ 65];    d2[16] = s[ 66];   d3[16] = s[ 67];
   d0[17] = s[ 68];   d1[17] = s[ 69];    d2[17] = s[ 70];   d3[17] = s[ 71];
   d0[18] = s[ 72];   d1[18] = s[ 73];    d2[18] = s[ 74];   d3[18] = s[ 75];
   d0[19] = s[ 76];   d1[19] = s[ 77];    d2[19] = s[ 78];   d3[19] = s[ 79];
   if ( bit_len <= 640 ) return;
   d0[20] = s[ 80];   d1[20] = s[ 81];    d2[20] = s[ 82];   d3[20] = s[ 83];
   d0[21] = s[ 84];   d1[21] = s[ 85];    d2[21] = s[ 86];   d3[21] = s[ 87];
   d0[22] = s[ 88];   d1[22] = s[ 89];    d2[22] = s[ 90];   d3[22] = s[ 91];
   d0[23] = s[ 92];   d1[23] = s[ 93];    d2[23] = s[ 94];   d3[23] = s[ 95];
   d0[24] = s[ 96];   d1[24] = s[ 97];    d2[24] = s[ 98];   d3[24] = s[ 99];
   d0[25] = s[100];   d1[25] = s[101];    d2[25] = s[102];   d3[25] = s[103];
   d0[26] = s[104];   d1[26] = s[105];    d2[26] = s[106];   d3[26] = s[107];
   d0[27] = s[108];   d1[27] = s[109];    d2[27] = s[110];   d3[27] = s[111];
   d0[28] = s[112];   d1[28] = s[113];    d2[28] = s[114];   d3[28] = s[115];
   d0[29] = s[116];   d1[29] = s[117];    d2[29] = s[118];   d3[29] = s[119];
   d0[30] = s[120];   d1[30] = s[121];    d2[30] = s[122];   d3[30] = s[123];
   d0[31] = s[124];   d1[31] = s[125];    d2[31] = s[126];   d3[31] = s[127];
}

/*
static inline void dintrlv_4x32_512( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src )
{
   __m64 *d0 = (__m64*)dst0;
   __m64 *d1 = (__m64*)dst1;
   __m64 *d2 = (__m64*)dst2;
   __m64 *d3 = (__m64*)dst3;
   const __m64 *s = (const __m64*)src;

   d0[0] = _mm_unpacklo_pi32( s[ 0], s[ 2] );
   d1[0] = _mm_unpackhi_pi32( s[ 0], s[ 2] );
   d2[0] = _mm_unpacklo_pi32( s[ 1], s[ 3] );
   d3[0] = _mm_unpackhi_pi32( s[ 1], s[ 3] );
   d0[1] = _mm_unpacklo_pi32( s[ 4], s[ 6] );
   d1[1] = _mm_unpackhi_pi32( s[ 4], s[ 6] );
   d2[1] = _mm_unpacklo_pi32( s[ 5], s[ 7] );
   d3[1] = _mm_unpackhi_pi32( s[ 5], s[ 7] );

   d0[2] = _mm_unpacklo_pi32( s[ 8], s[10] );
   d1[2] = _mm_unpackhi_pi32( s[ 8], s[10] );
   d2[2] = _mm_unpacklo_pi32( s[ 9], s[11] );
   d3[2] = _mm_unpackhi_pi32( s[ 9], s[11] );
   d0[3] = _mm_unpacklo_pi32( s[12], s[14] );
   d1[3] = _mm_unpackhi_pi32( s[12], s[14] );
   d2[3] = _mm_unpacklo_pi32( s[13], s[15] );
   d3[3] = _mm_unpackhi_pi32( s[13], s[15] );

   d0[4] = _mm_unpacklo_pi32( s[16], s[18] );
   d1[4] = _mm_unpackhi_pi32( s[16], s[18] );
   d2[4] = _mm_unpacklo_pi32( s[17], s[19] );
   d3[4] = _mm_unpackhi_pi32( s[17], s[19] );
   d0[5] = _mm_unpacklo_pi32( s[20], s[22] );
   d1[5] = _mm_unpackhi_pi32( s[20], s[22] );
   d2[5] = _mm_unpacklo_pi32( s[21], s[23] );
   d3[5] = _mm_unpackhi_pi32( s[21], s[23] );

   d0[6] = _mm_unpacklo_pi32( s[24], s[26] );
   d1[6] = _mm_unpackhi_pi32( s[24], s[26] );
   d2[6] = _mm_unpacklo_pi32( s[25], s[27] );
   d3[6] = _mm_unpackhi_pi32( s[25], s[27] );
   d0[7] = _mm_unpacklo_pi32( s[28], s[30] );
   d1[7] = _mm_unpackhi_pi32( s[28], s[30] );
   d2[7] = _mm_unpacklo_pi32( s[29], s[31] );
   d3[7] = _mm_unpackhi_pi32( s[29], s[31] );
}
*/

static inline void dintrlv_4x32_512( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src )
{
   uint32_t *d0 = (uint32_t*)dst0;
   uint32_t *d1 = (uint32_t*)dst1;
   uint32_t *d2 = (uint32_t*)dst2;
   uint32_t *d3 = (uint32_t*)dst3;
   const uint32_t *s = (const uint32_t*)src;
   d0[ 0] = s[  0];   d1[ 0] = s[  1];    d2[ 0] = s[  2];   d3[ 0] = s[  3];
   d0[ 1] = s[  4];   d1[ 1] = s[  5];    d2[ 1] = s[  6];   d3[ 1] = s[  7];
   d0[ 2] = s[  8];   d1[ 2] = s[  9];    d2[ 2] = s[ 10];   d3[ 2] = s[ 11];
   d0[ 3] = s[ 12];   d1[ 3] = s[ 13];    d2[ 3] = s[ 14];   d3[ 3] = s[ 15];
   d0[ 4] = s[ 16];   d1[ 4] = s[ 17];    d2[ 4] = s[ 18];   d3[ 4] = s[ 19];
   d0[ 5] = s[ 20];   d1[ 5] = s[ 21];    d2[ 5] = s[ 22];   d3[ 5] = s[ 23];
   d0[ 6] = s[ 24];   d1[ 6] = s[ 25];    d2[ 6] = s[ 26];   d3[ 6] = s[ 27];
   d0[ 7] = s[ 28];   d1[ 7] = s[ 29];    d2[ 7] = s[ 30];   d3[ 7] = s[ 31];
   d0[ 8] = s[ 32];   d1[ 8] = s[ 33];    d2[ 8] = s[ 34];   d3[ 8] = s[ 35];
   d0[ 9] = s[ 36];   d1[ 9] = s[ 37];    d2[ 9] = s[ 38];   d3[ 9] = s[ 39];
   d0[10] = s[ 40];   d1[10] = s[ 41];    d2[10] = s[ 42];   d3[10] = s[ 43];
   d0[11] = s[ 44];   d1[11] = s[ 45];    d2[11] = s[ 46];   d3[11] = s[ 47];
   d0[12] = s[ 48];   d1[12] = s[ 49];    d2[12] = s[ 50];   d3[12] = s[ 51];
   d0[13] = s[ 52];   d1[13] = s[ 53];    d2[13] = s[ 54];   d3[13] = s[ 55];
   d0[14] = s[ 56];   d1[14] = s[ 57];    d2[14] = s[ 58];   d3[14] = s[ 59];
   d0[15] = s[ 60];   d1[15] = s[ 61];    d2[15] = s[ 62];   d3[15] = s[ 63];
}


static inline void extr_lane_4x32( void *d, const void *s,
                                   const int lane, const int bit_len )
{
   ((uint32_t*)d)[ 0] = ((const uint32_t*)s)[ lane    ];
   ((uint32_t*)d)[ 1] = ((const uint32_t*)s)[ lane+ 4 ];
   ((uint32_t*)d)[ 2] = ((const uint32_t*)s)[ lane+ 8 ];
   ((uint32_t*)d)[ 3] = ((const uint32_t*)s)[ lane+12 ];
   ((uint32_t*)d)[ 4] = ((const uint32_t*)s)[ lane+16 ];
   ((uint32_t*)d)[ 5] = ((const uint32_t*)s)[ lane+20 ];
   ((uint32_t*)d)[ 6] = ((const uint32_t*)s)[ lane+24 ];
   ((uint32_t*)d)[ 7] = ((const uint32_t*)s)[ lane+28 ];
   if ( bit_len <= 256 ) return;
   ((uint32_t*)d)[ 8] = ((const uint32_t*)s)[ lane+32 ];
   ((uint32_t*)d)[ 9] = ((const uint32_t*)s)[ lane+36 ];
   ((uint32_t*)d)[10] = ((const uint32_t*)s)[ lane+40 ];
   ((uint32_t*)d)[11] = ((const uint32_t*)s)[ lane+44 ];
   ((uint32_t*)d)[12] = ((const uint32_t*)s)[ lane+48 ];
   ((uint32_t*)d)[13] = ((const uint32_t*)s)[ lane+52 ];
   ((uint32_t*)d)[14] = ((const uint32_t*)s)[ lane+56 ];
   ((uint32_t*)d)[15] = ((const uint32_t*)s)[ lane+60 ];
}



// Still used by decred due to odd data size: 180 bytes
// bit_len must be multiple of 32
static inline void mm128_intrlv_4x32x( void *dst, void *src0, void  *src1,
                                 void *src2, void *src3, const int bit_len )
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

#if defined(__SSSE3__)

static inline void mm128_bswap32_80( void *d, void *s )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  casti_m128i( d, 0 ) = _mm_shuffle_epi8( casti_m128i( s, 0 ), bswap_shuf );
  casti_m128i( d, 1 ) = _mm_shuffle_epi8( casti_m128i( s, 1 ), bswap_shuf );
  casti_m128i( d, 2 ) = _mm_shuffle_epi8( casti_m128i( s, 2 ), bswap_shuf );
  casti_m128i( d, 3 ) = _mm_shuffle_epi8( casti_m128i( s, 3 ), bswap_shuf );
  casti_m128i( d, 4 ) = _mm_shuffle_epi8( casti_m128i( s, 4 ), bswap_shuf );
}

#else

static inline void mm128_bswap32_80( void *d, void *s )
{
  ( (uint32_t*)d )[ 0] = bswap_32( ( (uint32_t*)s )[ 0] );
  ( (uint32_t*)d )[ 1] = bswap_32( ( (uint32_t*)s )[ 1] );
  ( (uint32_t*)d )[ 2] = bswap_32( ( (uint32_t*)s )[ 2] );
  ( (uint32_t*)d )[ 3] = bswap_32( ( (uint32_t*)s )[ 3] );
  ( (uint32_t*)d )[ 4] = bswap_32( ( (uint32_t*)s )[ 4] );
  ( (uint32_t*)d )[ 5] = bswap_32( ( (uint32_t*)s )[ 5] );
  ( (uint32_t*)d )[ 6] = bswap_32( ( (uint32_t*)s )[ 6] );
  ( (uint32_t*)d )[ 7] = bswap_32( ( (uint32_t*)s )[ 7] );
  ( (uint32_t*)d )[ 8] = bswap_32( ( (uint32_t*)s )[ 8] );
  ( (uint32_t*)d )[ 9] = bswap_32( ( (uint32_t*)s )[ 9] );
  ( (uint32_t*)d )[10] = bswap_32( ( (uint32_t*)s )[10] );
  ( (uint32_t*)d )[11] = bswap_32( ( (uint32_t*)s )[11] );
  ( (uint32_t*)d )[12] = bswap_32( ( (uint32_t*)s )[12] );
  ( (uint32_t*)d )[13] = bswap_32( ( (uint32_t*)s )[13] );
  ( (uint32_t*)d )[14] = bswap_32( ( (uint32_t*)s )[14] );
  ( (uint32_t*)d )[15] = bswap_32( ( (uint32_t*)s )[15] );
  ( (uint32_t*)d )[16] = bswap_32( ( (uint32_t*)s )[16] );
  ( (uint32_t*)d )[17] = bswap_32( ( (uint32_t*)s )[17] );
  ( (uint32_t*)d )[18] = bswap_32( ( (uint32_t*)s )[18] );
  ( (uint32_t*)d )[19] = bswap_32( ( (uint32_t*)s )[19] );
}

#endif

static inline void mm128_bswap32_intrlv80_4x32( void *d, const void *src )
{
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

#if defined(__SSSE3__)

  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

#else

  s0 = mm128_bswap_32( s0 );
  s1 = mm128_bswap_32( s1 );
  s2 = mm128_bswap_32( s2 );
  s3 = mm128_bswap_32( s3 );
  s4 = mm128_bswap_32( s4 );

#endif

  casti_m128i( d, 0 ) = _mm_shuffle_epi32( s0, 0x00 );
  casti_m128i( d, 1 ) = _mm_shuffle_epi32( s0, 0x55 );
  casti_m128i( d, 2 ) = _mm_shuffle_epi32( s0, 0xaa );
  casti_m128i( d, 3 ) = _mm_shuffle_epi32( s0, 0xff );

  casti_m128i( d, 4 ) = _mm_shuffle_epi32( s1, 0x00 );
  casti_m128i( d, 5 ) = _mm_shuffle_epi32( s1, 0x55 );
  casti_m128i( d, 6 ) = _mm_shuffle_epi32( s1, 0xaa );
  casti_m128i( d, 7 ) = _mm_shuffle_epi32( s1, 0xff );

  casti_m128i( d, 8 ) = _mm_shuffle_epi32( s2, 0x00 );
  casti_m128i( d, 9 ) = _mm_shuffle_epi32( s2, 0x55 );
  casti_m128i( d,10 ) = _mm_shuffle_epi32( s2, 0xaa );
  casti_m128i( d,11 ) = _mm_shuffle_epi32( s2, 0xff );

  casti_m128i( d,12 ) = _mm_shuffle_epi32( s3, 0x00 );
  casti_m128i( d,13 ) = _mm_shuffle_epi32( s3, 0x55 );
  casti_m128i( d,14 ) = _mm_shuffle_epi32( s3, 0xaa );
  casti_m128i( d,15 ) = _mm_shuffle_epi32( s3, 0xff );

  casti_m128i( d,16 ) = _mm_shuffle_epi32( s4, 0x00 );
  casti_m128i( d,17 ) = _mm_shuffle_epi32( s4, 0x55 );
  casti_m128i( d,18 ) = _mm_shuffle_epi32( s4, 0xaa );
  casti_m128i( d,19 ) = _mm_shuffle_epi32( s4, 0xff );
}

// 8x32

#define ILEAVE_8x32( i ) do \
{ \
  uint32_t *d = (uint32_t*)(dst) + ( (i) << 3 ); \
  d[0] = *( (const uint32_t*)(s0) +(i) ); \
  d[1] = *( (const uint32_t*)(s1) +(i) ); \
  d[2] = *( (const uint32_t*)(s2) +(i) ); \
  d[3] = *( (const uint32_t*)(s3) +(i) ); \
  d[4] = *( (const uint32_t*)(s4) +(i) ); \
  d[5] = *( (const uint32_t*)(s5) +(i) ); \
  d[6] = *( (const uint32_t*)(s6) +(i) ); \
  d[7] = *( (const uint32_t*)(s7) +(i) ); \
} while(0)
  
static inline void intrlv_8x32b( void *dst, const void *s0, const void *s1,
           const void *s2, const void *s3, const void *s4, const void *s5,
           const void *s6, const void *s7, const int bit_len )
{
   for ( int i = 0; i < bit_len/32; i++ )
      ILEAVE_8x32( i );
}

static inline void intrlv_8x32( void *dst, const void *s0, const void *s1,
           const void *s2, const void *s3, const void *s4, const void *s5,
           const void *s6, const void *s7, const int bit_len )
{
   ILEAVE_8x32(  0 );   ILEAVE_8x32(  1 );
   ILEAVE_8x32(  2 );   ILEAVE_8x32(  3 );
   ILEAVE_8x32(  4 );   ILEAVE_8x32(  5 );
   ILEAVE_8x32(  6 );   ILEAVE_8x32(  7 );
   if ( bit_len <= 256 ) return;
   ILEAVE_8x32(  8 );   ILEAVE_8x32(  9 );
   ILEAVE_8x32( 10 );   ILEAVE_8x32( 11 );
   ILEAVE_8x32( 12 );   ILEAVE_8x32( 13 );
   ILEAVE_8x32( 14 );   ILEAVE_8x32( 15 );
   if ( bit_len <= 512 ) return;
   ILEAVE_8x32( 16 );   ILEAVE_8x32( 17 );
   ILEAVE_8x32( 18 );   ILEAVE_8x32( 19 );
   if ( bit_len <= 640 ) return;
   ILEAVE_8x32( 20 );   ILEAVE_8x32( 21 );
   ILEAVE_8x32( 22 );   ILEAVE_8x32( 23 );
   ILEAVE_8x32( 24 );   ILEAVE_8x32( 25 );
   ILEAVE_8x32( 26 );   ILEAVE_8x32( 27 );
   ILEAVE_8x32( 28 );   ILEAVE_8x32( 29 );
   ILEAVE_8x32( 30 );   ILEAVE_8x32( 31 );
}

static inline void intrlv_8x32_512( void *dst, const void *s0, const void *s1,
               const void *s2, const void *s3, const void *s4, const void *s5,
               const void *s6, const void *s7 )
{
   ILEAVE_8x32(  0 );   ILEAVE_8x32(  1 );
   ILEAVE_8x32(  2 );   ILEAVE_8x32(  3 );
   ILEAVE_8x32(  4 );   ILEAVE_8x32(  5 );
   ILEAVE_8x32(  6 );   ILEAVE_8x32(  7 );
   ILEAVE_8x32(  8 );   ILEAVE_8x32(  9 );
   ILEAVE_8x32( 10 );   ILEAVE_8x32( 11 );
   ILEAVE_8x32( 12 );   ILEAVE_8x32( 13 );
   ILEAVE_8x32( 14 );   ILEAVE_8x32( 15 );
}

#undef ILEAVE_8x32

#define DLEAVE_8x32( i ) do \
{ \
   const uint32_t *s = (const uint32_t*)(src) + ( (i) << 3 ); \
   *( (uint32_t*)(d0) +(i) ) = s[0]; \
   *( (uint32_t*)(d1) +(i) ) = s[1]; \
   *( (uint32_t*)(d2) +(i) ) = s[2]; \
   *( (uint32_t*)(d3) +(i) ) = s[3]; \
   *( (uint32_t*)(d4) +(i) ) = s[4]; \
   *( (uint32_t*)(d5) +(i) ) = s[5]; \
   *( (uint32_t*)(d6) +(i) ) = s[6]; \
   *( (uint32_t*)(d7) +(i) ) = s[7]; \
} while(0)

static inline void dintrlv_8x32b( void *d0, void *d1, void *d2, void *d3,
             void *d4, void *d5, void *d6, void *d7, const void *src,
             const int bit_len )
{
   for ( int i = 0; i < bit_len/32; i++ )
      DLEAVE_8x32( i );
}

static inline void dintrlv_8x32( void *d0, void *d1, void *d2, void *d3,
             void *d4, void *d5, void *d6, void *d7, const void *src,
             const int bit_len )
{
   DLEAVE_8x32(  0 );   DLEAVE_8x32(  1 );
   DLEAVE_8x32(  2 );   DLEAVE_8x32(  3 );
   DLEAVE_8x32(  4 );   DLEAVE_8x32(  5 );
   DLEAVE_8x32(  6 );   DLEAVE_8x32(  7 );
   if ( bit_len <= 256 ) return;
   DLEAVE_8x32(  8 );   DLEAVE_8x32(  9 );
   DLEAVE_8x32( 10 );   DLEAVE_8x32( 11 );
   DLEAVE_8x32( 12 );   DLEAVE_8x32( 13 );
   DLEAVE_8x32( 14 );   DLEAVE_8x32( 15 );
   if ( bit_len <= 512 ) return;
   DLEAVE_8x32( 16 );   DLEAVE_8x32( 17 );
   DLEAVE_8x32( 18 );   DLEAVE_8x32( 19 );
   if ( bit_len <= 640 ) return;
   DLEAVE_8x32( 20 );   DLEAVE_8x32( 21 );
   DLEAVE_8x32( 22 );   DLEAVE_8x32( 23 );
   DLEAVE_8x32( 24 );   DLEAVE_8x32( 25 );
   DLEAVE_8x32( 26 );   DLEAVE_8x32( 27 );
   DLEAVE_8x32( 28 );   DLEAVE_8x32( 29 );
   DLEAVE_8x32( 30 );   DLEAVE_8x32( 31 );
}

static inline void dintrlv_8x32_512( void *d0, void *d1, void *d2, void *d3,
                     void *d4, void *d5, void *d6, void *d7, const void *src )
{
   DLEAVE_8x32(  0 );   DLEAVE_8x32(  1 );
   DLEAVE_8x32(  2 );   DLEAVE_8x32(  3 );
   DLEAVE_8x32(  4 );   DLEAVE_8x32(  5 );
   DLEAVE_8x32(  6 );   DLEAVE_8x32(  7 );
   DLEAVE_8x32(  8 );   DLEAVE_8x32(  9 );
   DLEAVE_8x32( 10 );   DLEAVE_8x32( 11 );
   DLEAVE_8x32( 12 );   DLEAVE_8x32( 13 );
   DLEAVE_8x32( 14 );   DLEAVE_8x32( 15 );
}

#undef DLEAVE_8x32

static inline void extr_lane_8x32( void *d, const void *s,
                                   const int lane, const int bit_len )
{
   ((uint32_t*)d)[ 0] = ((const uint32_t*)s)[ lane     ];
   ((uint32_t*)d)[ 1] = ((const uint32_t*)s)[ lane+  8 ];
   ((uint32_t*)d)[ 2] = ((const uint32_t*)s)[ lane+ 16 ];
   ((uint32_t*)d)[ 3] = ((const uint32_t*)s)[ lane+ 24 ];
   ((uint32_t*)d)[ 4] = ((const uint32_t*)s)[ lane+ 32 ];
   ((uint32_t*)d)[ 5] = ((const uint32_t*)s)[ lane+ 40 ];
   ((uint32_t*)d)[ 6] = ((const uint32_t*)s)[ lane+ 48 ];
   ((uint32_t*)d)[ 7] = ((const uint32_t*)s)[ lane+ 56 ];
   if ( bit_len <= 256 ) return;
   ((uint32_t*)d)[ 8] = ((const uint32_t*)s)[ lane+ 64 ];
   ((uint32_t*)d)[ 9] = ((const uint32_t*)s)[ lane+ 72 ];
   ((uint32_t*)d)[10] = ((const uint32_t*)s)[ lane+ 80 ];
   ((uint32_t*)d)[11] = ((const uint32_t*)s)[ lane+ 88 ];
   ((uint32_t*)d)[12] = ((const uint32_t*)s)[ lane+ 96 ];
   ((uint32_t*)d)[13] = ((const uint32_t*)s)[ lane+104 ];
   ((uint32_t*)d)[14] = ((const uint32_t*)s)[ lane+112 ];
   ((uint32_t*)d)[15] = ((const uint32_t*)s)[ lane+120 ];
}

#if defined(__AVX2__)

static inline void mm256_bswap32_intrlv80_8x32( void *d, const void *src )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

   casti_m128i( d, 0 ) = 
   casti_m128i( d, 1 ) = _mm_shuffle_epi32( s0 , 0x00 );
   casti_m128i( d, 2 ) = 
   casti_m128i( d, 3 ) = _mm_shuffle_epi32( s0 , 0x55 );
   casti_m128i( d, 4 ) = 
   casti_m128i( d, 5 ) = _mm_shuffle_epi32( s0 , 0xaa );
   casti_m128i( d, 6 ) = 
   casti_m128i( d, 7 ) = _mm_shuffle_epi32( s0 , 0xff );

   casti_m128i( d, 8 ) = 
   casti_m128i( d, 9 ) = _mm_shuffle_epi32( s1 , 0x00 );
   casti_m128i( d,10 ) = 
   casti_m128i( d,11 ) = _mm_shuffle_epi32( s1 , 0x55 );
   casti_m128i( d,12 ) = 
   casti_m128i( d,13 ) = _mm_shuffle_epi32( s1 , 0xaa );
   casti_m128i( d,14 ) = 
   casti_m128i( d,15 ) = _mm_shuffle_epi32( s1 , 0xff );

   casti_m128i( d,16 ) = 
   casti_m128i( d,17 ) = _mm_shuffle_epi32( s2 , 0x00 );
   casti_m128i( d,18 ) = 
   casti_m128i( d,19 ) = _mm_shuffle_epi32( s2 , 0x55 );
   casti_m128i( d,20 ) = 
   casti_m128i( d,21 ) = _mm_shuffle_epi32( s2 , 0xaa );
   casti_m128i( d,22 ) = 
   casti_m128i( d,23 ) = _mm_shuffle_epi32( s2 , 0xff );

   casti_m128i( d,24 ) = 
   casti_m128i( d,25 ) = _mm_shuffle_epi32( s3 , 0x00 );
   casti_m128i( d,26 ) = 
   casti_m128i( d,27 ) = _mm_shuffle_epi32( s3 , 0x55 );
   casti_m128i( d,28 ) = 
   casti_m128i( d,29 ) = _mm_shuffle_epi32( s3 , 0xaa );
   casti_m128i( d,30 ) = 
   casti_m128i( d,31 ) = _mm_shuffle_epi32( s3 , 0xff );

   casti_m128i( d,32 ) = 
   casti_m128i( d,33 ) = _mm_shuffle_epi32( s4 , 0x00 );
   casti_m128i( d,34 ) = 
   casti_m128i( d,35 ) = _mm_shuffle_epi32( s4 , 0x55 );
   casti_m128i( d,36 ) = 
   casti_m128i( d,37 ) = _mm_shuffle_epi32( s4 , 0xaa );
   casti_m128i( d,38 ) = 
   casti_m128i( d,39 ) = _mm_shuffle_epi32( s4 , 0xff );
} 

#endif   // AVX2

// 16x32

#define ILEAVE_16x32( i ) do \
{ \
  uint32_t *d = (uint32_t*)(dst) + ( (i) << 4 ); \
  d[ 0] = *( (const uint32_t*)(s00) +(i) ); \
  d[ 1] = *( (const uint32_t*)(s01) +(i) ); \
  d[ 2] = *( (const uint32_t*)(s02) +(i) ); \
  d[ 3] = *( (const uint32_t*)(s03) +(i) ); \
  d[ 4] = *( (const uint32_t*)(s04) +(i) ); \
  d[ 5] = *( (const uint32_t*)(s05) +(i) ); \
  d[ 6] = *( (const uint32_t*)(s06) +(i) ); \
  d[ 7] = *( (const uint32_t*)(s07) +(i) ); \
  d[ 8] = *( (const uint32_t*)(s08) +(i) ); \
  d[ 9] = *( (const uint32_t*)(s09) +(i) ); \
  d[10] = *( (const uint32_t*)(s10) +(i) ); \
  d[11] = *( (const uint32_t*)(s11) +(i) ); \
  d[12] = *( (const uint32_t*)(s12) +(i) ); \
  d[13] = *( (const uint32_t*)(s13) +(i) ); \
  d[14] = *( (const uint32_t*)(s14) +(i) ); \
  d[15] = *( (const uint32_t*)(s15) +(i) ); \
} while(0)

static inline void intrlv_16x32( void *dst, const void *s00,
        const void *s01, const void *s02, const void *s03, const void *s04,
        const void *s05, const void *s06, const void *s07, const void *s08,
        const void *s09, const void *s10, const void *s11, const void *s12,
        const void *s13, const void *s14, const void *s15, const int bit_len )
{
   ILEAVE_16x32(  0 );   ILEAVE_16x32(  1 );
   ILEAVE_16x32(  2 );   ILEAVE_16x32(  3 );
   ILEAVE_16x32(  4 );   ILEAVE_16x32(  5 );
   ILEAVE_16x32(  6 );   ILEAVE_16x32(  7 );
   if ( bit_len <= 256 ) return;
   ILEAVE_16x32(  8 );   ILEAVE_16x32(  9 );
   ILEAVE_16x32( 10 );   ILEAVE_16x32( 11 );
   ILEAVE_16x32( 12 );   ILEAVE_16x32( 13 );
   ILEAVE_16x32( 14 );   ILEAVE_16x32( 15 );
   if ( bit_len <= 512 ) return;
   ILEAVE_16x32( 16 );   ILEAVE_16x32( 17 );
   ILEAVE_16x32( 18 );   ILEAVE_16x32( 19 );
   if ( bit_len <= 640 ) return;
   ILEAVE_16x32( 20 );   ILEAVE_16x32( 21 );
   ILEAVE_16x32( 22 );   ILEAVE_16x32( 23 );
   ILEAVE_16x32( 24 );   ILEAVE_16x32( 25 );
   ILEAVE_16x32( 26 );   ILEAVE_16x32( 27 );
   ILEAVE_16x32( 28 );   ILEAVE_16x32( 29 );
   ILEAVE_16x32( 30 );   ILEAVE_16x32( 31 );
}

static inline void intrlv_16x32_512( void *dst, const void *s00,
        const void *s01, const void *s02, const void *s03, const void *s04,
        const void *s05, const void *s06, const void *s07, const void *s08,
        const void *s09, const void *s10, const void *s11, const void *s12,
        const void *s13, const void *s14, const void *s15 )
{
   ILEAVE_16x32(  0 );   ILEAVE_16x32(  1 );
   ILEAVE_16x32(  2 );   ILEAVE_16x32(  3 );
   ILEAVE_16x32(  4 );   ILEAVE_16x32(  5 );
   ILEAVE_16x32(  6 );   ILEAVE_16x32(  7 );
   ILEAVE_16x32(  8 );   ILEAVE_16x32(  9 );
   ILEAVE_16x32( 10 );   ILEAVE_16x32( 11 );
   ILEAVE_16x32( 12 );   ILEAVE_16x32( 13 );
   ILEAVE_16x32( 14 );   ILEAVE_16x32( 15 );
}

#undef ILEAVE_16x32

#define DLEAVE_16x32( i ) do \
{ \
   const uint32_t *s = (const uint32_t*)(src) + ( (i) << 4 ); \
   *( (uint32_t*)(d00) +(i) ) = s[ 0]; \
   *( (uint32_t*)(d01) +(i) ) = s[ 1]; \
   *( (uint32_t*)(d02) +(i) ) = s[ 2]; \
   *( (uint32_t*)(d03) +(i) ) = s[ 3]; \
   *( (uint32_t*)(d04) +(i) ) = s[ 4]; \
   *( (uint32_t*)(d05) +(i) ) = s[ 5]; \
   *( (uint32_t*)(d06) +(i) ) = s[ 6]; \
   *( (uint32_t*)(d07) +(i) ) = s[ 7]; \
   *( (uint32_t*)(d08) +(i) ) = s[ 8]; \
   *( (uint32_t*)(d09) +(i) ) = s[ 9]; \
   *( (uint32_t*)(d10) +(i) ) = s[10]; \
   *( (uint32_t*)(d11) +(i) ) = s[11]; \
   *( (uint32_t*)(d12) +(i) ) = s[12]; \
   *( (uint32_t*)(d13) +(i) ) = s[13]; \
   *( (uint32_t*)(d14) +(i) ) = s[14]; \
   *( (uint32_t*)(d15) +(i) ) = s[15]; \
} while(0)

static inline void dintrlv_16x32( void *d00, void *d01, void *d02, void *d03,
            void *d04, void *d05, void *d06, void *d07, void *d08, void *d09,
            void *d10, void *d11, void *d12, void *d13, void *d14, void *d15,
            const void *src, const int bit_len )
{
   DLEAVE_16x32(  0 );   DLEAVE_16x32(  1 );
   DLEAVE_16x32(  2 );   DLEAVE_16x32(  3 );
   DLEAVE_16x32(  4 );   DLEAVE_16x32(  5 );
   DLEAVE_16x32(  6 );   DLEAVE_16x32(  7 );
   if ( bit_len <= 256 ) return;
   DLEAVE_16x32(  8 );   DLEAVE_16x32(  9 );
   DLEAVE_16x32( 10 );   DLEAVE_16x32( 11 );
   DLEAVE_16x32( 12 );   DLEAVE_16x32( 13 );
   DLEAVE_16x32( 14 );   DLEAVE_16x32( 15 );
   if ( bit_len <= 512 ) return;
   DLEAVE_16x32( 16 );   DLEAVE_16x32( 17 );
   DLEAVE_16x32( 18 );   DLEAVE_16x32( 19 );
   if ( bit_len <= 640 ) return;
   DLEAVE_16x32( 20 );   DLEAVE_16x32( 21 );
   DLEAVE_16x32( 22 );   DLEAVE_16x32( 23 );
   DLEAVE_16x32( 24 );   DLEAVE_16x32( 25 );
   DLEAVE_16x32( 26 );   DLEAVE_16x32( 27 );
   DLEAVE_16x32( 28 );   DLEAVE_16x32( 29 );
   DLEAVE_16x32( 30 );   DLEAVE_16x32( 31 );
}

static inline void dintrlv_16x32_512( void *d00, void *d01, void *d02,
                void *d03, void *d04, void *d05, void *d06, void *d07,
                void *d08, void *d09, void *d10, void *d11, void *d12,
                void *d13, void *d14, void *d15, const void *src )
{
   DLEAVE_16x32(  0 );   DLEAVE_16x32(  1 );
   DLEAVE_16x32(  2 );   DLEAVE_16x32(  3 );
   DLEAVE_16x32(  4 );   DLEAVE_16x32(  5 );
   DLEAVE_16x32(  6 );   DLEAVE_16x32(  7 );
   DLEAVE_16x32(  8 );   DLEAVE_16x32(  9 );
   DLEAVE_16x32( 10 );   DLEAVE_16x32( 11 );
   DLEAVE_16x32( 12 );   DLEAVE_16x32( 13 );
   DLEAVE_16x32( 14 );   DLEAVE_16x32( 15 );
}

#undef DLEAVE_16x32

static inline void extr_lane_16x32( void *d, const void *s,
                                    const int lane, const int bit_len )
{
   ((uint32_t*)d)[ 0] = ((const uint32_t*)s)[ lane    ];
   ((uint32_t*)d)[ 1] = ((const uint32_t*)s)[ lane+16 ];
   ((uint32_t*)d)[ 2] = ((const uint32_t*)s)[ lane+32 ];
   ((uint32_t*)d)[ 3] = ((const uint32_t*)s)[ lane+48 ];
   ((uint32_t*)d)[ 4] = ((const uint32_t*)s)[ lane+64 ];
   ((uint32_t*)d)[ 5] = ((const uint32_t*)s)[ lane+80 ];
   ((uint32_t*)d)[ 6] = ((const uint32_t*)s)[ lane+96 ];
   ((uint32_t*)d)[ 7] = ((const uint32_t*)s)[ lane+112 ];
   if ( bit_len <= 256 ) return;
   ((uint32_t*)d)[ 8] = ((const uint32_t*)s)[ lane+128 ];
   ((uint32_t*)d)[ 9] = ((const uint32_t*)s)[ lane+144 ];
   ((uint32_t*)d)[10] = ((const uint32_t*)s)[ lane+160 ];
   ((uint32_t*)d)[11] = ((const uint32_t*)s)[ lane+176 ];
   ((uint32_t*)d)[12] = ((const uint32_t*)s)[ lane+192 ];
   ((uint32_t*)d)[13] = ((const uint32_t*)s)[ lane+208 ];
   ((uint32_t*)d)[14] = ((const uint32_t*)s)[ lane+224 ];
   ((uint32_t*)d)[15] = ((const uint32_t*)s)[ lane+240 ];
}

#if defined(__AVX512F__) && defined(__AVX512VL__)

static inline void mm512_bswap32_intrlv80_16x32( void *d, const void *src )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

   casti_m128i( d, 0 ) = 
   casti_m128i( d, 1 ) = 
   casti_m128i( d, 2 ) = 
   casti_m128i( d, 3 ) = _mm_shuffle_epi32( s0 , 0x00 );
   casti_m128i( d, 4 ) = 
   casti_m128i( d, 5 ) = 
   casti_m128i( d, 6 ) = 
   casti_m128i( d, 7 ) = _mm_shuffle_epi32( s0 , 0x55 );
   casti_m128i( d, 8 ) = 
   casti_m128i( d, 9 ) = 
   casti_m128i( d,10 ) = 
   casti_m128i( d,11 ) = _mm_shuffle_epi32( s0 , 0xaa );
   casti_m128i( d,12 ) = 
   casti_m128i( d,13 ) = 
   casti_m128i( d,14 ) = 
   casti_m128i( d,15 ) = _mm_shuffle_epi32( s0 , 0xff );

   casti_m128i( d,16 ) = 
   casti_m128i( d,17 ) = 
   casti_m128i( d,18 ) = 
   casti_m128i( d,19 ) = _mm_shuffle_epi32( s1 , 0x00 );
   casti_m128i( d,20 ) = 
   casti_m128i( d,21 ) = 
   casti_m128i( d,22 ) = 
   casti_m128i( d,23 ) = _mm_shuffle_epi32( s1 , 0x55 );
   casti_m128i( d,24 ) = 
   casti_m128i( d,25 ) = 
   casti_m128i( d,26 ) = 
   casti_m128i( d,27 ) = _mm_shuffle_epi32( s1 , 0xaa );
   casti_m128i( d,28 ) = 
   casti_m128i( d,29 ) = 
   casti_m128i( d,30 ) = 
   casti_m128i( d,31 ) = _mm_shuffle_epi32( s1 , 0xff );

   casti_m128i( d,32 ) = 
   casti_m128i( d,33 ) = 
   casti_m128i( d,34 ) = 
   casti_m128i( d,35 ) = _mm_shuffle_epi32( s2 , 0x00 );
   casti_m128i( d,36 ) = 
   casti_m128i( d,37 ) = 
   casti_m128i( d,38 ) = 
   casti_m128i( d,39 ) = _mm_shuffle_epi32( s2 , 0x55 );
   casti_m128i( d,40 ) = 
   casti_m128i( d,41 ) = 
   casti_m128i( d,42 ) = 
   casti_m128i( d,43 ) = _mm_shuffle_epi32( s2 , 0xaa );
   casti_m128i( d,44 ) = 
   casti_m128i( d,45 ) = 
   casti_m128i( d,46 ) = 
   casti_m128i( d,47 ) = _mm_shuffle_epi32( s2 , 0xff );

   casti_m128i( d,48 ) = 
   casti_m128i( d,49 ) = 
   casti_m128i( d,50 ) = 
   casti_m128i( d,51 ) = _mm_shuffle_epi32( s3 , 0x00 );
   casti_m128i( d,52 ) = 
   casti_m128i( d,53 ) = 
   casti_m128i( d,54 ) = 
   casti_m128i( d,55 ) = _mm_shuffle_epi32( s3 , 0x55 );
   casti_m128i( d,56 ) = 
   casti_m128i( d,57 ) = 
   casti_m128i( d,58 ) = 
   casti_m128i( d,59 ) = _mm_shuffle_epi32( s3 , 0xaa );
   casti_m128i( d,60 ) = 
   casti_m128i( d,61 ) = 
   casti_m128i( d,62 ) = 
   casti_m128i( d,63 ) = _mm_shuffle_epi32( s3 , 0xff );

   casti_m128i( d,64 ) = 
   casti_m128i( d,65 ) = 
   casti_m128i( d,66 ) = 
   casti_m128i( d,67 ) = _mm_shuffle_epi32( s4 , 0x00 );
   casti_m128i( d,68 ) = 
   casti_m128i( d,69 ) = 
   casti_m128i( d,70 ) = 
   casti_m128i( d,71 ) = _mm_shuffle_epi32( s4 , 0x55 );
   casti_m128i( d,72 ) = 
   casti_m128i( d,73 ) = 
   casti_m128i( d,74 ) = 
   casti_m128i( d,75 ) = _mm_shuffle_epi32( s4 , 0xaa );
   casti_m128i( d,76 ) = 
   casti_m128i( d,77 ) = 
   casti_m128i( d,78 ) = 
   casti_m128i( d,79 ) = _mm_shuffle_epi32( s4 , 0xff );
}

#endif    // AVX512

///////////////////////////
//
//     64 bit data

// 2x64    (SSE2)

static inline void intrlv_2x64( void *dst, const void *src0,
                                const void *src1, const int bit_len )
{
   uint64_t *d = (uint64_t*)dst;;
   const uint64_t *s0 = (const uint64_t*)src0;
   const uint64_t *s1 = (const uint64_t*)src1;
   d[ 0] = s0[ 0];    d[ 1] = s1[ 0];   d[ 2] = s0[ 1];    d[ 3] = s1[ 1];
   d[ 4] = s0[ 2];    d[ 5] = s1[ 2];   d[ 6] = s0[ 3];    d[ 7] = s1[ 3];
   if ( bit_len <= 256 ) return;
   d[ 8] = s0[ 4];    d[ 9] = s1[ 4];   d[10] = s0[ 5];    d[11] = s1[ 5];
   d[12] = s0[ 6];    d[13] = s1[ 6];   d[14] = s0[ 7];    d[15] = s1[ 7];
   if ( bit_len <= 512 ) return;
   d[16] = s0[ 8];    d[17] = s1[ 8];   d[18] = s0[ 9];    d[19] = s1[ 9];
   if ( bit_len <= 640 ) return;
   d[20] = s0[10];    d[21] = s1[10];   d[22] = s0[11];    d[23] = s1[11];
   d[24] = s0[12];    d[25] = s1[12];   d[26] = s0[13];    d[27] = s1[13];
   d[28] = s0[14];    d[29] = s1[14];   d[30] = s0[15];    d[31] = s1[15];
}

static inline void dintrlv_2x64( void *dst0, void *dst1,
                                 const void *src, const int bit_len )
{
   uint64_t *d0 = (uint64_t*)dst0;
   uint64_t *d1 = (uint64_t*)dst1;
   const uint64_t *s = (const uint64_t*)src;

   d0[ 0] = s[ 0];   d1[ 0] = s[ 1];   d0[ 1] = s[ 2];   d1[ 1] = s[ 3];
   d0[ 2] = s[ 4];   d1[ 2] = s[ 5];   d0[ 3] = s[ 6];   d1[ 3] = s[ 7];
   if ( bit_len <= 256 ) return;
   d0[ 4] = s[ 8];   d1[ 4] = s[ 9];   d0[ 5] = s[10];   d1[ 5] = s[11];
   d0[ 6] = s[12];   d1[ 6] = s[13];   d0[ 7] = s[14];   d1[ 7] = s[15];
   if ( bit_len <= 512 ) return;
   d0[ 8] = s[16];   d1[ 8] = s[17];   d0[ 9] = s[18];   d1[ 9] = s[19];
   if ( bit_len <= 640 ) return;
   d0[10] = s[20];   d1[10] = s[21];   d0[11] = s[22];   d1[11] = s[23];
   d0[12] = s[24];   d1[12] = s[25];   d0[13] = s[26];   d1[13] = s[27];
   d0[14] = s[28];   d1[14] = s[29];   d0[15] = s[30];   d1[15] = s[31];
}

// 4x64   (AVX2)

static inline void intrlv_4x64( void *dst, const void *src0,
                    const void *src1, const void *src2, const void *src3,
                    const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3;
   d[ 0] = _mm_unpacklo_epi64( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_epi64( s2[0], s3[0] );
   d[ 2] = _mm_unpackhi_epi64( s0[0], s1[0] );
   d[ 3] = _mm_unpackhi_epi64( s2[0], s3[0] );
   d[ 4] = _mm_unpacklo_epi64( s0[1], s1[1] );
   d[ 5] = _mm_unpacklo_epi64( s2[1], s3[1] );
   d[ 6] = _mm_unpackhi_epi64( s0[1], s1[1] );
   d[ 7] = _mm_unpackhi_epi64( s2[1], s3[1] );
   if ( bit_len <= 256 ) return;
   d[ 8] = _mm_unpacklo_epi64( s0[2], s1[2] );
   d[ 9] = _mm_unpacklo_epi64( s2[2], s3[2] );
   d[10] = _mm_unpackhi_epi64( s0[2], s1[2] );
   d[11] = _mm_unpackhi_epi64( s2[2], s3[2] );
   d[12] = _mm_unpacklo_epi64( s0[3], s1[3] );
   d[13] = _mm_unpacklo_epi64( s2[3], s3[3] );
   d[14] = _mm_unpackhi_epi64( s0[3], s1[3] );
   d[15] = _mm_unpackhi_epi64( s2[3], s3[3] );
   if ( bit_len <= 512 ) return;
   d[16] = _mm_unpacklo_epi64( s0[4], s1[4] );
   d[17] = _mm_unpacklo_epi64( s2[4], s3[4] );
   d[18] = _mm_unpackhi_epi64( s0[4], s1[4] );
   d[19] = _mm_unpackhi_epi64( s2[4], s3[4] );
   if ( bit_len <= 640 ) return;
   d[20] = _mm_unpacklo_epi64( s0[5], s1[5] );
   d[21] = _mm_unpacklo_epi64( s2[5], s3[5] );
   d[22] = _mm_unpackhi_epi64( s0[5], s1[5] );
   d[23] = _mm_unpackhi_epi64( s2[5], s3[5] );
   d[24] = _mm_unpacklo_epi64( s0[6], s1[6] );
   d[25] = _mm_unpacklo_epi64( s2[6], s3[6] );
   d[26] = _mm_unpackhi_epi64( s0[6], s1[6] );
   d[27] = _mm_unpackhi_epi64( s2[6], s3[6] );
   d[28] = _mm_unpacklo_epi64( s0[7], s1[7] );
   d[29] = _mm_unpacklo_epi64( s2[7], s3[7] );
   d[30] = _mm_unpackhi_epi64( s0[7], s1[7] );
   d[31] = _mm_unpackhi_epi64( s2[7], s3[7] );
}

static inline void intrlv_4x64_512( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3 )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3;
   d[ 0] = _mm_unpacklo_epi64( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_epi64( s2[0], s3[0] );
   d[ 2] = _mm_unpackhi_epi64( s0[0], s1[0] );
   d[ 3] = _mm_unpackhi_epi64( s2[0], s3[0] );
   d[ 4] = _mm_unpacklo_epi64( s0[1], s1[1] );
   d[ 5] = _mm_unpacklo_epi64( s2[1], s3[1] );
   d[ 6] = _mm_unpackhi_epi64( s0[1], s1[1] );
   d[ 7] = _mm_unpackhi_epi64( s2[1], s3[1] );
   d[ 8] = _mm_unpacklo_epi64( s0[2], s1[2] );
   d[ 9] = _mm_unpacklo_epi64( s2[2], s3[2] );
   d[10] = _mm_unpackhi_epi64( s0[2], s1[2] );
   d[11] = _mm_unpackhi_epi64( s2[2], s3[2] );
   d[12] = _mm_unpacklo_epi64( s0[3], s1[3] );
   d[13] = _mm_unpacklo_epi64( s2[3], s3[3] );
   d[14] = _mm_unpackhi_epi64( s0[3], s1[3] );
   d[15] = _mm_unpackhi_epi64( s2[3], s3[3] );
}

static inline void dintrlv_4x64( void *dst0, void *dst1, void *dst2,
                           void *dst3, const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   const __m128i *s = (const __m128i*)src;
   d0[0] = _mm_unpacklo_epi64( s[ 0], s[ 2] );
   d1[0] = _mm_unpackhi_epi64( s[ 0], s[ 2] );
   d2[0] = _mm_unpacklo_epi64( s[ 1], s[ 3] );
   d3[0] = _mm_unpackhi_epi64( s[ 1], s[ 3] );
   d0[1] = _mm_unpacklo_epi64( s[ 4], s[ 6] );
   d1[1] = _mm_unpackhi_epi64( s[ 4], s[ 6] );
   d2[1] = _mm_unpacklo_epi64( s[ 5], s[ 7] );
   d3[1] = _mm_unpackhi_epi64( s[ 5], s[ 7] );
   if ( bit_len <= 256 ) return;
   d0[2] = _mm_unpacklo_epi64( s[ 8], s[10] );
   d1[2] = _mm_unpackhi_epi64( s[ 8], s[10] );
   d2[2] = _mm_unpacklo_epi64( s[ 9], s[11] );
   d3[2] = _mm_unpackhi_epi64( s[ 9], s[11] );
   d0[3] = _mm_unpacklo_epi64( s[12], s[14] );
   d1[3] = _mm_unpackhi_epi64( s[12], s[14] );
   d2[3] = _mm_unpacklo_epi64( s[13], s[15] );
   d3[3] = _mm_unpackhi_epi64( s[13], s[15] );
   if ( bit_len <= 512 ) return;
   d0[4] = _mm_unpacklo_epi64( s[16], s[18] );
   d1[4] = _mm_unpackhi_epi64( s[16], s[18] );
   d2[4] = _mm_unpacklo_epi64( s[17], s[19] );
   d3[4] = _mm_unpackhi_epi64( s[17], s[19] );
   if ( bit_len <= 640 ) return;
   d0[5] = _mm_unpacklo_epi64( s[20], s[22] );
   d1[5] = _mm_unpackhi_epi64( s[20], s[22] );
   d2[5] = _mm_unpacklo_epi64( s[21], s[23] );
   d3[5] = _mm_unpackhi_epi64( s[21], s[23] );
   d0[6] = _mm_unpacklo_epi64( s[24], s[26] );
   d1[6] = _mm_unpackhi_epi64( s[24], s[26] );
   d2[6] = _mm_unpacklo_epi64( s[25], s[27] );
   d3[6] = _mm_unpackhi_epi64( s[25], s[27] );
   d0[7] = _mm_unpacklo_epi64( s[28], s[30] );
   d1[7] = _mm_unpackhi_epi64( s[28], s[30] );
   d2[7] = _mm_unpacklo_epi64( s[29], s[31] );
   d3[7] = _mm_unpackhi_epi64( s[29], s[31] );
}

static inline void dintrlv_4x64_512( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   const __m128i *s = (const __m128i*)src;
   d0[0] = _mm_unpacklo_epi64( s[ 0], s[ 2] );
   d1[0] = _mm_unpackhi_epi64( s[ 0], s[ 2] );
   d2[0] = _mm_unpacklo_epi64( s[ 1], s[ 3] );
   d3[0] = _mm_unpackhi_epi64( s[ 1], s[ 3] );
   d0[1] = _mm_unpacklo_epi64( s[ 4], s[ 6] );
   d1[1] = _mm_unpackhi_epi64( s[ 4], s[ 6] );
   d2[1] = _mm_unpacklo_epi64( s[ 5], s[ 7] );
   d3[1] = _mm_unpackhi_epi64( s[ 5], s[ 7] );
   d0[2] = _mm_unpacklo_epi64( s[ 8], s[10] );
   d1[2] = _mm_unpackhi_epi64( s[ 8], s[10] );
   d2[2] = _mm_unpacklo_epi64( s[ 9], s[11] );
   d3[2] = _mm_unpackhi_epi64( s[ 9], s[11] );
   d0[3] = _mm_unpacklo_epi64( s[12], s[14] );
   d1[3] = _mm_unpackhi_epi64( s[12], s[14] );
   d2[3] = _mm_unpacklo_epi64( s[13], s[15] );
   d3[3] = _mm_unpackhi_epi64( s[13], s[15] );
}

static inline void extr_lane_4x64( void *d, const void *s,
                                   const int lane, const int bit_len )
{
   ((uint64_t*)d)[ 0] = ((const uint64_t*)s)[ lane    ];
   ((uint64_t*)d)[ 1] = ((const uint64_t*)s)[ lane+ 4 ];
   ((uint64_t*)d)[ 2] = ((const uint64_t*)s)[ lane+ 8 ];
   ((uint64_t*)d)[ 3] = ((const uint64_t*)s)[ lane+12 ];
   if ( bit_len <= 256 ) return;
   ((uint64_t*)d)[ 4] = ((const uint64_t*)s)[ lane+16 ];
   ((uint64_t*)d)[ 5] = ((const uint64_t*)s)[ lane+20 ];
   ((uint64_t*)d)[ 6] = ((const uint64_t*)s)[ lane+24 ];
   ((uint64_t*)d)[ 7] = ((const uint64_t*)s)[ lane+28 ];
}

#if defined(__AVX2__)
// Doesn't really need AVX2, just SSSE3, but is only used with AVX2 code.

static inline void mm256_intrlv80_4x64( void *d, const void *src )
{
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  casti_m128i( d,  0 ) =
  casti_m128i( d,  1 ) = _mm_shuffle_epi32( s0, 0x44 );
  casti_m128i( d,  2 ) =
  casti_m128i( d,  3 ) = _mm_shuffle_epi32( s0, 0xee );

  casti_m128i( d,  4 ) =
  casti_m128i( d,  5 ) = _mm_shuffle_epi32( s1, 0x44 );
  casti_m128i( d,  6 ) =
  casti_m128i( d,  7 ) = _mm_shuffle_epi32( s1, 0xee );

  casti_m128i( d,  8 ) =
  casti_m128i( d,  9 ) = _mm_shuffle_epi32( s2, 0x44 );
  casti_m128i( d, 10 ) =
  casti_m128i( d, 11 ) = _mm_shuffle_epi32( s2, 0xee );

  casti_m128i( d, 12 ) =
  casti_m128i( d, 13 ) = _mm_shuffle_epi32( s3, 0x44 );
  casti_m128i( d, 14 ) =
  casti_m128i( d, 15 ) = _mm_shuffle_epi32( s3, 0xee );

  casti_m128i( d, 16 ) =
  casti_m128i( d, 17 ) = _mm_shuffle_epi32( s4, 0x44 );
  casti_m128i( d, 18 ) =
  casti_m128i( d, 19 ) = _mm_shuffle_epi32( s4, 0xee );
}

static inline void mm256_bswap32_intrlv80_4x64( void *d, const void *src )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m128i( d,  0 ) = 
  casti_m128i( d,  1 ) = _mm_shuffle_epi32( s0, 0x44 );
  casti_m128i( d,  2 ) =   
  casti_m128i( d,  3 ) = _mm_shuffle_epi32( s0, 0xee );

  casti_m128i( d,  4 ) =   
  casti_m128i( d,  5 ) = _mm_shuffle_epi32( s1, 0x44 );
  casti_m128i( d,  6 ) =
  casti_m128i( d,  7 ) = _mm_shuffle_epi32( s1, 0xee );

  casti_m128i( d,  8 ) =
  casti_m128i( d,  9 ) = _mm_shuffle_epi32( s2, 0x44 );
  casti_m128i( d, 10 ) =
  casti_m128i( d, 11 ) = _mm_shuffle_epi32( s2, 0xee );

  casti_m128i( d, 12 ) =
  casti_m128i( d, 13 ) = _mm_shuffle_epi32( s3, 0x44 );
  casti_m128i( d, 14 ) =
  casti_m128i( d, 15 ) = _mm_shuffle_epi32( s3, 0xee );

  casti_m128i( d, 16 ) =
  casti_m128i( d, 17 ) = _mm_shuffle_epi32( s4, 0x44 );
  casti_m128i( d, 18 ) =
  casti_m128i( d, 19 ) = _mm_shuffle_epi32( s4, 0xee );

}

#endif  // AVX2

// 8x64   (AVX512)

static inline void intrlv_8x64( void *dst, const void *src0,
       const void *src1, const void *src2, const void *src3,
       const void *src4, const void *src5, const void *src6,
       const void *src7, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3;
   const __m128i *s4 = (const __m128i*)src4;
   const __m128i *s5 = (const __m128i*)src5;
   const __m128i *s6 = (const __m128i*)src6;
   const __m128i *s7 = (const __m128i*)src7;

   d[ 0] = _mm_unpacklo_epi64( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_epi64( s2[0], s3[0] );
   d[ 2] = _mm_unpacklo_epi64( s4[0], s5[0] );
   d[ 3] = _mm_unpacklo_epi64( s6[0], s7[0] );
   d[ 4] = _mm_unpackhi_epi64( s0[0], s1[0] );
   d[ 5] = _mm_unpackhi_epi64( s2[0], s3[0] );
   d[ 6] = _mm_unpackhi_epi64( s4[0], s5[0] );
   d[ 7] = _mm_unpackhi_epi64( s6[0], s7[0] );

   d[ 8] = _mm_unpacklo_epi64( s0[1], s1[1] );
   d[ 9] = _mm_unpacklo_epi64( s2[1], s3[1] );
   d[10] = _mm_unpacklo_epi64( s4[1], s5[1] );
   d[11] = _mm_unpacklo_epi64( s6[1], s7[1] );
   d[12] = _mm_unpackhi_epi64( s0[1], s1[1] );
   d[13] = _mm_unpackhi_epi64( s2[1], s3[1] );
   d[14] = _mm_unpackhi_epi64( s4[1], s5[1] );
   d[15] = _mm_unpackhi_epi64( s6[1], s7[1] );

   if ( bit_len <= 256 ) return;

   d[16] = _mm_unpacklo_epi64( s0[2], s1[2] );
   d[17] = _mm_unpacklo_epi64( s2[2], s3[2] );
   d[18] = _mm_unpacklo_epi64( s4[2], s5[2] );
   d[19] = _mm_unpacklo_epi64( s6[2], s7[2] );
   d[20] = _mm_unpackhi_epi64( s0[2], s1[2] );
   d[21] = _mm_unpackhi_epi64( s2[2], s3[2] );
   d[22] = _mm_unpackhi_epi64( s4[2], s5[2] );
   d[23] = _mm_unpackhi_epi64( s6[2], s7[2] );

   d[24] = _mm_unpacklo_epi64( s0[3], s1[3] );
   d[25] = _mm_unpacklo_epi64( s2[3], s3[3] );
   d[26] = _mm_unpacklo_epi64( s4[3], s5[3] );
   d[27] = _mm_unpacklo_epi64( s6[3], s7[3] );
   d[28] = _mm_unpackhi_epi64( s0[3], s1[3] );
   d[29] = _mm_unpackhi_epi64( s2[3], s3[3] );
   d[30] = _mm_unpackhi_epi64( s4[3], s5[3] );
   d[31] = _mm_unpackhi_epi64( s6[3], s7[3] );

   if ( bit_len <= 512 ) return;

   d[32] = _mm_unpacklo_epi64( s0[4], s1[4] );
   d[33] = _mm_unpacklo_epi64( s2[4], s3[4] );
   d[34] = _mm_unpacklo_epi64( s4[4], s5[4] );
   d[35] = _mm_unpacklo_epi64( s6[4], s7[4] );
   d[36] = _mm_unpackhi_epi64( s0[4], s1[4] );
   d[37] = _mm_unpackhi_epi64( s2[4], s3[4] );
   d[38] = _mm_unpackhi_epi64( s4[4], s5[4] );
   d[39] = _mm_unpackhi_epi64( s6[4], s7[4] );

   if ( bit_len <= 640 ) return;

   d[40] = _mm_unpacklo_epi64( s0[5], s1[5] );
   d[41] = _mm_unpacklo_epi64( s2[5], s3[5] );
   d[42] = _mm_unpacklo_epi64( s4[5], s5[5] );
   d[43] = _mm_unpacklo_epi64( s6[5], s7[5] );
   d[44] = _mm_unpackhi_epi64( s0[5], s1[5] );
   d[45] = _mm_unpackhi_epi64( s2[5], s3[5] );
   d[46] = _mm_unpackhi_epi64( s4[5], s5[5] );
   d[47] = _mm_unpackhi_epi64( s6[5], s7[5] );

   d[48] = _mm_unpacklo_epi64( s0[6], s1[6] );
   d[49] = _mm_unpacklo_epi64( s2[6], s3[6] );
   d[50] = _mm_unpacklo_epi64( s4[6], s5[6] );
   d[51] = _mm_unpacklo_epi64( s6[6], s7[6] );
   d[52] = _mm_unpackhi_epi64( s0[6], s1[6] );
   d[53] = _mm_unpackhi_epi64( s2[6], s3[6] );
   d[54] = _mm_unpackhi_epi64( s4[6], s5[6] );
   d[55] = _mm_unpackhi_epi64( s6[6], s7[6] );

   d[56] = _mm_unpacklo_epi64( s0[7], s1[7] );
   d[57] = _mm_unpacklo_epi64( s2[7], s3[7] );
   d[58] = _mm_unpacklo_epi64( s4[7], s5[7] );
   d[59] = _mm_unpacklo_epi64( s6[7], s7[7] );
   d[60] = _mm_unpackhi_epi64( s0[7], s1[7] );
   d[61] = _mm_unpackhi_epi64( s2[7], s3[7] );
   d[62] = _mm_unpackhi_epi64( s4[7], s5[7] );
   d[63] = _mm_unpackhi_epi64( s6[7], s7[7] );
}

static inline void intrlv_8x64_512( void *dst, const void *src0,
       const void *src1, const void *src2, const void *src3,
       const void *src4, const void *src5, const void *src6,
       const void *src7 )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3;
   const __m128i *s4 = (const __m128i*)src4;
   const __m128i *s5 = (const __m128i*)src5;
   const __m128i *s6 = (const __m128i*)src6;
   const __m128i *s7 = (const __m128i*)src7;

   d[ 0] = _mm_unpacklo_epi64( s0[0], s1[0] );
   d[ 1] = _mm_unpacklo_epi64( s2[0], s3[0] );
   d[ 2] = _mm_unpacklo_epi64( s4[0], s5[0] );
   d[ 3] = _mm_unpacklo_epi64( s6[0], s7[0] );
   d[ 4] = _mm_unpackhi_epi64( s0[0], s1[0] );
   d[ 5] = _mm_unpackhi_epi64( s2[0], s3[0] );
   d[ 6] = _mm_unpackhi_epi64( s4[0], s5[0] );
   d[ 7] = _mm_unpackhi_epi64( s6[0], s7[0] );

   d[ 8] = _mm_unpacklo_epi64( s0[1], s1[1] );
   d[ 9] = _mm_unpacklo_epi64( s2[1], s3[1] );
   d[10] = _mm_unpacklo_epi64( s4[1], s5[1] );
   d[11] = _mm_unpacklo_epi64( s6[1], s7[1] );
   d[12] = _mm_unpackhi_epi64( s0[1], s1[1] );
   d[13] = _mm_unpackhi_epi64( s2[1], s3[1] );
   d[14] = _mm_unpackhi_epi64( s4[1], s5[1] );
   d[15] = _mm_unpackhi_epi64( s6[1], s7[1] );

   d[16] = _mm_unpacklo_epi64( s0[2], s1[2] );
   d[17] = _mm_unpacklo_epi64( s2[2], s3[2] );
   d[18] = _mm_unpacklo_epi64( s4[2], s5[2] );
   d[19] = _mm_unpacklo_epi64( s6[2], s7[2] );
   d[20] = _mm_unpackhi_epi64( s0[2], s1[2] );
   d[21] = _mm_unpackhi_epi64( s2[2], s3[2] );
   d[22] = _mm_unpackhi_epi64( s4[2], s5[2] );
   d[23] = _mm_unpackhi_epi64( s6[2], s7[2] );

   d[24] = _mm_unpacklo_epi64( s0[3], s1[3] );
   d[25] = _mm_unpacklo_epi64( s2[3], s3[3] );
   d[26] = _mm_unpacklo_epi64( s4[3], s5[3] );
   d[27] = _mm_unpacklo_epi64( s6[3], s7[3] );
   d[28] = _mm_unpackhi_epi64( s0[3], s1[3] );
   d[29] = _mm_unpackhi_epi64( s2[3], s3[3] );
   d[30] = _mm_unpackhi_epi64( s4[3], s5[3] );
   d[31] = _mm_unpackhi_epi64( s6[3], s7[3] );
}


static inline void dintrlv_8x64( void *dst0, void *dst1, void *dst2,
         void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
         const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   __m128i *d4 = (__m128i*)dst4;
   __m128i *d5 = (__m128i*)dst5;
   __m128i *d6 = (__m128i*)dst6;
   __m128i *d7 = (__m128i*)dst7;
   const __m128i* s = (const __m128i*)src;

   d0[0] = _mm_unpacklo_epi64( s[ 0], s[ 4] );
   d1[0] = _mm_unpackhi_epi64( s[ 0], s[ 4] );
   d2[0] = _mm_unpacklo_epi64( s[ 1], s[ 5] );
   d3[0] = _mm_unpackhi_epi64( s[ 1], s[ 5] );
   d4[0] = _mm_unpacklo_epi64( s[ 2], s[ 6] );
   d5[0] = _mm_unpackhi_epi64( s[ 2], s[ 6] );
   d6[0] = _mm_unpacklo_epi64( s[ 3], s[ 7] );
   d7[0] = _mm_unpackhi_epi64( s[ 3], s[ 7] );

   d0[1] = _mm_unpacklo_epi64( s[ 8], s[12] );
   d1[1] = _mm_unpackhi_epi64( s[ 8], s[12] );
   d2[1] = _mm_unpacklo_epi64( s[ 9], s[13] );
   d3[1] = _mm_unpackhi_epi64( s[ 9], s[13] );
   d4[1] = _mm_unpacklo_epi64( s[10], s[14] );
   d5[1] = _mm_unpackhi_epi64( s[10], s[14] );
   d6[1] = _mm_unpacklo_epi64( s[11], s[15] );
   d7[1] = _mm_unpackhi_epi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[2] = _mm_unpacklo_epi64( s[16], s[20] );
   d1[2] = _mm_unpackhi_epi64( s[16], s[20] );
   d2[2] = _mm_unpacklo_epi64( s[17], s[21] );
   d3[2] = _mm_unpackhi_epi64( s[17], s[21] );
   d4[2] = _mm_unpacklo_epi64( s[18], s[22] );
   d5[2] = _mm_unpackhi_epi64( s[18], s[22] );
   d6[2] = _mm_unpacklo_epi64( s[19], s[23] );
   d7[2] = _mm_unpackhi_epi64( s[19], s[23] );

   d0[3] = _mm_unpacklo_epi64( s[24], s[28] );
   d1[3] = _mm_unpackhi_epi64( s[24], s[28] );
   d2[3] = _mm_unpacklo_epi64( s[25], s[29] );
   d3[3] = _mm_unpackhi_epi64( s[25], s[29] );
   d4[3] = _mm_unpacklo_epi64( s[26], s[30] );
   d5[3] = _mm_unpackhi_epi64( s[26], s[30] );
   d6[3] = _mm_unpacklo_epi64( s[27], s[31] );
   d7[3] = _mm_unpackhi_epi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[4] = _mm_unpacklo_epi64( s[32], s[36] );
   d1[4] = _mm_unpackhi_epi64( s[32], s[36] );
   d2[4] = _mm_unpacklo_epi64( s[33], s[37] );
   d3[4] = _mm_unpackhi_epi64( s[33], s[37] );
   d4[4] = _mm_unpacklo_epi64( s[34], s[38] );
   d5[4] = _mm_unpackhi_epi64( s[34], s[38] );
   d6[4] = _mm_unpacklo_epi64( s[35], s[39] );
   d7[4] = _mm_unpackhi_epi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[5] = _mm_unpacklo_epi64( s[40], s[44] );
   d1[5] = _mm_unpackhi_epi64( s[40], s[44] );
   d2[5] = _mm_unpacklo_epi64( s[41], s[45] );
   d3[5] = _mm_unpackhi_epi64( s[41], s[45] );
   d4[5] = _mm_unpacklo_epi64( s[42], s[46] );
   d5[5] = _mm_unpackhi_epi64( s[42], s[46] );
   d6[5] = _mm_unpacklo_epi64( s[43], s[47] );
   d7[5] = _mm_unpackhi_epi64( s[43], s[47] );

   d0[6] = _mm_unpacklo_epi64( s[48], s[52] );
   d1[6] = _mm_unpackhi_epi64( s[48], s[52] );
   d2[6] = _mm_unpacklo_epi64( s[49], s[53] );
   d3[6] = _mm_unpackhi_epi64( s[49], s[53] );
   d4[6] = _mm_unpacklo_epi64( s[50], s[54] );
   d5[6] = _mm_unpackhi_epi64( s[50], s[54] );
   d6[6] = _mm_unpacklo_epi64( s[51], s[55] );
   d7[6] = _mm_unpackhi_epi64( s[51], s[55] );

   d0[7] = _mm_unpacklo_epi64( s[56], s[60] );
   d1[7] = _mm_unpackhi_epi64( s[56], s[60] );
   d2[7] = _mm_unpacklo_epi64( s[57], s[61] );
   d3[7] = _mm_unpackhi_epi64( s[57], s[61] );
   d4[7] = _mm_unpacklo_epi64( s[58], s[62] );
   d5[7] = _mm_unpackhi_epi64( s[58], s[62] );
   d6[7] = _mm_unpacklo_epi64( s[59], s[63] );
   d7[7] = _mm_unpackhi_epi64( s[59], s[63] );
}

static inline void dintrlv_8x64_512( void *dst0, void *dst1, void *dst2,
         void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
         const void *src )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   __m128i *d4 = (__m128i*)dst4;
   __m128i *d5 = (__m128i*)dst5;
   __m128i *d6 = (__m128i*)dst6;
   __m128i *d7 = (__m128i*)dst7;
   const __m128i* s = (const __m128i*)src;

   d0[0] = _mm_unpacklo_epi64( s[ 0], s[ 4] );
   d1[0] = _mm_unpackhi_epi64( s[ 0], s[ 4] );
   d2[0] = _mm_unpacklo_epi64( s[ 1], s[ 5] );
   d3[0] = _mm_unpackhi_epi64( s[ 1], s[ 5] );
   d4[0] = _mm_unpacklo_epi64( s[ 2], s[ 6] );
   d5[0] = _mm_unpackhi_epi64( s[ 2], s[ 6] );
   d6[0] = _mm_unpacklo_epi64( s[ 3], s[ 7] );
   d7[0] = _mm_unpackhi_epi64( s[ 3], s[ 7] );

   d0[1] = _mm_unpacklo_epi64( s[ 8], s[12] );
   d1[1] = _mm_unpackhi_epi64( s[ 8], s[12] );
   d2[1] = _mm_unpacklo_epi64( s[ 9], s[13] );
   d3[1] = _mm_unpackhi_epi64( s[ 9], s[13] );
   d4[1] = _mm_unpacklo_epi64( s[10], s[14] );
   d5[1] = _mm_unpackhi_epi64( s[10], s[14] );
   d6[1] = _mm_unpacklo_epi64( s[11], s[15] );
   d7[1] = _mm_unpackhi_epi64( s[11], s[15] );

   d0[2] = _mm_unpacklo_epi64( s[16], s[20] );
   d1[2] = _mm_unpackhi_epi64( s[16], s[20] );
   d2[2] = _mm_unpacklo_epi64( s[17], s[21] );
   d3[2] = _mm_unpackhi_epi64( s[17], s[21] );
   d4[2] = _mm_unpacklo_epi64( s[18], s[22] );
   d5[2] = _mm_unpackhi_epi64( s[18], s[22] );
   d6[2] = _mm_unpacklo_epi64( s[19], s[23] );
   d7[2] = _mm_unpackhi_epi64( s[19], s[23] );

   d0[3] = _mm_unpacklo_epi64( s[24], s[28] );
   d1[3] = _mm_unpackhi_epi64( s[24], s[28] );
   d2[3] = _mm_unpacklo_epi64( s[25], s[29] );
   d3[3] = _mm_unpackhi_epi64( s[25], s[29] );
   d4[3] = _mm_unpacklo_epi64( s[26], s[30] );
   d5[3] = _mm_unpackhi_epi64( s[26], s[30] );
   d6[3] = _mm_unpacklo_epi64( s[27], s[31] );
   d7[3] = _mm_unpackhi_epi64( s[27], s[31] );
}

static inline void extr_lane_8x64( void *d, const void *s,
                                   const int lane, const int bit_len )
{
   ((uint64_t*)d)[ 0] = ((const uint64_t*)s)[ lane     ];
   ((uint64_t*)d)[ 1] = ((const uint64_t*)s)[ lane+  8 ];
   ((uint64_t*)d)[ 2] = ((const uint64_t*)s)[ lane+ 16 ];
   ((uint64_t*)d)[ 3] = ((const uint64_t*)s)[ lane+ 24 ];
   if ( bit_len <= 256 ) return;
   ((uint64_t*)d)[ 4] = ((const uint64_t*)s)[ lane+ 32 ];
   ((uint64_t*)d)[ 5] = ((const uint64_t*)s)[ lane+ 40 ];
   ((uint64_t*)d)[ 6] = ((const uint64_t*)s)[ lane+ 48 ];
   ((uint64_t*)d)[ 7] = ((const uint64_t*)s)[ lane+ 56 ];
}

#if defined(__AVX512F__) && defined(__AVX512VL__)

static inline void mm512_bswap32_intrlv80_8x64( void *d, const void *src )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m128i( d,  0 ) =
  casti_m128i( d,  1 ) =
  casti_m128i( d,  2 ) =
  casti_m128i( d,  3 ) = _mm_shuffle_epi32( s0, 0x44 );
  casti_m128i( d,  4 ) =
  casti_m128i( d,  5 ) =
  casti_m128i( d,  6 ) =
  casti_m128i( d,  7 ) = _mm_shuffle_epi32( s0, 0xee );

  casti_m128i( d,  8 ) =
  casti_m128i( d,  9 ) =
  casti_m128i( d, 10 ) =
  casti_m128i( d, 11 ) = _mm_shuffle_epi32( s1, 0x44 );
  casti_m128i( d, 12 ) =
  casti_m128i( d, 13 ) =
  casti_m128i( d, 14 ) =
  casti_m128i( d, 15 ) = _mm_shuffle_epi32( s1, 0xee );

  casti_m128i( d, 16 ) =
  casti_m128i( d, 17 ) =
  casti_m128i( d, 18 ) =
  casti_m128i( d, 19 ) = _mm_shuffle_epi32( s2, 0x44 );
  casti_m128i( d, 20 ) =
  casti_m128i( d, 21 ) =
  casti_m128i( d, 22 ) =
  casti_m128i( d, 23 ) = _mm_shuffle_epi32( s2, 0xee );

  casti_m128i( d, 24 ) =
  casti_m128i( d, 25 ) =
  casti_m128i( d, 26 ) =
  casti_m128i( d, 27 ) = _mm_shuffle_epi32( s3, 0x44 );
  casti_m128i( d, 28 ) =
  casti_m128i( d, 29 ) =
  casti_m128i( d, 30 ) =
  casti_m128i( d, 31 ) = _mm_shuffle_epi32( s3, 0xee );

  casti_m128i( d, 32 ) =
  casti_m128i( d, 33 ) =
  casti_m128i( d, 34 ) =
  casti_m128i( d, 35 ) = _mm_shuffle_epi32( s4, 0x44 );
  casti_m128i( d, 36 ) =
  casti_m128i( d, 37 ) =
  casti_m128i( d, 38 ) =
  casti_m128i( d, 39 ) = _mm_shuffle_epi32( s4, 0xee );
}

#endif  // AVX512

//////////////////////////
//
//      128 bit data

// 2x128  (AVX2)

static inline void intrlv_2x128( void *dst, const void *src0,
                                 const void *src1, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   d[ 0] = s0[0];   d[ 1] = s1[0];
   d[ 2] = s0[1];   d[ 3] = s1[1];
   if ( bit_len <= 256 ) return;
   d[ 4] = s0[2];   d[ 5] = s1[2];
   d[ 6] = s0[3];   d[ 7] = s1[3];
   if ( bit_len <= 512 ) return;
   d[ 8] = s0[4];   d[ 9] = s1[4];
   if ( bit_len <= 640 ) return;
   d[10] = s0[5];   d[11] = s1[5];
   d[12] = s0[6];   d[13] = s1[6];
   d[14] = s0[7];   d[15] = s1[7];
}

static inline void intrlv_2x128_512( void *dst, const void *src0,
                                     const void *src1 )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   d[0] = s0[0];   d[1] = s1[0];
   d[2] = s0[1];   d[3] = s1[1];
   d[4] = s0[2];   d[5] = s1[2];
   d[6] = s0[3];   d[7] = s1[3];
}

static inline void dintrlv_2x128( void *dst0, void *dst1,
                                  const void *src, int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   const __m128i *s = (const __m128i*)src;

   d0[0] = s[ 0];   d1[0] = s[ 1];
   d0[1] = s[ 2];   d1[1] = s[ 3];
   if ( bit_len <= 256 ) return;
   d0[2] = s[ 4];   d1[2] = s[ 5];
   d0[3] = s[ 6];   d1[3] = s[ 7];
   if ( bit_len <= 512 ) return;
   d0[4] = s[ 8];   d1[4] = s[ 9];
   if ( bit_len <= 640 ) return;
   d0[5] = s[10];   d1[5] = s[11];
   d0[6] = s[12];   d1[6] = s[13];
   d0[7] = s[14];   d1[7] = s[15];
}

static inline void dintrlv_2x128_512( void *dst0, void *dst1, const void *src )
{
   __m128i *d0 = (__m128i*)dst0;   
   __m128i *d1 = (__m128i*)dst1;
   const __m128i *s = (const __m128i*)src;

   d0[0] = s[0];   d1[0] = s[1];
   d0[1] = s[2];   d1[1] = s[3];
   d0[2] = s[4];   d1[2] = s[5];
   d0[3] = s[6];   d1[3] = s[7];
}

// 4x128  (AVX512)

static inline void intrlv_4x128( void *dst, const void *src0,
     const void *src1, const void *src2, const void *src3, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3;
   d[ 0] = s0[0];    d[ 1] = s1[0];    d[ 2] = s2[0];    d[ 3] = s3[0];
   d[ 4] = s0[1];    d[ 5] = s1[1];    d[ 6] = s2[1];    d[ 7] = s3[1];
   if ( bit_len <= 256 ) return;
   d[ 8] = s0[2];    d[ 9] = s1[2];    d[10] = s2[2];    d[11] = s3[2];
   d[12] = s0[3];    d[13] = s1[3];    d[14] = s2[3];    d[15] = s3[3];
   if ( bit_len <= 512 ) return;
   d[16] = s0[4];    d[17] = s1[4];    d[18] = s2[4];    d[19] = s3[4];
   if ( bit_len <= 640 ) return;
   d[20] = s0[5];    d[21] = s1[5];    d[22] = s2[5];    d[23] = s3[5];
   d[24] = s0[6];    d[25] = s1[6];    d[26] = s2[6];    d[27] = s3[6];
   d[28] = s0[7];    d[29] = s1[7];    d[30] = s2[7];    d[31] = s3[7];
}

static inline void intrlv_4x128_512( void *dst, const void *src0,
                      const void *src1, const void *src2, const void *src3 )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   const __m128i *s2 = (const __m128i*)src2;
   const __m128i *s3 = (const __m128i*)src3; 
   d[ 0] = s0[0];    d[ 1] = s1[0];    d[ 2] = s2[0];    d[ 3] = s3[0];
   d[ 4] = s0[1];    d[ 5] = s1[1];    d[ 6] = s2[1];    d[ 7] = s3[1];
   d[ 8] = s0[2];    d[ 9] = s1[2];    d[10] = s2[2];    d[11] = s3[2];
   d[12] = s0[3];    d[13] = s1[3];    d[14] = s2[3];    d[15] = s3[3];
}

static inline void dintrlv_4x128( void *dst0, void *dst1, void *dst2,
                             void *dst3, const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   const __m128i *s = (const __m128i*)src;
   d0[0] = s[ 0];   d1[0] = s[ 1];    d2[0] = s[ 2];   d3[0] = s[ 3];
   d0[1] = s[ 4];   d1[1] = s[ 5];    d2[1] = s[ 6];   d3[1] = s[ 7];
   if ( bit_len <= 256 ) return;
   d0[2] = s[ 8];   d1[2] = s[ 9];    d2[2] = s[10];   d3[2] = s[11];
   d0[3] = s[12];   d1[3] = s[13];    d2[3] = s[14];   d3[3] = s[15];
   if ( bit_len <= 512 ) return;
   d0[4] = s[16];   d1[4] = s[17];    d2[4] = s[18];   d3[4] = s[19];
   if ( bit_len <= 640 ) return;
   d0[5] = s[20];   d1[5] = s[21];    d2[5] = s[22];   d3[5] = s[23];
   d0[6] = s[24];   d1[6] = s[25];    d2[6] = s[26];   d3[6] = s[27];
   d0[7] = s[28];   d1[7] = s[29];    d2[7] = s[30];   d3[7] = s[31];
}

static inline void dintrlv_4x128_512( void *dst0, void *dst1, void *dst2,
                                      void *dst3, const void *src )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   const __m128i *s = (const __m128i*)src;
   d0[0] = s[ 0];   d1[0] = s[ 1];    d2[0] = s[ 2];   d3[0] = s[ 3];
   d0[1] = s[ 4];   d1[1] = s[ 5];    d2[1] = s[ 6];   d3[1] = s[ 7];
   d0[2] = s[ 8];   d1[2] = s[ 9];    d2[2] = s[10];   d3[2] = s[11];
   d0[3] = s[12];   d1[3] = s[13];    d2[3] = s[14];   d3[3] = s[15];
}


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

static inline void mm512_bswap32_intrlv80_4x128( void *d, void *src )
{
  __m128i bswap_shuf = m128_const_64( 0x0c0d0e0f08090a0b, 0x0405060700010203 );
  __m128i s0 = casti_m128i( src,0 );
  __m128i s1 = casti_m128i( src,1 );
  __m128i s2 = casti_m128i( src,2 );
  __m128i s3 = casti_m128i( src,3 );
  __m128i s4 = casti_m128i( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m512i( d, 0 ) = _mm512_broadcast_i64x2( s0 );
  casti_m512i( d, 1 ) = _mm512_broadcast_i64x2( s1 );
  casti_m512i( d, 2 ) = _mm512_broadcast_i64x2( s2 );
  casti_m512i( d, 3 ) = _mm512_broadcast_i64x2( s3 );
  casti_m512i( d, 4 ) = _mm512_broadcast_i64x2( s4 );
}  

#endif

// 2x256 (AVX512)

#if defined (__AVX__)

static inline void intrlv_2x256( void *dst, const void *src0,
                                 const void *src1, const int bit_len )
{
   __m256i *d = (__m256i*)dst;
   const __m256i *s0 = (const __m256i*)src0;
   const __m256i *s1 = (const __m256i*)src1;
   d[0] = s0[0];      d[1] = s1[0];
   if ( bit_len <= 256 ) return;
   d[2] = s0[1];      d[3] = s1[1];
   if ( bit_len <= 512 ) return;
   d[4] = s0[2];
   if ( bit_len <= 640 ) return;
                      d[5] = s1[2];
   d[6] = s0[3];      d[7] = s1[3];
}

// No 80 byte dintrlv
static inline void dintrlv_2x256( void *dst0, void *dst1,
                                  const void *src, int bit_len )
{
   __m256i *d0 = (__m256i*)dst0;
   __m256i *d1 = (__m256i*)dst1;
   const __m256i *s = (const __m256i*)src;

   d0[0] = s[0];      d1[0] = s[1];
   if ( bit_len <= 256 ) return;
   d0[1] = s[2];      d1[1] = s[3];
   if ( bit_len <= 512 ) return;
   d0[2] = s[4];      d1[2] = s[5];
   d0[3] = s[6];      d1[3] = s[7];
}

#endif // AVX

///////////////////////////
//
// Re-intereleaving

// 4x64 -> 4x32

#define RLEAVE_4x64_4x32( i ) do \
{ \
   uint32_t *d = (uint32_t*)dst + (i); \
   const uint32_t *s = (const uint32_t*)src + (i); \
   d[0] = s[0];   d[1] = s[2]; \
   d[2] = s[4];   d[3] = s[6]; \
   d[4] = s[1];   d[5] = s[3]; \
   d[6] = s[5];   d[7] = s[7]; \
} while(0)


// Convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
static inline void rintrlv_4x64_4x32( void *dst, const void *src,
                                            const int  bit_len )
{
   RLEAVE_4x64_4x32(   0 );   RLEAVE_4x64_4x32(   8 );
   RLEAVE_4x64_4x32(  16 );   RLEAVE_4x64_4x32(  24 );
   if ( bit_len <= 256 ) return;
   RLEAVE_4x64_4x32(  32 );   RLEAVE_4x64_4x32(  40 );
   RLEAVE_4x64_4x32(  48 );   RLEAVE_4x64_4x32(  56 );
   if ( bit_len <= 512 ) return;
   RLEAVE_4x64_4x32(  64 );   RLEAVE_4x64_4x32(  72 );
   if ( bit_len <= 640 ) return;
   RLEAVE_4x64_4x32(  80 );   RLEAVE_4x64_4x32(  88 );
   RLEAVE_4x64_4x32(  96 );   RLEAVE_4x64_4x32( 104 );
   RLEAVE_4x64_4x32( 112 );   RLEAVE_4x64_4x32( 120 );
}

#undef RLEAVE_4x64_4x32

#define RLEAVE_8x64_8x32( i ) do \
{ \
   uint32_t *d = (uint32_t*)dst + (i); \
   const uint32_t *s = (const uint32_t*)src + (i); \
   d[ 0] = s[ 0];  d[ 1] = s[ 2];  d[ 2] = s[ 4];  d[ 3] = s[ 6]; \
   d[ 4] = s[ 8];  d[ 5] = s[10];  d[ 6] = s[12];  d[ 7] = s[14]; \
   d[ 8] = s[ 1];  d[ 9] = s[ 3];  d[10] = s[ 5];  d[11] = s[ 7]; \
   d[12] = s[ 9];  d[13] = s[11];  d[14] = s[13];  d[15] = s[15]; \
} while(0)


// 8x64 -> 8x32

static inline void rintrlv_8x64_8x32( void *dst, const void *src,
                                      const int  bit_len )
{
   RLEAVE_8x64_8x32(   0 );   RLEAVE_8x64_8x32(  16 );
   RLEAVE_8x64_8x32(  32 );   RLEAVE_8x64_8x32(  48 );

   if ( bit_len <= 256 ) return;

   RLEAVE_8x64_8x32(  64 );   RLEAVE_8x64_8x32(  80 );
   RLEAVE_8x64_8x32(  96 );   RLEAVE_8x64_8x32( 112 );

   if ( bit_len <= 512 ) return;
   
   RLEAVE_8x64_8x32( 128 );   RLEAVE_8x64_8x32( 144 );

   if ( bit_len <= 640 ) return;

   RLEAVE_8x64_8x32( 160 );   RLEAVE_8x64_8x32( 176 );
   RLEAVE_8x64_8x32( 192 );   RLEAVE_8x64_8x32( 208 );
   RLEAVE_8x64_8x32( 224 );   RLEAVE_8x64_8x32( 240 );
}

#undef RLEAVE_8x64_8x32

// 4x32 -> 4x64

static inline void rintrlv_4x32_4x64( void *dst,
                                      const void *src, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s = (const __m128i*)src;
   d[ 0] = _mm_unpacklo_epi32( s[ 0], s[ 1] );
   d[ 1] = _mm_unpackhi_epi32( s[ 0], s[ 1] );
   d[ 2] = _mm_unpacklo_epi32( s[ 2], s[ 3] );
   d[ 3] = _mm_unpackhi_epi32( s[ 2], s[ 3] );
   d[ 4] = _mm_unpacklo_epi32( s[ 4], s[ 5] );
   d[ 5] = _mm_unpackhi_epi32( s[ 4], s[ 5] );
   d[ 6] = _mm_unpacklo_epi32( s[ 6], s[ 7] );
   d[ 7] = _mm_unpackhi_epi32( s[ 6], s[ 7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = _mm_unpacklo_epi32( s[ 8], s[ 9] );
   d[ 9] = _mm_unpackhi_epi32( s[ 8], s[ 9] );
   d[10] = _mm_unpacklo_epi32( s[10], s[11] );
   d[11] = _mm_unpackhi_epi32( s[10], s[11] );
   d[12] = _mm_unpacklo_epi32( s[12], s[13] );
   d[13] = _mm_unpackhi_epi32( s[12], s[13] );
   d[14] = _mm_unpacklo_epi32( s[14], s[15] );
   d[15] = _mm_unpackhi_epi32( s[14], s[15] );

   if ( bit_len <= 512 ) return;

   d[16] = _mm_unpacklo_epi32( s[16], s[17] );
   d[17] = _mm_unpackhi_epi32( s[16], s[17] );
   d[18] = _mm_unpacklo_epi32( s[18], s[19] );
   d[19] = _mm_unpackhi_epi32( s[18], s[19] );

   if ( bit_len <= 640 ) return;

   d[20] = _mm_unpacklo_epi32( s[20], s[21] );
   d[21] = _mm_unpackhi_epi32( s[20], s[21] );
   d[22] = _mm_unpacklo_epi32( s[22], s[23] );
   d[23] = _mm_unpackhi_epi32( s[22], s[23] );

   d[24] = _mm_unpacklo_epi32( s[24], s[25] );
   d[25] = _mm_unpackhi_epi32( s[24], s[25] );
   d[26] = _mm_unpacklo_epi32( s[26], s[27] );
   d[27] = _mm_unpackhi_epi32( s[26], s[27] );
   d[28] = _mm_unpacklo_epi32( s[28], s[29] );
   d[29] = _mm_unpackhi_epi32( s[28], s[29] );
   d[30] = _mm_unpacklo_epi32( s[30], s[31] );
   d[31] = _mm_unpackhi_epi32( s[30], s[31] );
}

// 8x32 -> 8x64

static inline void rintrlv_8x32_8x64( void *dst,
                                      const void *src, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s = (const __m128i*)src;

   d[ 0] = _mm_unpacklo_epi32( s[ 0], s[ 2] );
   d[ 1] = _mm_unpackhi_epi32( s[ 0], s[ 2] );
   d[ 2] = _mm_unpacklo_epi32( s[ 1], s[ 3] );
   d[ 3] = _mm_unpackhi_epi32( s[ 1], s[ 3] );
   d[ 4] = _mm_unpacklo_epi32( s[ 4], s[ 6] );
   d[ 5] = _mm_unpackhi_epi32( s[ 4], s[ 6] );
   d[ 6] = _mm_unpacklo_epi32( s[ 5], s[ 7] );
   d[ 7] = _mm_unpackhi_epi32( s[ 5], s[ 7] );

   d[ 8] = _mm_unpacklo_epi32( s[ 8], s[10] );
   d[ 9] = _mm_unpackhi_epi32( s[ 8], s[10] );
   d[10] = _mm_unpacklo_epi32( s[ 9], s[11] );
   d[11] = _mm_unpackhi_epi32( s[ 9], s[11] );
   d[12] = _mm_unpacklo_epi32( s[12], s[14] );
   d[13] = _mm_unpackhi_epi32( s[12], s[14] );
   d[14] = _mm_unpacklo_epi32( s[13], s[15] );
   d[15] = _mm_unpackhi_epi32( s[13], s[15] );

   if ( bit_len <= 256 ) return;

   d[16] = _mm_unpacklo_epi32( s[16], s[18] );
   d[17] = _mm_unpackhi_epi32( s[16], s[18] );
   d[18] = _mm_unpacklo_epi32( s[17], s[19] );
   d[19] = _mm_unpackhi_epi32( s[17], s[19] );
   d[20] = _mm_unpacklo_epi32( s[20], s[22] );
   d[21] = _mm_unpackhi_epi32( s[20], s[22] );
   d[22] = _mm_unpacklo_epi32( s[21], s[23] );
   d[23] = _mm_unpackhi_epi32( s[21], s[23] );

   d[24] = _mm_unpacklo_epi32( s[24], s[26] );
   d[25] = _mm_unpackhi_epi32( s[24], s[26] );
   d[26] = _mm_unpacklo_epi32( s[25], s[27] );
   d[27] = _mm_unpackhi_epi32( s[25], s[27] );
   d[28] = _mm_unpacklo_epi32( s[28], s[30] );
   d[29] = _mm_unpackhi_epi32( s[28], s[30] );
   d[30] = _mm_unpacklo_epi32( s[29], s[31] );
   d[31] = _mm_unpackhi_epi32( s[29], s[31] );

   if ( bit_len <= 512 ) return;

   d[32] = _mm_unpacklo_epi32( s[32], s[34] );
   d[33] = _mm_unpackhi_epi32( s[32], s[34] );
   d[34] = _mm_unpacklo_epi32( s[33], s[35] );
   d[35] = _mm_unpackhi_epi32( s[33], s[35] );
   d[36] = _mm_unpacklo_epi32( s[36], s[38] );
   d[37] = _mm_unpackhi_epi32( s[36], s[38] );
   d[38] = _mm_unpacklo_epi32( s[37], s[39] );
   d[39] = _mm_unpackhi_epi32( s[37], s[39] );

   if ( bit_len <= 640 ) return;
   
   d[40] = _mm_unpacklo_epi32( s[40], s[42] );
   d[41] = _mm_unpackhi_epi32( s[40], s[42] );
   d[42] = _mm_unpacklo_epi32( s[41], s[43] );
   d[43] = _mm_unpackhi_epi32( s[41], s[43] );
   d[44] = _mm_unpacklo_epi32( s[44], s[46] );
   d[45] = _mm_unpackhi_epi32( s[44], s[46] );
   d[46] = _mm_unpacklo_epi32( s[45], s[47] );
   d[47] = _mm_unpackhi_epi32( s[45], s[47] );

   d[48] = _mm_unpacklo_epi32( s[48], s[50] );
   d[49] = _mm_unpackhi_epi32( s[48], s[50] );
   d[50] = _mm_unpacklo_epi32( s[49], s[51] );
   d[51] = _mm_unpackhi_epi32( s[49], s[51] );
   d[52] = _mm_unpacklo_epi32( s[52], s[54] );
   d[53] = _mm_unpackhi_epi32( s[52], s[54] );
   d[54] = _mm_unpacklo_epi32( s[53], s[55] );
   d[55] = _mm_unpackhi_epi32( s[53], s[55] );

   d[56] = _mm_unpacklo_epi32( s[56], s[58] );
   d[57] = _mm_unpackhi_epi32( s[56], s[58] );
   d[58] = _mm_unpacklo_epi32( s[57], s[59] );
   d[59] = _mm_unpackhi_epi32( s[57], s[59] );
   d[60] = _mm_unpacklo_epi32( s[60], s[62] );
   d[61] = _mm_unpackhi_epi32( s[60], s[62] );
   d[62] = _mm_unpacklo_epi32( s[61], s[63] );
   d[63] = _mm_unpackhi_epi32( s[61], s[63] );
}

// 8x32 -> 4x128

// 16 bytes per lane
#define RLEAVE_8X32_4X128( i ) \
do { \
    uint32_t *d0 = (uint32_t*)dst0 + (i); \
    uint32_t *d1 = (uint32_t*)dst1 + (i); \
    const uint32_t *s  = (const uint32_t*)src + ((i)<<1); \
   d0[ 0] = s[ 0];      d1[ 0] = s[ 4]; \
   d0[ 1] = s[ 8];      d1[ 1] = s[12]; \
   d0[ 2] = s[16];      d1[ 2] = s[20]; \
   d0[ 3] = s[24];      d1[ 3] = s[28]; \
\
   d0[ 4] = s[ 1];      d1[ 4] = s[ 5]; \
   d0[ 5] = s[ 9];      d1[ 5] = s[13]; \
   d0[ 6] = s[17];      d1[ 6] = s[21]; \
   d0[ 7] = s[25];      d1[ 7] = s[29]; \
\
   d0[ 8] = s[ 2];      d1[ 8] = s[ 6]; \
   d0[ 9] = s[10];      d1[ 9] = s[14]; \
   d0[10] = s[18];      d1[10] = s[22]; \
   d0[11] = s[26];      d1[11] = s[30]; \
\
   d0[12] = s[ 3];      d1[12] = s[ 7]; \
   d0[13] = s[11];      d1[13] = s[15]; \
   d0[14] = s[19];      d1[14] = s[23]; \
   d0[15] = s[27];      d1[15] = s[31]; \
} while(0)  

static inline void rintrlv_8x32_4x128( void *dst0, void *dst1,
                                    const void *src, const int bit_len )
{
   RLEAVE_8X32_4X128(   0 );    RLEAVE_8X32_4X128(  16 );
   if ( bit_len <= 256 ) return;
   RLEAVE_8X32_4X128(  32 );    RLEAVE_8X32_4X128(  48 );
   if ( bit_len <= 512 ) return;
   RLEAVE_8X32_4X128(  64 );
   if ( bit_len <= 640 ) return;
   RLEAVE_8X32_4X128(  80 );
   RLEAVE_8X32_4X128(  96 );    RLEAVE_8X32_4X128( 112 );
}
#undef RLEAVE_8X32_4X128

/*
#define RLEAVE_4x32_4x64(i) do \
{ \
 uint32_t *d = (uint32_t*)dst + (i); \
 const uint32_t *s = (const uint32_t*)src + (i); \
 d[0] = s[0];  d[1] = s[4]; \
 d[2] = s[1];  d[3] = s[5]; \
 d[4] = s[2];  d[5] = s[6]; \
 d[6] = s[3];  d[7] = s[7]; \
} while(0)

static inline void rintrlv_4x32_4x64( void *dst,
                                      const void *src, int  bit_len )
{
  RLEAVE_4x32_4x64(   0 );  RLEAVE_4x32_4x64(   8 );
  RLEAVE_4x32_4x64(  16 );  RLEAVE_4x32_4x64(  24 );
  if ( bit_len <= 256 ) return;
  RLEAVE_4x32_4x64(  32 );  RLEAVE_4x32_4x64(  40 );
  RLEAVE_4x32_4x64(  48 );  RLEAVE_4x32_4x64(  56 );
  if ( bit_len <= 512 ) return;
  RLEAVE_4x32_4x64(  64 );  RLEAVE_4x32_4x64(  72 );
  RLEAVE_4x32_4x64(  80 );  RLEAVE_4x32_4x64(  88 );
  RLEAVE_4x32_4x64(  96 );  RLEAVE_4x32_4x64( 104 );
  RLEAVE_4x32_4x64( 112 );  RLEAVE_4x32_4x64( 120 );
}

#undef RLEAVE_4x32_4x64
*/

// 2x128 -> 4x64

static inline void rintrlv_2x128_4x64( void *dst, const void *src0,
                                       const void *src1, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;
   d[ 0] = _mm_unpacklo_epi64( s0[ 0], s0[ 1] );
   d[ 1] = _mm_unpacklo_epi64( s1[ 0], s1[ 1] );
   d[ 2] = _mm_unpackhi_epi64( s0[ 0], s0[ 1] );
   d[ 3] = _mm_unpackhi_epi64( s1[ 0], s1[ 1] );
   d[ 4] = _mm_unpacklo_epi64( s0[ 2], s0[ 3] );
   d[ 5] = _mm_unpacklo_epi64( s1[ 2], s1[ 3] );
   d[ 6] = _mm_unpackhi_epi64( s0[ 2], s0[ 3] );
   d[ 7] = _mm_unpackhi_epi64( s1[ 2], s1[ 3] );
   if ( bit_len <= 256 ) return;
   d[ 8] = _mm_unpacklo_epi64( s0[ 4], s0[ 5] );
   d[ 9] = _mm_unpacklo_epi64( s1[ 4], s1[ 5] );
   d[10] = _mm_unpackhi_epi64( s0[ 4], s0[ 5] );
   d[11] = _mm_unpackhi_epi64( s1[ 4], s1[ 5] );
   d[12] = _mm_unpacklo_epi64( s0[ 6], s0[ 7] );
   d[13] = _mm_unpacklo_epi64( s1[ 6], s1[ 7] );
   d[14] = _mm_unpackhi_epi64( s0[ 6], s0[ 7] );
   d[15] = _mm_unpackhi_epi64( s1[ 6], s1[ 7] );
   if ( bit_len <= 512 ) return;
   d[16] = _mm_unpacklo_epi64( s0[ 8], s0[ 9] );
   d[17] = _mm_unpacklo_epi64( s1[ 8], s1[ 9] );
   d[18] = _mm_unpackhi_epi64( s0[ 8], s0[ 9] );
   d[19] = _mm_unpackhi_epi64( s1[ 8], s1[ 9] );
   if ( bit_len <= 640 ) return;
   d[20] = _mm_unpacklo_epi64( s0[10], s0[11] );
   d[21] = _mm_unpacklo_epi64( s1[10], s1[11] );
   d[22] = _mm_unpackhi_epi64( s0[10], s0[11] );
   d[23] = _mm_unpackhi_epi64( s1[10], s1[11] );
   d[24] = _mm_unpacklo_epi64( s0[12], s0[13] );
   d[25] = _mm_unpacklo_epi64( s1[12], s1[13] );
   d[26] = _mm_unpackhi_epi64( s0[12], s0[13] );
   d[27] = _mm_unpackhi_epi64( s1[12], s1[13] );
   d[28] = _mm_unpacklo_epi64( s0[14], s0[15] );
   d[29] = _mm_unpacklo_epi64( s1[14], s1[15] );
   d[30] = _mm_unpackhi_epi64( s0[14], s0[15] );
   d[31] = _mm_unpackhi_epi64( s1[14], s1[15] );
}

/*
#define RLEAVE_2x128_4x64( i ) do \
{ \
   uint64_t *d = (uint64_t*)dst + ((i)<<1); \
   const uint64_t *s0 = (const uint64_t*)src0 + (i); \
   const uint64_t *s1 = (const uint64_t*)src1 + (i); \
   d[0] = s0[0];    d[1] = s0[2]; \
   d[2] = s1[0];    d[3] = s1[2]; \
   d[4] = s0[1];    d[5] = s0[3]; \
   d[6] = s1[1];    d[7] = s1[3]; \
} while(0)

static inline void rintrlv_2x128_4x64( void *dst, const void *src0,
                                         const void *src1, int  bit_len )
{
   RLEAVE_2x128_4x64(  0 );   RLEAVE_2x128_4x64(  4 );
   if ( bit_len <= 256 ) return;
   RLEAVE_2x128_4x64(  8 );   RLEAVE_2x128_4x64( 12 );
   if ( bit_len <= 512 ) return;
   RLEAVE_2x128_4x64( 16 );   RLEAVE_2x128_4x64( 20 );
   RLEAVE_2x128_4x64( 24 );   RLEAVE_2x128_4x64( 28 );
}

#undef RLEAVE_2x128_4x64
*/

// 4x64 -> 2x128

static inline void rintrlv_4x64_2x128( void *dst0, void *dst1,
                                       const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   const __m128i* s = (const __m128i*)src;
   d0[ 0] = _mm_unpacklo_epi64( s[ 0], s[ 2] );
   d0[ 1] = _mm_unpackhi_epi64( s[ 0], s[ 2] );
   d1[ 0] = _mm_unpacklo_epi64( s[ 1], s[ 3] );
   d1[ 1] = _mm_unpackhi_epi64( s[ 1], s[ 3] );
   d0[ 2] = _mm_unpacklo_epi64( s[ 4], s[ 6] );
   d0[ 3] = _mm_unpackhi_epi64( s[ 4], s[ 6] );
   d1[ 2] = _mm_unpacklo_epi64( s[ 5], s[ 7] );
   d1[ 3] = _mm_unpackhi_epi64( s[ 5], s[ 7] );
   if ( bit_len <= 256 ) return;
   d0[ 4] = _mm_unpacklo_epi64( s[ 8], s[10] );
   d0[ 5] = _mm_unpackhi_epi64( s[ 8], s[10] );
   d1[ 4] = _mm_unpacklo_epi64( s[ 9], s[11] );
   d1[ 5] = _mm_unpackhi_epi64( s[ 9], s[11] );
   d0[ 6] = _mm_unpacklo_epi64( s[12], s[14] );
   d0[ 7] = _mm_unpackhi_epi64( s[12], s[14] );
   d1[ 6] = _mm_unpacklo_epi64( s[13], s[15] );
   d1[ 7] = _mm_unpackhi_epi64( s[13], s[15] );
   if ( bit_len <= 512 ) return;
   d0[ 8] = _mm_unpacklo_epi64( s[16], s[18] );
   d0[ 9] = _mm_unpackhi_epi64( s[16], s[18] );
   d1[ 8] = _mm_unpacklo_epi64( s[17], s[19] );
   d1[ 9] = _mm_unpackhi_epi64( s[17], s[19] );
   if ( bit_len <= 640 ) return;
   d0[10] = _mm_unpacklo_epi64( s[20], s[22] );
   d0[11] = _mm_unpackhi_epi64( s[20], s[22] );
   d1[10] = _mm_unpacklo_epi64( s[21], s[23] );
   d1[11] = _mm_unpackhi_epi64( s[21], s[23] );
   d0[12] = _mm_unpacklo_epi64( s[24], s[26] );
   d0[13] = _mm_unpackhi_epi64( s[24], s[26] );
   d1[12] = _mm_unpacklo_epi64( s[25], s[27] );
   d1[13] = _mm_unpackhi_epi64( s[25], s[27] );
   d0[14] = _mm_unpacklo_epi64( s[28], s[30] );
   d0[15] = _mm_unpackhi_epi64( s[28], s[30] );
   d1[14] = _mm_unpacklo_epi64( s[29], s[31] );
   d1[15] = _mm_unpackhi_epi64( s[29], s[31] );
}

/*
#define RLEAVE_4x64_2x128( i ) do \
{ \
   uint64_t *d0 = (uint64_t*)dst0 + (i); \
   uint64_t *d1 = (uint64_t*)dst1 + (i); \
   const uint64_t *s = (const uint64_t*)src + ((i)<<1); \
   d0[0] = s[0];   d0[1] = s[4]; \
   d0[2] = s[1];   d0[3] = s[5]; \
   d1[0] = s[2];   d1[1] = s[6]; \
   d1[2] = s[3];   d1[3] = s[7]; \
} while(0)

static inline void rintrlv_4x64_2x128( void *dst0, void *dst1,
                                       const void *src, int bit_len )
{
   RLEAVE_4x64_2x128(  0 );   RLEAVE_4x64_2x128(  4 );
   if ( bit_len <= 256 ) return;
   RLEAVE_4x64_2x128(  8 );   RLEAVE_4x64_2x128( 12 );
   if ( bit_len <= 512 ) return;
   RLEAVE_4x64_2x128( 16 );   RLEAVE_4x64_2x128( 20 );
   RLEAVE_4x64_2x128( 24 );   RLEAVE_4x64_2x128( 28 );
}
*/

// 2x128 -> 8x64

static inline void rintrlv_4x128_8x64( void *dst, const void *src0,
                                       const void *src1, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   const __m128i *s0 = (const __m128i*)src0;
   const __m128i *s1 = (const __m128i*)src1;

   d[ 0] = _mm_unpacklo_epi64( s0[ 0], s0[ 1] );
   d[ 1] = _mm_unpacklo_epi64( s0[ 2], s0[ 3] );
   d[ 2] = _mm_unpacklo_epi64( s1[ 0], s1[ 1] );
   d[ 3] = _mm_unpacklo_epi64( s1[ 2], s1[ 3] );
   d[ 4] = _mm_unpackhi_epi64( s0[ 0], s0[ 1] );
   d[ 5] = _mm_unpackhi_epi64( s0[ 2], s0[ 3] );
   d[ 6] = _mm_unpackhi_epi64( s1[ 0], s1[ 1] );
   d[ 7] = _mm_unpackhi_epi64( s1[ 2], s1[ 3] );

   d[ 8] = _mm_unpacklo_epi64( s0[ 4], s0[ 5] );
   d[ 9] = _mm_unpacklo_epi64( s0[ 6], s0[ 7] );
   d[10] = _mm_unpacklo_epi64( s1[ 4], s1[ 5] );
   d[11] = _mm_unpacklo_epi64( s1[ 6], s1[ 7] );
   d[12] = _mm_unpackhi_epi64( s0[ 4], s0[ 5] );
   d[13] = _mm_unpackhi_epi64( s0[ 6], s0[ 7] );
   d[14] = _mm_unpackhi_epi64( s1[ 4], s1[ 5] );
   d[15] = _mm_unpackhi_epi64( s1[ 6], s1[ 7] );

   if ( bit_len <= 256 ) return;

   d[16] = _mm_unpacklo_epi64( s0[ 8], s0[ 9] );
   d[17] = _mm_unpacklo_epi64( s0[10], s0[11] );
   d[18] = _mm_unpacklo_epi64( s1[ 8], s1[ 9] );
   d[19] = _mm_unpacklo_epi64( s1[10], s1[11] );
   d[20] = _mm_unpackhi_epi64( s0[ 8], s0[ 9] );
   d[21] = _mm_unpackhi_epi64( s0[10], s0[11] );
   d[22] = _mm_unpackhi_epi64( s1[ 8], s1[ 9] );
   d[23] = _mm_unpackhi_epi64( s1[10], s1[11] );

   d[24] = _mm_unpacklo_epi64( s0[12], s0[13] );
   d[25] = _mm_unpacklo_epi64( s0[14], s0[15] );
   d[26] = _mm_unpacklo_epi64( s1[12], s1[13] );
   d[27] = _mm_unpacklo_epi64( s1[14], s1[15] );
   d[28] = _mm_unpackhi_epi64( s0[12], s0[13] );
   d[29] = _mm_unpackhi_epi64( s0[14], s0[15] );
   d[30] = _mm_unpackhi_epi64( s1[12], s1[13] );
   d[31] = _mm_unpackhi_epi64( s1[14], s1[15] );

   if ( bit_len <= 512 ) return;

   d[32] = _mm_unpacklo_epi64( s0[16], s0[17] );
   d[33] = _mm_unpacklo_epi64( s0[18], s0[19] );
   d[34] = _mm_unpacklo_epi64( s1[16], s1[17] );
   d[35] = _mm_unpacklo_epi64( s1[18], s1[19] );
   d[36] = _mm_unpackhi_epi64( s0[16], s0[17] );
   d[37] = _mm_unpackhi_epi64( s0[18], s0[19] );
   d[38] = _mm_unpackhi_epi64( s1[16], s1[17] );
   d[39] = _mm_unpackhi_epi64( s1[18], s1[19] );

   if ( bit_len <= 640 ) return;
   
   d[40] = _mm_unpacklo_epi64( s0[20], s0[21] );
   d[41] = _mm_unpacklo_epi64( s0[22], s0[23] );
   d[42] = _mm_unpacklo_epi64( s1[20], s1[21] );
   d[43] = _mm_unpacklo_epi64( s1[22], s1[23] );
   d[44] = _mm_unpackhi_epi64( s0[20], s0[21] );
   d[45] = _mm_unpackhi_epi64( s0[22], s0[23] );
   d[46] = _mm_unpackhi_epi64( s1[20], s1[21] );
   d[47] = _mm_unpackhi_epi64( s1[22], s1[23] );

   d[48] = _mm_unpacklo_epi64( s0[24], s0[25] );
   d[49] = _mm_unpacklo_epi64( s0[26], s0[27] );
   d[50] = _mm_unpacklo_epi64( s1[24], s1[25] );
   d[51] = _mm_unpacklo_epi64( s1[26], s1[27] );
   d[52] = _mm_unpackhi_epi64( s0[24], s0[25] );
   d[53] = _mm_unpackhi_epi64( s0[26], s0[27] );
   d[54] = _mm_unpackhi_epi64( s1[24], s1[25] );
   d[55] = _mm_unpackhi_epi64( s1[26], s1[27] );

   d[56] = _mm_unpacklo_epi64( s0[28], s0[29] );
   d[57] = _mm_unpacklo_epi64( s0[30], s0[31] );
   d[58] = _mm_unpacklo_epi64( s1[28], s1[29] );
   d[59] = _mm_unpacklo_epi64( s1[30], s1[31] );
   d[60] = _mm_unpackhi_epi64( s0[28], s0[29] );
   d[61] = _mm_unpackhi_epi64( s0[30], s0[31] );
   d[62] = _mm_unpackhi_epi64( s1[28], s1[29] );
   d[63] = _mm_unpackhi_epi64( s1[30], s1[31] );
}

// 8x64 -> 4x128

static inline void rintrlv_8x64_4x128( void *dst0, void *dst1,
                                       const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   const __m128i* s = (const __m128i*)src;

   d0[ 0] = _mm_unpacklo_epi64( s[ 0], s[ 4] );
   d0[ 1] = _mm_unpackhi_epi64( s[ 0], s[ 4] );
   d1[ 0] = _mm_unpacklo_epi64( s[ 2], s[ 6] );
   d1[ 1] = _mm_unpackhi_epi64( s[ 2], s[ 6] );
   d0[ 2] = _mm_unpacklo_epi64( s[ 1], s[ 5] );
   d0[ 3] = _mm_unpackhi_epi64( s[ 1], s[ 5] );
   d1[ 2] = _mm_unpacklo_epi64( s[ 3], s[ 7] );
   d1[ 3] = _mm_unpackhi_epi64( s[ 3], s[ 7] );

   d0[ 4] = _mm_unpacklo_epi64( s[ 8], s[12] );
   d0[ 5] = _mm_unpackhi_epi64( s[ 8], s[12] );
   d1[ 4] = _mm_unpacklo_epi64( s[10], s[14] );
   d1[ 5] = _mm_unpackhi_epi64( s[10], s[14] );
   d0[ 6] = _mm_unpacklo_epi64( s[ 9], s[13] );
   d0[ 7] = _mm_unpackhi_epi64( s[ 9], s[13] );
   d1[ 6] = _mm_unpacklo_epi64( s[11], s[15] );
   d1[ 7] = _mm_unpackhi_epi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[ 8] = _mm_unpacklo_epi64( s[16], s[20] );
   d0[ 9] = _mm_unpackhi_epi64( s[16], s[20] );
   d1[ 8] = _mm_unpacklo_epi64( s[18], s[22] );
   d1[ 9] = _mm_unpackhi_epi64( s[18], s[22] );
   d0[10] = _mm_unpacklo_epi64( s[17], s[21] );
   d0[11] = _mm_unpackhi_epi64( s[17], s[21] );
   d1[10] = _mm_unpacklo_epi64( s[19], s[23] );
   d1[11] = _mm_unpackhi_epi64( s[19], s[23] );

   d0[12] = _mm_unpacklo_epi64( s[24], s[28] );
   d0[13] = _mm_unpackhi_epi64( s[24], s[28] );
   d1[12] = _mm_unpacklo_epi64( s[26], s[30] );
   d1[13] = _mm_unpackhi_epi64( s[26], s[30] );
   d0[14] = _mm_unpacklo_epi64( s[25], s[29] );
   d0[15] = _mm_unpackhi_epi64( s[25], s[29] );
   d1[14] = _mm_unpacklo_epi64( s[27], s[31] );
   d1[15] = _mm_unpackhi_epi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[16] = _mm_unpacklo_epi64( s[32], s[36] );
   d0[17] = _mm_unpackhi_epi64( s[32], s[36] );
   d1[16] = _mm_unpacklo_epi64( s[34], s[38] );
   d1[17] = _mm_unpackhi_epi64( s[34], s[38] );
   d0[18] = _mm_unpacklo_epi64( s[33], s[37] );
   d0[19] = _mm_unpackhi_epi64( s[33], s[37] );
   d1[18] = _mm_unpacklo_epi64( s[35], s[39] );
   d1[19] = _mm_unpackhi_epi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[20] = _mm_unpacklo_epi64( s[40], s[44] );
   d0[21] = _mm_unpackhi_epi64( s[40], s[44] );
   d1[20] = _mm_unpacklo_epi64( s[42], s[46] );
   d1[21] = _mm_unpackhi_epi64( s[42], s[46] );
   d0[22] = _mm_unpacklo_epi64( s[41], s[45] );
   d0[23] = _mm_unpackhi_epi64( s[41], s[45] );
   d1[22] = _mm_unpacklo_epi64( s[43], s[47] );
   d1[23] = _mm_unpackhi_epi64( s[43], s[47] );

   d0[24] = _mm_unpacklo_epi64( s[48], s[52] );
   d0[25] = _mm_unpackhi_epi64( s[48], s[52] );
   d1[24] = _mm_unpacklo_epi64( s[50], s[54] );
   d1[25] = _mm_unpackhi_epi64( s[50], s[54] );
   d0[26] = _mm_unpacklo_epi64( s[49], s[53] );
   d0[27] = _mm_unpackhi_epi64( s[49], s[53] );
   d1[26] = _mm_unpacklo_epi64( s[51], s[55] );
   d1[27] = _mm_unpackhi_epi64( s[51], s[55] );

   d0[28] = _mm_unpacklo_epi64( s[56], s[60] );
   d0[29] = _mm_unpackhi_epi64( s[56], s[60] );
   d1[28] = _mm_unpacklo_epi64( s[58], s[62] );
   d1[29] = _mm_unpackhi_epi64( s[58], s[62] );
   d0[30] = _mm_unpacklo_epi64( s[57], s[61] );
   d0[31] = _mm_unpackhi_epi64( s[57], s[61] );
   d1[30] = _mm_unpacklo_epi64( s[59], s[63] );
   d1[31] = _mm_unpackhi_epi64( s[59], s[63] );
}

// 8x64 -> 2x256

static inline void rintrlv_8x64_2x256( void *dst0, void *dst1, void *dst2,
                          void *dst3,  const void *src, const int bit_len )
{
   __m128i *d0 = (__m128i*)dst0;
   __m128i *d1 = (__m128i*)dst1;
   __m128i *d2 = (__m128i*)dst2;
   __m128i *d3 = (__m128i*)dst3;
   const __m128i* s = (const __m128i*)src;

   d0[ 0] = _mm_unpacklo_epi64( s[ 0], s[ 4] );
   d1[ 0] = _mm_unpackhi_epi64( s[ 0], s[ 4] );
   d2[ 0] = _mm_unpacklo_epi64( s[ 1], s[ 5] );   
   d3[ 0] = _mm_unpackhi_epi64( s[ 1], s[ 5] );
   d0[ 1] = _mm_unpacklo_epi64( s[ 2], s[ 6] ); 
   d1[ 1] = _mm_unpackhi_epi64( s[ 2], s[ 6] );
   d2[ 1] = _mm_unpacklo_epi64( s[ 3], s[ 7] ); 
   d3[ 1] = _mm_unpackhi_epi64( s[ 3], s[ 7] );
   
   d0[ 2] = _mm_unpacklo_epi64( s[ 8], s[12] ); 
   d1[ 2] = _mm_unpackhi_epi64( s[ 8], s[12] );
   d2[ 2] = _mm_unpacklo_epi64( s[ 9], s[13] ); 
   d3[ 2] = _mm_unpackhi_epi64( s[ 9], s[13] );
   d0[ 3] = _mm_unpacklo_epi64( s[10], s[14] );
   d1[ 3] = _mm_unpackhi_epi64( s[10], s[14] );
   d2[ 3] = _mm_unpacklo_epi64( s[11], s[15] );
   d3[ 3] = _mm_unpackhi_epi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[ 4] = _mm_unpacklo_epi64( s[16], s[20] );
   d1[ 4] = _mm_unpackhi_epi64( s[16], s[20] );
   d2[ 4] = _mm_unpacklo_epi64( s[17], s[21] );
   d3[ 4] = _mm_unpackhi_epi64( s[17], s[21] );
   d0[ 5] = _mm_unpacklo_epi64( s[18], s[22] );
   d1[ 5] = _mm_unpackhi_epi64( s[18], s[22] );
   d2[ 5] = _mm_unpacklo_epi64( s[19], s[23] );
   d3[ 5] = _mm_unpackhi_epi64( s[19], s[23] );
   
   d0[ 6] = _mm_unpacklo_epi64( s[24], s[28] );
   d1[ 6] = _mm_unpackhi_epi64( s[24], s[28] );
   d2[ 6] = _mm_unpacklo_epi64( s[25], s[29] );
   d3[ 6] = _mm_unpackhi_epi64( s[25], s[29] );
   d0[ 7] = _mm_unpacklo_epi64( s[26], s[30] );
   d1[ 7] = _mm_unpackhi_epi64( s[26], s[30] );
   d2[ 7] = _mm_unpacklo_epi64( s[27], s[31] );
   d3[ 7] = _mm_unpackhi_epi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[ 8] = _mm_unpacklo_epi64( s[32], s[36] );
   d1[ 8] = _mm_unpackhi_epi64( s[32], s[36] );
   d2[ 8] = _mm_unpacklo_epi64( s[33], s[37] );
   d3[ 8] = _mm_unpackhi_epi64( s[33], s[37] );
   d0[ 9] = _mm_unpacklo_epi64( s[34], s[38] );
   d1[ 9] = _mm_unpackhi_epi64( s[34], s[38] );
   d2[ 9] = _mm_unpacklo_epi64( s[35], s[39] );
   d3[ 9] = _mm_unpackhi_epi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[10] = _mm_unpacklo_epi64( s[40], s[44] );
   d1[10] = _mm_unpackhi_epi64( s[40], s[44] );
   d2[10] = _mm_unpacklo_epi64( s[41], s[45] );
   d3[10] = _mm_unpackhi_epi64( s[41], s[45] );
   d0[11] = _mm_unpacklo_epi64( s[42], s[46] );
   d1[11] = _mm_unpackhi_epi64( s[42], s[46] );
   d2[11] = _mm_unpacklo_epi64( s[43], s[47] );
   d3[11] = _mm_unpackhi_epi64( s[43], s[47] );

   d0[12] = _mm_unpacklo_epi64( s[48], s[52] );
   d1[12] = _mm_unpackhi_epi64( s[48], s[52] );
   d2[12] = _mm_unpacklo_epi64( s[49], s[53] );
   d3[12] = _mm_unpackhi_epi64( s[49], s[53] );
   d0[13] = _mm_unpacklo_epi64( s[50], s[54] );
   d1[13] = _mm_unpackhi_epi64( s[50], s[54] );
   d2[13] = _mm_unpacklo_epi64( s[51], s[55] );
   d3[13] = _mm_unpackhi_epi64( s[51], s[55] );

   d0[14] = _mm_unpacklo_epi64( s[56], s[60] );
   d1[14] = _mm_unpackhi_epi64( s[56], s[60] );
   d2[14] = _mm_unpacklo_epi64( s[57], s[61] );
   d3[14] = _mm_unpackhi_epi64( s[57], s[61] );
   d0[15] = _mm_unpacklo_epi64( s[58], s[62] );
   d1[15] = _mm_unpackhi_epi64( s[58], s[62] );
   d2[15] = _mm_unpacklo_epi64( s[59], s[63] );
   d3[15] = _mm_unpackhi_epi64( s[59], s[63] );
}

// 4x128 -> 8x64

static inline void rintrlv_2x256_8x64( void *dst, const void *src0,
      const void *src1, const void *src2, const void *src3, const int bit_len )
{
   __m128i *d = (__m128i*)dst;
   __m128i *s0 = (__m128i*)src0;
   __m128i *s1 = (__m128i*)src1;
   __m128i *s2 = (__m128i*)src2;
   __m128i *s3 = (__m128i*)src3;

   d[ 0] = _mm_unpacklo_epi64( s0[0], s0[2] );
   d[ 1] = _mm_unpacklo_epi64( s1[0], s1[2] );
   d[ 2] = _mm_unpacklo_epi64( s2[0], s2[2] );
   d[ 3] = _mm_unpacklo_epi64( s3[0], s3[2] );
   d[ 4] = _mm_unpackhi_epi64( s0[0], s0[2] );
   d[ 5] = _mm_unpackhi_epi64( s1[0], s1[2] );
   d[ 6] = _mm_unpackhi_epi64( s2[0], s2[2] );
   d[ 7] = _mm_unpackhi_epi64( s3[0], s3[2] );

   d[ 8] = _mm_unpacklo_epi64( s0[1], s0[3] );
   d[ 9] = _mm_unpacklo_epi64( s1[1], s1[3] );
   d[10] = _mm_unpacklo_epi64( s2[1], s2[3] );
   d[11] = _mm_unpacklo_epi64( s3[1], s3[3] );
   d[12] = _mm_unpackhi_epi64( s0[1], s0[3] );
   d[13] = _mm_unpackhi_epi64( s1[1], s1[3] );
   d[14] = _mm_unpackhi_epi64( s2[1], s2[3] );
   d[15] = _mm_unpackhi_epi64( s3[1], s3[3] );

   if ( bit_len <= 256 ) return;

   d[16] = _mm_unpacklo_epi64( s0[4], s0[6] );
   d[17] = _mm_unpacklo_epi64( s1[4], s1[6] );
   d[18] = _mm_unpacklo_epi64( s2[4], s2[6] );
   d[19] = _mm_unpacklo_epi64( s3[4], s3[6] );
   d[20] = _mm_unpackhi_epi64( s0[4], s0[6] );
   d[21] = _mm_unpackhi_epi64( s1[4], s1[6] );
   d[22] = _mm_unpackhi_epi64( s2[4], s2[6] );
   d[23] = _mm_unpackhi_epi64( s3[4], s3[6] );

   d[24] = _mm_unpacklo_epi64( s0[5], s0[7] );
   d[25] = _mm_unpacklo_epi64( s1[5], s1[7] );
   d[26] = _mm_unpacklo_epi64( s2[5], s2[7] );
   d[27] = _mm_unpacklo_epi64( s3[5], s3[7] );
   d[28] = _mm_unpackhi_epi64( s0[5], s0[7] );
   d[29] = _mm_unpackhi_epi64( s1[5], s1[7] );
   d[30] = _mm_unpackhi_epi64( s2[5], s2[7] );
   d[31] = _mm_unpackhi_epi64( s3[5], s3[7] );

   if ( bit_len <= 512 ) return;

   d[32] = _mm_unpacklo_epi64( s0[8], s0[10] );
   d[33] = _mm_unpacklo_epi64( s1[8], s1[10] );
   d[34] = _mm_unpacklo_epi64( s2[8], s2[10] );
   d[35] = _mm_unpacklo_epi64( s3[8], s3[10] );
   d[36] = _mm_unpackhi_epi64( s0[8], s0[10] );
   d[37] = _mm_unpackhi_epi64( s1[8], s1[10] );
   d[38] = _mm_unpackhi_epi64( s2[8], s2[10] );
   d[39] = _mm_unpackhi_epi64( s3[8], s3[10] );

   if ( bit_len <= 640 ) return;

   d[40] = _mm_unpacklo_epi64( s0[9], s0[11] );
   d[41] = _mm_unpacklo_epi64( s1[9], s1[11] );
   d[42] = _mm_unpacklo_epi64( s2[9], s2[11] );
   d[43] = _mm_unpacklo_epi64( s3[9], s3[11] );
   d[44] = _mm_unpackhi_epi64( s0[9], s0[11] );
   d[45] = _mm_unpackhi_epi64( s1[9], s1[11] );
   d[46] = _mm_unpackhi_epi64( s2[9], s2[11] );
   d[47] = _mm_unpackhi_epi64( s3[9], s3[11] );

   d[48] = _mm_unpacklo_epi64( s0[12], s0[14] );
   d[49] = _mm_unpacklo_epi64( s1[12], s1[14] );
   d[50] = _mm_unpacklo_epi64( s2[12], s2[14] );
   d[51] = _mm_unpacklo_epi64( s3[12], s3[14] );
   d[52] = _mm_unpackhi_epi64( s0[12], s0[14] );
   d[53] = _mm_unpackhi_epi64( s1[12], s1[14] );
   d[54] = _mm_unpackhi_epi64( s2[12], s2[14] );
   d[55] = _mm_unpackhi_epi64( s3[12], s3[14] );

   d[56] = _mm_unpacklo_epi64( s0[13], s0[15] );
   d[57] = _mm_unpacklo_epi64( s1[13], s1[15] );
   d[58] = _mm_unpacklo_epi64( s2[13], s2[15] );
   d[59] = _mm_unpacklo_epi64( s3[13], s3[15] );
   d[60] = _mm_unpackhi_epi64( s0[13], s0[15] );
   d[61] = _mm_unpackhi_epi64( s1[13], s1[15] );
   d[62] = _mm_unpackhi_epi64( s2[13], s2[15] );
   d[63] = _mm_unpackhi_epi64( s3[13], s3[15] );
}

//
// Some functions customized for mining.

// blend 2 vectors while interleaving: { hi[n], lo[n-1], ... hi[1], lo[0] }
#if defined(__SSE4_1__)
// No SSE2 implementation.

//#define mm128_intrlv_blend_64( hi, lo )   _mm_blend_epi16( hi, lo, 0x0f )
//#define mm128_intrlv_blend_32( hi, lo )   _mm_blend_epi16( hi, lo, 0x33 )

#endif   // SSE4_1

#if defined(__AVX2__)

//#define mm256_intrlv_blend_128( hi, lo )  _mm256_blend_epi32( hi, lo, 0x0f )
//#define mm256_intrlv_blend_64( hi, lo )   _mm256_blend_epi32( hi, lo, 0x33 )
#define mm256_intrlv_blend_32( hi, lo )   _mm256_blend_epi32( hi, lo, 0x55 )

// change to _mm256_blend_epi32
//
// Select lanes of 32 byte hash from 2 sources according to control mask.
// macro due to 256 bit value arg.
#define mm256_blend_hash_4x64( dst, a, b, mask ) \
do { \
    dst[0] = _mm256_blendv_epi8( a[0], b[0], mask ); \
    dst[1] = _mm256_blendv_epi8( a[1], b[1], mask ); \
    dst[2] = _mm256_blendv_epi8( a[2], b[2], mask ); \
    dst[3] = _mm256_blendv_epi8( a[3], b[3], mask ); \
    dst[4] = _mm256_blendv_epi8( a[4], b[4], mask ); \
    dst[5] = _mm256_blendv_epi8( a[5], b[5], mask ); \
    dst[6] = _mm256_blendv_epi8( a[6], b[6], mask ); \
    dst[7] = _mm256_blendv_epi8( a[7], b[7], mask ); \
} while(0)

#endif  // AVX2

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

/*
#define mm512_intrlv_blend_128( hi, lo ) \
   _mm512_mask_blend_epi32( 0x0f0f, hi, lo )

#define mm512_intrlv_blend_64( hi, lo ) \
   _mm512_mask_blend_epi32( 0x3333, hi, lo )
*/

#define mm512_intrlv_blend_32( hi, lo ) \
   _mm512_mask_blend_epi32( 0x5555, hi, lo )

#define mm512_blend_hash_8x64( dst, a, b, mask ) \
do { \
    dst[0] = _mm512_mask_blend_epi64( mask, a[0], b[0] ); \
    dst[1] = _mm512_mask_blend_epi64( mask, a[1], b[1] ); \
    dst[2] = _mm512_mask_blend_epi64( mask, a[2], b[2] ); \
    dst[3] = _mm512_mask_blend_epi64( mask, a[3], b[3] ); \
    dst[4] = _mm512_mask_blend_epi64( mask, a[4], b[4] ); \
    dst[5] = _mm512_mask_blend_epi64( mask, a[5], b[5] ); \
    dst[6] = _mm512_mask_blend_epi64( mask, a[6], b[6] ); \
    dst[7] = _mm512_mask_blend_epi64( mask, a[7], b[7] ); \
} while(0)

#endif // AVX512
#endif // INTERLEAVE_H__
