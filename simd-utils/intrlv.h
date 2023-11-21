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

#if ( defined(__x86_64__) && defined(__SSE4_1__) ) || ( defined(__aarch64__) && defined(__ARM_NEON) )

#define ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 ) \
   D0 = v128_movlane32( S0, 1, S1, 0 ); \
   D1 = v128_movlane32( S1, 0, S0, 1 ); \
   D2 = v128_movlane32( S2, 0, S0, 2 ); \
   D3 = v128_movlane32( S3, 0, S0, 3 ); \
   D0 = v128_movlane32( D0, 2, S2, 0 ); \
   D1 = v128_movlane32( D1, 2, S2, 1 ); \
   D2 = v128_movlane32( D2, 1, S1, 2 ); \
   D3 = v128_movlane32( D3, 1, S1, 3 ); \
   D0 = v128_movlane32( D0, 3, S3, 0 ); \
   D1 = v128_movlane32( D1, 3, S3, 1 ); \
   D2 = v128_movlane32( D2, 3, S3, 2 ); \
   D3 = v128_movlane32( D3, 2, S2, 3 ); 

#define LOAD_SRCE( S0, S1, S2, S3, src0, i0, src1, i1, src2, i2, src3, i3 ) \
   S0 = v128_load( (const v128_t*)(src0) + (i0) ); \
   S1 = v128_load( (const v128_t*)(src1) + (i1) ); \
   S2 = v128_load( (const v128_t*)(src2) + (i2) ); \
   S3 = v128_load( (const v128_t*)(src3) + (i3) );

#define STORE_DEST( D0, D1, D2, D3, dst0, i0, dst1, i1, dst2, i2, dst3, i3 ) \
   v128_store( (v128_t*)(dst0) + (i0), D0 ); \
   v128_store( (v128_t*)(dst1) + (i1), D1 ); \
   v128_store( (v128_t*)(dst2) + (i2), D2 ); \
   v128_store( (v128_t*)(dst3) + (i3), D3 ); 

static inline void intrlv_4x32( void *dst, const void *src0, const void *src1,
                      const void *src2, const void *src3, const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src0, 0, src1, 0, src2, 0, src3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 1, src1, 1, src2, 1, src3, 1 );
   STORE_DEST( D0, D1, D2, D3, dst, 0, dst, 1, dst, 2, dst, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 4, dst, 5, dst, 6, dst, 7 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src0, 2, src1, 2, src2, 2, src3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 3, src1, 3, src2, 3, src3, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 8, dst, 9, dst, 10, dst, 11 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 12, dst, 13, dst, 14, dst, 15 );

   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src0, 4, src1, 4, src2, 4, src3, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 16, dst, 17, dst, 18, dst, 19 );

   if ( bit_len <= 640 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src0, 5, src1, 5, src2, 5, src3, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 6, src1, 6, src2, 6, src3, 6 );
   STORE_DEST( D0, D1, D2, D3, dst, 20, dst, 21, dst, 22, dst, 23 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 7, src1, 7, src2, 7, src3, 7 ); 
   STORE_DEST( D0, D1, D2, D3, dst, 24, dst, 25, dst, 26, dst, 27 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 28, dst, 29, dst, 30, dst, 31 );

// if ( bit_len <= 1024 ) return;
}

static inline void intrlv_4x32_512( void *dst, const void *src0,
                     const void *src1, const void *src2, const void *src3 )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src0, 0, src1, 0, src2, 0, src3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 1, src1, 1, src2, 1, src3, 1 );
   STORE_DEST( D0, D1, D2, D3, dst, 0, dst, 1, dst, 2, dst, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 2, src1, 2, src2, 2, src3, 2 );
   STORE_DEST( D0, D1, D2, D3, dst, 4, dst, 5, dst, 6, dst, 7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src0, 3, src1, 3, src2, 3, src3, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 8, dst, 9, dst, 10, dst, 11 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 12, dst, 13, dst, 14, dst, 15 );
}

static inline void dintrlv_4x32( void *dst0, void *dst1, void *dst2,
                           void *dst3, const void *src, const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src, 0, src, 1, src, 2, src, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 4, src, 5, src, 6, src, 7 );
   STORE_DEST( D0, D1, D2, D3, dst0, 0, dst1, 0, dst2, 0, dst3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst0, 1, dst1, 1, dst2, 1, dst3, 1 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 8, src, 9, src, 10, src, 11 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 12, src, 13, src, 14, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst0, 2, dst1, 2, dst2, 2, dst3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst0, 3, dst1, 3, dst2, 3, dst3, 3 );

   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 16, src, 17, src, 18, src, 19 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst0, 4, dst1, 4, dst2, 4, dst3, 4 );

   if ( bit_len <= 640 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 20, src, 21, src, 22, src, 23 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 24, src, 25, src, 26, src, 27 );
   STORE_DEST( D0, D1, D2, D3, dst0, 5, dst1, 5, dst2, 5, dst3, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 28, src, 29, src, 30, src, 31 );
   STORE_DEST( D0, D1, D2, D3, dst0, 6, dst1, 6, dst2, 6, dst3, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst0, 7, dst1, 7, dst2, 7, dst3, 7 );

// if ( bit_len <= 1024 ) return;
}

static inline void dintrlv_4x32_512( void *dst0, void *dst1, void *dst2,
                           void *dst3, const void *src )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src, 0, src, 1, src, 2, src, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 4, src, 5, src, 6, src, 7 );
   STORE_DEST( D0, D1, D2, D3, dst0, 0, dst1, 0, dst2, 0, dst3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 8, src, 9, src, 10, src, 11 );
   STORE_DEST( D0, D1, D2, D3, dst0, 1, dst1, 1, dst2, 1, dst3, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 12, src, 13, src, 14, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst0, 2, dst1, 2, dst2, 2, dst3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst0, 3, dst1, 3, dst2, 3, dst3, 3 );
}

#else  // SSE2

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

#endif   // SSE4_1 or NEON else SSE2

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

#if defined(__SSSE3__)

static inline void v128_bswap32_80( void *d, void *s )
{
  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );
  casti_v128( d, 0 ) = _mm_shuffle_epi8( casti_v128( s, 0 ), bswap_shuf );
  casti_v128( d, 1 ) = _mm_shuffle_epi8( casti_v128( s, 1 ), bswap_shuf );
  casti_v128( d, 2 ) = _mm_shuffle_epi8( casti_v128( s, 2 ), bswap_shuf );
  casti_v128( d, 3 ) = _mm_shuffle_epi8( casti_v128( s, 3 ), bswap_shuf );
  casti_v128( d, 4 ) = _mm_shuffle_epi8( casti_v128( s, 4 ), bswap_shuf );
}

#elif defined(__aarch64__) && defined(__ARM_NEON)

static inline void v128_bswap32_80( void *d, void *s )
{
  casti_v128( d, 0 ) = v128_bswap32( casti_v128( s, 0 ) );
  casti_v128( d, 1 ) = v128_bswap32( casti_v128( s, 1 ) );
  casti_v128( d, 2 ) = v128_bswap32( casti_v128( s, 2 ) );
  casti_v128( d, 3 ) = v128_bswap32( casti_v128( s, 3 ) );
  casti_v128( d, 4 ) = v128_bswap32( casti_v128( s, 4 ) );
}  

#else

static inline void v128_bswap32_80( void *d, void *s )
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

#if defined(__SSE2__)

static inline void v128_bswap32_intrlv80_4x32( void *d, const void *src )
{
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

#if defined(__SSSE3__)

  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

#else

  s0 = v128_bswap32( s0 );
  s1 = v128_bswap32( s1 );
  s2 = v128_bswap32( s2 );
  s3 = v128_bswap32( s3 );
  s4 = v128_bswap32( s4 );

#endif

  casti_v128( d, 0 ) = _mm_shuffle_epi32( s0, 0x00 );
  casti_v128( d, 1 ) = _mm_shuffle_epi32( s0, 0x55 );
  casti_v128( d, 2 ) = _mm_shuffle_epi32( s0, 0xaa );
  casti_v128( d, 3 ) = _mm_shuffle_epi32( s0, 0xff );

  casti_v128( d, 4 ) = _mm_shuffle_epi32( s1, 0x00 );
  casti_v128( d, 5 ) = _mm_shuffle_epi32( s1, 0x55 );
  casti_v128( d, 6 ) = _mm_shuffle_epi32( s1, 0xaa );
  casti_v128( d, 7 ) = _mm_shuffle_epi32( s1, 0xff );

  casti_v128( d, 8 ) = _mm_shuffle_epi32( s2, 0x00 );
  casti_v128( d, 9 ) = _mm_shuffle_epi32( s2, 0x55 );
  casti_v128( d,10 ) = _mm_shuffle_epi32( s2, 0xaa );
  casti_v128( d,11 ) = _mm_shuffle_epi32( s2, 0xff );

  casti_v128( d,12 ) = _mm_shuffle_epi32( s3, 0x00 );
  casti_v128( d,13 ) = _mm_shuffle_epi32( s3, 0x55 );
  casti_v128( d,14 ) = _mm_shuffle_epi32( s3, 0xaa );
  casti_v128( d,15 ) = _mm_shuffle_epi32( s3, 0xff );

  casti_v128( d,16 ) = _mm_shuffle_epi32( s4, 0x00 );
  casti_v128( d,17 ) = _mm_shuffle_epi32( s4, 0x55 );
  casti_v128( d,18 ) = _mm_shuffle_epi32( s4, 0xaa );
  casti_v128( d,19 ) = _mm_shuffle_epi32( s4, 0xff );
}

#elif defined(__aarch64__) && defined(__ARM_NEON)

static inline void v128_bswap32_intrlv80_4x32( void *d, const void *src )
{
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

  s0 = v128_bswap32( s0 );
  s1 = v128_bswap32( s1 );
  s2 = v128_bswap32( s2 );
  s3 = v128_bswap32( s3 );
  s4 = v128_bswap32( s4 );

  casti_v128( d, 0 ) = vdupq_laneq_u32( s0, 0 );
  casti_v128( d, 1 ) = vdupq_laneq_u32( s0, 1 );
  casti_v128( d, 2 ) = vdupq_laneq_u32( s0, 2 );
  casti_v128( d, 3 ) = vdupq_laneq_u32( s0, 3 );

  casti_v128( d, 4 ) = vdupq_laneq_u32( s1, 0 );
  casti_v128( d, 5 ) = vdupq_laneq_u32( s1, 1 );
  casti_v128( d, 6 ) = vdupq_laneq_u32( s1, 2 );
  casti_v128( d, 7 ) = vdupq_laneq_u32( s1, 3 );

  casti_v128( d, 8 ) = vdupq_laneq_u32( s2, 0 );
  casti_v128( d, 9 ) = vdupq_laneq_u32( s2, 1 );
  casti_v128( d,10 ) = vdupq_laneq_u32( s2, 2 );
  casti_v128( d,11 ) = vdupq_laneq_u32( s2, 3 );

  casti_v128( d,12 ) = vdupq_laneq_u32( s3, 0 );
  casti_v128( d,13 ) = vdupq_laneq_u32( s3, 1 );
  casti_v128( d,14 ) = vdupq_laneq_u32( s3, 2 );
  casti_v128( d,15 ) = vdupq_laneq_u32( s3, 3 );

  casti_v128( d,16 ) = vdupq_laneq_u32( s2, 0 );
  casti_v128( d,17 ) = vdupq_laneq_u32( s2, 1 );
  casti_v128( d,18 ) = vdupq_laneq_u32( s2, 2 );
  casti_v128( d,19 ) = vdupq_laneq_u32( s2, 3 );
}

#endif

// 8x32

#if defined(__SSE4_1__)

static inline void intrlv_8x32( void *dst, const void *s0, const void *s1,
           const void *s2, const void *s3, const void *s4, const void *s5,
           const void *s6, const void *s7, const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, s0, 0, s1, 0, s2, 0, s3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 0, s5, 0, s6, 0, s7, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,  0, dst,  2, dst,  4, dst,  6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 1, s1, 1, s2, 1, s3, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  1, dst,  3, dst,  5, dst,  7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 1, s5, 1, s6, 1, s7, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  8, dst, 10, dst, 12, dst, 14 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst,  9, dst, 11, dst, 13, dst, 15 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s0, 2, s1, 2, s2, 2, s3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 2, s5, 2, s6, 2, s7, 2 );
   STORE_DEST( D0, D1, D2, D3, dst, 16, dst, 18, dst, 20, dst, 22 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 3, s1, 3, s2, 3, s3, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 17, dst, 19, dst, 21, dst, 23 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 3, s5, 3, s6, 3, s7, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 24, dst, 26, dst, 28, dst, 30 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 25, dst, 27, dst, 29, dst, 31 );

   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s0, 4, s1, 4, s2, 4, s3, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 4, s5, 4, s6, 4, s7, 4 );
   STORE_DEST( D0, D1, D2, D3, dst, 32, dst, 34, dst, 36, dst, 38 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 33, dst, 35, dst, 37, dst, 39 );

   if ( bit_len <= 640 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s0, 5, s1, 5, s2, 5, s3, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 5, s5, 5, s6, 5, s7, 5 );
   STORE_DEST( D0, D1, D2, D3, dst, 40, dst, 42, dst, 44, dst, 46 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 6, s1, 6, s2, 6, s3, 6 );
   STORE_DEST( D0, D1, D2, D3, dst, 41, dst, 43, dst, 45, dst, 47 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 6, s5, 6, s6, 6, s7, 6 );
   STORE_DEST( D0, D1, D2, D3, dst, 48, dst, 50, dst, 52, dst, 54 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 7, s1, 7, s2, 7, s3, 7 );
   STORE_DEST( D0, D1, D2, D3, dst, 49, dst, 51, dst, 53, dst, 55 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 7, s5, 7, s6, 7, s7, 7 );
   STORE_DEST( D0, D1, D2, D3, dst, 56, dst, 58, dst, 60, dst, 62 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 57, dst, 59, dst, 61, dst, 63 );

// if ( bit_len <= 1024 ) return;
}

static inline void intrlv_8x32_512( void *dst, const void *s0, const void *s1,
               const void *s2, const void *s3, const void *s4, const void *s5,
               const void *s6, const void *s7 )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, s0, 0, s1, 0, s2, 0, s3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 0, s5, 0, s6, 0, s7, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,  0, dst,  2, dst,  4, dst,  6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 1, s1, 1, s2, 1, s3, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  1, dst,  3, dst,  5, dst,  7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 1, s5, 1, s6, 1, s7, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  8, dst, 10, dst, 12, dst, 14 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 2, s1, 2, s2, 2, s3, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  9, dst, 11, dst, 13, dst, 15 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 2, s5, 2, s6, 2, s7, 2 );
   STORE_DEST( D0, D1, D2, D3, dst, 16, dst, 18, dst, 20, dst, 22 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s0, 3, s1, 3, s2, 3, s3, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 17, dst, 19, dst, 21, dst, 23 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s4, 3, s5, 3, s6, 3, s7, 3 );
   STORE_DEST( D0, D1, D2, D3, dst, 24, dst, 26, dst, 28, dst, 30 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 25, dst, 27, dst, 29, dst, 31 );
}

static inline void dintrlv_8x32( void *dst0, void *dst1, void *dst2, void *dst3,
             void *dst4, void *dst5, void *dst6, void *dst7, const void *src,
             const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src,  0, src,  2, src,  4, src,  6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  1, src,  3, src,  5, src,  7 );
   STORE_DEST( D0, D1, D2, D3, dst0, 0, dst1, 0, dst2, 0, dst3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  8, src, 10, src, 12, src, 14 );
   STORE_DEST( D0, D1, D2, D3, dst4, 0, dst5, 0, dst6, 0, dst7, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  9, src, 11, src, 13, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst0, 1, dst1, 1, dst2, 1, dst3, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst4, 1, dst5, 1, dst6, 1, dst7, 1 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 16, src, 18, src, 20, src, 22 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 17, src, 19, src, 21, src, 23 );
   STORE_DEST( D0, D1, D2, D3, dst0, 2, dst1, 2, dst2, 2, dst3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 24, src, 26, src, 28, src, 30 );
   STORE_DEST( D0, D1, D2, D3, dst4, 2, dst5, 2, dst6, 2, dst7, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 25, src, 27, src, 29, src, 31 );
   STORE_DEST( D0, D1, D2, D3, dst0, 3, dst1, 3, dst2, 3, dst3, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst4, 3, dst5, 3, dst6, 3, dst7, 3 );

   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 32, src, 34, src, 36, src, 38 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 33, src, 35, src, 37, src, 39 );
   STORE_DEST( D0, D1, D2, D3, dst0, 4, dst1, 4, dst2, 4, dst3, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst4, 4, dst5, 4, dst6, 4, dst7, 4 );

   if ( bit_len <= 640 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 40, src, 42, src, 44, src, 46 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 41, src, 43, src, 45, src, 47 );
   STORE_DEST( D0, D1, D2, D3, dst0, 5, dst1, 5, dst2, 5, dst3, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 48, src, 50, src, 52, src, 54 );
   STORE_DEST( D0, D1, D2, D3, dst4, 5, dst5, 5, dst6, 5, dst7, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 49, src, 51, src, 53, src, 55 );
   STORE_DEST( D0, D1, D2, D3, dst0, 6, dst1, 6, dst2, 6, dst3, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 56, src, 58, src, 60, src, 62 );
   STORE_DEST( D0, D1, D2, D3, dst4, 6, dst5, 6, dst6, 6, dst7, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 57, src, 59, src, 61, src, 63 );
   STORE_DEST( D0, D1, D2, D3, dst0, 7, dst1, 7, dst2, 7, dst3, 7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst4, 7, dst5, 7, dst6, 7, dst7, 7 );

// if ( bit_len <= 1024 ) return;
}

static inline void dintrlv_8x32_512( void *dst0, void *dst1, void *dst2,
             void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
             const void *src )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src,  0, src,  2, src,  4, src,  6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  1, src,  3, src,  5, src,  7 );
   STORE_DEST( D0, D1, D2, D3, dst0, 0, dst1, 0, dst2, 0, dst3, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  8, src, 10, src, 12, src, 14 );
   STORE_DEST( D0, D1, D2, D3, dst4, 0, dst5, 0, dst6, 0, dst7, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  9, src, 11, src, 13, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst0, 1, dst1, 1, dst2, 1, dst3, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 16, src, 18, src, 20, src, 22 );
   STORE_DEST( D0, D1, D2, D3, dst4, 1, dst5, 1, dst6, 1, dst7, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 17, src, 19, src, 21, src, 23 );
   STORE_DEST( D0, D1, D2, D3, dst0, 2, dst1, 2, dst2, 2, dst3, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 24, src, 26, src, 28, src, 30 );
   STORE_DEST( D0, D1, D2, D3, dst4, 2, dst5, 2, dst6, 2, dst7, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 25, src, 27, src, 29, src, 31 );
   STORE_DEST( D0, D1, D2, D3, dst0, 3, dst1, 3, dst2, 3, dst3, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst4, 3, dst5, 3, dst6, 3, dst7, 3 );
}

#endif  // SSE4_1

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

#if defined(__AVX512VL__) && defined(__AVX512VBMI__)

//TODO Enable for AVX10_256 AVX10_512

// Combine byte swap & broadcast in one permute
static inline void mm256_bswap32_intrlv80_8x32( void *d, const void *src )
{
   const __m256i c0 = v256_32( 0x00010203 );
   const __m256i c1 = v256_32( 0x04050607 );
   const __m256i c2 = v256_32( 0x08090a0b );
   const __m256i c3 = v256_32( 0x0c0d0e0f );
   const v128_t s0 = casti_v128( src,0 );
   const v128_t s1 = casti_v128( src,1 );
   const v128_t s2 = casti_v128( src,2 );
   const v128_t s3 = casti_v128( src,3 );
   const v128_t s4 = casti_v128( src,4 );

   casti_m256i( d, 0 ) = _mm256_permutexvar_epi8( c0,
                          _mm256_castsi128_si256( s0 ) );
   casti_m256i( d, 1 ) = _mm256_permutexvar_epi8( c1,
                          _mm256_castsi128_si256( s0 ) );
   casti_m256i( d, 2 ) = _mm256_permutexvar_epi8( c2,
                          _mm256_castsi128_si256( s0 ) );
   casti_m256i( d, 3 ) = _mm256_permutexvar_epi8( c3,
                          _mm256_castsi128_si256( s0 ) );
   casti_m256i( d, 4 ) = _mm256_permutexvar_epi8( c0,
                          _mm256_castsi128_si256( s1 ) );
   casti_m256i( d, 5 ) = _mm256_permutexvar_epi8( c1,
                          _mm256_castsi128_si256( s1 ) );
   casti_m256i( d, 6 ) = _mm256_permutexvar_epi8( c2,
                          _mm256_castsi128_si256( s1 ) );
   casti_m256i( d, 7 ) = _mm256_permutexvar_epi8( c3,
                          _mm256_castsi128_si256( s1 ) );
   casti_m256i( d, 8 ) = _mm256_permutexvar_epi8( c0,
                          _mm256_castsi128_si256( s2 ) );
   casti_m256i( d, 9 ) = _mm256_permutexvar_epi8( c1,
                          _mm256_castsi128_si256( s2 ) );
   casti_m256i( d,10 ) = _mm256_permutexvar_epi8( c2,
                          _mm256_castsi128_si256( s2 ) );
   casti_m256i( d,11 ) = _mm256_permutexvar_epi8( c3,
                          _mm256_castsi128_si256( s2 ) );
   casti_m256i( d,12 ) = _mm256_permutexvar_epi8( c0,
                          _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,13 ) = _mm256_permutexvar_epi8( c1,
                          _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,14 ) = _mm256_permutexvar_epi8( c2,
                          _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,15 ) = _mm256_permutexvar_epi8( c3,
                          _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,16 ) = _mm256_permutexvar_epi8( c0,
                          _mm256_castsi128_si256( s4 ) );
   casti_m256i( d,17 ) = _mm256_permutexvar_epi8( c1,
                          _mm256_castsi128_si256( s4 ) );
   casti_m256i( d,18 ) = _mm256_permutexvar_epi8( c2,
                          _mm256_castsi128_si256( s4 ) );
   casti_m256i( d,19 ) = _mm256_permutexvar_epi8( c3,
                          _mm256_castsi128_si256( s4 ) );
}

#else

static inline void mm256_bswap32_intrlv80_8x32( void *d, const void *src )
{
  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );
  const __m256i c1 = v256_32( 1 );
  const __m256i c2 = _mm256_add_epi32( c1, c1 );
  const __m256i c3 = _mm256_add_epi32( c2, c1 );

  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m256i( d, 0 ) = _mm256_broadcastd_epi32( s0 );
  casti_m256i( d, 1 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s0 ), c1 );
  casti_m256i( d, 2 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s0 ), c2 );
  casti_m256i( d, 3 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s0 ), c3 );

  casti_m256i( d, 4 ) = _mm256_broadcastd_epi32( s1 );
  casti_m256i( d, 5 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s1 ), c1 );
  casti_m256i( d, 6 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s1 ), c2 );
  casti_m256i( d, 7 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s1 ), c3 );

  casti_m256i( d, 8 ) = _mm256_broadcastd_epi32( s2 );
  casti_m256i( d, 9 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s2 ), c1 );
  casti_m256i( d,10 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s2 ), c2 );
  casti_m256i( d,11 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s2 ), c3 );

  casti_m256i( d,12 ) = _mm256_broadcastd_epi32( s3 );
  casti_m256i( d,13 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s3 ), c1 );
  casti_m256i( d,14 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s3 ), c2 );
  casti_m256i( d,15 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s3 ), c3 );

  casti_m256i( d,16 ) = _mm256_broadcastd_epi32( s4 );
  casti_m256i( d,17 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s4 ), c1 );
  casti_m256i( d,18 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s4 ), c2 );
  casti_m256i( d,19 ) = _mm256_permutevar8x32_epi32(
                         _mm256_castsi128_si256( s4 ), c3 );
}

#endif   // AVX512VBMI else
#endif   // AVX2

// 16x32

#if defined(__SSE4_1__)

static inline void intrlv_16x32( void *dst, const void *s00,
        const void *s01, const void *s02, const void *s03, const void *s04,
        const void *s05, const void *s06, const void *s07, const void *s08,
        const void *s09, const void *s10, const void *s11, const void *s12,
        const void *s13, const void *s14, const void *s15, const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, s00, 0, s01, 0, s02, 0, s03, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 0, s05, 0, s06, 0, s07, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   0, dst,   4, dst,   8, dst,  12 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 0, s09, 0, s10, 0, s11, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   1, dst,   5, dst,   9, dst,  13 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 0, s13, 0, s14, 0, s15, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   2, dst,   6, dst,  10, dst,  14 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 1, s01, 1, s02, 1, s03, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,   3, dst,   7, dst,  11, dst,  15 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 1, s05, 1, s06, 1, s07, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  16, dst,  20, dst,  24, dst,  28 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 1, s09, 1, s10, 1, s11, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  17, dst,  21, dst,  25, dst,  29 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 1, s13, 1, s14, 1, s15, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  18, dst,  22, dst,  26, dst,  30 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst,  19, dst,  23, dst,  27, dst,  31 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s00, 2, s01, 2, s02, 2, s03, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 2, s05, 2, s06, 2, s07, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  32, dst,  36, dst,  40, dst,  44 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 2, s09, 2, s10, 2, s11, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  33, dst,  37, dst,  41, dst,  45 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 2, s13, 2, s14, 2, s15, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  34, dst,  38, dst,  42, dst,  46 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 3, s01, 3, s02, 3, s03, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  35, dst,  39, dst,  43, dst,  47 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 3, s05, 3, s06, 3, s07, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  48, dst,  52, dst,  56, dst,  60 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 3, s09, 3, s10, 3, s11, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  49, dst,  53, dst,  57, dst,  61 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 3, s13, 3, s14, 3, s15, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  50, dst,  54, dst,  58, dst,  62 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst,  51, dst,  55, dst,  59, dst,  63 );
   
   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s00, 4, s01, 4, s02, 4, s03, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 4, s05, 4, s06, 4, s07, 4 );
   STORE_DEST( D0, D1, D2, D3, dst,  64, dst,  68, dst,  72, dst,  76 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 4, s09, 4, s10, 4, s11, 4 );
   STORE_DEST( D0, D1, D2, D3, dst,  65, dst,  69, dst,  73, dst,  77 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 4, s13, 4, s14, 4, s15, 4 );
   STORE_DEST( D0, D1, D2, D3, dst,  66, dst,  70, dst,  74, dst,  78 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst,  67, dst,  71, dst,  75, dst,  79 );

   if ( bit_len <= 640 ) return;

   LOAD_SRCE( S0, S1, S2, S3, s00, 5, s01, 5, s02, 5, s03, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 5, s05, 5, s06, 5, s07, 5 );
   STORE_DEST( D0, D1, D2, D3, dst,  80, dst,  84, dst,  88, dst,  92 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 5, s09, 5, s10, 5, s11, 5 );
   STORE_DEST( D0, D1, D2, D3, dst,  81, dst,  85, dst,  89, dst,  93 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 5, s13, 5, s14, 5, s15, 5 );
   STORE_DEST( D0, D1, D2, D3, dst,  82, dst,  86, dst,  90, dst,  94 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 6, s01, 6, s02, 6, s03, 6 );
   STORE_DEST( D0, D1, D2, D3, dst,  83, dst,  87, dst,  91, dst,  95 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 6, s05, 6, s06, 6, s07, 6 );
   STORE_DEST( D0, D1, D2, D3, dst,  96, dst, 100, dst, 104, dst, 108 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 6, s09, 6, s10, 6, s11, 6 );
   STORE_DEST( D0, D1, D2, D3, dst,  97, dst, 101, dst, 105, dst, 109 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 6, s13, 6, s14, 6, s15, 6 );
   STORE_DEST( D0, D1, D2, D3, dst,  98, dst, 102, dst, 106, dst, 110 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 7, s01, 7, s02, 7, s03, 7 );
   STORE_DEST( D0, D1, D2, D3, dst,  99, dst, 103, dst, 107, dst, 111 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 7, s05, 7, s06, 7, s07, 7 );
   STORE_DEST( D0, D1, D2, D3, dst, 112, dst, 116, dst, 120, dst, 124 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 7, s09, 7, s10, 7, s11, 7 );
   STORE_DEST( D0, D1, D2, D3, dst, 113, dst, 117, dst, 121, dst, 125 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 7, s13, 7, s14, 7, s15, 7 );
   STORE_DEST( D0, D1, D2, D3, dst, 114, dst, 118, dst, 122, dst, 126 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst, 115, dst, 119, dst, 123, dst, 127 );

//    if ( bit_len <= 1024 ) return;
}

// not used
static inline void intrlv_16x32_512( void *dst, const void *s00,
        const void *s01, const void *s02, const void *s03, const void *s04,
        const void *s05, const void *s06, const void *s07, const void *s08,
        const void *s09, const void *s10, const void *s11, const void *s12,
        const void *s13, const void *s14, const void *s15 )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, s00, 0, s01, 0, s02, 0, s03, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 0, s05, 0, s06, 0, s07, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   0, dst,   4, dst,   8, dst,  12 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 0, s09, 0, s10, 0, s11, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   1, dst,   5, dst,   9, dst,  13 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 0, s13, 0, s14, 0, s15, 0 );
   STORE_DEST( D0, D1, D2, D3, dst,   2, dst,   6, dst,  10, dst,  14 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 1, s01, 1, s02, 1, s03, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,   3, dst,   7, dst,  11, dst,  15 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 1, s05, 1, s06, 1, s07, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  16, dst,  20, dst,  24, dst,  28 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 1, s09, 1, s10, 1, s11, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  17, dst,  21, dst,  25, dst,  29 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 1, s13, 1, s14, 1, s15, 1 );
   STORE_DEST( D0, D1, D2, D3, dst,  18, dst,  22, dst,  26, dst,  30 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 2, s01, 2, s02, 2, s03, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  19, dst,  23, dst,  27, dst,  31 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 2, s05, 2, s06, 2, s07, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  32, dst,  36, dst,  40, dst,  44 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 2, s09, 2, s10, 2, s11, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  33, dst,  37, dst,  41, dst,  45 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 2, s13, 2, s14, 2, s15, 2 );
   STORE_DEST( D0, D1, D2, D3, dst,  34, dst,  38, dst,  42, dst,  46 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s00, 3, s01, 3, s02, 3, s03, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  35, dst,  39, dst,  43, dst,  47 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s04, 3, s05, 3, s06, 3, s07, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  48, dst,  52, dst,  56, dst,  60 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s08, 3, s09, 3, s10, 3, s11, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  49, dst,  53, dst,  57, dst,  61 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, s12, 3, s13, 3, s14, 3, s15, 3 );
   STORE_DEST( D0, D1, D2, D3, dst,  50, dst,  54, dst,  58, dst,  62 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst,  51, dst,  55, dst,  59, dst,  63 );
}

static inline void dintrlv_16x32( void *dst00, void *dst01, void *dst02,
      void *dst03, void *dst04, void *dst05, void *dst06, void *dst07,
      void *dst08, void *dst09, void *dst10, void *dst11, void *dst12,
      void *dst13, void *dst14, void *dst15, const void *src,
      const int bit_len )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src,  0, src,  4, src,  8, src, 12 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  1, src,  5, src,  9, src, 13 );
   STORE_DEST( D0, D1, D2, D3, dst00, 0, dst01, 0, dst02, 0, dst03, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  2, src,  6, src, 10, src, 14 );
   STORE_DEST( D0, D1, D2, D3, dst04, 0, dst05, 0, dst06, 0, dst07, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  3, src,  7, src, 11, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst08, 0, dst09, 0, dst10, 0, dst11, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 16, src, 20, src, 24, src, 28 );
   STORE_DEST( D0, D1, D2, D3, dst12, 0, dst13, 0, dst14, 0, dst15, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 17, src, 21, src, 25, src, 29 );
   STORE_DEST( D0, D1, D2, D3, dst00, 1, dst01, 1, dst02, 1, dst03, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 18, src, 22, src, 26, src, 30 );
   STORE_DEST( D0, D1, D2, D3, dst04, 1, dst05, 1, dst06, 1, dst07, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 19, src, 23, src, 27, src, 31 );
   STORE_DEST( D0, D1, D2, D3, dst08, 1, dst09, 1, dst10, 1, dst11, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 1, dst13, 1, dst14, 1, dst15, 1 );

   if ( bit_len <= 256 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src, 32, src, 36, src, 40, src, 44 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 33, src, 37, src, 41, src, 45 );
   STORE_DEST( D0, D1, D2, D3, dst00, 2, dst01, 2, dst02, 2, dst03, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 34, src, 38, src, 42, src, 46 );
   STORE_DEST( D0, D1, D2, D3, dst04, 2, dst05, 2, dst06, 2, dst07, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 35, src, 39, src, 43, src, 47 );
   STORE_DEST( D0, D1, D2, D3, dst08, 2, dst09, 2, dst10, 2, dst11, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 48, src, 52, src, 56, src, 60 );
   STORE_DEST( D0, D1, D2, D3, dst12, 2, dst13, 2, dst14, 2, dst15, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 49, src, 53, src, 57, src, 61 );
   STORE_DEST( D0, D1, D2, D3, dst00, 3, dst01, 3, dst02, 3, dst03, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 50, src, 54, src, 58, src, 62 );
   STORE_DEST( D0, D1, D2, D3, dst04, 3, dst05, 3, dst06, 3, dst07, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 51, src, 55, src, 59, src, 63 );
   STORE_DEST( D0, D1, D2, D3, dst08, 3, dst09, 3, dst10, 3, dst11, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 3, dst13, 3, dst14, 3, dst15, 3 );

   if ( bit_len <= 512 ) return;

   LOAD_SRCE( S0, S1, S2, S3, src,  64, src,  68, src,  72, src,  76 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  65, src,  69, src,  73, src,  77 );
   STORE_DEST( D0, D1, D2, D3, dst00, 4, dst01, 4, dst02, 4, dst03, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  66, src,  70, src,  74, src,  78 );
   STORE_DEST( D0, D1, D2, D3, dst04, 4, dst05, 4, dst06, 4, dst07, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  67, src,  71, src,  75, src,  79 );
   STORE_DEST( D0, D1, D2, D3, dst08, 4, dst09, 4, dst10, 4, dst11, 4 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 4, dst13, 4, dst14, 4, dst15, 4 );
   
   if ( bit_len <= 640 ) return;
   
   LOAD_SRCE( S0, S1, S2, S3, src,  80, src,  84, src,  88, src,  92 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  81, src,  85, src,  89, src,  93 );
   STORE_DEST( D0, D1, D2, D3, dst00, 5, dst01, 5, dst02, 5, dst03, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  82, src,  86, src,  90, src,  94 );
   STORE_DEST( D0, D1, D2, D3, dst04, 5, dst05, 5, dst06, 5, dst07, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  83, src,  87, src,  91, src,  95 );
   STORE_DEST( D0, D1, D2, D3, dst08, 5, dst09, 5, dst10, 5, dst11, 5 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 5, dst13, 5, dst14, 5, dst15, 5 );
   LOAD_SRCE( S0, S1, S2, S3, src,  96, src, 100, src, 104, src, 108 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  97, src, 101, src, 105, src, 109 );
   STORE_DEST( D0, D1, D2, D3, dst00, 6, dst01, 6, dst02, 6, dst03, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  98, src, 102, src, 106, src, 110 );
   STORE_DEST( D0, D1, D2, D3, dst04, 6, dst05, 6, dst06, 6, dst07, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  99, src, 103, src, 107, src, 111 );
   STORE_DEST( D0, D1, D2, D3, dst08, 6, dst09, 6, dst10, 6, dst11, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 112, src, 116, src, 120, src, 124 );
   STORE_DEST( D0, D1, D2, D3, dst12, 6, dst13, 6, dst14, 6, dst15, 6 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 113, src, 117, src, 121, src, 125 );
   STORE_DEST( D0, D1, D2, D3, dst00, 7, dst01, 7, dst02, 7, dst03, 7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 114, src, 118, src, 122, src, 126 );
   STORE_DEST( D0, D1, D2, D3, dst04, 7, dst05, 7, dst06, 7, dst07, 7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 115, src, 119, src, 123, src, 127 );
   STORE_DEST( D0, D1, D2, D3, dst08, 7, dst09, 7, dst10, 7, dst11, 7 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 7, dst13, 7, dst14, 7, dst15, 7 );

// if ( bit_len <= 1024 ) return;
}

// not used
static inline void dintrlv_16x32_512( void *dst00, void *dst01, void *dst02,
            void *dst03, void *dst04, void *dst05, void *dst06, void *dst07,
            void *dst08, void *dst09, void *dst10, void *dst11, void *dst12,
            void *dst13, void *dst14, void *dst15, const void *src )
{
   v128_t D0, D1, D2, D3, S0, S1, S2, S3;

   LOAD_SRCE( S0, S1, S2, S3, src,  0, src,  4, src,  8, src, 12 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  1, src,  5, src,  9, src, 13 );
   STORE_DEST( D0, D1, D2, D3, dst00, 0, dst01, 0, dst02, 0, dst03, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  2, src,  6, src, 10, src, 14 );
   STORE_DEST( D0, D1, D2, D3, dst04, 0, dst05, 0, dst06, 0, dst07, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src,  3, src,  7, src, 11, src, 15 );
   STORE_DEST( D0, D1, D2, D3, dst08, 0, dst09, 0, dst10, 0, dst11, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 16, src, 20, src, 24, src, 28 );
   STORE_DEST( D0, D1, D2, D3, dst12, 0, dst13, 0, dst14, 0, dst15, 0 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 17, src, 21, src, 25, src, 29 );
   STORE_DEST( D0, D1, D2, D3, dst00, 1, dst01, 1, dst02, 1, dst03, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 18, src, 22, src, 26, src, 30 );
   STORE_DEST( D0, D1, D2, D3, dst04, 1, dst05, 1, dst06, 1, dst07, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 19, src, 23, src, 27, src, 31 );
   STORE_DEST( D0, D1, D2, D3, dst08, 1, dst09, 1, dst10, 1, dst11, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 32, src, 36, src, 40, src, 44 );
   STORE_DEST( D0, D1, D2, D3, dst12, 1, dst13, 1, dst14, 1, dst15, 1 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 33, src, 37, src, 41, src, 45 );
   STORE_DEST( D0, D1, D2, D3, dst00, 2, dst01, 2, dst02, 2, dst03, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 34, src, 38, src, 42, src, 46 );
   STORE_DEST( D0, D1, D2, D3, dst04, 2, dst05, 2, dst06, 2, dst07, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 35, src, 39, src, 43, src, 47 );
   STORE_DEST( D0, D1, D2, D3, dst08, 2, dst09, 2, dst10, 2, dst11, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 48, src, 52, src, 56, src, 60 );
   STORE_DEST( D0, D1, D2, D3, dst12, 2, dst13, 2, dst14, 2, dst15, 2 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 49, src, 53, src, 57, src, 61 );
   STORE_DEST( D0, D1, D2, D3, dst00, 3, dst01, 3, dst02, 3, dst03, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 50, src, 54, src, 58, src, 62 );
   STORE_DEST( D0, D1, D2, D3, dst04, 3, dst05, 3, dst06, 3, dst07, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   LOAD_SRCE( S0, S1, S2, S3, src, 51, src, 55, src, 59, src, 63 );
   STORE_DEST( D0, D1, D2, D3, dst08, 3, dst09, 3, dst10, 3, dst11, 3 );
   ILEAVE_4x32( D0, D1, D2, D3, S0, S1, S2, S3 );
   STORE_DEST( D0, D1, D2, D3, dst12, 3, dst13, 3, dst14, 3, dst15, 3 );
}

#endif  // SSE4_1

static inline void extr_lane_16x32( void *d, const void *s,
                                    const int lane, const int bit_len )
{
   ((uint32_t*)d)[ 0] = ((const uint32_t*)s)[ lane     ];
   ((uint32_t*)d)[ 1] = ((const uint32_t*)s)[ lane+ 16 ];
   ((uint32_t*)d)[ 2] = ((const uint32_t*)s)[ lane+ 32 ];
   ((uint32_t*)d)[ 3] = ((const uint32_t*)s)[ lane+ 48 ];
   ((uint32_t*)d)[ 4] = ((const uint32_t*)s)[ lane+ 64 ];
   ((uint32_t*)d)[ 5] = ((const uint32_t*)s)[ lane+ 80 ];
   ((uint32_t*)d)[ 6] = ((const uint32_t*)s)[ lane+ 96 ];
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

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#if defined(__AVX512VBMI__)

// TODO Enable for AVX10_512

// Combine byte swap & broadcast in one permute
static inline void mm512_bswap32_intrlv80_16x32( void *d, const void *src )
{
   const __m512i c0 = v512_32( 0x00010203 );
   const __m512i c1 = v512_32( 0x04050607 );
   const __m512i c2 = v512_32( 0x08090a0b );
   const __m512i c3 = v512_32( 0x0c0d0e0f );
   const v128_t s0 = casti_v128( src,0 );
   const v128_t s1 = casti_v128( src,1 );
   const v128_t s2 = casti_v128( src,2 );
   const v128_t s3 = casti_v128( src,3 );
   const v128_t s4 = casti_v128( src,4 );
 
   casti_m512i( d, 0 ) = _mm512_permutexvar_epi8( c0,
                          _mm512_castsi128_si512( s0 ) );
   casti_m512i( d, 1 ) = _mm512_permutexvar_epi8( c1,
                          _mm512_castsi128_si512( s0 ) );
   casti_m512i( d, 2 ) = _mm512_permutexvar_epi8( c2,
                          _mm512_castsi128_si512( s0 ) );
   casti_m512i( d, 3 ) = _mm512_permutexvar_epi8( c3,
                          _mm512_castsi128_si512( s0 ) );
   casti_m512i( d, 4 ) = _mm512_permutexvar_epi8( c0,
                          _mm512_castsi128_si512( s1 ) );
   casti_m512i( d, 5 ) = _mm512_permutexvar_epi8( c1,
                          _mm512_castsi128_si512( s1 ) );
   casti_m512i( d, 6 ) = _mm512_permutexvar_epi8( c2,
                          _mm512_castsi128_si512( s1 ) );
   casti_m512i( d, 7 ) = _mm512_permutexvar_epi8( c3,
                          _mm512_castsi128_si512( s1 ) );
   casti_m512i( d, 8 ) = _mm512_permutexvar_epi8( c0,
                          _mm512_castsi128_si512( s2 ) );
   casti_m512i( d, 9 ) = _mm512_permutexvar_epi8( c1,
                          _mm512_castsi128_si512( s2 ) );
   casti_m512i( d,10 ) = _mm512_permutexvar_epi8( c2,
                          _mm512_castsi128_si512( s2 ) );
   casti_m512i( d,11 ) = _mm512_permutexvar_epi8( c3,
                          _mm512_castsi128_si512( s2 ) );
   casti_m512i( d,12 ) = _mm512_permutexvar_epi8( c0,
                          _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,13 ) = _mm512_permutexvar_epi8( c1,
                          _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,14 ) = _mm512_permutexvar_epi8( c2,
                          _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,15 ) = _mm512_permutexvar_epi8( c3,
                          _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,16 ) = _mm512_permutexvar_epi8( c0,
                          _mm512_castsi128_si512( s4 ) );
   casti_m512i( d,17 ) = _mm512_permutexvar_epi8( c1,
                          _mm512_castsi128_si512( s4 ) );
   casti_m512i( d,18 ) = _mm512_permutexvar_epi8( c2,
                          _mm512_castsi128_si512( s4 ) );
   casti_m512i( d,19 ) = _mm512_permutexvar_epi8( c3,
                          _mm512_castsi128_si512( s4 ) );
}

#else

static inline void mm512_bswap32_intrlv80_16x32( void *d, const void *src )
{
  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );
  const __m512i c1 = v512_32( 1 );
  const __m512i c2 = _mm512_add_epi32( c1, c1 );
  const __m512i c3 = _mm512_add_epi32( c2, c1 );
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m512i( d, 0 ) = _mm512_broadcastd_epi32(  s0 );
  casti_m512i( d, 1 ) = _mm512_permutexvar_epi32( c1,
                          _mm512_castsi128_si512( s0 ) );
  casti_m512i( d, 2 ) = _mm512_permutexvar_epi32( c2,
                          _mm512_castsi128_si512( s0 ) );
  casti_m512i( d, 3 ) = _mm512_permutexvar_epi32( c3,
                          _mm512_castsi128_si512( s0 ) );

  casti_m512i( d, 4 ) = _mm512_broadcastd_epi32(  s1 );
  casti_m512i( d, 5 ) = _mm512_permutexvar_epi32( c1,
                          _mm512_castsi128_si512( s1 ) );
  casti_m512i( d, 6 ) = _mm512_permutexvar_epi32( c2,
                          _mm512_castsi128_si512( s1 ) );
  casti_m512i( d, 7 ) = _mm512_permutexvar_epi32( c3,
                          _mm512_castsi128_si512( s1 ) );

  casti_m512i( d, 8 ) = _mm512_broadcastd_epi32(  s2 );
  casti_m512i( d, 9 ) = _mm512_permutexvar_epi32( c1,
                          _mm512_castsi128_si512( s2 ) );
  casti_m512i( d,10 ) = _mm512_permutexvar_epi32( c2,
                          _mm512_castsi128_si512( s2 ) );
  casti_m512i( d,11 ) = _mm512_permutexvar_epi32( c3,
                          _mm512_castsi128_si512( s2 ) );

  casti_m512i( d,12 ) = _mm512_broadcastd_epi32(  s3 );
  casti_m512i( d,13 ) = _mm512_permutexvar_epi32( c1,
                          _mm512_castsi128_si512( s3 ) );
  casti_m512i( d,14 ) = _mm512_permutexvar_epi32( c2,
                          _mm512_castsi128_si512( s3 ) );
  casti_m512i( d,15 ) = _mm512_permutexvar_epi32( c3,
                          _mm512_castsi128_si512( s3 ) );

  casti_m512i( d,16 ) = _mm512_broadcastd_epi32(  s4 );
  casti_m512i( d,17 ) = _mm512_permutexvar_epi32( c1,
                          _mm512_castsi128_si512( s4 ) );
  casti_m512i( d,18 ) = _mm512_permutexvar_epi32( c2,
                          _mm512_castsi128_si512( s4 ) );
  casti_m512i( d,19 ) = _mm512_permutexvar_epi32( c3,
                          _mm512_castsi128_si512( s4 ) );
}

#endif    // VBMI else
#endif    // AVX512

///////////////////////////
//
//     64 bit data

// 2x64    SSE2, NEON

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

static inline void v128_bswap32_intrlv80_2x64( void *d, const void *src )
{
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

#if defined(__SSSE3__)

  const v128u64_t bswap_shuf = v128_set64( 0x0c0d0e0f08090a0b,
                                           0x0405060700010203 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

#else

  s0 = v128_bswap32( s0 );
  s1 = v128_bswap32( s1 );
  s2 = v128_bswap32( s2 );
  s3 = v128_bswap32( s3 );
  s4 = v128_bswap32( s4 );

#endif

#if defined(__SSE2__)

  casti_v128( d,0 ) = _mm_shuffle_epi32( s0, 0x44 );
  casti_v128( d,1 ) = _mm_shuffle_epi32( s0, 0xee );

  casti_v128( d,2 ) = _mm_shuffle_epi32( s1, 0x44 );
  casti_v128( d,3 ) = _mm_shuffle_epi32( s1, 0xee );

  casti_v128( d,4 ) = _mm_shuffle_epi32( s2, 0x44 );
  casti_v128( d,5 ) = _mm_shuffle_epi32( s2, 0xee );

  casti_v128( d,6 ) = _mm_shuffle_epi32( s3, 0x44 );
  casti_v128( d,7 ) = _mm_shuffle_epi32( s3, 0xee );

  casti_v128( d,8 ) = _mm_shuffle_epi32( s4, 0x44 );
  casti_v128( d,9 ) = _mm_shuffle_epi32( s4, 0xee );

#elif defined(__ARM_NEON)

  casti_v128u64( d,0 ) = vdupq_laneq_u64( (uint64x2_t)s0, 0 );
  casti_v128u64( d,1 ) = vdupq_laneq_u64( (uint64x2_t)s0, 1 );

  casti_v128u64( d,2 ) = vdupq_laneq_u64( (uint64x2_t)s1, 0 );
  casti_v128u64( d,3 ) = vdupq_laneq_u64( (uint64x2_t)s1, 1 );

  casti_v128u64( d,4 ) = vdupq_laneq_u64( (uint64x2_t)s2, 0 );
  casti_v128u64( d,5 ) = vdupq_laneq_u64( (uint64x2_t)s2, 1 );

  casti_v128u64( d,6 ) = vdupq_laneq_u64( (uint64x2_t)s3, 0 );
  casti_v128u64( d,7 ) = vdupq_laneq_u64( (uint64x2_t)s3, 1 );

  casti_v128u64( d,8 ) = vdupq_laneq_u64( (uint64x2_t)s4, 0 );
  casti_v128u64( d,9 ) = vdupq_laneq_u64( (uint64x2_t)s4, 1 );

#endif
}

static inline void extr_lane_2x64( void *dst, const void *src,
                                   const int lane, const int bit_len )
{
   uint64_t *d = (uint64_t*)dst;
   const uint64_t *s = (const uint64_t*)src;
   d[ 0] = s[ lane    ];   d[ 1] = s[ lane+ 2 ];
   d[ 2] = s[ lane+ 4 ];   d[ 3] = s[ lane+ 6 ];
   if ( bit_len <= 256 ) return;
   d[ 4] = s[ lane+ 8 ];   d[ 5] = s[ lane+10 ];
   d[ 6] = s[ lane+12 ];   d[ 7] = s[ lane+14 ];
}


// 4x64   (AVX2)

#if defined(__SSE2__)

static inline void intrlv_4x64( void *dst, const void *src0,
                    const void *src1, const void *src2, const void *src3,
                    const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s0 = (const v128_t*)src0;
   const v128_t *s1 = (const v128_t*)src1;
   const v128_t *s2 = (const v128_t*)src2;
   const v128_t *s3 = (const v128_t*)src3;
   d[ 0] = v128_unpacklo64( s0[0], s1[0] );
   d[ 1] = v128_unpacklo64( s2[0], s3[0] );
   d[ 2] = v128_unpackhi64( s0[0], s1[0] );
   d[ 3] = v128_unpackhi64( s2[0], s3[0] );
   d[ 4] = v128_unpacklo64( s0[1], s1[1] );
   d[ 5] = v128_unpacklo64( s2[1], s3[1] );
   d[ 6] = v128_unpackhi64( s0[1], s1[1] );
   d[ 7] = v128_unpackhi64( s2[1], s3[1] );
   if ( bit_len <= 256 ) return;
   d[ 8] = v128_unpacklo64( s0[2], s1[2] );
   d[ 9] = v128_unpacklo64( s2[2], s3[2] );
   d[10] = v128_unpackhi64( s0[2], s1[2] );
   d[11] = v128_unpackhi64( s2[2], s3[2] );
   d[12] = v128_unpacklo64( s0[3], s1[3] );
   d[13] = v128_unpacklo64( s2[3], s3[3] );
   d[14] = v128_unpackhi64( s0[3], s1[3] );
   d[15] = v128_unpackhi64( s2[3], s3[3] );
   if ( bit_len <= 512 ) return;
   d[16] = v128_unpacklo64( s0[4], s1[4] );
   d[17] = v128_unpacklo64( s2[4], s3[4] );
   d[18] = v128_unpackhi64( s0[4], s1[4] );
   d[19] = v128_unpackhi64( s2[4], s3[4] );
   if ( bit_len <= 640 ) return;
   d[20] = v128_unpacklo64( s0[5], s1[5] );
   d[21] = v128_unpacklo64( s2[5], s3[5] );
   d[22] = v128_unpackhi64( s0[5], s1[5] );
   d[23] = v128_unpackhi64( s2[5], s3[5] );
   d[24] = v128_unpacklo64( s0[6], s1[6] );
   d[25] = v128_unpacklo64( s2[6], s3[6] );
   d[26] = v128_unpackhi64( s0[6], s1[6] );
   d[27] = v128_unpackhi64( s2[6], s3[6] );
   d[28] = v128_unpacklo64( s0[7], s1[7] );
   d[29] = v128_unpacklo64( s2[7], s3[7] );
   d[30] = v128_unpackhi64( s0[7], s1[7] );
   d[31] = v128_unpackhi64( s2[7], s3[7] );
}

static inline void intrlv_4x64_512( void *dst, const void *src0,
           const void *src1, const void *src2, const void *src3 )
{
   v128_t *d = (v128_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;
   const v128u64_t *s2 = (const v128u64_t*)src2;
   const v128u64_t *s3 = (const v128u64_t*)src3;
   d[ 0] = v128_unpacklo64( s0[0], s1[0] );
   d[ 1] = v128_unpacklo64( s2[0], s3[0] );
   d[ 2] = v128_unpackhi64( s0[0], s1[0] );
   d[ 3] = v128_unpackhi64( s2[0], s3[0] );
   d[ 4] = v128_unpacklo64( s0[1], s1[1] );
   d[ 5] = v128_unpacklo64( s2[1], s3[1] );
   d[ 6] = v128_unpackhi64( s0[1], s1[1] );
   d[ 7] = v128_unpackhi64( s2[1], s3[1] );
   d[ 8] = v128_unpacklo64( s0[2], s1[2] );
   d[ 9] = v128_unpacklo64( s2[2], s3[2] );
   d[10] = v128_unpackhi64( s0[2], s1[2] );
   d[11] = v128_unpackhi64( s2[2], s3[2] );
   d[12] = v128_unpacklo64( s0[3], s1[3] );
   d[13] = v128_unpacklo64( s2[3], s3[3] );
   d[14] = v128_unpackhi64( s0[3], s1[3] );
   d[15] = v128_unpackhi64( s2[3], s3[3] );
}

static inline void dintrlv_4x64( void *dst0, void *dst1, void *dst2,
                           void *dst3, const void *src, const int bit_len )
{
   v128u64_t *d0 = (v128_t*)dst0;
   v128u64_t *d1 = (v128_t*)dst1;
   v128u64_t *d2 = (v128_t*)dst2;
   v128u64_t *d3 = (v128_t*)dst3;
   const v128u64_t *s = (const v128u64_t*)src;
   d0[0] = v128_unpacklo64( s[ 0], s[ 2] );
   d1[0] = v128_unpackhi64( s[ 0], s[ 2] );
   d2[0] = v128_unpacklo64( s[ 1], s[ 3] );
   d3[0] = v128_unpackhi64( s[ 1], s[ 3] );
   d0[1] = v128_unpacklo64( s[ 4], s[ 6] );
   d1[1] = v128_unpackhi64( s[ 4], s[ 6] );
   d2[1] = v128_unpacklo64( s[ 5], s[ 7] );
   d3[1] = v128_unpackhi64( s[ 5], s[ 7] );
   if ( bit_len <= 256 ) return;
   d0[2] = v128_unpacklo64( s[ 8], s[10] );
   d1[2] = v128_unpackhi64( s[ 8], s[10] );
   d2[2] = v128_unpacklo64( s[ 9], s[11] );
   d3[2] = v128_unpackhi64( s[ 9], s[11] );
   d0[3] = v128_unpacklo64( s[12], s[14] );
   d1[3] = v128_unpackhi64( s[12], s[14] );
   d2[3] = v128_unpacklo64( s[13], s[15] );
   d3[3] = v128_unpackhi64( s[13], s[15] );
   if ( bit_len <= 512 ) return;
   d0[4] = v128_unpacklo64( s[16], s[18] );
   d1[4] = v128_unpackhi64( s[16], s[18] );
   d2[4] = v128_unpacklo64( s[17], s[19] );
   d3[4] = v128_unpackhi64( s[17], s[19] );
   if ( bit_len <= 640 ) return;
   d0[5] = v128_unpacklo64( s[20], s[22] );
   d1[5] = v128_unpackhi64( s[20], s[22] );
   d2[5] = v128_unpacklo64( s[21], s[23] );
   d3[5] = v128_unpackhi64( s[21], s[23] );
   d0[6] = v128_unpacklo64( s[24], s[26] );
   d1[6] = v128_unpackhi64( s[24], s[26] );
   d2[6] = v128_unpacklo64( s[25], s[27] );
   d3[6] = v128_unpackhi64( s[25], s[27] );
   d0[7] = v128_unpacklo64( s[28], s[30] );
   d1[7] = v128_unpackhi64( s[28], s[30] );
   d2[7] = v128_unpacklo64( s[29], s[31] );
   d3[7] = v128_unpackhi64( s[29], s[31] );
}

static inline void dintrlv_4x64_512( void *dst0, void *dst1, void *dst2,
                                     void *dst3, const void *src )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   v128u64_t *d2 = (v128u64_t*)dst2;
   v128u64_t *d3 = (v128u64_t*)dst3;
   const v128_t *s = (const v128_t*)src;
   d0[0] = v128_unpacklo64( s[ 0], s[ 2] );
   d1[0] = v128_unpackhi64( s[ 0], s[ 2] );
   d2[0] = v128_unpacklo64( s[ 1], s[ 3] );
   d3[0] = v128_unpackhi64( s[ 1], s[ 3] );
   d0[1] = v128_unpacklo64( s[ 4], s[ 6] );
   d1[1] = v128_unpackhi64( s[ 4], s[ 6] );
   d2[1] = v128_unpacklo64( s[ 5], s[ 7] );
   d3[1] = v128_unpackhi64( s[ 5], s[ 7] );
   d0[2] = v128_unpacklo64( s[ 8], s[10] );
   d1[2] = v128_unpackhi64( s[ 8], s[10] );
   d2[2] = v128_unpacklo64( s[ 9], s[11] );
   d3[2] = v128_unpackhi64( s[ 9], s[11] );
   d0[3] = v128_unpacklo64( s[12], s[14] );
   d1[3] = v128_unpackhi64( s[12], s[14] );
   d2[3] = v128_unpacklo64( s[13], s[15] );
   d3[3] = v128_unpackhi64( s[13], s[15] );
}


static inline void extr_lane_4x64( void *dst, const void *src, const int lane,
     const int bit_len )
{
   v128u64_t *d = (v128u64_t*)dst;
   const v128u64_t *s = (const v128u64_t*)src;
   int i = lane / 2;
   if ( lane % 2 )   // odd lanes
   { 
      d[0] = v128_unpackhi64( s[ i+ 0 ], s[ i+ 2 ] );
      d[1] = v128_unpackhi64( s[ i+ 4 ], s[ i+ 6 ] );
      if ( bit_len <= 256 ) return;
      d[2] = v128_unpackhi64( s[ i+ 8 ], s[ i+10 ] );
      d[3] = v128_unpackhi64( s[ i+12 ], s[ i+14 ] );
   }
   else     // even lanes
   { 
      d[0] = v128_unpacklo64( s[ i+ 0 ], s[ i+ 2 ] );
      d[1] = v128_unpacklo64( s[ i+ 4 ], s[ i+ 6 ] );
      if ( bit_len <= 256 ) return;
      d[2] = v128_unpacklo64( s[ i+ 8 ], s[ i+10 ] );
      d[3] = v128_unpacklo64( s[ i+12 ], s[ i+14 ] );
   }
   return;    // bit_len == 512   
}

#if defined(__AVX2__)

static inline void mm256_intrlv80_4x64( void *d, const void *src )
{
  __m256i s0 = casti_m256i( src,0 );
  __m256i s1 = casti_m256i( src,1 );
  v128_t s4 = casti_v128( src,4 );

  casti_m256i( d, 0 ) = _mm256_permute4x64_epi64( s0, 0x00 );
  casti_m256i( d, 1 ) = _mm256_permute4x64_epi64( s0, 0x55 );
  casti_m256i( d, 2 ) = _mm256_permute4x64_epi64( s0, 0xaa );
  casti_m256i( d, 3 ) = _mm256_permute4x64_epi64( s0, 0xff );

  casti_m256i( d, 4 ) = _mm256_permute4x64_epi64( s1, 0x00 );
  casti_m256i( d, 5 ) = _mm256_permute4x64_epi64( s1, 0x55 );
  casti_m256i( d, 6 ) = _mm256_permute4x64_epi64( s1, 0xaa );
  casti_m256i( d, 7 ) = _mm256_permute4x64_epi64( s1, 0xff );

  casti_m256i( d, 8 ) = _mm256_permute4x64_epi64(
                          _mm256_castsi128_si256( s4 ), 0x00 );
  casti_m256i( d, 9 ) = _mm256_permute4x64_epi64(
                          _mm256_castsi128_si256( s4 ), 0x55 );
}

#endif

#if defined(__AVX512VL__) && defined(__AVX512VBMI__)

//TODO Enable for AVX10_256 AVX10_512

static inline void mm256_bswap32_intrlv80_4x64( void *d, const void *src )
{
   const __m256i c0 = v256_64( 0x0405060700010203 );
   const __m256i c1 = v256_64( 0x0c0d0e0f08090a0b );
   const v128_t s0 = casti_v128( src,0 );
   const v128_t s1 = casti_v128( src,1 );
   const v128_t s2 = casti_v128( src,2 );
   const v128_t s3 = casti_v128( src,3 );
   const v128_t s4 = casti_v128( src,4 );

   casti_m256i( d,0 ) = _mm256_permutexvar_epi8( c0,
                         _mm256_castsi128_si256( s0 ) );
   casti_m256i( d,1 ) = _mm256_permutexvar_epi8( c1,
                         _mm256_castsi128_si256( s0 ) );
   casti_m256i( d,2 ) = _mm256_permutexvar_epi8( c0,
                         _mm256_castsi128_si256( s1 ) );
   casti_m256i( d,3 ) = _mm256_permutexvar_epi8( c1,
                         _mm256_castsi128_si256( s1 ) );
   casti_m256i( d,4 ) = _mm256_permutexvar_epi8( c0,
                         _mm256_castsi128_si256( s2 ) );
   casti_m256i( d,5 ) = _mm256_permutexvar_epi8( c1,
                         _mm256_castsi128_si256( s2 ) );
   casti_m256i( d,6 ) = _mm256_permutexvar_epi8( c0,
                         _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,7 ) = _mm256_permutexvar_epi8( c1,
                         _mm256_castsi128_si256( s3 ) );
   casti_m256i( d,8 ) = _mm256_permutexvar_epi8( c0,
                         _mm256_castsi128_si256( s4 ) );
   casti_m256i( d,9 ) = _mm256_permutexvar_epi8( c1,
                         _mm256_castsi128_si256( s4 ) );
}

#elif defined(__AVX2__)

static inline void mm256_bswap32_intrlv80_4x64( void *d, const void *src )
{
  const __m256i bswap_shuf = mm256_bcast_m128(
                    _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ) );
  __m256i s0 = casti_m256i( src,0 );
  __m256i s1 = casti_m256i( src,1 );
  v128_t s4 = casti_v128( src,4 );

  s0 = _mm256_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm256_shuffle_epi8( s1, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, _mm256_castsi256_si128( bswap_shuf ) );

  casti_m256i( d, 0 ) = _mm256_permute4x64_epi64( s0, 0x00 );
  casti_m256i( d, 1 ) = _mm256_permute4x64_epi64( s0, 0x55 );
  casti_m256i( d, 2 ) = _mm256_permute4x64_epi64( s0, 0xaa );
  casti_m256i( d, 3 ) = _mm256_permute4x64_epi64( s0, 0xff );
  
  casti_m256i( d, 4 ) = _mm256_permute4x64_epi64( s1, 0x00 );
  casti_m256i( d, 5 ) = _mm256_permute4x64_epi64( s1, 0x55 );
  casti_m256i( d, 6 ) = _mm256_permute4x64_epi64( s1, 0xaa );
  casti_m256i( d, 7 ) = _mm256_permute4x64_epi64( s1, 0xff );

  casti_m256i( d, 8 ) = _mm256_permute4x64_epi64(
                          _mm256_castsi128_si256( s4 ), 0x00 );
  casti_m256i( d, 9 ) = _mm256_permute4x64_epi64(
                          _mm256_castsi128_si256( s4 ), 0x55 );
}

#endif   // AVX2

#endif  // SSE2

// 8x64   (AVX512)

#if defined(__SSE2__)

static inline void intrlv_8x64( void *dst, const void *src0,
       const void *src1, const void *src2, const void *src3,
       const void *src4, const void *src5, const void *src6,
       const void *src7, const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;
   const v128u64_t *s2 = (const v128u64_t*)src2;
   const v128u64_t *s3 = (const v128u64_t*)src3;
   const v128u64_t *s4 = (const v128u64_t*)src4;
   const v128u64_t *s5 = (const v128u64_t*)src5;
   const v128u64_t *s6 = (const v128u64_t*)src6;
   const v128u64_t *s7 = (const v128u64_t*)src7;

   d[ 0] = v128_unpacklo64( s0[0], s1[0] );
   d[ 1] = v128_unpacklo64( s2[0], s3[0] );
   d[ 2] = v128_unpacklo64( s4[0], s5[0] );
   d[ 3] = v128_unpacklo64( s6[0], s7[0] );
   d[ 4] = v128_unpackhi64( s0[0], s1[0] );
   d[ 5] = v128_unpackhi64( s2[0], s3[0] );
   d[ 6] = v128_unpackhi64( s4[0], s5[0] );
   d[ 7] = v128_unpackhi64( s6[0], s7[0] );

   d[ 8] = v128_unpacklo64( s0[1], s1[1] );
   d[ 9] = v128_unpacklo64( s2[1], s3[1] );
   d[10] = v128_unpacklo64( s4[1], s5[1] );
   d[11] = v128_unpacklo64( s6[1], s7[1] );
   d[12] = v128_unpackhi64( s0[1], s1[1] );
   d[13] = v128_unpackhi64( s2[1], s3[1] );
   d[14] = v128_unpackhi64( s4[1], s5[1] );
   d[15] = v128_unpackhi64( s6[1], s7[1] );

   if ( bit_len <= 256 ) return;

   d[16] = v128_unpacklo64( s0[2], s1[2] );
   d[17] = v128_unpacklo64( s2[2], s3[2] );
   d[18] = v128_unpacklo64( s4[2], s5[2] );
   d[19] = v128_unpacklo64( s6[2], s7[2] );
   d[20] = v128_unpackhi64( s0[2], s1[2] );
   d[21] = v128_unpackhi64( s2[2], s3[2] );
   d[22] = v128_unpackhi64( s4[2], s5[2] );
   d[23] = v128_unpackhi64( s6[2], s7[2] );

   d[24] = v128_unpacklo64( s0[3], s1[3] );
   d[25] = v128_unpacklo64( s2[3], s3[3] );
   d[26] = v128_unpacklo64( s4[3], s5[3] );
   d[27] = v128_unpacklo64( s6[3], s7[3] );
   d[28] = v128_unpackhi64( s0[3], s1[3] );
   d[29] = v128_unpackhi64( s2[3], s3[3] );
   d[30] = v128_unpackhi64( s4[3], s5[3] );
   d[31] = v128_unpackhi64( s6[3], s7[3] );

   if ( bit_len <= 512 ) return;

   d[32] = v128_unpacklo64( s0[4], s1[4] );
   d[33] = v128_unpacklo64( s2[4], s3[4] );
   d[34] = v128_unpacklo64( s4[4], s5[4] );
   d[35] = v128_unpacklo64( s6[4], s7[4] );
   d[36] = v128_unpackhi64( s0[4], s1[4] );
   d[37] = v128_unpackhi64( s2[4], s3[4] );
   d[38] = v128_unpackhi64( s4[4], s5[4] );
   d[39] = v128_unpackhi64( s6[4], s7[4] );

   if ( bit_len <= 640 ) return;

   d[40] = v128_unpacklo64( s0[5], s1[5] );
   d[41] = v128_unpacklo64( s2[5], s3[5] );
   d[42] = v128_unpacklo64( s4[5], s5[5] );
   d[43] = v128_unpacklo64( s6[5], s7[5] );
   d[44] = v128_unpackhi64( s0[5], s1[5] );
   d[45] = v128_unpackhi64( s2[5], s3[5] );
   d[46] = v128_unpackhi64( s4[5], s5[5] );
   d[47] = v128_unpackhi64( s6[5], s7[5] );

   d[48] = v128_unpacklo64( s0[6], s1[6] );
   d[49] = v128_unpacklo64( s2[6], s3[6] );
   d[50] = v128_unpacklo64( s4[6], s5[6] );
   d[51] = v128_unpacklo64( s6[6], s7[6] );
   d[52] = v128_unpackhi64( s0[6], s1[6] );
   d[53] = v128_unpackhi64( s2[6], s3[6] );
   d[54] = v128_unpackhi64( s4[6], s5[6] );
   d[55] = v128_unpackhi64( s6[6], s7[6] );

   d[56] = v128_unpacklo64( s0[7], s1[7] );
   d[57] = v128_unpacklo64( s2[7], s3[7] );
   d[58] = v128_unpacklo64( s4[7], s5[7] );
   d[59] = v128_unpacklo64( s6[7], s7[7] );
   d[60] = v128_unpackhi64( s0[7], s1[7] );
   d[61] = v128_unpackhi64( s2[7], s3[7] );
   d[62] = v128_unpackhi64( s4[7], s5[7] );
   d[63] = v128_unpackhi64( s6[7], s7[7] );
}

static inline void intrlv_8x64_512( void *dst, const void *src0,
       const void *src1, const void *src2, const void *src3,
       const void *src4, const void *src5, const void *src6,
       const void *src7 )
{
   v128_t *d = (v128_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;
   const v128u64_t *s2 = (const v128u64_t*)src2;
   const v128u64_t *s3 = (const v128u64_t*)src3;
   const v128u64_t *s4 = (const v128u64_t*)src4;
   const v128u64_t *s5 = (const v128u64_t*)src5;
   const v128u64_t *s6 = (const v128u64_t*)src6;
   const v128u64_t *s7 = (const v128u64_t*)src7;

   d[ 0] = v128_unpacklo64( s0[0], s1[0] );
   d[ 1] = v128_unpacklo64( s2[0], s3[0] );
   d[ 2] = v128_unpacklo64( s4[0], s5[0] );
   d[ 3] = v128_unpacklo64( s6[0], s7[0] );
   d[ 4] = v128_unpackhi64( s0[0], s1[0] );
   d[ 5] = v128_unpackhi64( s2[0], s3[0] );
   d[ 6] = v128_unpackhi64( s4[0], s5[0] );
   d[ 7] = v128_unpackhi64( s6[0], s7[0] );

   d[ 8] = v128_unpacklo64( s0[1], s1[1] );
   d[ 9] = v128_unpacklo64( s2[1], s3[1] );
   d[10] = v128_unpacklo64( s4[1], s5[1] );
   d[11] = v128_unpacklo64( s6[1], s7[1] );
   d[12] = v128_unpackhi64( s0[1], s1[1] );
   d[13] = v128_unpackhi64( s2[1], s3[1] );
   d[14] = v128_unpackhi64( s4[1], s5[1] );
   d[15] = v128_unpackhi64( s6[1], s7[1] );

   d[16] = v128_unpacklo64( s0[2], s1[2] );
   d[17] = v128_unpacklo64( s2[2], s3[2] );
   d[18] = v128_unpacklo64( s4[2], s5[2] );
   d[19] = v128_unpacklo64( s6[2], s7[2] );
   d[20] = v128_unpackhi64( s0[2], s1[2] );
   d[21] = v128_unpackhi64( s2[2], s3[2] );
   d[22] = v128_unpackhi64( s4[2], s5[2] );
   d[23] = v128_unpackhi64( s6[2], s7[2] );

   d[24] = v128_unpacklo64( s0[3], s1[3] );
   d[25] = v128_unpacklo64( s2[3], s3[3] );
   d[26] = v128_unpacklo64( s4[3], s5[3] );
   d[27] = v128_unpacklo64( s6[3], s7[3] );
   d[28] = v128_unpackhi64( s0[3], s1[3] );
   d[29] = v128_unpackhi64( s2[3], s3[3] );
   d[30] = v128_unpackhi64( s4[3], s5[3] );
   d[31] = v128_unpackhi64( s6[3], s7[3] );
}


static inline void dintrlv_8x64( void *dst0, void *dst1, void *dst2,
         void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
         const void *src, const int bit_len )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   v128u64_t *d2 = (v128u64_t*)dst2;
   v128u64_t *d3 = (v128u64_t*)dst3;
   v128u64_t *d4 = (v128u64_t*)dst4;
   v128u64_t *d5 = (v128u64_t*)dst5;
   v128u64_t *d6 = (v128u64_t*)dst6;
   v128u64_t *d7 = (v128u64_t*)dst7;
   const v128u64_t* s = (const v128u64_t*)src;

   d0[0] = v128_unpacklo64( s[ 0], s[ 4] );
   d1[0] = v128_unpackhi64( s[ 0], s[ 4] );
   d2[0] = v128_unpacklo64( s[ 1], s[ 5] );
   d3[0] = v128_unpackhi64( s[ 1], s[ 5] );
   d4[0] = v128_unpacklo64( s[ 2], s[ 6] );
   d5[0] = v128_unpackhi64( s[ 2], s[ 6] );
   d6[0] = v128_unpacklo64( s[ 3], s[ 7] );
   d7[0] = v128_unpackhi64( s[ 3], s[ 7] );

   d0[1] = v128_unpacklo64( s[ 8], s[12] );
   d1[1] = v128_unpackhi64( s[ 8], s[12] );
   d2[1] = v128_unpacklo64( s[ 9], s[13] );
   d3[1] = v128_unpackhi64( s[ 9], s[13] );
   d4[1] = v128_unpacklo64( s[10], s[14] );
   d5[1] = v128_unpackhi64( s[10], s[14] );
   d6[1] = v128_unpacklo64( s[11], s[15] );
   d7[1] = v128_unpackhi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[2] = v128_unpacklo64( s[16], s[20] );
   d1[2] = v128_unpackhi64( s[16], s[20] );
   d2[2] = v128_unpacklo64( s[17], s[21] );
   d3[2] = v128_unpackhi64( s[17], s[21] );
   d4[2] = v128_unpacklo64( s[18], s[22] );
   d5[2] = v128_unpackhi64( s[18], s[22] );
   d6[2] = v128_unpacklo64( s[19], s[23] );
   d7[2] = v128_unpackhi64( s[19], s[23] );

   d0[3] = v128_unpacklo64( s[24], s[28] );
   d1[3] = v128_unpackhi64( s[24], s[28] );
   d2[3] = v128_unpacklo64( s[25], s[29] );
   d3[3] = v128_unpackhi64( s[25], s[29] );
   d4[3] = v128_unpacklo64( s[26], s[30] );
   d5[3] = v128_unpackhi64( s[26], s[30] );
   d6[3] = v128_unpacklo64( s[27], s[31] );
   d7[3] = v128_unpackhi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[4] = v128_unpacklo64( s[32], s[36] );
   d1[4] = v128_unpackhi64( s[32], s[36] );
   d2[4] = v128_unpacklo64( s[33], s[37] );
   d3[4] = v128_unpackhi64( s[33], s[37] );
   d4[4] = v128_unpacklo64( s[34], s[38] );
   d5[4] = v128_unpackhi64( s[34], s[38] );
   d6[4] = v128_unpacklo64( s[35], s[39] );
   d7[4] = v128_unpackhi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[5] = v128_unpacklo64( s[40], s[44] );
   d1[5] = v128_unpackhi64( s[40], s[44] );
   d2[5] = v128_unpacklo64( s[41], s[45] );
   d3[5] = v128_unpackhi64( s[41], s[45] );
   d4[5] = v128_unpacklo64( s[42], s[46] );
   d5[5] = v128_unpackhi64( s[42], s[46] );
   d6[5] = v128_unpacklo64( s[43], s[47] );
   d7[5] = v128_unpackhi64( s[43], s[47] );

   d0[6] = v128_unpacklo64( s[48], s[52] );
   d1[6] = v128_unpackhi64( s[48], s[52] );
   d2[6] = v128_unpacklo64( s[49], s[53] );
   d3[6] = v128_unpackhi64( s[49], s[53] );
   d4[6] = v128_unpacklo64( s[50], s[54] );
   d5[6] = v128_unpackhi64( s[50], s[54] );
   d6[6] = v128_unpacklo64( s[51], s[55] );
   d7[6] = v128_unpackhi64( s[51], s[55] );

   d0[7] = v128_unpacklo64( s[56], s[60] );
   d1[7] = v128_unpackhi64( s[56], s[60] );
   d2[7] = v128_unpacklo64( s[57], s[61] );
   d3[7] = v128_unpackhi64( s[57], s[61] );
   d4[7] = v128_unpacklo64( s[58], s[62] );
   d5[7] = v128_unpackhi64( s[58], s[62] );
   d6[7] = v128_unpacklo64( s[59], s[63] );
   d7[7] = v128_unpackhi64( s[59], s[63] );
}

static inline void dintrlv_8x64_512( void *dst0, void *dst1, void *dst2,
         void *dst3, void *dst4, void *dst5, void *dst6, void *dst7,
         const void *src )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   v128u64_t *d2 = (v128u64_t*)dst2;
   v128u64_t *d3 = (v128u64_t*)dst3;
   v128u64_t *d4 = (v128u64_t*)dst4;
   v128u64_t *d5 = (v128u64_t*)dst5;
   v128u64_t *d6 = (v128u64_t*)dst6;
   v128u64_t *d7 = (v128u64_t*)dst7;
   const v128u64_t* s = (const v128u64_t*)src;

   d0[0] = v128_unpacklo64( s[ 0], s[ 4] );
   d1[0] = v128_unpackhi64( s[ 0], s[ 4] );
   d2[0] = v128_unpacklo64( s[ 1], s[ 5] );
   d3[0] = v128_unpackhi64( s[ 1], s[ 5] );
   d4[0] = v128_unpacklo64( s[ 2], s[ 6] );
   d5[0] = v128_unpackhi64( s[ 2], s[ 6] );
   d6[0] = v128_unpacklo64( s[ 3], s[ 7] );
   d7[0] = v128_unpackhi64( s[ 3], s[ 7] );

   d0[1] = v128_unpacklo64( s[ 8], s[12] );
   d1[1] = v128_unpackhi64( s[ 8], s[12] );
   d2[1] = v128_unpacklo64( s[ 9], s[13] );
   d3[1] = v128_unpackhi64( s[ 9], s[13] );
   d4[1] = v128_unpacklo64( s[10], s[14] );
   d5[1] = v128_unpackhi64( s[10], s[14] );
   d6[1] = v128_unpacklo64( s[11], s[15] );
   d7[1] = v128_unpackhi64( s[11], s[15] );

   d0[2] = v128_unpacklo64( s[16], s[20] );
   d1[2] = v128_unpackhi64( s[16], s[20] );
   d2[2] = v128_unpacklo64( s[17], s[21] );
   d3[2] = v128_unpackhi64( s[17], s[21] );
   d4[2] = v128_unpacklo64( s[18], s[22] );
   d5[2] = v128_unpackhi64( s[18], s[22] );
   d6[2] = v128_unpacklo64( s[19], s[23] );
   d7[2] = v128_unpackhi64( s[19], s[23] );

   d0[3] = v128_unpacklo64( s[24], s[28] );
   d1[3] = v128_unpackhi64( s[24], s[28] );
   d2[3] = v128_unpacklo64( s[25], s[29] );
   d3[3] = v128_unpackhi64( s[25], s[29] );
   d4[3] = v128_unpacklo64( s[26], s[30] );
   d5[3] = v128_unpackhi64( s[26], s[30] );
   d6[3] = v128_unpacklo64( s[27], s[31] );
   d7[3] = v128_unpackhi64( s[27], s[31] );
}

static inline void extr_lane_8x64( void *dst, const void *src, const int lane,
     const int bit_len )
{
   v128u64_t *d = (v128u64_t*)dst;
   const v128u64_t *s = (const v128u64_t*)src;
   int i = lane / 2;
   if ( lane % 2 )   // odd lanes
   {
      d[0] = v128_unpackhi64( s[ i+ 0], s[ i+ 4] );
      d[1] = v128_unpackhi64( s[ i+ 8], s[ i+12] );
      if ( bit_len <= 256 ) return;
      d[2] = v128_unpackhi64( s[ i+16], s[ i+20] );
      d[3] = v128_unpackhi64( s[ i+24], s[ i+28] );
   }
   else   // even lanes
   {
      d[0] = v128_unpacklo64( s[ i+ 0], s[ i+ 4] );
      d[1] = v128_unpacklo64( s[ i+ 8], s[ i+12] );
      if ( bit_len <= 256 ) return;
      d[2] = v128_unpacklo64( s[ i+16], s[ i+20] );
      d[3] = v128_unpacklo64( s[ i+24], s[ i+28] );
   }
   return;
}

#endif  // SSE2

#if defined(__AVX512F__) && defined(__AVX512VL__)

//TODO Enable for AVX10_512

// broadcast to all lanes
static inline void mm512_intrlv80_8x64( void *dst, const void *src )
{
   __m512i *d = (__m512i*)dst;
  const uint64_t *s = (const uint64_t*)src;

  d[0] = v512_64( s[0] );
  d[1] = v512_64( s[1] );
  d[2] = v512_64( s[2] );
  d[3] = v512_64( s[3] );
  d[4] = v512_64( s[4] );
  d[5] = v512_64( s[5] );
  d[6] = v512_64( s[6] );
  d[7] = v512_64( s[7] );
  d[8] = v512_64( s[8] );
  d[9] = v512_64( s[9] );
}

// byte swap and broadcast to all lanes

#if defined(__AVX512VBMI__)

// Combine byte swap & broadcast in one permute
static inline void mm512_bswap32_intrlv80_8x64( void *d, const void *src )
{
   const __m512i c0 = v512_64( 0x0405060700010203 );
   const __m512i c1 = v512_64( 0x0c0d0e0f08090a0b );
   const v128_t s0 = casti_v128( src,0 );
   const v128_t s1 = casti_v128( src,1 );
   const v128_t s2 = casti_v128( src,2 );
   const v128_t s3 = casti_v128( src,3 );
   const v128_t s4 = casti_v128( src,4 );

   casti_m512i( d,0 ) = _mm512_permutexvar_epi8( c0,
                         _mm512_castsi128_si512( s0 ) );
   casti_m512i( d,1 ) = _mm512_permutexvar_epi8( c1,
                         _mm512_castsi128_si512( s0 ) );
   casti_m512i( d,2 ) = _mm512_permutexvar_epi8( c0,
                         _mm512_castsi128_si512( s1 ) );
   casti_m512i( d,3 ) = _mm512_permutexvar_epi8( c1,
                         _mm512_castsi128_si512( s1 ) );
   casti_m512i( d,4 ) = _mm512_permutexvar_epi8( c0,
                         _mm512_castsi128_si512( s2 ) );
   casti_m512i( d,5 ) = _mm512_permutexvar_epi8( c1,
                         _mm512_castsi128_si512( s2 ) );
   casti_m512i( d,6 ) = _mm512_permutexvar_epi8( c0,
                         _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,7 ) = _mm512_permutexvar_epi8( c1,
                         _mm512_castsi128_si512( s3 ) );
   casti_m512i( d,8 ) = _mm512_permutexvar_epi8( c0,
                         _mm512_castsi128_si512( s4 ) );
   casti_m512i( d,9 ) = _mm512_permutexvar_epi8( c1,
                         _mm512_castsi128_si512( s4 ) );
}

#else

static inline void mm512_bswap32_intrlv80_8x64( void *d, const void *src )
{
  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );
  const __m512i c1 = v512_64( 1 );
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m512i( d,0 ) = _mm512_broadcastq_epi64(  s0 );
  casti_m512i( d,1 ) = _mm512_permutexvar_epi64( c1,
                         _mm512_castsi128_si512( s0 ) );
  casti_m512i( d,2 ) = _mm512_broadcastq_epi64(  s1 );
  casti_m512i( d,3 ) = _mm512_permutexvar_epi64( c1,
                         _mm512_castsi128_si512( s1 ) );
  casti_m512i( d,4 ) = _mm512_broadcastq_epi64(  s2 );
  casti_m512i( d,5 ) = _mm512_permutexvar_epi64( c1,
                         _mm512_castsi128_si512( s2 ) );
  casti_m512i( d,6 ) = _mm512_broadcastq_epi64(  s3 );
  casti_m512i( d,7 ) = _mm512_permutexvar_epi64( c1,
                         _mm512_castsi128_si512( s3 ) );
  casti_m512i( d,8 ) = _mm512_broadcastq_epi64(  s4 );
  casti_m512i( d,9 ) = _mm512_permutexvar_epi64( c1,
                         _mm512_castsi128_si512( s4 ) );
}

#endif  // VBMI else
#endif  // AVX512

//////////////////////////
//
//      128 bit data

// 2x128  (AVX2)

#if defined(__SSE2__)

static inline void intrlv_2x128( void *dst, const void *src0,
                                 const void *src1, const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s0 = (const v128_t*)src0;
   const v128_t *s1 = (const v128_t*)src1;
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
   if ( bit_len <= 1024 ) return;
   d[16] = s0[8];   d[17] = s1[8];
   d[18] = s0[9];   d[19] = s1[9];
   //   if ( bit_len <= 1280 ) return;
}

static inline void intrlv_2x128_512( void *dst, const void *src0,
                                     const void *src1 )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s0 = (const v128_t*)src0;
   const v128_t *s1 = (const v128_t*)src1;
   d[0] = s0[0];   d[1] = s1[0];
   d[2] = s0[1];   d[3] = s1[1];
   d[4] = s0[2];   d[5] = s1[2];
   d[6] = s0[3];   d[7] = s1[3];
}

static inline void dintrlv_2x128( void *dst0, void *dst1,
                                  const void *src, int bit_len )
{
   v128_t *d0 = (v128_t*)dst0;
   v128_t *d1 = (v128_t*)dst1;
   const v128_t *s = (const v128_t*)src;

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
   v128_t *d0 = (v128_t*)dst0;   
   v128_t *d1 = (v128_t*)dst1;
   const v128_t *s = (const v128_t*)src;

   d0[0] = s[0];   d1[0] = s[1];
   d0[1] = s[2];   d1[1] = s[3];
   d0[2] = s[4];   d1[2] = s[5];
   d0[3] = s[6];   d1[3] = s[7];
}

// 4x128  (AVX512)

static inline void intrlv_4x128( void *dst, const void *src0,
     const void *src1, const void *src2, const void *src3, const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s0 = (const v128_t*)src0;
   const v128_t *s1 = (const v128_t*)src1;
   const v128_t *s2 = (const v128_t*)src2;
   const v128_t *s3 = (const v128_t*)src3;
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
   if ( bit_len <= 1024 ) return;
   d[32] = s0[8];    d[33] = s1[8];    d[34] = s2[8];    d[35] = s3[8];
   d[36] = s0[9];    d[37] = s1[9];    d[38] = s2[9];    d[39] = s3[9];
   // if ( bit_len <= 1280 ) return;
}

static inline void intrlv_4x128_512( void *dst, const void *src0,
                      const void *src1, const void *src2, const void *src3 )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s0 = (const v128_t*)src0;
   const v128_t *s1 = (const v128_t*)src1;
   const v128_t *s2 = (const v128_t*)src2;
   const v128_t *s3 = (const v128_t*)src3; 
   d[ 0] = s0[0];    d[ 1] = s1[0];    d[ 2] = s2[0];    d[ 3] = s3[0];
   d[ 4] = s0[1];    d[ 5] = s1[1];    d[ 6] = s2[1];    d[ 7] = s3[1];
   d[ 8] = s0[2];    d[ 9] = s1[2];    d[10] = s2[2];    d[11] = s3[2];
   d[12] = s0[3];    d[13] = s1[3];    d[14] = s2[3];    d[15] = s3[3];
}

static inline void dintrlv_4x128( void *dst0, void *dst1, void *dst2,
                             void *dst3, const void *src, const int bit_len )
{
   v128_t *d0 = (v128_t*)dst0;
   v128_t *d1 = (v128_t*)dst1;
   v128_t *d2 = (v128_t*)dst2;
   v128_t *d3 = (v128_t*)dst3;
   const v128_t *s = (const v128_t*)src;
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
   v128_t *d0 = (v128_t*)dst0;
   v128_t *d1 = (v128_t*)dst1;
   v128_t *d2 = (v128_t*)dst2;
   v128_t *d3 = (v128_t*)dst3;
   const v128_t *s = (const v128_t*)src;
   d0[0] = s[ 0];   d1[0] = s[ 1];    d2[0] = s[ 2];   d3[0] = s[ 3];
   d0[1] = s[ 4];   d1[1] = s[ 5];    d2[1] = s[ 6];   d3[1] = s[ 7];
   d0[2] = s[ 8];   d1[2] = s[ 9];    d2[2] = s[10];   d3[2] = s[11];
   d0[3] = s[12];   d1[3] = s[13];    d2[3] = s[14];   d3[3] = s[15];
}

#endif  // SSE2

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#if defined(__AVX512VBMI__)
//TODO Enable for AVX10_512

static inline void mm512_bswap32_intrlv80_4x128( void *d, const void *src )
{
  const __m512i bswap_shuf = mm512_bcast_m128(
                    _mm_set_epi64x( 0x0c0d0e0f08090a0b, 0x0405060700010203 ) );
  const v128_t s0 = casti_v128( src,0 );
  const v128_t s1 = casti_v128( src,1 );
  const v128_t s2 = casti_v128( src,2 );
  const v128_t s3 = casti_v128( src,3 );
  const v128_t s4 = casti_v128( src,4 );

  casti_m512i( d,0 ) = _mm512_permutexvar_epi8( _mm512_castsi128_si512( s0 ),
                                                 bswap_shuf );
  casti_m512i( d,1 ) = _mm512_permutexvar_epi8( _mm512_castsi128_si512( s1 ),
                                                 bswap_shuf );
  casti_m512i( d,2 ) = _mm512_permutexvar_epi8( _mm512_castsi128_si512( s2 ),
                                                 bswap_shuf );
  casti_m512i( d,3 ) = _mm512_permutexvar_epi8( _mm512_castsi128_si512( s3 ),
                                                 bswap_shuf );
  casti_m512i( d,4 ) = _mm512_permutexvar_epi8( _mm512_castsi128_si512( s4 ),
                                                 bswap_shuf );
}

#else

static inline void mm512_bswap32_intrlv80_4x128( void *d, const void *src )
{
  const v128_t bswap_shuf = _mm_set_epi64x( 0x0c0d0e0f08090a0b,
                                             0x0405060700010203 );
  v128_t s0 = casti_v128( src,0 );
  v128_t s1 = casti_v128( src,1 );
  v128_t s2 = casti_v128( src,2 );
  v128_t s3 = casti_v128( src,3 );
  v128_t s4 = casti_v128( src,4 );

  s0 = _mm_shuffle_epi8( s0, bswap_shuf );
  s1 = _mm_shuffle_epi8( s1, bswap_shuf );
  s2 = _mm_shuffle_epi8( s2, bswap_shuf );
  s3 = _mm_shuffle_epi8( s3, bswap_shuf );
  s4 = _mm_shuffle_epi8( s4, bswap_shuf );

  casti_m512i( d,0 ) = mm512_bcast_m128( s0 );
  casti_m512i( d,1 ) = mm512_bcast_m128( s1 );
  casti_m512i( d,2 ) = mm512_bcast_m128( s2 );
  casti_m512i( d,3 ) = mm512_bcast_m128( s3 );
  casti_m512i( d,4 ) = mm512_bcast_m128( s4 );
}

#endif   // AVX512VBMI ELSE
#endif   // AVX512

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

#if defined(__SSE2__)

static inline void rintrlv_4x64_4x32( void *dst, const void *src,
                                            const int  bit_len )
{
   const v128_t *s = (const v128_t*)src;
   v128_t *d = (v128_t*)dst;

   d[ 0] = v128_shuffle2_32( s[ 0], s[ 1], 0x88 );
   d[ 1] = v128_shuffle2_32( s[ 0], s[ 1], 0xdd );
   d[ 2] = v128_shuffle2_32( s[ 2], s[ 3], 0x88 );
   d[ 3] = v128_shuffle2_32( s[ 2], s[ 3], 0xdd );
   d[ 4] = v128_shuffle2_32( s[ 4], s[ 5], 0x88 );
   d[ 5] = v128_shuffle2_32( s[ 4], s[ 5], 0xdd );
   d[ 6] = v128_shuffle2_32( s[ 6], s[ 7], 0x88 );
   d[ 7] = v128_shuffle2_32( s[ 6], s[ 7], 0xdd );

   if ( bit_len <= 256 ) return;

   d[ 8] = v128_shuffle2_32( s[ 8], s[ 9], 0x88 );
   d[ 9] = v128_shuffle2_32( s[ 8], s[ 9], 0xdd );
   d[10] = v128_shuffle2_32( s[10], s[11], 0x88 );
   d[11] = v128_shuffle2_32( s[10], s[11], 0xdd );
   d[12] = v128_shuffle2_32( s[12], s[13], 0x88 );
   d[13] = v128_shuffle2_32( s[12], s[13], 0xdd );
   d[14] = v128_shuffle2_32( s[14], s[15], 0x88 );
   d[15] = v128_shuffle2_32( s[14], s[15], 0xdd );

   if ( bit_len <= 512 ) return;

   d[16] = v128_shuffle2_32( s[16], s[17], 0x88 );
   d[17] = v128_shuffle2_32( s[16], s[17], 0xdd );
   d[18] = v128_shuffle2_32( s[18], s[19], 0x88 );
   d[19] = v128_shuffle2_32( s[18], s[19], 0xdd );
   d[20] = v128_shuffle2_32( s[20], s[21], 0x88 );
   d[21] = v128_shuffle2_32( s[20], s[21], 0xdd );
   d[22] = v128_shuffle2_32( s[22], s[23], 0x88 );
   d[23] = v128_shuffle2_32( s[22], s[23], 0xdd );
   d[24] = v128_shuffle2_32( s[24], s[25], 0x88 );
   d[25] = v128_shuffle2_32( s[24], s[25], 0xdd );
   d[26] = v128_shuffle2_32( s[26], s[27], 0x88 );
   d[27] = v128_shuffle2_32( s[26], s[27], 0xdd );
   d[28] = v128_shuffle2_32( s[28], s[29], 0x88 );
   d[29] = v128_shuffle2_32( s[28], s[29], 0xdd );
   d[30] = v128_shuffle2_32( s[30], s[31], 0x88 );
   d[31] = v128_shuffle2_32( s[30], s[31], 0xdd );

// if ( bit_len <= 1024 ) return;
}

static inline void rintrlv_8x64_8x32( void *dst, const void *src,
                                            const int  bit_len )
{
   const v128_t *s = (const v128_t*)src;
   v128_t *d = (v128_t*)dst;

   d[ 0] = v128_shuffle2_32( s[ 0], s[ 1], 0x88 );
   d[ 1] = v128_shuffle2_32( s[ 2], s[ 3], 0x88 );
   d[ 2] = v128_shuffle2_32( s[ 0], s[ 1], 0xdd );
   d[ 3] = v128_shuffle2_32( s[ 2], s[ 3], 0xdd );
   d[ 4] = v128_shuffle2_32( s[ 4], s[ 5], 0x88 );
   d[ 5] = v128_shuffle2_32( s[ 6], s[ 7], 0x88 );
   d[ 6] = v128_shuffle2_32( s[ 4], s[ 5], 0xdd );
   d[ 7] = v128_shuffle2_32( s[ 6], s[ 7], 0xdd );
   d[ 8] = v128_shuffle2_32( s[ 8], s[ 9], 0x88 );
   d[ 9] = v128_shuffle2_32( s[10], s[11], 0x88 );
   d[10] = v128_shuffle2_32( s[ 8], s[ 9], 0xdd );
   d[11] = v128_shuffle2_32( s[10], s[11], 0xdd );
   d[12] = v128_shuffle2_32( s[12], s[13], 0x88 );
   d[13] = v128_shuffle2_32( s[14], s[15], 0x88 );
   d[14] = v128_shuffle2_32( s[12], s[13], 0xdd );
   d[15] = v128_shuffle2_32( s[14], s[15], 0xdd );

   if ( bit_len <= 256 ) return;

   d[16] = v128_shuffle2_32( s[16], s[17], 0x88 );
   d[17] = v128_shuffle2_32( s[18], s[19], 0x88 );
   d[18] = v128_shuffle2_32( s[16], s[17], 0xdd );
   d[19] = v128_shuffle2_32( s[18], s[19], 0xdd );
   d[20] = v128_shuffle2_32( s[20], s[21], 0x88 );
   d[21] = v128_shuffle2_32( s[22], s[23], 0x88 );
   d[22] = v128_shuffle2_32( s[20], s[21], 0xdd );
   d[23] = v128_shuffle2_32( s[22], s[23], 0xdd );
   d[24] = v128_shuffle2_32( s[24], s[25], 0x88 );
   d[25] = v128_shuffle2_32( s[26], s[27], 0x88 );
   d[26] = v128_shuffle2_32( s[24], s[25], 0xdd );
   d[27] = v128_shuffle2_32( s[26], s[27], 0xdd );
   d[28] = v128_shuffle2_32( s[28], s[29], 0x88 );
   d[29] = v128_shuffle2_32( s[30], s[31], 0x88 );
   d[30] = v128_shuffle2_32( s[28], s[29], 0xdd );
   d[31] = v128_shuffle2_32( s[30], s[31], 0xdd );

   if ( bit_len <= 512 ) return;

   d[32] = v128_shuffle2_32( s[32], s[33], 0x88 );
   d[33] = v128_shuffle2_32( s[34], s[35], 0x88 );
   d[34] = v128_shuffle2_32( s[32], s[33], 0xdd );
   d[35] = v128_shuffle2_32( s[34], s[35], 0xdd );
   d[36] = v128_shuffle2_32( s[36], s[37], 0x88 );
   d[37] = v128_shuffle2_32( s[38], s[39], 0x88 );
   d[38] = v128_shuffle2_32( s[36], s[37], 0xdd );
   d[39] = v128_shuffle2_32( s[38], s[39], 0xdd );
   d[40] = v128_shuffle2_32( s[40], s[41], 0x88 );
   d[41] = v128_shuffle2_32( s[42], s[43], 0x88 );
   d[42] = v128_shuffle2_32( s[40], s[41], 0xdd );
   d[43] = v128_shuffle2_32( s[42], s[43], 0xdd );
   d[44] = v128_shuffle2_32( s[44], s[45], 0x88 );
   d[45] = v128_shuffle2_32( s[46], s[47], 0x88 );
   d[46] = v128_shuffle2_32( s[44], s[45], 0xdd );
   d[47] = v128_shuffle2_32( s[46], s[47], 0xdd );

   d[48] = v128_shuffle2_32( s[48], s[49], 0x88 );
   d[49] = v128_shuffle2_32( s[50], s[51], 0x88 );
   d[50] = v128_shuffle2_32( s[48], s[49], 0xdd );
   d[51] = v128_shuffle2_32( s[50], s[51], 0xdd );
   d[52] = v128_shuffle2_32( s[52], s[53], 0x88 );
   d[53] = v128_shuffle2_32( s[54], s[55], 0x88 );
   d[54] = v128_shuffle2_32( s[52], s[53], 0xdd );
   d[55] = v128_shuffle2_32( s[54], s[55], 0xdd );
   d[56] = v128_shuffle2_32( s[56], s[57], 0x88 );
   d[57] = v128_shuffle2_32( s[58], s[59], 0x88 );
   d[58] = v128_shuffle2_32( s[56], s[57], 0xdd );
   d[59] = v128_shuffle2_32( s[58], s[59], 0xdd );
   d[60] = v128_shuffle2_32( s[60], s[61], 0x88 );
   d[61] = v128_shuffle2_32( s[62], s[63], 0x88 );
   d[62] = v128_shuffle2_32( s[60], s[61], 0xdd );
   d[63] = v128_shuffle2_32( s[62], s[63], 0xdd );

// if ( bit_len <= 1024 ) return;
}

// 4x32 -> 4x64

static inline void rintrlv_4x32_4x64( void *dst,
                                      const void *src, const int bit_len )
{
   v128_t *d = (v128u64_t*)dst;
   const v128u32_t *s = (const v128u32_t*)src;
   d[ 0] = v128_unpacklo32( s[ 0], s[ 1] );
   d[ 1] = v128_unpackhi32( s[ 0], s[ 1] );
   d[ 2] = v128_unpacklo32( s[ 2], s[ 3] );
   d[ 3] = v128_unpackhi32( s[ 2], s[ 3] );
   d[ 4] = v128_unpacklo32( s[ 4], s[ 5] );
   d[ 5] = v128_unpackhi32( s[ 4], s[ 5] );
   d[ 6] = v128_unpacklo32( s[ 6], s[ 7] );
   d[ 7] = v128_unpackhi32( s[ 6], s[ 7] );

   if ( bit_len <= 256 ) return;

   d[ 8] = v128_unpacklo32( s[ 8], s[ 9] );
   d[ 9] = v128_unpackhi32( s[ 8], s[ 9] );
   d[10] = v128_unpacklo32( s[10], s[11] );
   d[11] = v128_unpackhi32( s[10], s[11] );
   d[12] = v128_unpacklo32( s[12], s[13] );
   d[13] = v128_unpackhi32( s[12], s[13] );
   d[14] = v128_unpacklo32( s[14], s[15] );
   d[15] = v128_unpackhi32( s[14], s[15] );

   if ( bit_len <= 512 ) return;

   d[16] = v128_unpacklo32( s[16], s[17] );
   d[17] = v128_unpackhi32( s[16], s[17] );
   d[18] = v128_unpacklo32( s[18], s[19] );
   d[19] = v128_unpackhi32( s[18], s[19] );

   if ( bit_len <= 640 ) return;

   d[20] = v128_unpacklo32( s[20], s[21] );
   d[21] = v128_unpackhi32( s[20], s[21] );
   d[22] = v128_unpacklo32( s[22], s[23] );
   d[23] = v128_unpackhi32( s[22], s[23] );

   d[24] = v128_unpacklo32( s[24], s[25] );
   d[25] = v128_unpackhi32( s[24], s[25] );
   d[26] = v128_unpacklo32( s[26], s[27] );
   d[27] = v128_unpackhi32( s[26], s[27] );
   d[28] = v128_unpacklo32( s[28], s[29] );
   d[29] = v128_unpackhi32( s[28], s[29] );
   d[30] = v128_unpacklo32( s[30], s[31] );
   d[31] = v128_unpackhi32( s[30], s[31] );
}

// 8x32 -> 8x64

static inline void rintrlv_8x32_8x64( void *dst,
                                      const void *src, const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128_t *s = (const v128_t*)src;

   d[ 0] = v128_unpacklo32( s[ 0], s[ 2] );
   d[ 1] = v128_unpackhi32( s[ 0], s[ 2] );
   d[ 2] = v128_unpacklo32( s[ 1], s[ 3] );
   d[ 3] = v128_unpackhi32( s[ 1], s[ 3] );
   d[ 4] = v128_unpacklo32( s[ 4], s[ 6] );
   d[ 5] = v128_unpackhi32( s[ 4], s[ 6] );
   d[ 6] = v128_unpacklo32( s[ 5], s[ 7] );
   d[ 7] = v128_unpackhi32( s[ 5], s[ 7] );

   d[ 8] = v128_unpacklo32( s[ 8], s[10] );
   d[ 9] = v128_unpackhi32( s[ 8], s[10] );
   d[10] = v128_unpacklo32( s[ 9], s[11] );
   d[11] = v128_unpackhi32( s[ 9], s[11] );
   d[12] = v128_unpacklo32( s[12], s[14] );
   d[13] = v128_unpackhi32( s[12], s[14] );
   d[14] = v128_unpacklo32( s[13], s[15] );
   d[15] = v128_unpackhi32( s[13], s[15] );

   if ( bit_len <= 256 ) return;

   d[16] = v128_unpacklo32( s[16], s[18] );
   d[17] = v128_unpackhi32( s[16], s[18] );
   d[18] = v128_unpacklo32( s[17], s[19] );
   d[19] = v128_unpackhi32( s[17], s[19] );
   d[20] = v128_unpacklo32( s[20], s[22] );
   d[21] = v128_unpackhi32( s[20], s[22] );
   d[22] = v128_unpacklo32( s[21], s[23] );
   d[23] = v128_unpackhi32( s[21], s[23] );

   d[24] = v128_unpacklo32( s[24], s[26] );
   d[25] = v128_unpackhi32( s[24], s[26] );
   d[26] = v128_unpacklo32( s[25], s[27] );
   d[27] = v128_unpackhi32( s[25], s[27] );
   d[28] = v128_unpacklo32( s[28], s[30] );
   d[29] = v128_unpackhi32( s[28], s[30] );
   d[30] = v128_unpacklo32( s[29], s[31] );
   d[31] = v128_unpackhi32( s[29], s[31] );

   if ( bit_len <= 512 ) return;

   d[32] = v128_unpacklo32( s[32], s[34] );
   d[33] = v128_unpackhi32( s[32], s[34] );
   d[34] = v128_unpacklo32( s[33], s[35] );
   d[35] = v128_unpackhi32( s[33], s[35] );
   d[36] = v128_unpacklo32( s[36], s[38] );
   d[37] = v128_unpackhi32( s[36], s[38] );
   d[38] = v128_unpacklo32( s[37], s[39] );
   d[39] = v128_unpackhi32( s[37], s[39] );

   if ( bit_len <= 640 ) return;
   
   d[40] = v128_unpacklo32( s[40], s[42] );
   d[41] = v128_unpackhi32( s[40], s[42] );
   d[42] = v128_unpacklo32( s[41], s[43] );
   d[43] = v128_unpackhi32( s[41], s[43] );
   d[44] = v128_unpacklo32( s[44], s[46] );
   d[45] = v128_unpackhi32( s[44], s[46] );
   d[46] = v128_unpacklo32( s[45], s[47] );
   d[47] = v128_unpackhi32( s[45], s[47] );

   d[48] = v128_unpacklo32( s[48], s[50] );
   d[49] = v128_unpackhi32( s[48], s[50] );
   d[50] = v128_unpacklo32( s[49], s[51] );
   d[51] = v128_unpackhi32( s[49], s[51] );
   d[52] = v128_unpacklo32( s[52], s[54] );
   d[53] = v128_unpackhi32( s[52], s[54] );
   d[54] = v128_unpacklo32( s[53], s[55] );
   d[55] = v128_unpackhi32( s[53], s[55] );

   d[56] = v128_unpacklo32( s[56], s[58] );
   d[57] = v128_unpackhi32( s[56], s[58] );
   d[58] = v128_unpacklo32( s[57], s[59] );
   d[59] = v128_unpackhi32( s[57], s[59] );
   d[60] = v128_unpacklo32( s[60], s[62] );
   d[61] = v128_unpackhi32( s[60], s[62] );
   d[62] = v128_unpacklo32( s[61], s[63] );
   d[63] = v128_unpackhi32( s[61], s[63] );
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

// 2x128 -> 4x64


static inline void rintrlv_2x128_4x64( void *dst, const void *src0,
                                       const void *src1, const int bit_len )
{
   v128_t *d = (v128_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;
   d[ 0] = v128_unpacklo64( s0[ 0], s0[ 1] );
   d[ 1] = v128_unpacklo64( s1[ 0], s1[ 1] );
   d[ 2] = v128_unpackhi64( s0[ 0], s0[ 1] );
   d[ 3] = v128_unpackhi64( s1[ 0], s1[ 1] );
   d[ 4] = v128_unpacklo64( s0[ 2], s0[ 3] );
   d[ 5] = v128_unpacklo64( s1[ 2], s1[ 3] );
   d[ 6] = v128_unpackhi64( s0[ 2], s0[ 3] );
   d[ 7] = v128_unpackhi64( s1[ 2], s1[ 3] );
   if ( bit_len <= 256 ) return;
   d[ 8] = v128_unpacklo64( s0[ 4], s0[ 5] );
   d[ 9] = v128_unpacklo64( s1[ 4], s1[ 5] );
   d[10] = v128_unpackhi64( s0[ 4], s0[ 5] );
   d[11] = v128_unpackhi64( s1[ 4], s1[ 5] );
   d[12] = v128_unpacklo64( s0[ 6], s0[ 7] );
   d[13] = v128_unpacklo64( s1[ 6], s1[ 7] );
   d[14] = v128_unpackhi64( s0[ 6], s0[ 7] );
   d[15] = v128_unpackhi64( s1[ 6], s1[ 7] );
   if ( bit_len <= 512 ) return;
   d[16] = v128_unpacklo64( s0[ 8], s0[ 9] );
   d[17] = v128_unpacklo64( s1[ 8], s1[ 9] );
   d[18] = v128_unpackhi64( s0[ 8], s0[ 9] );
   d[19] = v128_unpackhi64( s1[ 8], s1[ 9] );
   if ( bit_len <= 640 ) return;
   d[20] = v128_unpacklo64( s0[10], s0[11] );
   d[21] = v128_unpacklo64( s1[10], s1[11] );
   d[22] = v128_unpackhi64( s0[10], s0[11] );
   d[23] = v128_unpackhi64( s1[10], s1[11] );
   d[24] = v128_unpacklo64( s0[12], s0[13] );
   d[25] = v128_unpacklo64( s1[12], s1[13] );
   d[26] = v128_unpackhi64( s0[12], s0[13] );
   d[27] = v128_unpackhi64( s1[12], s1[13] );
   d[28] = v128_unpacklo64( s0[14], s0[15] );
   d[29] = v128_unpacklo64( s1[14], s1[15] );
   d[30] = v128_unpackhi64( s0[14], s0[15] );
   d[31] = v128_unpackhi64( s1[14], s1[15] );
}

// 4x64 -> 2x128

static inline void rintrlv_4x64_2x128( void *dst0, void *dst1,
                                       const void *src, const int bit_len )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   const v128u64_t* s = (const v128u64_t*)src;
   d0[ 0] = v128_unpacklo64( s[ 0], s[ 2] );
   d0[ 1] = v128_unpackhi64( s[ 0], s[ 2] );
   d1[ 0] = v128_unpacklo64( s[ 1], s[ 3] );
   d1[ 1] = v128_unpackhi64( s[ 1], s[ 3] );
   d0[ 2] = v128_unpacklo64( s[ 4], s[ 6] );
   d0[ 3] = v128_unpackhi64( s[ 4], s[ 6] );
   d1[ 2] = v128_unpacklo64( s[ 5], s[ 7] );
   d1[ 3] = v128_unpackhi64( s[ 5], s[ 7] );
   if ( bit_len <= 256 ) return;
   d0[ 4] = v128_unpacklo64( s[ 8], s[10] );
   d0[ 5] = v128_unpackhi64( s[ 8], s[10] );
   d1[ 4] = v128_unpacklo64( s[ 9], s[11] );
   d1[ 5] = v128_unpackhi64( s[ 9], s[11] );
   d0[ 6] = v128_unpacklo64( s[12], s[14] );
   d0[ 7] = v128_unpackhi64( s[12], s[14] );
   d1[ 6] = v128_unpacklo64( s[13], s[15] );
   d1[ 7] = v128_unpackhi64( s[13], s[15] );
   if ( bit_len <= 512 ) return;
   d0[ 8] = v128_unpacklo64( s[16], s[18] );
   d0[ 9] = v128_unpackhi64( s[16], s[18] );
   d1[ 8] = v128_unpacklo64( s[17], s[19] );
   d1[ 9] = v128_unpackhi64( s[17], s[19] );
   if ( bit_len <= 640 ) return;
   d0[10] = v128_unpacklo64( s[20], s[22] );
   d0[11] = v128_unpackhi64( s[20], s[22] );
   d1[10] = v128_unpacklo64( s[21], s[23] );
   d1[11] = v128_unpackhi64( s[21], s[23] );
   d0[12] = v128_unpacklo64( s[24], s[26] );
   d0[13] = v128_unpackhi64( s[24], s[26] );
   d1[12] = v128_unpacklo64( s[25], s[27] );
   d1[13] = v128_unpackhi64( s[25], s[27] );
   d0[14] = v128_unpacklo64( s[28], s[30] );
   d0[15] = v128_unpackhi64( s[28], s[30] );
   d1[14] = v128_unpacklo64( s[29], s[31] );
   d1[15] = v128_unpackhi64( s[29], s[31] );
}

// 2x128 -> 8x64

static inline void rintrlv_4x128_8x64( void *dst, const void *src0,
                                       const void *src1, const int bit_len )
{
   v128u64_t *d = (v128_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;

   d[ 0] = v128_unpacklo64( s0[ 0], s0[ 1] );
   d[ 1] = v128_unpacklo64( s0[ 2], s0[ 3] );
   d[ 2] = v128_unpacklo64( s1[ 0], s1[ 1] );
   d[ 3] = v128_unpacklo64( s1[ 2], s1[ 3] );
   d[ 4] = v128_unpackhi64( s0[ 0], s0[ 1] );
   d[ 5] = v128_unpackhi64( s0[ 2], s0[ 3] );
   d[ 6] = v128_unpackhi64( s1[ 0], s1[ 1] );
   d[ 7] = v128_unpackhi64( s1[ 2], s1[ 3] );

   d[ 8] = v128_unpacklo64( s0[ 4], s0[ 5] );
   d[ 9] = v128_unpacklo64( s0[ 6], s0[ 7] );
   d[10] = v128_unpacklo64( s1[ 4], s1[ 5] );
   d[11] = v128_unpacklo64( s1[ 6], s1[ 7] );
   d[12] = v128_unpackhi64( s0[ 4], s0[ 5] );
   d[13] = v128_unpackhi64( s0[ 6], s0[ 7] );
   d[14] = v128_unpackhi64( s1[ 4], s1[ 5] );
   d[15] = v128_unpackhi64( s1[ 6], s1[ 7] );

   if ( bit_len <= 256 ) return;

   d[16] = v128_unpacklo64( s0[ 8], s0[ 9] );
   d[17] = v128_unpacklo64( s0[10], s0[11] );
   d[18] = v128_unpacklo64( s1[ 8], s1[ 9] );
   d[19] = v128_unpacklo64( s1[10], s1[11] );
   d[20] = v128_unpackhi64( s0[ 8], s0[ 9] );
   d[21] = v128_unpackhi64( s0[10], s0[11] );
   d[22] = v128_unpackhi64( s1[ 8], s1[ 9] );
   d[23] = v128_unpackhi64( s1[10], s1[11] );

   d[24] = v128_unpacklo64( s0[12], s0[13] );
   d[25] = v128_unpacklo64( s0[14], s0[15] );
   d[26] = v128_unpacklo64( s1[12], s1[13] );
   d[27] = v128_unpacklo64( s1[14], s1[15] );
   d[28] = v128_unpackhi64( s0[12], s0[13] );
   d[29] = v128_unpackhi64( s0[14], s0[15] );
   d[30] = v128_unpackhi64( s1[12], s1[13] );
   d[31] = v128_unpackhi64( s1[14], s1[15] );

   if ( bit_len <= 512 ) return;

   d[32] = v128_unpacklo64( s0[16], s0[17] );
   d[33] = v128_unpacklo64( s0[18], s0[19] );
   d[34] = v128_unpacklo64( s1[16], s1[17] );
   d[35] = v128_unpacklo64( s1[18], s1[19] );
   d[36] = v128_unpackhi64( s0[16], s0[17] );
   d[37] = v128_unpackhi64( s0[18], s0[19] );
   d[38] = v128_unpackhi64( s1[16], s1[17] );
   d[39] = v128_unpackhi64( s1[18], s1[19] );

   if ( bit_len <= 640 ) return;
   
   d[40] = v128_unpacklo64( s0[20], s0[21] );
   d[41] = v128_unpacklo64( s0[22], s0[23] );
   d[42] = v128_unpacklo64( s1[20], s1[21] );
   d[43] = v128_unpacklo64( s1[22], s1[23] );
   d[44] = v128_unpackhi64( s0[20], s0[21] );
   d[45] = v128_unpackhi64( s0[22], s0[23] );
   d[46] = v128_unpackhi64( s1[20], s1[21] );
   d[47] = v128_unpackhi64( s1[22], s1[23] );

   d[48] = v128_unpacklo64( s0[24], s0[25] );
   d[49] = v128_unpacklo64( s0[26], s0[27] );
   d[50] = v128_unpacklo64( s1[24], s1[25] );
   d[51] = v128_unpacklo64( s1[26], s1[27] );
   d[52] = v128_unpackhi64( s0[24], s0[25] );
   d[53] = v128_unpackhi64( s0[26], s0[27] );
   d[54] = v128_unpackhi64( s1[24], s1[25] );
   d[55] = v128_unpackhi64( s1[26], s1[27] );

   d[56] = v128_unpacklo64( s0[28], s0[29] );
   d[57] = v128_unpacklo64( s0[30], s0[31] );
   d[58] = v128_unpacklo64( s1[28], s1[29] );
   d[59] = v128_unpacklo64( s1[30], s1[31] );
   d[60] = v128_unpackhi64( s0[28], s0[29] );
   d[61] = v128_unpackhi64( s0[30], s0[31] );
   d[62] = v128_unpackhi64( s1[28], s1[29] );
   d[63] = v128_unpackhi64( s1[30], s1[31] );
}

// 8x64 -> 4x128

static inline void rintrlv_8x64_4x128( void *dst0, void *dst1,
                                       const void *src, const int bit_len )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   const v128u64_t* s = (const v128u64_t*)src;

   d0[ 0] = v128_unpacklo64( s[ 0], s[ 4] );
   d0[ 1] = v128_unpackhi64( s[ 0], s[ 4] );
   d1[ 0] = v128_unpacklo64( s[ 2], s[ 6] );
   d1[ 1] = v128_unpackhi64( s[ 2], s[ 6] );
   d0[ 2] = v128_unpacklo64( s[ 1], s[ 5] );
   d0[ 3] = v128_unpackhi64( s[ 1], s[ 5] );
   d1[ 2] = v128_unpacklo64( s[ 3], s[ 7] );
   d1[ 3] = v128_unpackhi64( s[ 3], s[ 7] );

   d0[ 4] = v128_unpacklo64( s[ 8], s[12] );
   d0[ 5] = v128_unpackhi64( s[ 8], s[12] );
   d1[ 4] = v128_unpacklo64( s[10], s[14] );
   d1[ 5] = v128_unpackhi64( s[10], s[14] );
   d0[ 6] = v128_unpacklo64( s[ 9], s[13] );
   d0[ 7] = v128_unpackhi64( s[ 9], s[13] );
   d1[ 6] = v128_unpacklo64( s[11], s[15] );
   d1[ 7] = v128_unpackhi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[ 8] = v128_unpacklo64( s[16], s[20] );
   d0[ 9] = v128_unpackhi64( s[16], s[20] );
   d1[ 8] = v128_unpacklo64( s[18], s[22] );
   d1[ 9] = v128_unpackhi64( s[18], s[22] );
   d0[10] = v128_unpacklo64( s[17], s[21] );
   d0[11] = v128_unpackhi64( s[17], s[21] );
   d1[10] = v128_unpacklo64( s[19], s[23] );
   d1[11] = v128_unpackhi64( s[19], s[23] );

   d0[12] = v128_unpacklo64( s[24], s[28] );
   d0[13] = v128_unpackhi64( s[24], s[28] );
   d1[12] = v128_unpacklo64( s[26], s[30] );
   d1[13] = v128_unpackhi64( s[26], s[30] );
   d0[14] = v128_unpacklo64( s[25], s[29] );
   d0[15] = v128_unpackhi64( s[25], s[29] );
   d1[14] = v128_unpacklo64( s[27], s[31] );
   d1[15] = v128_unpackhi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[16] = v128_unpacklo64( s[32], s[36] );
   d0[17] = v128_unpackhi64( s[32], s[36] );
   d1[16] = v128_unpacklo64( s[34], s[38] );
   d1[17] = v128_unpackhi64( s[34], s[38] );
   d0[18] = v128_unpacklo64( s[33], s[37] );
   d0[19] = v128_unpackhi64( s[33], s[37] );
   d1[18] = v128_unpacklo64( s[35], s[39] );
   d1[19] = v128_unpackhi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[20] = v128_unpacklo64( s[40], s[44] );
   d0[21] = v128_unpackhi64( s[40], s[44] );
   d1[20] = v128_unpacklo64( s[42], s[46] );
   d1[21] = v128_unpackhi64( s[42], s[46] );
   d0[22] = v128_unpacklo64( s[41], s[45] );
   d0[23] = v128_unpackhi64( s[41], s[45] );
   d1[22] = v128_unpacklo64( s[43], s[47] );
   d1[23] = v128_unpackhi64( s[43], s[47] );

   d0[24] = v128_unpacklo64( s[48], s[52] );
   d0[25] = v128_unpackhi64( s[48], s[52] );
   d1[24] = v128_unpacklo64( s[50], s[54] );
   d1[25] = v128_unpackhi64( s[50], s[54] );
   d0[26] = v128_unpacklo64( s[49], s[53] );
   d0[27] = v128_unpackhi64( s[49], s[53] );
   d1[26] = v128_unpacklo64( s[51], s[55] );
   d1[27] = v128_unpackhi64( s[51], s[55] );

   d0[28] = v128_unpacklo64( s[56], s[60] );
   d0[29] = v128_unpackhi64( s[56], s[60] );
   d1[28] = v128_unpacklo64( s[58], s[62] );
   d1[29] = v128_unpackhi64( s[58], s[62] );
   d0[30] = v128_unpacklo64( s[57], s[61] );
   d0[31] = v128_unpackhi64( s[57], s[61] );
   d1[30] = v128_unpacklo64( s[59], s[63] );
   d1[31] = v128_unpackhi64( s[59], s[63] );
}

// 8x64 -> 2x256


static inline void rintrlv_8x64_2x256( void *dst0, void *dst1, void *dst2,
                          void *dst3,  const void *src, const int bit_len )
{
   v128u64_t *d0 = (v128u64_t*)dst0;
   v128u64_t *d1 = (v128u64_t*)dst1;
   v128u64_t *d2 = (v128u64_t*)dst2;
   v128u64_t *d3 = (v128u64_t*)dst3;
   const v128_t* s = (const v128_t*)src;

   d0[ 0] = v128_unpacklo64( s[ 0], s[ 4] );
   d1[ 0] = v128_unpackhi64( s[ 0], s[ 4] );
   d2[ 0] = v128_unpacklo64( s[ 1], s[ 5] );   
   d3[ 0] = v128_unpackhi64( s[ 1], s[ 5] );
   d0[ 1] = v128_unpacklo64( s[ 2], s[ 6] ); 
   d1[ 1] = v128_unpackhi64( s[ 2], s[ 6] );
   d2[ 1] = v128_unpacklo64( s[ 3], s[ 7] ); 
   d3[ 1] = v128_unpackhi64( s[ 3], s[ 7] );
   
   d0[ 2] = v128_unpacklo64( s[ 8], s[12] ); 
   d1[ 2] = v128_unpackhi64( s[ 8], s[12] );
   d2[ 2] = v128_unpacklo64( s[ 9], s[13] ); 
   d3[ 2] = v128_unpackhi64( s[ 9], s[13] );
   d0[ 3] = v128_unpacklo64( s[10], s[14] );
   d1[ 3] = v128_unpackhi64( s[10], s[14] );
   d2[ 3] = v128_unpacklo64( s[11], s[15] );
   d3[ 3] = v128_unpackhi64( s[11], s[15] );

   if ( bit_len <= 256 ) return;

   d0[ 4] = v128_unpacklo64( s[16], s[20] );
   d1[ 4] = v128_unpackhi64( s[16], s[20] );
   d2[ 4] = v128_unpacklo64( s[17], s[21] );
   d3[ 4] = v128_unpackhi64( s[17], s[21] );
   d0[ 5] = v128_unpacklo64( s[18], s[22] );
   d1[ 5] = v128_unpackhi64( s[18], s[22] );
   d2[ 5] = v128_unpacklo64( s[19], s[23] );
   d3[ 5] = v128_unpackhi64( s[19], s[23] );
   
   d0[ 6] = v128_unpacklo64( s[24], s[28] );
   d1[ 6] = v128_unpackhi64( s[24], s[28] );
   d2[ 6] = v128_unpacklo64( s[25], s[29] );
   d3[ 6] = v128_unpackhi64( s[25], s[29] );
   d0[ 7] = v128_unpacklo64( s[26], s[30] );
   d1[ 7] = v128_unpackhi64( s[26], s[30] );
   d2[ 7] = v128_unpacklo64( s[27], s[31] );
   d3[ 7] = v128_unpackhi64( s[27], s[31] );

   if ( bit_len <= 512 ) return;

   d0[ 8] = v128_unpacklo64( s[32], s[36] );
   d1[ 8] = v128_unpackhi64( s[32], s[36] );
   d2[ 8] = v128_unpacklo64( s[33], s[37] );
   d3[ 8] = v128_unpackhi64( s[33], s[37] );
   d0[ 9] = v128_unpacklo64( s[34], s[38] );
   d1[ 9] = v128_unpackhi64( s[34], s[38] );
   d2[ 9] = v128_unpacklo64( s[35], s[39] );
   d3[ 9] = v128_unpackhi64( s[35], s[39] );

   if ( bit_len <= 640 ) return;

   d0[10] = v128_unpacklo64( s[40], s[44] );
   d1[10] = v128_unpackhi64( s[40], s[44] );
   d2[10] = v128_unpacklo64( s[41], s[45] );
   d3[10] = v128_unpackhi64( s[41], s[45] );
   d0[11] = v128_unpacklo64( s[42], s[46] );
   d1[11] = v128_unpackhi64( s[42], s[46] );
   d2[11] = v128_unpacklo64( s[43], s[47] );
   d3[11] = v128_unpackhi64( s[43], s[47] );

   d0[12] = v128_unpacklo64( s[48], s[52] );
   d1[12] = v128_unpackhi64( s[48], s[52] );
   d2[12] = v128_unpacklo64( s[49], s[53] );
   d3[12] = v128_unpackhi64( s[49], s[53] );
   d0[13] = v128_unpacklo64( s[50], s[54] );
   d1[13] = v128_unpackhi64( s[50], s[54] );
   d2[13] = v128_unpacklo64( s[51], s[55] );
   d3[13] = v128_unpackhi64( s[51], s[55] );

   d0[14] = v128_unpacklo64( s[56], s[60] );
   d1[14] = v128_unpackhi64( s[56], s[60] );
   d2[14] = v128_unpacklo64( s[57], s[61] );
   d3[14] = v128_unpackhi64( s[57], s[61] );
   d0[15] = v128_unpacklo64( s[58], s[62] );
   d1[15] = v128_unpackhi64( s[58], s[62] );
   d2[15] = v128_unpacklo64( s[59], s[63] );
   d3[15] = v128_unpackhi64( s[59], s[63] );
}

// 4x128 -> 8x64

static inline void rintrlv_2x256_8x64( void *dst, const void *src0,
      const void *src1, const void *src2, const void *src3, const int bit_len )
{
   v128u64_t *d = (v128u64_t*)dst;
   const v128u64_t *s0 = (const v128u64_t*)src0;
   const v128u64_t *s1 = (const v128u64_t*)src1;
   const v128u64_t *s2 = (const v128u64_t*)src2;
   const v128u64_t *s3 = (const v128u64_t*)src3;

   d[ 0] = v128_unpacklo64( s0[0], s0[2] );
   d[ 1] = v128_unpacklo64( s1[0], s1[2] );
   d[ 2] = v128_unpacklo64( s2[0], s2[2] );
   d[ 3] = v128_unpacklo64( s3[0], s3[2] );
   d[ 4] = v128_unpackhi64( s0[0], s0[2] );
   d[ 5] = v128_unpackhi64( s1[0], s1[2] );
   d[ 6] = v128_unpackhi64( s2[0], s2[2] );
   d[ 7] = v128_unpackhi64( s3[0], s3[2] );

   d[ 8] = v128_unpacklo64( s0[1], s0[3] );
   d[ 9] = v128_unpacklo64( s1[1], s1[3] );
   d[10] = v128_unpacklo64( s2[1], s2[3] );
   d[11] = v128_unpacklo64( s3[1], s3[3] );
   d[12] = v128_unpackhi64( s0[1], s0[3] );
   d[13] = v128_unpackhi64( s1[1], s1[3] );
   d[14] = v128_unpackhi64( s2[1], s2[3] );
   d[15] = v128_unpackhi64( s3[1], s3[3] );

   if ( bit_len <= 256 ) return;

   d[16] = v128_unpacklo64( s0[4], s0[6] );
   d[17] = v128_unpacklo64( s1[4], s1[6] );
   d[18] = v128_unpacklo64( s2[4], s2[6] );
   d[19] = v128_unpacklo64( s3[4], s3[6] );
   d[20] = v128_unpackhi64( s0[4], s0[6] );
   d[21] = v128_unpackhi64( s1[4], s1[6] );
   d[22] = v128_unpackhi64( s2[4], s2[6] );
   d[23] = v128_unpackhi64( s3[4], s3[6] );

   d[24] = v128_unpacklo64( s0[5], s0[7] );
   d[25] = v128_unpacklo64( s1[5], s1[7] );
   d[26] = v128_unpacklo64( s2[5], s2[7] );
   d[27] = v128_unpacklo64( s3[5], s3[7] );
   d[28] = v128_unpackhi64( s0[5], s0[7] );
   d[29] = v128_unpackhi64( s1[5], s1[7] );
   d[30] = v128_unpackhi64( s2[5], s2[7] );
   d[31] = v128_unpackhi64( s3[5], s3[7] );

   if ( bit_len <= 512 ) return;

   d[32] = v128_unpacklo64( s0[8], s0[10] );
   d[33] = v128_unpacklo64( s1[8], s1[10] );
   d[34] = v128_unpacklo64( s2[8], s2[10] );
   d[35] = v128_unpacklo64( s3[8], s3[10] );
   d[36] = v128_unpackhi64( s0[8], s0[10] );
   d[37] = v128_unpackhi64( s1[8], s1[10] );
   d[38] = v128_unpackhi64( s2[8], s2[10] );
   d[39] = v128_unpackhi64( s3[8], s3[10] );

   if ( bit_len <= 640 ) return;

   d[40] = v128_unpacklo64( s0[9], s0[11] );
   d[41] = v128_unpacklo64( s1[9], s1[11] );
   d[42] = v128_unpacklo64( s2[9], s2[11] );
   d[43] = v128_unpacklo64( s3[9], s3[11] );
   d[44] = v128_unpackhi64( s0[9], s0[11] );
   d[45] = v128_unpackhi64( s1[9], s1[11] );
   d[46] = v128_unpackhi64( s2[9], s2[11] );
   d[47] = v128_unpackhi64( s3[9], s3[11] );

   d[48] = v128_unpacklo64( s0[12], s0[14] );
   d[49] = v128_unpacklo64( s1[12], s1[14] );
   d[50] = v128_unpacklo64( s2[12], s2[14] );
   d[51] = v128_unpacklo64( s3[12], s3[14] );
   d[52] = v128_unpackhi64( s0[12], s0[14] );
   d[53] = v128_unpackhi64( s1[12], s1[14] );
   d[54] = v128_unpackhi64( s2[12], s2[14] );
   d[55] = v128_unpackhi64( s3[12], s3[14] );

   d[56] = v128_unpacklo64( s0[13], s0[15] );
   d[57] = v128_unpacklo64( s1[13], s1[15] );
   d[58] = v128_unpacklo64( s2[13], s2[15] );
   d[59] = v128_unpacklo64( s3[13], s3[15] );
   d[60] = v128_unpackhi64( s0[13], s0[15] );
   d[61] = v128_unpackhi64( s1[13], s1[15] );
   d[62] = v128_unpackhi64( s2[13], s2[15] );
   d[63] = v128_unpackhi64( s3[13], s3[15] );
}

#endif  // SSE2

//
// Some functions customized for mining.

// blend 2 vectors while interleaving: { hi[n], lo[n-1], ... hi[1], lo[0] }
#if defined(__SSE4_1__)

#define v128_intrlv_blend_64( hi, lo )   _mm_blend_epi16( hi, lo, 0x0f )
#define v128_intrlv_blend_32( hi, lo )   _mm_blend_epi16( hi, lo, 0x33 )

#elif defined(__SSE2__) || defined(__ARM_NEON)

#define v128_intrlv_blend_64( hi, lo )  \
   v128_blendv( hi, lo, v128_set64( 0ull, 0xffffffffffffffffull ) )

#define v128_intrlv_blend_32( hi, lo ) \
   v128_blendv( hi, lo, v128_set64( 0xffffffffull, 0xffffffffull ) )

#else
// unknown, unsupported architecture
#endif

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

//TODO Enable for AVX10_512

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

#undef ILEAVE_4x32
#undef LOAD_SRCE
#undef ILEAVE_STORE_DEST

#endif // INTERLEAVE_H__
