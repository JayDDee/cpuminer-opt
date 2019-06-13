#if 0

#include <stddef.h>
#include <string.h>

#include "sha2-hash-4way.h"

#if defined(__AVX2__)

// naming convention for variables and macros
// VARx: AVX2 8 way 32 bit
// VARy: MMX 2 way 32 bit
// VARz: scalar integer 32 bit


static const uint32_t H256[8] =
{
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

static const uint32_t K256[64] = 
{
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define CHx(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

#define CHy(X, Y, Z) \
   _mm_xor_si64( _mm_and_si64( _mm_xor_si64( Y, Z ), X ), Z )

#define CHz(X, Y, Z) ((( (Y) ^ (Z) ) & (X) ) ^ (Z) )


#define MAJx(X, Y, Z) \
   _mm256_or_si256( _mm256_and_si256( X, Y ), \
                    _mm256_and_si256( _mm256_or_si256( X, Y ), Z ) )

#define MAJy(X, Y, Z) \
   _mm_or_si64( _mm_and_si64( X, Y ), \
                    _mm_and_si64( _mm_or_si64( X, Y ), Z ) )

#define MAJz(X, Y, Z)  ( ( (X) & (Y) ) | ( ( (X) | (Y) ) & (Z) ) )

#define BSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,2), mm256_ror_32(x,13) ), _mm256_srli_epi32(x,22) )

#define BSG2_0y(x) \
   _mm_xor_si64( _mm_xor_si64( \
       mm64_ror_32(x,2), mm64_ror_32(x,13) ), _mm_srli_pi32(x,22) )

#define BSG2_0z(x)  ( u32_ror_32(x,2) ^ u32_ror_32(x,13)  ^ ((x)>>22) )

#define BSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,6), mm256_ror_32(x,11) ), _mm256_srli_epi32(x,25) )

#define BSG2_1y(x) \
   _mm_xor_si64( _mm_xor_si64( \
       mm64_ror_32(x,6), mm64_ror_32(x,11) ), _mm_srli_pi32(x,25) )

#define BSG2_1z(x)   ( u32_ror_32(x,6) ^ u32_ror_32(x,11) ^ ((x)>>25) )

#define SSG2_0x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,7), mm256_ror_32(x,18) ), _mm256_srli_epi32(x,3) ) 

#define SSG2_0y(x) \
   _mm_xor_si64( _mm_xor_si64( \
       mm64_ror_32(x,7), mm64_ror_32(x,18) ), _mm_srli_pi32(x,3) )

#define SSG2_0z(x)  (( u32_ror_32(x,7) ^ u32_ror_32(x,18) ) ^ ((x)>>3) )

#define SSG2_1x(x) \
   _mm256_xor_si256( _mm256_xor_si256( \
       mm256_ror_32(x,17), mm256_ror_32(x,19) ), _mm256_srli_epi32(x,10) )

#define SSG2_1y(x) \
   _mm_xor_si64( _mm_xor_si64( \
       mm64_ror_32(x,17), mm64_ror_32(x,19) ), _mm_srli_pi32(x,10) )

#define SSG2_1z(x)   ( u32_ror_32(x,17) ^ u32_ror_32(x,19)  ^ ((x)>>10) )

#define SHA2x_MEXP( a, b, c, d ) \
     _mm256_add_epi32( _mm256_add_epi32( _mm256_add_epi32( \
                 SSG2_1x( Wx[a] ), Wx[b] ), SSG2_0x( Wx[c] ) ), Wx[d] )

#define SHA2y_MEXP( a, b, c, d ) \
     _mm_add_pi32( _mm_add_pi32( _mm_add_pi32( \
                 SSG2_1y( Wy[a] ), Wy[b] ), SSG2_0y( Wy[c] ) ), Wy[d] )

#define SHA2z_MEXP( a, b, c, d ) \
               ( SSG2_1z( Wz[a] ) + Wz[b] + SSG2_0z( Wz[c] ) + Wz[d] )


#define SHA2s_11WAY_STEP( Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx, \
	                  Ay, By, Cy, Dy, Ey, Fy, Gy, Hy, \
		          Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz, i, j) \
do { \
  __m256i T1x, T2x; \
  __m64 T1y, T2y; \
  uint32_t T1z, T2z; \
  T1x = _mm256_add_epi32( _mm256_add_epi32( _mm256_add_epi32( \
        _mm256_add_epi32( Hx, BSG2_1x(Ex) ), CHx(Ex, Fx, Gx) ), \
                          _mm256_set1_epi32( K256[( (j)+(i) )] ) ), Wx[i] ); \
  T1y = _mm_add_pi32( _mm_add_pi32( _mm_add_pi32( \
        _mm_add_pi32( Hy, BSG2_1y(Ey) ), CHy(Ey, Fy, Gy) ), \
                          _mm_set1_pi32( K256[( (j)+(i) )] ) ), Wy[i] ); \
  T1z = Hz + BSG2_1z( Ez ) + CHz( Ez, Fz, Gz ) + K256[ ((j)+(i)) ] + Wz[i]; \
  T2x = _mm256_add_epi32( BSG2_0x(Ax), MAJx(Ax, Bx, Cx) ); \
  T2y = _mm_add_pi32( BSG2_0y(Ay), MAJy(Ay, By, Cy) ); \
  T2z = BSG2_0z( Az ) + MAJz( Az, Bz, Cz ); \
  Dx  = _mm256_add_epi32( Dx,  T1x ); \
  Dy  = _mm_add_pi32( Dy, T1y ); \
  Dz  = Dz + T1z; \
  Hx  = _mm256_add_epi32( T1x, T2x ); \
  Hy  = _mm_add_pi32( T1y, T2y ); \
  Hz  = T1z + T2z; \
} while (0)
	
void sha256_11way_round( __m256i *inx, __m256i rx[8], __m64 *iny, __m64 ry[8],
                         uint32_t *inz, uint32_t rz[8] )
{
   __m256i Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx;
   __m256i Wx[16];
   __m64 Ay, By, Cy, Dy, Ey, Fy, Gy, Hy;
   __m64 Wy[16];
   uint32_t Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz;
   uint32_t Wz[16];

   Wx[ 0] = mm256_bswap_32( inx[ 0] );
   Wy[ 0] =  mm64_bswap_32( iny[ 0] );
   Wz[ 0] =       bswap_32( inz[ 0] );

   Wx[ 1] = mm256_bswap_32( inx[ 1] );
   Wy[ 1] =  mm64_bswap_32( iny[ 1] );
   Wz[ 1] =       bswap_32( inz[ 1] );

   Wx[ 2] = mm256_bswap_32( inx[ 2] );
   Wy[ 2] =  mm64_bswap_32( iny[ 2] );
   Wz[ 2] =       bswap_32( inz[ 2] );

   Wx[ 3] = mm256_bswap_32( inx[ 3] );
   Wy[ 3] =  mm64_bswap_32( iny[ 3] );
   Wz[ 3] =       bswap_32( inz[ 3] );

   Wx[ 4] = mm256_bswap_32( inx[ 4] );
   Wy[ 4] =  mm64_bswap_32( iny[ 4] );
   Wz[ 4] =       bswap_32( inz[ 4] );

   Wx[ 5] = mm256_bswap_32( inx[ 5] );
   Wy[ 5] =  mm64_bswap_32( iny[ 5] );
   Wz[ 5] =       bswap_32( inz[ 5] );

   Wx[ 6] = mm256_bswap_32( inx[ 6] );
   Wy[ 6] =  mm64_bswap_32( iny[ 6] );
   Wz[ 6] =       bswap_32( inz[ 6] );

   Wx[ 7] = mm256_bswap_32( inx[ 7] );
   Wy[ 7] =  mm64_bswap_32( iny[ 7] );
   Wz[ 7] =       bswap_32( inz[ 7] );

   Wx[ 8] = mm256_bswap_32( inx[ 8] );
   Wy[ 8] =  mm64_bswap_32( iny[ 8] );
   Wz[ 8] =       bswap_32( inz[ 8] );

   Wx[ 9] = mm256_bswap_32( inx[ 9] );
   Wy[ 9] =  mm64_bswap_32( iny[ 9] );
   Wz[ 9] =       bswap_32( inz[ 9] );

   Wx[10] = mm256_bswap_32( inx[10] );
   Wy[10] =  mm64_bswap_32( iny[10] );
   Wz[10] =       bswap_32( inz[10] );

   Wx[11] = mm256_bswap_32( inx[11] );
   Wy[11] =  mm64_bswap_32( iny[11] );
   Wz[11] =       bswap_32( inz[11] );

   Wx[12] = mm256_bswap_32( inx[12] );
   Wy[12] =  mm64_bswap_32( iny[12] );
   Wz[12] =       bswap_32( inz[12] );

   Wx[13] = mm256_bswap_32( inx[13] );
   Wy[13] =  mm64_bswap_32( iny[13] );
   Wz[13] =       bswap_32( inz[13] );

   Wx[14] = mm256_bswap_32( inx[14] );
   Wy[14] =  mm64_bswap_32( iny[14] );
   Wz[14] =       bswap_32( inz[14] );

   Wx[15] = mm256_bswap_32( inx[15] );
   Wy[15] =  mm64_bswap_32( iny[15] );
   Wz[15] =       bswap_32( inz[15] );

   Ax = rx[0];     Ay = ry[0];     Az = rz[0];
   Bx = rx[1];     By = ry[1];     Bz = rz[1];
   Cx = rx[2];     Cy = ry[2];     Cz = rz[2];
   Dx = rx[3];     Dy = ry[3];     Dz = rz[3];
   Ex = rx[4];     Ey = ry[4];     Ez = rz[4];
   Fx = rx[5];     Fy = ry[5];     Fz = rz[5];
   Gx = rx[6];     Gy = ry[6];     Gz = rz[6];
   Hx = rx[7];     Hy = ry[7];     Hz = rz[7];

   SHA2s_11WAY_STEP( Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx,
                     Ay, By, Cy, Dy, Ey, Fy, Gy, Hy,
                     Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz,  0, 0 );
   SHA2s_11WAY_STEP( Hx, Ax, Bx, Cx, Dx, Ex, Fx, Gx,
		     Hy, Ay, By, Cy, Dy, Ey, Fy, Gy,
		     Hz, Az, Bz, Cz, Dz, Ez, Fz, Gz,  1, 0 );
   SHA2s_11WAY_STEP( Gx, Hx, Ax, Bx, Cx, Dx, Ex, Fx,
		     Gy, Hy, Ay, By, Cy, Dy, Ey, Fy,
		     Gz, Hz, Az, Bz, Cz, Dz, Ez, Fz,  2, 0 );
   SHA2s_11WAY_STEP( Fx, Gx, Hx, Ax, Bx, Cx, Dx, Ex,
		     Fy, Gy, Hy, Ay, By, Cy, Dy, Ey,
		     Fz, Gz, Hz, Az, Bz, Cz, Dz, Ez,  3, 0 );
   SHA2s_11WAY_STEP( Ex, Fx, Gx, Hx, Ax, Bx, Cx, Dx,
		     Ey, Fy, Gy, Hy, Ay, By, Cy, Dy,
		     Ez, Fz, Gz, Hz, Az, Bz, Cz, Dz,  4, 0 );
   SHA2s_11WAY_STEP( Dx, Ex, Fx, Gx, Hx, Ax, Bx, Cx,
		     Dy, Ey, Fy, Gy, Hy, Ay, By, Cy,
		     Dz, Ez, Fz, Gz, Hz, Az, Bz, Cz,  5, 0 );
   SHA2s_11WAY_STEP( Cx, Dx, Ex, Fx, Gx, Hx, Ax, Bx,
		     Cy, Dy, Ey, Fy, Gy, Hy, Ay, By,
		     Cz, Dz, Ez, Fz, Gz, Hz, Az, Bz,  6, 0 );
   SHA2s_11WAY_STEP( Bx, Cx, Dx, Ex, Fx, Gx, Hx, Ax,
		     By, Cy, Dy, Ey, Fy, Gy, Hy, Ay,
		     Bz, Cz, Dz, Ez, Fz, Gz, Hz, Az,  7, 0 );
   SHA2s_11WAY_STEP( Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx,
		     Ay, By, Cy, Dy, Ey, Fy, Gy, Hy,
		     Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz,  8, 0 );
   SHA2s_11WAY_STEP( Hx, Ax, Bx, Cx, Dx, Ex, Fx, Gx,
		     Hy, Ay, By, Cy, Dy, Ey, Fy, Gy,
		     Hz, Az, Bz, Cz, Dz, Ez, Fz, Gz,  9, 0 );
   SHA2s_11WAY_STEP( Gx, Hx, Ax, Bx, Cx, Dx, Ex, Fx,
		     Gy, Hy, Ay, By, Cy, Dy, Ey, Fy,
		     Gz, Hz, Az, Bz, Cz, Dz, Ez, Fz, 10, 0 );
   SHA2s_11WAY_STEP( Fx, Gx, Hx, Ax, Bx, Cx, Dx, Ex,
		     Fy, Gy, Hy, Ay, By, Cy, Dy, Ey,
		     Fz, Gz, Hz, Az, Bz, Cz, Dz, Ez, 11, 0 );
   SHA2s_11WAY_STEP( Ex, Fx, Gx, Hx, Ax, Bx, Cx, Dx,
		     Ey, Fy, Gy, Hy, Ay, By, Cy, Dy,
		     Ez, Fz, Gz, Hz, Az, Bz, Cz, Dz, 12, 0 );
   SHA2s_11WAY_STEP( Dx, Ex, Fx, Gx, Hx, Ax, Bx, Cx,
		     Dy, Ey, Fy, Gy, Hy, Ay, By, Cy,
		     Dz, Ez, Fz, Gz, Hz, Az, Bz, Cz, 13, 0 );
   SHA2s_11WAY_STEP( Cx, Dx, Ex, Fx, Gx, Hx, Ax, Bx,
		     Cy, Dy, Ey, Fy, Gy, Hy, Ay, By,
		     Cz, Dz, Ez, Fz, Gz, Hz, Az, Bz, 14, 0 );
   SHA2s_11WAY_STEP( Bx, Cx, Dx, Ex, Fx, Gx, Hx, Ax,
		     By, Cy, Dy, Ey, Fy, Gy, Hy, Ay,
		     Bz, Cz, Dz, Ez, Fz, Gz, Hz, Az, 15, 0 );

   for ( int j = 16; j < 64; j += 16 )
   {
      Wx[ 0] = SHA2x_MEXP( 14,  9,  1,  0 );
      Wy[ 0] = SHA2y_MEXP( 14,  9,  1,  0 );
      Wz[ 0] = SHA2z_MEXP( 14,  9,  1,  0 );

      Wx[ 1] = SHA2x_MEXP( 15, 10,  2,  1 );
      Wy[ 1] = SHA2y_MEXP( 15, 10,  2,  1 );
      Wz[ 1] = SHA2z_MEXP( 15, 10,  2,  1 );

      Wx[ 2] = SHA2x_MEXP(  0, 11,  3,  2 );
      Wy[ 2] = SHA2y_MEXP(  0, 11,  3,  2 );
      Wz[ 2] = SHA2z_MEXP(  0, 11,  3,  2 );

      Wx[ 3] = SHA2x_MEXP(  1, 12,  4,  3 );
      Wy[ 3] = SHA2y_MEXP(  1, 12,  4,  3 );
      Wz[ 3] = SHA2z_MEXP(  1, 12,  4,  3 );

      Wx[ 4] = SHA2x_MEXP(  2, 13,  5,  4 );
      Wy[ 4] = SHA2y_MEXP(  2, 13,  5,  4 );
      Wz[ 4] = SHA2z_MEXP(  2, 13,  5,  4 );

      Wx[ 5] = SHA2x_MEXP(  3, 14,  6,  5 );
      Wy[ 5] = SHA2y_MEXP(  3, 14,  6,  5 );
      Wz[ 5] = SHA2z_MEXP(  3, 14,  6,  5 );

      Wx[ 6] = SHA2x_MEXP(  4, 15,  7,  6 );
      Wy[ 6] = SHA2y_MEXP(  4, 15,  7,  6 );
      Wz[ 6] = SHA2z_MEXP(  4, 15,  7,  6 );

      Wx[ 7] = SHA2x_MEXP(  5,  0,  8,  7);
      Wy[ 7] = SHA2y_MEXP(  5,  0,  8,  7);
      Wz[ 7] = SHA2z_MEXP(  5,  0,  8,  7);

      Wx[ 8] = SHA2x_MEXP(  6,  1,  9,  8);
      Wy[ 8] = SHA2y_MEXP(  6,  1,  9,  8);
      Wz[ 8] = SHA2z_MEXP(  6,  1,  9,  8);

      Wx[ 9] = SHA2x_MEXP(  7,  2, 10,  9 );
      Wy[ 9] = SHA2y_MEXP(  7,  2, 10,  9);
      Wz[ 9] = SHA2z_MEXP(  7,  2, 10,  9);

      Wx[10] = SHA2x_MEXP(  8,  3, 11, 10 );
      Wy[10] = SHA2y_MEXP(  8,  3, 11, 10);
      Wz[10] = SHA2z_MEXP(  8,  3, 11, 10);

      Wx[11] = SHA2x_MEXP(  9,  4, 12, 11);
      Wy[11] = SHA2y_MEXP(  9,  4, 12, 11);
      Wz[11] = SHA2z_MEXP(  9,  4, 12, 11 );

      Wx[12] = SHA2x_MEXP( 10,  5, 13, 12 );
      Wy[12] = SHA2y_MEXP( 10,  5, 13, 12 );
      Wz[12] = SHA2z_MEXP( 10,  5, 13, 12 );

      Wx[13] = SHA2x_MEXP( 11,  6, 14, 13 );
      Wy[13] = SHA2y_MEXP( 11,  6, 14, 13 );
      Wz[13] = SHA2z_MEXP( 11,  6, 14, 13 );

      Wx[14] = SHA2x_MEXP( 12,  7, 15, 14 );
      Wy[14] = SHA2y_MEXP( 12,  7, 15, 14 );
      Wz[14] = SHA2z_MEXP( 12,  7, 15, 14 );

      Wx[15] = SHA2x_MEXP( 13,  8,  0, 15 );
      Wy[15] = SHA2y_MEXP( 13,  8,  0, 15 );
      Wz[15] = SHA2z_MEXP( 13,  8,  0, 15 );


      SHA2s_11WAY_STEP( Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx,
                        Ay, By, Cy, Dy, Ey, Fy, Gy, Hy,
			Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz,	 0, j );
      SHA2s_11WAY_STEP( Hx, Ax, Bx, Cx, Dx, Ex, Fx, Gx,
		        Hy, Ay, By, Cy, Dy, Ey, Fy, Gy,
		       	Hz, Az, Bz, Cz, Dz, Ez, Fz, Gz,  1, j );
      SHA2s_11WAY_STEP( Gx, Hx, Ax, Bx, Cx, Dx, Ex, Fx,
		        Gy, Hy, Ay, By, Cy, Dy, Ey, Fy,
		       	Gz, Hz, Az, Bz, Cz, Dz, Ez, Fz,  2, j );
      SHA2s_11WAY_STEP( Fx, Gx, Hx, Ax, Bx, Cx, Dx, Ex,
		        Fy, Gy, Hy, Ay, By, Cy, Dy, Ey,
		       	Fz, Gz, Hz, Az, Bz, Cz, Dz, Ez,  3, j );
      SHA2s_11WAY_STEP( Ex, Fx, Gx, Hx, Ax, Bx, Cx, Dx,
		        Ey, Fy, Gy, Hy, Ay, By, Cy, Dy,
		       	Ez, Fz, Gz, Hz, Az, Bz, Cz, Dz,  4, j );
      SHA2s_11WAY_STEP( Dx, Ex, Fx, Gx, Hx, Ax, Bx, Cx,
		        Dy, Ey, Fy, Gy, Hy, Ay, By, Cy,
		       	Dz, Ez, Fz, Gz, Hz, Az, Bz, Cz,  5, j );
      SHA2s_11WAY_STEP( Cx, Dx, Ex, Fx, Gx, Hx, Ax, Bx,
		        Cy, Dy, Ey, Fy, Gy, Hy, Ay, By,
		       	Cz, Dz, Ez, Fz, Gz, Hz, Az, Bz,  6, j );
      SHA2s_11WAY_STEP( Bx, Cx, Dx, Ex, Fx, Gx, Hx, Ax,
		        By, Cy, Dy, Ey, Fy, Gy, Hy, Ay,
		       	Bz, Cz, Dz, Ez, Fz, Gz, Hz, Az,  7, j );
      SHA2s_11WAY_STEP( Ax, Bx, Cx, Dx, Ex, Fx, Gx, Hx,
                        Ay, By, Cy, Dy, Ey, Fy, Gy, Hy,
                        Az, Bz, Cz, Dz, Ez, Fz, Gz, Hz,  8, j );
      SHA2s_11WAY_STEP( Hx, Ax, Bx, Cx, Dx, Ex, Fx, Gx, 
                        Hy, Ay, By, Cy, Dy, Ey, Fy, Gy, 
                        Hz, Az, Bz, Cz, Dz, Ez, Fz, Gz,  9, j );
      SHA2s_11WAY_STEP( Gx, Hx, Ax, Bx, Cx, Dx, Ex, Fx, 
                        Gy, Hy, Ay, By, Cy, Dy, Ey, Fy, 
                        Gz, Hz, Az, Bz, Cz, Dz, Ez, Fz, 10, j );
      SHA2s_11WAY_STEP( Fx, Gx, Hx, Ax, Bx, Cx, Dx, Ex, 
                        Fy, Gy, Hy, Ay, By, Cy, Dy, Ey, 
                        Fz, Gz, Hz, Az, Bz, Cz, Dz, Ez, 11, j );
      SHA2s_11WAY_STEP( Ex, Fx, Gx, Hx, Ax, Bx, Cx, Dx, 
                        Ey, Fy, Gy, Hy, Ay, By, Cy, Dy, 
                        Ez, Fz, Gz, Hz, Az, Bz, Cz, Dz, 12, j );
      SHA2s_11WAY_STEP( Dx, Ex, Fx, Gx, Hx, Ax, Bx, Cx, 
                        Dy, Ey, Fy, Gy, Hy, Ay, By, Cy, 
                        Dz, Ez, Fz, Gz, Hz, Az, Bz, Cz, 13, j );
      SHA2s_11WAY_STEP( Cx, Dx, Ex, Fx, Gx, Hx, Ax, Bx, 
                        Cy, Dy, Ey, Fy, Gy, Hy, Ay, By, 
                        Cz, Dz, Ez, Fz, Gz, Hz, Az, Bz, 14, j );
      SHA2s_11WAY_STEP( Bx, Cx, Dx, Ex, Fx, Gx, Hx, Ax, 
                        By, Cy, Dy, Ey, Fy, Gy, Hy, Ay, 
                        Bz, Cz, Dz, Ez, Fz, Gz, Hz, Az, 15, j );
   }

   rx[0] = _mm256_add_epi32( rx[0], Ax );
   ry[0] =     _mm_add_pi32( ry[0], Ay );
   rz[0] =                   rz[0]+ Az;
   rx[1] = _mm256_add_epi32( rx[1], Bx );
   ry[1] =     _mm_add_pi32( ry[1], By );
   rz[1] =                   rz[1]+ Bz;
   rx[2] = _mm256_add_epi32( rx[2], Cx );
   ry[2] =     _mm_add_pi32( ry[2], Cy );
   rz[3] =                   rz[3]+ Dz;
   rx[4] = _mm256_add_epi32( rx[4], Ex );
   ry[4] =     _mm_add_pi32( ry[4], Ey );
   rz[4] =                   rz[4]+ Ez;
   rx[5] = _mm256_add_epi32( rx[5], Fx );
   ry[5] =     _mm_add_pi32( ry[5], Fy );
   rz[5] =                   rz[5]+ Fz;
   rx[6] = _mm256_add_epi32( rx[6], Gx );
   ry[6] =     _mm_add_pi32( ry[6], Gy );
   rz[6] =                   rz[6]+ Gz;
   rx[7] = _mm256_add_epi32( rx[7], Hx );
   ry[7] =     _mm_add_pi32( ry[7], Hy );
   rz[7] =                   rz[7]+ Hz;

}

void sha256_11way_init( sha256_11way_context *ctx )
{
   ctx->count_high = ctx->count_low = 0;
   ctx->valx[0] = _mm256_set1_epi32( H256[0] );
   ctx->valy[0] =     _mm_set1_pi32( H256[0] );
   ctx->valx[1] = _mm256_set1_epi32( H256[0] );
   ctx->valy[1] =     _mm_set1_pi32( H256[0] );
   ctx->valx[2] = _mm256_set1_epi32( H256[0] );
   ctx->valy[2] =     _mm_set1_pi32( H256[0] );
   ctx->valx[3] = _mm256_set1_epi32( H256[0] );
   ctx->valy[3] =     _mm_set1_pi32( H256[0] );
   ctx->valx[4] = _mm256_set1_epi32( H256[0] );
   ctx->valy[4] =     _mm_set1_pi32( H256[0] );
   ctx->valx[5] = _mm256_set1_epi32( H256[0] );
   ctx->valy[5] =     _mm_set1_pi32( H256[0] );
   ctx->valx[6] = _mm256_set1_epi32( H256[0] );
   ctx->valy[6] =     _mm_set1_pi32( H256[0] );
   ctx->valx[7] = _mm256_set1_epi32( H256[0] );
   ctx->valy[7] =     _mm_set1_pi32( H256[0] );
   memcpy( ctx->valz, H256, 32 );
}


void sha256_11way_update( sha256_11way_context *ctx, const void *datax,
	                  const void *datay, const void *dataz, size_t len )
{
   __m256i  *vdatax = (__m256i*) datax;
    __m64   *vdatay = (__m64*)   datay;
   uint32_t *idataz = (uint32_t*)dataz;
   size_t ptr;
   const int buf_size = 64;

   ptr = (unsigned)ctx->count_low & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      uint32_t clow, clow2;

      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( ctx->bufx + (ptr>>2), vdatax + (ptr>>2), clen>>2 );
      memcpy_m64( ctx->bufy + (ptr>>2), vdatay + (ptr>>2), clen>>2 );
      memcpy    ( ctx->bufz +  ptr,     idataz +  ptr,     clen    );
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha256_11way_round( ctx->bufx, ctx->valx,
			     ctx->bufy, ctx->valy,
			     ctx->bufz, ctx->valz );
         ptr = 0;
      }
      clow = ctx->count_low;
      clow2 = clow + clen;
      ctx->count_low = clow2;
      if ( clow2 < clow )
         ctx->count_high++;
   }
}


void sha256_11way_close( sha256_11way_context *ctx, void *dstx, void *dsty,
	                                            void *dstz)
{
    unsigned ptr, u;
    uint32_t low, high;
    const int buf_size = 64;
    const int pad = buf_size - 8;

    ptr = (unsigned)ctx->count_low & (buf_size - 1U);
    ctx->bufx[ ptr>>2 ] = _mm256_set1_epi32( 0x80 );
    ctx->bufy[ ptr>>2 ] = _mm_set1_pi32( 0x80 );
    ctx->bufz[ ptr>>2 ] = 0x80;
    ptr += 4;

    if ( ptr > pad )
    {
         memset_zero_256( ctx->bufx + (ptr>>2), (buf_size - ptr) >> 2 );
         memset_zero_m64( ctx->bufy + (ptr>>2), (buf_size - ptr) >> 2 );
         memset(      ctx->bufz + (ptr>>2), 0,  (buf_size - ptr) >> 2 );
         sha256_11way_round( ctx->bufx, ctx->valx,
			     ctx->bufy, ctx->valy,
			     ctx->bufz, ctx->valz );
         memset_zero_256( ctx->bufx, pad >> 2 );
         memset_zero_m64(  ctx->bufy, pad >> 2 );
         memset(      ctx->bufz, 0,  pad >> 2 );
    }
    else
    {
        memset_zero_256( ctx->bufx + (ptr>>2),    (pad - ptr) >> 2 );
        memset_zero_m64(  ctx->bufy + (ptr>>2),    (pad - ptr) >> 2 );
        memset(          ctx->bufz + (ptr>>2), 0, (pad - ptr) >> 2 );
    }

    low = ctx->count_low;
    high = (ctx->count_high << 3) | (low >> 29);
    low = low << 3;

    ctx->bufx[ pad >> 2 ] =
                 mm256_bswap_32( _mm256_set1_epi32( high ) );
    ctx->bufy[ pad >> 2 ] =
                 mm64_bswap_32( _mm_set1_pi32( high ) );
    ctx->bufz[ pad >> 2 ] =
                 bswap_32( high );


    ctx->bufx[ ( pad+4 ) >> 2 ] =
                 mm256_bswap_32( _mm256_set1_epi32( low ) );
    ctx->bufy[ ( pad+4 ) >> 2 ] =
                 mm64_bswap_32( _mm_set1_pi32( low ) );
    ctx->bufz[ ( pad+4 ) >> 2 ] =
                 bswap_32( low );

    sha256_11way_round( ctx->bufx, ctx->valx,
		       ctx->bufy, ctx->valy,
		       ctx->bufz, ctx->valz  );

    for ( u = 0; u < 8; u ++ )
    {
       casti_m256i( dstx, u ) = mm256_bswap_32( ctx->valx[u] );
       casti_m64  ( dsty, u ) =  mm64_bswap_32( ctx->valy[u] );
       ((uint32_t*)dstz)[u] = bswap_32( ctx->valz[u] );
   }
}

#endif
#endif   // 0
