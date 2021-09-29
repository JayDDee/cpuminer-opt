#include "scrypt-core-ref.h"

#define ROTL(a, b) (((a) << (b)) | ((a) >> (32 - (b))))

static void xor_salsa8(uint32_t * const B, const uint32_t * const C)
{
   uint32_t x0 = (B[ 0] ^= C[ 0]),
            x1 = (B[ 1] ^= C[ 1]),
            x2 = (B[ 2] ^= C[ 2]),
            x3 = (B[ 3] ^= C[ 3]);
   uint32_t x4 = (B[ 4] ^= C[ 4]),
            x5 = (B[ 5] ^= C[ 5]),
            x6 = (B[ 6] ^= C[ 6]),
            x7 = (B[ 7] ^= C[ 7]);
   uint32_t x8 = (B[ 8] ^= C[ 8]),
            x9 = (B[ 9] ^= C[ 9]),
            xa = (B[10] ^= C[10]),
            xb = (B[11] ^= C[11]);
   uint32_t xc = (B[12] ^= C[12]),
            xd = (B[13] ^= C[13]),
            xe = (B[14] ^= C[14]),
            xf = (B[15] ^= C[15]);

   /* Operate on columns. */
   x4 ^= ROTL(x0 + xc,  7);
   x9 ^= ROTL(x5 + x1,  7);
   xe ^= ROTL(xa + x6,  7);
   x3 ^= ROTL(xf + xb,  7);
   x8 ^= ROTL(x4 + x0,  9);
   xd ^= ROTL(x9 + x5,  9);
   x2 ^= ROTL(xe + xa,  9);
   x7 ^= ROTL(x3 + xf,  9);
   xc ^= ROTL(x8 + x4, 13);
   x1 ^= ROTL(xd + x9, 13);
   x6 ^= ROTL(x2 + xe, 13);
   xb ^= ROTL(x7 + x3, 13);
   x0 ^= ROTL(xc + x8, 18);
   x5 ^= ROTL(x1 + xd, 18);
   xa ^= ROTL(x6 + x2, 18);
   xf ^= ROTL(xb + x7, 18);

   /* Operate on rows. */
   x1 ^= ROTL(x0 + x3,  7);
   x6 ^= ROTL(x5 + x4,  7);
   xb ^= ROTL(xa + x9,  7);
   xc ^= ROTL(xf + xe,  7);
   x2 ^= ROTL(x1 + x0,  9);
   x7 ^= ROTL(x6 + x5,  9);
   x8 ^= ROTL(xb + xa,  9);
   xd ^= ROTL(xc + xf,  9);
   x3 ^= ROTL(x2 + x1, 13);
   x4 ^= ROTL(x7 + x6, 13);
   x9 ^= ROTL(x8 + xb, 13);
   xe ^= ROTL(xd + xc, 13);
   x0 ^= ROTL(x3 + x2, 18);
   x5 ^= ROTL(x4 + x7, 18);
   xa ^= ROTL(x9 + x8, 18);
   xf ^= ROTL(xe + xd, 18);

   /* Operate on columns. */
   x4 ^= ROTL(x0 + xc,  7);
   x9 ^= ROTL(x5 + x1,  7);
   xe ^= ROTL(xa + x6,  7);
   x3 ^= ROTL(xf + xb,  7);
   x8 ^= ROTL(x4 + x0,  9);
   xd ^= ROTL(x9 + x5,  9);
   x2 ^= ROTL(xe + xa,  9);
   x7 ^= ROTL(x3 + xf,  9);
   xc ^= ROTL(x8 + x4, 13);
   x1 ^= ROTL(xd + x9, 13);
   x6 ^= ROTL(x2 + xe, 13);
   xb ^= ROTL(x7 + x3, 13);
   x0 ^= ROTL(xc + x8, 18);
   x5 ^= ROTL(x1 + xd, 18);
   xa ^= ROTL(x6 + x2, 18);
   xf ^= ROTL(xb + x7, 18);

   /* Operate on rows. */
   x1 ^= ROTL(x0 + x3,  7);
   x6 ^= ROTL(x5 + x4,  7);
   xb ^= ROTL(xa + x9,  7);
   xc ^= ROTL(xf + xe,  7);
   x2 ^= ROTL(x1 + x0,  9);
   x7 ^= ROTL(x6 + x5,  9);
   x8 ^= ROTL(xb + xa,  9);
   xd ^= ROTL(xc + xf,  9);
   x3 ^= ROTL(x2 + x1, 13);
   x4 ^= ROTL(x7 + x6, 13);
   x9 ^= ROTL(x8 + xb, 13);
   xe ^= ROTL(xd + xc, 13);
   x0 ^= ROTL(x3 + x2, 18);
   x5 ^= ROTL(x4 + x7, 18);
   xa ^= ROTL(x9 + x8, 18);
   xf ^= ROTL(xe + xd, 18);

   /* Operate on columns. */
   x4 ^= ROTL(x0 + xc,  7);
   x9 ^= ROTL(x5 + x1,  7);
   xe ^= ROTL(xa + x6,  7);
   x3 ^= ROTL(xf + xb,  7);
   x8 ^= ROTL(x4 + x0,  9);
   xd ^= ROTL(x9 + x5,  9);
   x2 ^= ROTL(xe + xa,  9);
   x7 ^= ROTL(x3 + xf,  9);
   xc ^= ROTL(x8 + x4, 13);
   x1 ^= ROTL(xd + x9, 13);
   x6 ^= ROTL(x2 + xe, 13);
   xb ^= ROTL(x7 + x3, 13);
   x0 ^= ROTL(xc + x8, 18);
   x5 ^= ROTL(x1 + xd, 18);
   xa ^= ROTL(x6 + x2, 18);
   xf ^= ROTL(xb + x7, 18);

   /* Operate on rows. */
   x1 ^= ROTL(x0 + x3,  7);
   x6 ^= ROTL(x5 + x4,  7);
   xb ^= ROTL(xa + x9,  7);
   xc ^= ROTL(xf + xe,  7);
   x2 ^= ROTL(x1 + x0,  9);
   x7 ^= ROTL(x6 + x5,  9);
   x8 ^= ROTL(xb + xa,  9);
   xd ^= ROTL(xc + xf,  9);
   x3 ^= ROTL(x2 + x1, 13);
   x4 ^= ROTL(x7 + x6, 13);
   x9 ^= ROTL(x8 + xb, 13);
   xe ^= ROTL(xd + xc, 13);
   x0 ^= ROTL(x3 + x2, 18);
   x5 ^= ROTL(x4 + x7, 18);
   xa ^= ROTL(x9 + x8, 18);
   xf ^= ROTL(xe + xd, 18);

   /* Operate on columns. */
   x4 ^= ROTL(x0 + xc,  7);
   x9 ^= ROTL(x5 + x1,  7);
   xe ^= ROTL(xa + x6,  7);
   x3 ^= ROTL(xf + xb,  7);
   x8 ^= ROTL(x4 + x0,  9);
   xd ^= ROTL(x9 + x5,  9);
   x2 ^= ROTL(xe + xa,  9);
   x7 ^= ROTL(x3 + xf,  9);
   xc ^= ROTL(x8 + x4, 13);
   x1 ^= ROTL(xd + x9, 13);
   x6 ^= ROTL(x2 + xe, 13);
   xb ^= ROTL(x7 + x3, 13);
   x0 ^= ROTL(xc + x8, 18);
   x5 ^= ROTL(x1 + xd, 18);
   xa ^= ROTL(x6 + x2, 18);
   xf ^= ROTL(xb + x7, 18);

   /* Operate on rows. */
   x1 ^= ROTL(x0 + x3,  7);
   x6 ^= ROTL(x5 + x4,  7);
   xb ^= ROTL(xa + x9,  7);
   xc ^= ROTL(xf + xe,  7);
   x2 ^= ROTL(x1 + x0,  9);
   x7 ^= ROTL(x6 + x5,  9);
   x8 ^= ROTL(xb + xa,  9);
   xd ^= ROTL(xc + xf,  9);
   x3 ^= ROTL(x2 + x1, 13);
   x4 ^= ROTL(x7 + x6, 13);
   x9 ^= ROTL(x8 + xb, 13);
   xe ^= ROTL(xd + xc, 13);
   x0 ^= ROTL(x3 + x2, 18);
   x5 ^= ROTL(x4 + x7, 18);
   xa ^= ROTL(x9 + x8, 18);
   xf ^= ROTL(xe + xd, 18);

   B[ 0] += x0;
   B[ 1] += x1;
   B[ 2] += x2;
   B[ 3] += x3;
   B[ 4] += x4;
   B[ 5] += x5;
   B[ 6] += x6;
   B[ 7] += x7;
   B[ 8] += x8;
   B[ 9] += x9;
   B[10] += xa;
   B[11] += xb;
   B[12] += xc;
   B[13] += xd;
   B[14] += xe;
   B[15] += xf;
}

/**
 * @param X input/ouput
 * @param V scratch buffer
 * @param N factor (def. 1024)
 */
void scrypt_core_ref(uint32_t *X, uint32_t *V, uint32_t N)
{
   for (uint32_t i = 0; i < N; i++) {
      memcpy(&V[i * 32], X, 128);
      xor_salsa8(&X[0], &X[16]);
      xor_salsa8(&X[16], &X[0]);
   }
   for (uint32_t i = 0; i < N; i++) {
      uint32_t j = 32 * (X[16] & (N - 1));
      for (uint8_t k = 0; k < 32; k++)
         X[k] ^= V[j + k];
      xor_salsa8(&X[0], &X[16]);
      xor_salsa8(&X[16], &X[0]);
   }
}

