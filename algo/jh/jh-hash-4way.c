/* $Id: jh.c 255 2011-06-07 19:50:20Z tp $ */
/*
 * JH implementation.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#include <stddef.h>
#include <string.h>
#include "jh-hash-4way.h"

static const uint64_t C[] =
{
   0x67f815dfa2ded572, 0x571523b70a15847b,
   0xf6875a4d90d6ab81, 0x402bd1c3c54f9f4e,
   0x9cfa455ce03a98ea, 0x9a99b26699d2c503,
   0x8a53bbf2b4960266, 0x31a2db881a1456b5,
   0xdb0e199a5c5aa303, 0x1044c1870ab23f40,
   0x1d959e848019051c, 0xdccde75eadeb336f,
   0x416bbf029213ba10, 0xd027bbf7156578dc,
   0x5078aa3739812c0a, 0xd3910041d2bf1a3f,
   0x907eccf60d5a2d42, 0xce97c0929c9f62dd,
   0xac442bc70ba75c18, 0x23fcc663d665dfd1,
   0x1ab8e09e036c6e97, 0xa8ec6c447e450521,
   0xfa618e5dbb03f1ee, 0x97818394b29796fd,
   0x2f3003db37858e4a, 0x956a9ffb2d8d672a,
   0x6c69b8f88173fe8a, 0x14427fc04672c78a,
   0xc45ec7bd8f15f4c5, 0x80bb118fa76f4475,
   0xbc88e4aeb775de52, 0xf4a3a6981e00b882,
   0x1563a3a9338ff48e, 0x89f9b7d524565faa,
   0xfde05a7c20edf1b6, 0x362c42065ae9ca36,
   0x3d98fe4e433529ce, 0xa74b9a7374f93a53,
   0x86814e6f591ff5d0, 0x9f5ad8af81ad9d0e,
   0x6a6234ee670605a7, 0x2717b96ebe280b8b,
   0x3f1080c626077447, 0x7b487ec66f7ea0e0,
   0xc0a4f84aa50a550d, 0x9ef18e979fe7e391,
   0xd48d605081727686, 0x62b0e5f3415a9e7e,
   0x7a205440ec1f9ffc, 0x84c9f4ce001ae4e3,
   0xd895fa9df594d74f, 0xa554c324117e2e55,
   0x286efebd2872df5b, 0xb2c4a50fe27ff578,
   0x2ed349eeef7c8905, 0x7f5928eb85937e44,
   0x4a3124b337695f70, 0x65e4d61df128865e,
   0xe720b95104771bc7, 0x8a87d423e843fe74,
   0xf2947692a3e8297d, 0xc1d9309b097acbdd,
   0xe01bdc5bfb301b1d, 0xbf829cf24f4924da,
   0xffbf70b431bae7a4, 0x48bcf8de0544320d,
   0x39d3bb5332fcae3b, 0xa08b29e0c1c39f45,
   0x0f09aef7fd05c9e5, 0x34f1904212347094,
   0x95ed44e301b771a2, 0x4a982f4f368e3be9,
   0x15f66ca0631d4088, 0xffaf52874b44c147,
   0x30c60ae2f14abb7e, 0xe68c6eccc5b67046,
   0x00ca4fbd56a4d5a4, 0xae183ec84b849dda,
   0xadd1643045ce5773, 0x67255c1468cea6e8,
   0x16e10ecbf28cdaa3, 0x9a99949a5806e933,
   0x7b846fc220b2601f, 0x1885d1a07facced1,
   0xd319dd8da15b5932, 0x46b4a5aac01c9a50,
   0xba6b04e467633d9f, 0x7eee560bab19caf6,
   0x742128a9ea79b11f, 0xee51363b35f7bde9,
   0x76d350755aac571d, 0x01707da3fec2463a,
   0x42d8a498afc135f7, 0x79676b9e20eced78,
   0xa8db3aea15638341, 0x832c83324d3bc3fa,
   0xf347271c1f3b40a7, 0x9a762db734f04059,
   0xfd4f21d26c4e3ee7, 0xef5957dc398dfdb8,
   0xdaeb492b490c9b8d, 0x0d70f36849d7a25b,
   0x84558d7ad0ae3b7d, 0x658ef8e4f0e9a5f5,
   0x533b1036f4a2b8a0, 0x5aec3e759e07a80c,
   0x4f88e85692946891, 0x4cbcbaf8555cb05b,
   0x7b9487f3993bbbe3, 0x5d1c6b72d6f4da75,
   0x6db334dc28acae64, 0x71db28b850a5346c,
   0x2a518d10f2e261f8, 0xfc75dd593364dbe3,
   0xa23fce43f1bcac1c, 0xb043e8023cd1bb67,
   0x75a12988ca5b0a33, 0x5c5316b44d19347f,
   0x1e4d790ec3943b92, 0x3fafeeb6d7757479,
   0x21391abef7d4a8ea, 0x5127234c097ef45c,
   0xd23c32ba5324a326, 0xadd5a66d4a17a344,
   0x08c9f2afa63e1db5, 0x563c6b91983d5983,
   0x4d608672a17cf84c, 0xf6c76e08cc3ee246,
   0x5e76bcb1b333982f, 0x2ae6c4efa566d62b,
   0x36d4c1bee8b6f406, 0x6321efbc1582ee74,
   0x69c953f40d4ec1fd, 0x26585806c45a7da7,
   0x16fae0061614c17e, 0x3f9d63283daf907e,
   0x0cd29b00e3f2c9d2, 0x300cd4b730ceaa5f,
   0x9832e0f216512a74, 0x9af8cee3d830eb0d,
   0x9279f1b57b9ec54b, 0xd36886046ee651ff,
   0x316796e6574d239b, 0x05750a17f3a6e6cc,
   0xce6c3213d98176b1, 0x62a205f88452173c,
   0x47154778b3cb2bf4, 0x486a9323825446ff,
   0x65655e4e0758df38, 0x8e5086fc897cfcf2,
   0x86ca0bd0442e7031, 0x4e477830a20940f0,
   0x8338f7d139eea065, 0xbd3a2ce437e95ef7,
   0x6ff8130126b29721, 0xe7de9fefd1ed44a3,
   0xd992257615dfa08b, 0xbe42dc12f6f7853c,
   0x7eb027ab7ceca7d8, 0xdea83eaada7d8d53,
   0xd86902bd93ce25aa, 0xf908731afd43f65a,
   0xa5194a17daef5fc0, 0x6a21fd4c33664d97,
   0x701541db3198b435, 0x9b54cdedbb0f1eea,
   0x72409751a163d09a, 0xe26f4791bf9d75f6
};

/*
static const uint64_t IV256[] =
{
    0xeb98a3412c20d3eb,  0x92cdbe7b9cb245c1,
    0x1c93519160d4c7fa,  0x260082d67e508a03,
    0xa4239e267726b945,  0xe0fb1a48d41a9477,
    0xcdb5ab26026b177a,  0x56f024420fff2fa8,
    0x71a396897f2e4d75,  0x1d144908f77de262,
    0x277695f776248f94,  0x87d5b6574780296c,
    0x5c5e272dac8e0d6c,  0x518450c657057a0f,
    0x7be4d367702412ea,  0x89e3ab13d31cd769
};


static const uint64_t IV512[] =
{
    0x6fd14b963e00aa17,  0x636a2e057a15d543,
    0x8a225e8d0c97ef0b,  0xe9341259f2b3c361,
    0x891da0c1536f801e,  0x2aa9056bea2b6d80,
    0x588eccdb2075baa6,  0xa90f3a76baf83bf7,
    0x0169e60541e34a69,  0x46b58a8e2e6fe65a,
    0x1047a7d0c1843c24,  0x3b6e71b12d5ac199,
    0xcf57f6ec9db1f856,  0xa706887c5716b156,
    0xe3c2fcdfe68517fb,  0x545a4678cc8cdd4b
};
*/

#define Ceven_hi(r)   (C[((r) << 2) + 0])
#define Ceven_lo(r)   (C[((r) << 2) + 1])
#define Codd_hi(r)    (C[((r) << 2) + 2])
#define Codd_lo(r)    (C[((r) << 2) + 3])

#define S(x0, x1, x2, x3, cb, r)   do { \
      Sb(x0 ## h, x1 ## h, x2 ## h, x3 ## h, cb ## hi(r)); \
      Sb(x0 ## l, x1 ## l, x2 ## l, x3 ## l, cb ## lo(r)); \
   } while (0)

#define L(x0, x1, x2, x3, x4, x5, x6, x7)   do { \
      Lb(x0 ## h, x1 ## h, x2 ## h, x3 ## h, \
         x4 ## h, x5 ## h, x6 ## h, x7 ## h); \
      Lb(x0 ## l, x1 ## l, x2 ## l, x3 ## l, \
         x4 ## l, x5 ## l, x6 ## l, x7 ## l); \
   } while (0)

#define READ_STATE(state)   do { \
      h0h = (state)->H[ 0]; \
      h0l = (state)->H[ 1]; \
      h1h = (state)->H[ 2]; \
      h1l = (state)->H[ 3]; \
      h2h = (state)->H[ 4]; \
      h2l = (state)->H[ 5]; \
      h3h = (state)->H[ 6]; \
      h3l = (state)->H[ 7]; \
      h4h = (state)->H[ 8]; \
      h4l = (state)->H[ 9]; \
      h5h = (state)->H[10]; \
      h5l = (state)->H[11]; \
      h6h = (state)->H[12]; \
      h6l = (state)->H[13]; \
      h7h = (state)->H[14]; \
      h7l = (state)->H[15]; \
   } while (0)

#define WRITE_STATE(state)   do { \
      (state)->H[ 0] = h0h; \
      (state)->H[ 1] = h0l; \
      (state)->H[ 2] = h1h; \
      (state)->H[ 3] = h1l; \
      (state)->H[ 4] = h2h; \
      (state)->H[ 5] = h2l; \
      (state)->H[ 6] = h3h; \
      (state)->H[ 7] = h3l; \
      (state)->H[ 8] = h4h; \
      (state)->H[ 9] = h4l; \
      (state)->H[10] = h5h; \
      (state)->H[11] = h5l; \
      (state)->H[12] = h6h; \
      (state)->H[13] = h6l; \
      (state)->H[14] = h7h; \
      (state)->H[15] = h7l; \
   } while (0)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define Sb_8W(x0, x1, x2, x3, c) \
{ \
    const __m512i cc = _mm512_set1_epi64( c ); \
    x0 = mm512_xorandnot( x0, x2, cc ); \
    tmp = mm512_xorand( cc, x0, x1 ); \
    x0 = mm512_xorandnot( x0, x3, x2 ); \
    x3 = _mm512_ternarylogic_epi64( x3, x1, x2, 0x2d ); /* ~x3 ^ (~x1 & x2) */\
    x1 = mm512_xorand( x1, x0, x2 ); \
    x2 = mm512_xorandnot( x2, x3, x0 ); \
    x0 = mm512_xoror( x0, x1, x3 ); \
    x3 = mm512_xorand( x3, x1, x2 ); \
    x1 = mm512_xorand( x1, tmp, x0 ); \
    x2 = _mm512_xor_si512( x2, tmp ); \
}

#define Lb_8W(x0, x1, x2, x3, x4, x5, x6, x7) \
{ \
    x4 = _mm512_xor_si512( x4, x1 ); \
    x5 = _mm512_xor_si512( x5, x2 ); \
    x6 = mm512_xor3( x6, x3, x0 ); \
    x7 = _mm512_xor_si512( x7, x0 ); \
    x0 = _mm512_xor_si512( x0, x5 ); \
    x1 = _mm512_xor_si512( x1, x6 ); \
    x2 = mm512_xor3( x2, x7, x4 ); \
    x3 = _mm512_xor_si512( x3, x4 ); \
}

#define S_8W(x0, x1, x2, x3, cb, r) \
{ \
      Sb_8W(x0 ## h, x1 ## h, x2 ## h, x3 ## h, cb ## hi(r)); \
      Sb_8W(x0 ## l, x1 ## l, x2 ## l, x3 ## l, cb ## lo(r)); \
}

#define L_8W(x0, x1, x2, x3, x4, x5, x6, x7) \
{ \
      Lb_8W(x0 ## h, x1 ## h, x2 ## h, x3 ## h, \
         x4 ## h, x5 ## h, x6 ## h, x7 ## h); \
      Lb_8W(x0 ## l, x1 ## l, x2 ## l, x3 ## l, \
         x4 ## l, x5 ## l, x6 ## l, x7 ## l); \
}

#define Wz_8W(x, c, n) \
{ \
   __m512i t = _mm512_slli_epi64( _mm512_and_si512( x ## h, (c) ), (n) ); \
   x ## h = mm512_orand( t, _mm512_srli_epi64( x ## h, (n) ), (c) ); \
   t = _mm512_slli_epi64( _mm512_and_si512( x ## l, (c) ), (n) ); \
   x ## l = mm512_orand( t, _mm512_srli_epi64( x ## l, (n) ), (c) ); \
}

#define W80(x)   Wz_8W(x, _mm512_set1_epi64( 0x5555555555555555 ),  1 )
#define W81(x)   Wz_8W(x, _mm512_set1_epi64( 0x3333333333333333 ),  2 )
#define W82(x)   Wz_8W(x, _mm512_set1_epi64( 0x0F0F0F0F0F0F0F0F ),  4 )
#define W83(x)   Wz_8W(x, _mm512_set1_epi64( 0x00FF00FF00FF00FF ),  8 )
#define W84(x)   Wz_8W(x, _mm512_set1_epi64( 0x0000FFFF0000FFFF ), 16 )
#define W85(x)   Wz_8W(x, _mm512_set1_epi64( 0x00000000FFFFFFFF ), 32 )
#define W86(x) \
{ \
   __m512i t = x ## h; \
   x ## h = x ## l; \
   x ## l = t; \
}

#define DECL_STATE_8W \
   __m512i h0h, h1h, h2h, h3h, h4h, h5h, h6h, h7h; \
   __m512i h0l, h1l, h2l, h3l, h4l, h5l, h6l, h7l; \
   __m512i tmp;

#define SL_8W(ro)   SLu_8W(r + ro, ro)

#define SLu_8W(r, ro) \
{ \
      S_8W(h0, h2, h4, h6, Ceven_, r); \
      S_8W(h1, h3, h5, h7, Codd_, r); \
      L_8W(h0, h2, h4, h6, h1, h3, h5, h7); \
      W8 ## ro(h1); \
      W8 ## ro(h3); \
      W8 ## ro(h5); \
      W8 ## ro(h7); \
}

#define INPUT_BUF1_8W \
   __m512i m0h = buf[0]; \
   __m512i m0l = buf[1]; \
   __m512i m1h = buf[2]; \
   __m512i m1l = buf[3]; \
   __m512i m2h = buf[4]; \
   __m512i m2l = buf[5]; \
   __m512i m3h = buf[6]; \
   __m512i m3l = buf[7]; \
   h0h = _mm512_xor_si512( h0h, m0h ); \
   h0l = _mm512_xor_si512( h0l, m0l ); \
   h1h = _mm512_xor_si512( h1h, m1h ); \
   h1l = _mm512_xor_si512( h1l, m1l ); \
   h2h = _mm512_xor_si512( h2h, m2h ); \
   h2l = _mm512_xor_si512( h2l, m2l ); \
   h3h = _mm512_xor_si512( h3h, m3h ); \
   h3l = _mm512_xor_si512( h3l, m3l ); \

#define INPUT_BUF2_8W \
   h4h = _mm512_xor_si512( h4h, m0h ); \
   h4l = _mm512_xor_si512( h4l, m0l ); \
   h5h = _mm512_xor_si512( h5h, m1h ); \
   h5l = _mm512_xor_si512( h5l, m1l ); \
   h6h = _mm512_xor_si512( h6h, m2h ); \
   h6l = _mm512_xor_si512( h6l, m2l ); \
   h7h = _mm512_xor_si512( h7h, m3h ); \
   h7l = _mm512_xor_si512( h7l, m3l ); \

#define E8_8W \
{ \
      SLu_8W( 0, 0); \
      SLu_8W( 1, 1); \
      SLu_8W( 2, 2); \
      SLu_8W( 3, 3); \
      SLu_8W( 4, 4); \
      SLu_8W( 5, 5); \
      SLu_8W( 6, 6); \
      SLu_8W( 7, 0); \
      SLu_8W( 8, 1); \
      SLu_8W( 9, 2); \
      SLu_8W(10, 3); \
      SLu_8W(11, 4); \
      SLu_8W(12, 5); \
      SLu_8W(13, 6); \
      SLu_8W(14, 0); \
      SLu_8W(15, 1); \
      SLu_8W(16, 2); \
      SLu_8W(17, 3); \
      SLu_8W(18, 4); \
      SLu_8W(19, 5); \
      SLu_8W(20, 6); \
      SLu_8W(21, 0); \
      SLu_8W(22, 1); \
      SLu_8W(23, 2); \
      SLu_8W(24, 3); \
      SLu_8W(25, 4); \
      SLu_8W(26, 5); \
      SLu_8W(27, 6); \
      SLu_8W(28, 0); \
      SLu_8W(29, 1); \
      SLu_8W(30, 2); \
      SLu_8W(31, 3); \
      SLu_8W(32, 4); \
      SLu_8W(33, 5); \
      SLu_8W(34, 6); \
      SLu_8W(35, 0); \
      SLu_8W(36, 1); \
      SLu_8W(37, 2); \
      SLu_8W(38, 3); \
      SLu_8W(39, 4); \
      SLu_8W(40, 5); \
      SLu_8W(41, 6); \
}

#endif // AVX512

#if defined(__AVX2__)

#if defined(__AVX512VL__)
//TODO enable for AVX10_256, not used with AVX512VL

#define notxorandnot( a, b, c ) \
   _mm256_ternarylogic_epi64( a, b, c, 0x2d )

#else

#define notxorandnot( a, b, c ) \
   _mm256_xor_si256( mm256_not( a ), _mm256_andnot_si256( b, c ) )

#endif

#define Sb(x0, x1, x2, x3, c) \
{ \
    const __m256i cc = _mm256_set1_epi64x( c ); \
    x0 = mm256_xorandnot( x0, x2, cc ); \
    tmp = mm256_xorand( cc, x0, x1 ); \
    x0 = mm256_xorandnot( x0, x3, x2 ); \
    x3 = notxorandnot( x3, x1, x2 ); \
    x1 = mm256_xorand( x1, x0, x2 ); \
    x2 = mm256_xorandnot( x2, x3, x0 ); \
    x0 = mm256_xoror( x0, x1, x3 ); \
    x3 = mm256_xorand( x3, x1, x2 ); \
    x1 = mm256_xorand( x1, tmp, x0 ); \
    x2 = _mm256_xor_si256( x2, tmp ); \
}

#define Lb(x0, x1, x2, x3, x4, x5, x6, x7) \
{ \
    x4 = _mm256_xor_si256( x4, x1 ); \
    x5 = _mm256_xor_si256( x5, x2 ); \
    x6 = mm256_xor3( x6, x3, x0 ); \
    x7 = _mm256_xor_si256( x7, x0 ); \
    x0 = _mm256_xor_si256( x0, x5 ); \
    x1 = _mm256_xor_si256( x1, x6 ); \
    x2 = mm256_xor3( x2, x7, x4 ); \
    x3 = _mm256_xor_si256( x3, x4 ); \
}
 
#define Wz(x, c, n) \
{ \
   __m256i t = _mm256_slli_epi64( _mm256_and_si256( x ## h, (c) ), (n) ); \
   x ## h = _mm256_or_si256( _mm256_and_si256( \
                                _mm256_srli_epi64( x ## h, (n) ), (c) ), t ); \
   t = _mm256_slli_epi64( _mm256_and_si256( x ## l, (c) ), (n) ); \
   x ## l = _mm256_or_si256( _mm256_and_si256( \
                                _mm256_srli_epi64( x ## l, (n) ), (c) ), t ); \
}

#define W0(x)   Wz(x, _mm256_set1_epi64x( 0x5555555555555555 ),  1 )
#define W1(x)   Wz(x, _mm256_set1_epi64x( 0x3333333333333333 ),  2 )
#define W2(x)   Wz(x, _mm256_set1_epi64x( 0x0F0F0F0F0F0F0F0F ),  4 )
#define W3(x)   Wz(x, _mm256_set1_epi64x( 0x00FF00FF00FF00FF ),  8 ) 
#define W4(x)   Wz(x, _mm256_set1_epi64x( 0x0000FFFF0000FFFF ), 16 )
#define W5(x)   Wz(x, _mm256_set1_epi64x( 0x00000000FFFFFFFF ), 32 )

#define W6(x) \
{ \
   __m256i t = x ## h; \
   x ## h = x ## l; \
   x ## l = t; \
}

#define DECL_STATE \
	__m256i h0h, h1h, h2h, h3h, h4h, h5h, h6h, h7h; \
	__m256i h0l, h1l, h2l, h3l, h4l, h5l, h6l, h7l; \
	__m256i tmp;

#define INPUT_BUF1 \
	__m256i m0h = buf[0]; \
	__m256i m0l = buf[1]; \
	__m256i m1h = buf[2]; \
	__m256i m1l = buf[3]; \
	__m256i m2h = buf[4]; \
	__m256i m2l = buf[5]; \
	__m256i m3h = buf[6]; \
	__m256i m3l = buf[7]; \
   h0h = _mm256_xor_si256( h0h, m0h ); \
   h0l = _mm256_xor_si256( h0l, m0l ); \
   h1h = _mm256_xor_si256( h1h, m1h ); \
   h1l = _mm256_xor_si256( h1l, m1l ); \
   h2h = _mm256_xor_si256( h2h, m2h ); \
   h2l = _mm256_xor_si256( h2l, m2l ); \
   h3h = _mm256_xor_si256( h3h, m3h ); \
   h3l = _mm256_xor_si256( h3l, m3l );

#define INPUT_BUF2 \
   h4h = _mm256_xor_si256( h4h, m0h ); \
   h4l = _mm256_xor_si256( h4l, m0l ); \
   h5h = _mm256_xor_si256( h5h, m1h ); \
   h5l = _mm256_xor_si256( h5l, m1l ); \
   h6h = _mm256_xor_si256( h6h, m2h ); \
   h6l = _mm256_xor_si256( h6l, m2l ); \
   h7h = _mm256_xor_si256( h7h, m3h ); \
   h7l = _mm256_xor_si256( h7l, m3l );

#define SL(ro)   SLu(r + ro, ro)

#define SLu( r, ro ) \
{ \
		S(h0, h2, h4, h6, Ceven_, r); \
		S(h1, h3, h5, h7, Codd_, r); \
		L(h0, h2, h4, h6, h1, h3, h5, h7); \
		W ## ro(h1); \
		W ## ro(h3); \
		W ## ro(h5); \
		W ## ro(h7); \
}

#define E8 \
{ \
      SLu( 0, 0); \
      SLu( 1, 1); \
      SLu( 2, 2); \
      SLu( 3, 3); \
      SLu( 4, 4); \
      SLu( 5, 5); \
      SLu( 6, 6); \
      SLu( 7, 0); \
      SLu( 8, 1); \
      SLu( 9, 2); \
      SLu(10, 3); \
      SLu(11, 4); \
      SLu(12, 5); \
      SLu(13, 6); \
      SLu(14, 0); \
      SLu(15, 1); \
      SLu(16, 2); \
      SLu(17, 3); \
      SLu(18, 4); \
      SLu(19, 5); \
      SLu(20, 6); \
      SLu(21, 0); \
      SLu(22, 1); \
      SLu(23, 2); \
      SLu(24, 3); \
      SLu(25, 4); \
      SLu(26, 5); \
      SLu(27, 6); \
      SLu(28, 0); \
      SLu(29, 1); \
      SLu(30, 2); \
      SLu(31, 3); \
      SLu(32, 4); \
      SLu(33, 5); \
      SLu(34, 6); \
      SLu(35, 0); \
      SLu(36, 1); \
      SLu(37, 2); \
      SLu(38, 3); \
      SLu(39, 4); \
      SLu(40, 5); \
      SLu(41, 6); \
}

#endif   // AVX2

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

void jh256_8x64_init( jh_8x64_context *sc )
{
    // bswapped IV256
    sc->H[ 0] = _mm512_set1_epi64( 0xebd3202c41a398eb );
    sc->H[ 1] = _mm512_set1_epi64( 0xc145b29c7bbecd92 );
    sc->H[ 2] = _mm512_set1_epi64( 0xfac7d4609151931c );
    sc->H[ 3] = _mm512_set1_epi64( 0x038a507ed6820026 );
    sc->H[ 4] = _mm512_set1_epi64( 0x45b92677269e23a4 );
    sc->H[ 5] = _mm512_set1_epi64( 0x77941ad4481afbe0 );
    sc->H[ 6] = _mm512_set1_epi64( 0x7a176b0226abb5cd );
    sc->H[ 7] = _mm512_set1_epi64( 0xa82fff0f4224f056 );
    sc->H[ 8] = _mm512_set1_epi64( 0x754d2e7f8996a371 );
    sc->H[ 9] = _mm512_set1_epi64( 0x62e27df70849141d );
    sc->H[10] = _mm512_set1_epi64( 0x948f2476f7957627 );
    sc->H[11] = _mm512_set1_epi64( 0x6c29804757b6d587 );
    sc->H[12] = _mm512_set1_epi64( 0x6c0d8eac2d275e5c );
    sc->H[13] = _mm512_set1_epi64( 0x0f7a0557c6508451 );
    sc->H[14] = _mm512_set1_epi64( 0xea12247067d3e47b );
    sc->H[15] = _mm512_set1_epi64( 0x69d71cd313abe389 );
    sc->ptr = 0;
    sc->block_count = 0;
}

void jh512_8x64_init( jh_8x64_context *sc )
{
    // bswapped IV512
    sc->H[ 0] = _mm512_set1_epi64( 0x17aa003e964bd16f );
    sc->H[ 1] = _mm512_set1_epi64( 0x43d5157a052e6a63 );
    sc->H[ 2] = _mm512_set1_epi64( 0x0bef970c8d5e228a );
    sc->H[ 3] = _mm512_set1_epi64( 0x61c3b3f2591234e9 );
    sc->H[ 4] = _mm512_set1_epi64( 0x1e806f53c1a01d89 );
    sc->H[ 5] = _mm512_set1_epi64( 0x806d2bea6b05a92a );
    sc->H[ 6] = _mm512_set1_epi64( 0xa6ba7520dbcc8e58 );
    sc->H[ 7] = _mm512_set1_epi64( 0xf73bf8ba763a0fa9 );
    sc->H[ 8] = _mm512_set1_epi64( 0x694ae34105e66901 );
    sc->H[ 9] = _mm512_set1_epi64( 0x5ae66f2e8e8ab546 );
    sc->H[10] = _mm512_set1_epi64( 0x243c84c1d0a74710 );
    sc->H[11] = _mm512_set1_epi64( 0x99c15a2db1716e3b );
    sc->H[12] = _mm512_set1_epi64( 0x56f8b19decf657cf );
    sc->H[13] = _mm512_set1_epi64( 0x56b116577c8806a7 );
    sc->H[14] = _mm512_set1_epi64( 0xfb1785e6dffcc2e3 );
    sc->H[15] = _mm512_set1_epi64( 0x4bdd8ccc78465a54 );
    sc->ptr = 0;
    sc->block_count = 0;
}

static void
jh_8x64_core( jh_8x64_context *sc, const void *data, size_t len )
{
    __m512i *buf;
    __m512i *vdata = (__m512i*)data;
   const int buf_size = 64;   // 64 * _m512i
   size_t ptr;
   DECL_STATE_8W

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr) )
   {
       memcpy_512( buf + (ptr>>3), vdata, len>>3 );
       ptr += len;
       sc->ptr = ptr;
       return;
   }

   READ_STATE(sc);
   while ( len > 0 )
   {
       size_t clen;
       clen = buf_size - ptr;
       if ( clen > len )
          clen = len;

       memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
       if ( ptr == buf_size )
       {
          INPUT_BUF1_8W;
          E8_8W;
          INPUT_BUF2_8W;
          sc->block_count ++;
          ptr = 0;
       }
   }
   WRITE_STATE(sc);
   sc->ptr = ptr;
}

static void
jh_8x64_close( jh_8x64_context *sc, unsigned ub, unsigned n, void *dst,
               size_t out_size_w32 )
{
   __m512i buf[16*4];
   __m512i *dst512 = (__m512i*)dst;
   size_t numz, u;
   uint64_t l0, l1;

   buf[0] = _mm512_set1_epi64( 0x80ULL );

   if ( sc->ptr == 0 )
       numz = 48;
   else
       numz = 112 - sc->ptr;

   memset_zero_512( buf+1, (numz>>3) - 1 );

   l0 = ( sc->block_count << 9 ) + ( sc->ptr << 3 );
   l1 = ( sc->block_count >> 55 );
   *(buf + (numz>>3)    ) = _mm512_set1_epi64( bswap_64( l1 ) );
   *(buf + (numz>>3) + 1) = _mm512_set1_epi64( bswap_64( l0 ) );

   jh_8x64_core( sc, buf, numz + 16 );

   for ( u=0; u < 8; u++ )
       buf[u] = sc->H[u+8];

    memcpy_512( dst512, buf, 8 );
}

void
jh256_8way_update(void *cc, const void *data, size_t len)
{
   jh_8x64_core(cc, data, len);
}

void
jh256_8x64_close(void *cc, void *dst)
{
   jh_8x64_close(cc, 0, 0, dst, 8);
}

void
jh512_8x64_update(void *cc, const void *data, size_t len)
{
   jh_8x64_core(cc, data, len);
}

void
jh512_8x64_close(void *cc, void *dst)
{
   jh_8x64_close(cc, 0, 0, dst, 16);
}

void jh512_8x64_ctx( jh_8x64_context *cc, void *dst, const void *data, size_t len )
{
   jh512_8x64_init( cc );
   jh512_8x64_update( cc, data, len);
   jh512_8x64_close( cc, dst);
}

#endif // AVX512

#if defined(__AVX2__)

void jh256_4x64_init( jh_4x64_context *sc )
{
    // bswapped IV256
    sc->H[ 0] = _mm256_set1_epi64x( 0xebd3202c41a398eb );
    sc->H[ 1] = _mm256_set1_epi64x( 0xc145b29c7bbecd92 );
    sc->H[ 2] = _mm256_set1_epi64x( 0xfac7d4609151931c );
    sc->H[ 3] = _mm256_set1_epi64x( 0x038a507ed6820026 );
    sc->H[ 4] = _mm256_set1_epi64x( 0x45b92677269e23a4 );
    sc->H[ 5] = _mm256_set1_epi64x( 0x77941ad4481afbe0 );
    sc->H[ 6] = _mm256_set1_epi64x( 0x7a176b0226abb5cd );
    sc->H[ 7] = _mm256_set1_epi64x( 0xa82fff0f4224f056 );
    sc->H[ 8] = _mm256_set1_epi64x( 0x754d2e7f8996a371 );
    sc->H[ 9] = _mm256_set1_epi64x( 0x62e27df70849141d );
    sc->H[10] = _mm256_set1_epi64x( 0x948f2476f7957627 );
    sc->H[11] = _mm256_set1_epi64x( 0x6c29804757b6d587 );
    sc->H[12] = _mm256_set1_epi64x( 0x6c0d8eac2d275e5c );
    sc->H[13] = _mm256_set1_epi64x( 0x0f7a0557c6508451 );
    sc->H[14] = _mm256_set1_epi64x( 0xea12247067d3e47b );
    sc->H[15] = _mm256_set1_epi64x( 0x69d71cd313abe389 );
    sc->ptr = 0;
    sc->block_count = 0;
}

void jh512_4x64_init( jh_4x64_context *sc )
{
    // bswapped IV512
    sc->H[ 0] = _mm256_set1_epi64x( 0x17aa003e964bd16f );
    sc->H[ 1] = _mm256_set1_epi64x( 0x43d5157a052e6a63 );
    sc->H[ 2] = _mm256_set1_epi64x( 0x0bef970c8d5e228a );
    sc->H[ 3] = _mm256_set1_epi64x( 0x61c3b3f2591234e9 );
    sc->H[ 4] = _mm256_set1_epi64x( 0x1e806f53c1a01d89 );
    sc->H[ 5] = _mm256_set1_epi64x( 0x806d2bea6b05a92a );
    sc->H[ 6] = _mm256_set1_epi64x( 0xa6ba7520dbcc8e58 );
    sc->H[ 7] = _mm256_set1_epi64x( 0xf73bf8ba763a0fa9 );
    sc->H[ 8] = _mm256_set1_epi64x( 0x694ae34105e66901 );
    sc->H[ 9] = _mm256_set1_epi64x( 0x5ae66f2e8e8ab546 );
    sc->H[10] = _mm256_set1_epi64x( 0x243c84c1d0a74710 );
    sc->H[11] = _mm256_set1_epi64x( 0x99c15a2db1716e3b );
    sc->H[12] = _mm256_set1_epi64x( 0x56f8b19decf657cf );
    sc->H[13] = _mm256_set1_epi64x( 0x56b116577c8806a7 );
    sc->H[14] = _mm256_set1_epi64x( 0xfb1785e6dffcc2e3 );
    sc->H[15] = _mm256_set1_epi64x( 0x4bdd8ccc78465a54 );
    sc->ptr = 0;
    sc->block_count = 0;
}

static void
jh_4x64_core( jh_4x64_context *sc, const void *data, size_t len )
{
    __m256i *buf;
    __m256i *vdata = (__m256i*)data;
   const int buf_size = 64;   // 64 * _m256i
   size_t ptr;
   DECL_STATE

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr) )
   {
       memcpy_256( buf + (ptr>>3), vdata, len>>3 );
       ptr += len;
       sc->ptr = ptr;
       return;
   }

   READ_STATE(sc);
   while ( len > 0 )
   {
       size_t clen;
       clen = buf_size - ptr;
       if ( clen > len )
          clen = len;

       memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
       if ( ptr == buf_size )
       {
          INPUT_BUF1;
          E8;
          INPUT_BUF2;
          sc->block_count ++;
          ptr = 0;
       }
   }
   WRITE_STATE(sc);
   sc->ptr = ptr;
}

static void
jh_4x64_close( jh_4x64_context *sc, unsigned ub, unsigned n, void *dst,
               size_t out_size_w32 )
{
   __m256i buf[16*4];
   __m256i *dst256 = (__m256i*)dst;
   size_t numz, u;
   uint64_t l0, l1;

   buf[0] = _mm256_set1_epi64x( 0x80ULL );

   if ( sc->ptr == 0 )
       numz = 48;
   else
       numz = 112 - sc->ptr;

   memset_zero_256( buf+1, (numz>>3) - 1 );   

   l0 = ( sc->block_count << 9 ) + ( sc->ptr << 3 );
   l1 = ( sc->block_count >> 55 );
   *(buf + (numz>>3)    ) = _mm256_set1_epi64x( bswap_64( l1 ) );
   *(buf + (numz>>3) + 1) = _mm256_set1_epi64x( bswap_64( l0 ) );

   jh_4x64_core( sc, buf, numz + 16 );

   for ( u=0; u < 8; u++ )
       buf[u] = sc->H[u+8];

    memcpy_256( dst256, buf, 8 );
}

void
jh256_4x64_update(void *cc, const void *data, size_t len)
{
	jh_4x64_core(cc, data, len);
}

void
jh256_4x64_close(void *cc, void *dst)
{
	jh_4x64_close(cc, 0, 0, dst, 8 );
}

void
jh512_4x64_update(void *cc, const void *data, size_t len)
{
	jh_4x64_core(cc, data, len);
}

void
jh512_4x64_close(void *cc, void *dst)
{
	jh_4x64_close(cc, 0, 0, dst, 16 );
}

void jh512_4x64_ctx( jh_4x64_context *cc, void *dst, const void *data, size_t len )
{
   jh512_4x64_init( cc );
   jh512_4x64_update( cc, data, len);
   jh512_4x64_close( cc, dst);
}

#undef Sb
#undef Lb
#undef Wz
#undef W0
#undef W1
#undef W2
#undef W3
#undef W4
#undef W5
#undef W6
#undef SL
#undef SLu
#undef E8

#endif    // AVX2
          
// SSE2 & NEON

#define v128_notxorandnot( a, b, c ) \
   v128_xor( v128_not( a ), v128_andnot( b, c ) )


#define Sb(x0, x1, x2, x3, c) \
{ \
    const v128u64_t cc = v128_64( c ); \
    x0 = v128_xorandnot( x0, x2, cc ); \
    tmp = v128_xorand( cc, x0, x1 ); \
    x0 = v128_xorandnot( x0, x3, x2 ); \
    x3 = v128_notxorandnot( x3, x1, x2 ); \
    x1 = v128_xorand( x1, x0, x2 ); \
    x2 = v128_xorandnot( x2, x3, x0 ); \
    x0 = v128_xoror( x0, x1, x3 ); \
    x3 = v128_xorand( x3, x1, x2 ); \
    x1 = v128_xorand( x1, tmp, x0 ); \
    x2 = v128_xor( x2, tmp ); \
}

#define Lb(x0, x1, x2, x3, x4, x5, x6, x7) \
{ \
    x4 = v128_xor( x4, x1 ); \
    x5 = v128_xor( x5, x2 ); \
    x6 = v128_xor3( x6, x3, x0 ); \
    x7 = v128_xor( x7, x0 ); \
    x0 = v128_xor( x0, x5 ); \
    x1 = v128_xor( x1, x6 ); \
    x2 = v128_xor3( x2, x7, x4 ); \
    x3 = v128_xor( x3, x4 ); \
}

#undef Wz
#define Wz(x, c, n) \
{ \
   v128u64_t t = v128_sl64( v128_and( x ## h, c ), n ); \
   x ## h = v128_or( v128_and( v128_sr64( x ## h, n ), c ), t ); \
   t = v128_sl64( v128_and( x ## l, c ), n ); \
   x ## l = v128_or( v128_and( v128_sr64( x ## l, n ), c ), t ); \
}

#define W0(x)   Wz(x, v128_64( 0x5555555555555555 ),  1 )
#define W1(x)   Wz(x, v128_64( 0x3333333333333333 ),  2 )
#define W2(x)   Wz(x, v128_64( 0x0F0F0F0F0F0F0F0F ),  4 )
#define W3(x)   Wz(x, v128_64( 0x00FF00FF00FF00FF ),  8 ) 
#define W4(x)   Wz(x, v128_64( 0x0000FFFF0000FFFF ), 16 )
#define W5(x)   Wz(x, v128_64( 0x00000000FFFFFFFF ), 32 )

#define W6(x) \
{ \
   v128u64_t t = x ## h; \
   x ## h = x ## l; \
   x ## l = t; \
}

#define DECL_STATE_2x64 \
   v128u64_t h0h, h1h, h2h, h3h, h4h, h5h, h6h, h7h; \
   v128u64_t h0l, h1l, h2l, h3l, h4l, h5l, h6l, h7l; \
   v128u64_t tmp;

#define INPUT_BUF1_2x64 \
   v128u64_t m0h = buf[0]; \
   v128u64_t m0l = buf[1]; \
   v128u64_t m1h = buf[2]; \
   v128u64_t m1l = buf[3]; \
   v128u64_t m2h = buf[4]; \
   v128u64_t m2l = buf[5]; \
   v128u64_t m3h = buf[6]; \
   v128u64_t m3l = buf[7]; \
   h0h = v128_xor( h0h, m0h ); \
   h0l = v128_xor( h0l, m0l ); \
   h1h = v128_xor( h1h, m1h ); \
   h1l = v128_xor( h1l, m1l ); \
   h2h = v128_xor( h2h, m2h ); \
   h2l = v128_xor( h2l, m2l ); \
   h3h = v128_xor( h3h, m3h ); \
   h3l = v128_xor( h3l, m3l );

#define INPUT_BUF2_2x64 \
   h4h = v128_xor( h4h, m0h ); \
   h4l = v128_xor( h4l, m0l ); \
   h5h = v128_xor( h5h, m1h ); \
   h5l = v128_xor( h5l, m1l ); \
   h6h = v128_xor( h6h, m2h ); \
   h6l = v128_xor( h6l, m2l ); \
   h7h = v128_xor( h7h, m3h ); \
   h7l = v128_xor( h7l, m3l );

#define SL(ro)   SLu(r + ro, ro)

#define SLu( r, ro ) \
{ \
      S(h0, h2, h4, h6, Ceven_, r); \
      S(h1, h3, h5, h7, Codd_, r); \
      L(h0, h2, h4, h6, h1, h3, h5, h7); \
      W ## ro(h1); \
      W ## ro(h3); \
      W ## ro(h5); \
      W ## ro(h7); \
}

#define E8 \
{ \
      SLu( 0, 0); \
      SLu( 1, 1); \
      SLu( 2, 2); \
      SLu( 3, 3); \
      SLu( 4, 4); \
      SLu( 5, 5); \
      SLu( 6, 6); \
      SLu( 7, 0); \
      SLu( 8, 1); \
      SLu( 9, 2); \
      SLu(10, 3); \
      SLu(11, 4); \
      SLu(12, 5); \
      SLu(13, 6); \
      SLu(14, 0); \
      SLu(15, 1); \
      SLu(16, 2); \
      SLu(17, 3); \
      SLu(18, 4); \
      SLu(19, 5); \
      SLu(20, 6); \
      SLu(21, 0); \
      SLu(22, 1); \
      SLu(23, 2); \
      SLu(24, 3); \
      SLu(25, 4); \
      SLu(26, 5); \
      SLu(27, 6); \
      SLu(28, 0); \
      SLu(29, 1); \
      SLu(30, 2); \
      SLu(31, 3); \
      SLu(32, 4); \
      SLu(33, 5); \
      SLu(34, 6); \
      SLu(35, 0); \
      SLu(36, 1); \
      SLu(37, 2); \
      SLu(38, 3); \
      SLu(39, 4); \
      SLu(40, 5); \
      SLu(41, 6); \
}

void jh256_2x64_init( jh256_2x64_context *sc )
{
    // bswapped IV256
    sc->H[ 0] = v128_64( 0xebd3202c41a398eb );
    sc->H[ 1] = v128_64( 0xc145b29c7bbecd92 );
    sc->H[ 2] = v128_64( 0xfac7d4609151931c );
    sc->H[ 3] = v128_64( 0x038a507ed6820026 );
    sc->H[ 4] = v128_64( 0x45b92677269e23a4 );
    sc->H[ 5] = v128_64( 0x77941ad4481afbe0 );
    sc->H[ 6] = v128_64( 0x7a176b0226abb5cd );
    sc->H[ 7] = v128_64( 0xa82fff0f4224f056 );
    sc->H[ 8] = v128_64( 0x754d2e7f8996a371 );
    sc->H[ 9] = v128_64( 0x62e27df70849141d );
    sc->H[10] = v128_64( 0x948f2476f7957627 );
    sc->H[11] = v128_64( 0x6c29804757b6d587 );
    sc->H[12] = v128_64( 0x6c0d8eac2d275e5c );
    sc->H[13] = v128_64( 0x0f7a0557c6508451 );
    sc->H[14] = v128_64( 0xea12247067d3e47b );
    sc->H[15] = v128_64( 0x69d71cd313abe389 );
    sc->ptr = 0;
    sc->block_count = 0;
}

void jh512_2x64_init( jh512_2x64_context *sc )
{
    // bswapped IV512
    sc->H[ 0] = v128_64( 0x17aa003e964bd16f );
    sc->H[ 1] = v128_64( 0x43d5157a052e6a63 );
    sc->H[ 2] = v128_64( 0x0bef970c8d5e228a );
    sc->H[ 3] = v128_64( 0x61c3b3f2591234e9 );
    sc->H[ 4] = v128_64( 0x1e806f53c1a01d89 );
    sc->H[ 5] = v128_64( 0x806d2bea6b05a92a );
    sc->H[ 6] = v128_64( 0xa6ba7520dbcc8e58 );
    sc->H[ 7] = v128_64( 0xf73bf8ba763a0fa9 );
    sc->H[ 8] = v128_64( 0x694ae34105e66901 );
    sc->H[ 9] = v128_64( 0x5ae66f2e8e8ab546 );
    sc->H[10] = v128_64( 0x243c84c1d0a74710 );
    sc->H[11] = v128_64( 0x99c15a2db1716e3b );
    sc->H[12] = v128_64( 0x56f8b19decf657cf );
    sc->H[13] = v128_64( 0x56b116577c8806a7 );
    sc->H[14] = v128_64( 0xfb1785e6dffcc2e3 );
    sc->H[15] = v128_64( 0x4bdd8ccc78465a54 );
    sc->ptr = 0;
    sc->block_count = 0;
}

static void
jh_2x64_core( jh_2x64_context *sc, const void *data, size_t len )
{
    v128u64_t *buf;
    v128u64_t *vdata = (v128u64_t*)data;
   const int buf_size = 64;   // 64 * _m256i
   size_t ptr;
   DECL_STATE_2x64;

   buf = sc->buf;
   ptr = sc->ptr;

   if ( len < (buf_size - ptr) )
   {
       v128_memcpy( buf + (ptr>>3), vdata, len>>3 );
       ptr += len;
       sc->ptr = ptr;
       return;
   }

   READ_STATE(sc);
   while ( len > 0 )
   {
       size_t clen;
       clen = buf_size - ptr;
       if ( clen > len )
          clen = len;

       v128_memcpy( buf + (ptr>>3), vdata, clen>>3 );
       ptr += clen;
       vdata += (clen>>3);
       len -= clen;
       if ( ptr == buf_size )
       {
          INPUT_BUF1_2x64;
          E8;
          INPUT_BUF2_2x64;
          sc->block_count ++;
          ptr = 0;
       }
   }
   WRITE_STATE(sc);
   sc->ptr = ptr;
}

static void
jh_2x64_close( jh_2x64_context *sc, unsigned ub, unsigned n, void *dst,
               size_t out_size_w32 )
{
   v128u64_t buf[16*4];
   v128u64_t *dst256 = (v128u64_t*)dst;
   size_t numz, u;
   uint64_t l0, l1;

   buf[0] = v128_64( 0x80ULL );

   if ( sc->ptr == 0 )
       numz = 48;
   else
       numz = 112 - sc->ptr;

   v128_memset_zero( buf+1, (numz>>3) - 1 );

   l0 = ( sc->block_count << 9 ) + ( sc->ptr << 3 );
   l1 = ( sc->block_count >> 55 );
   *(buf + (numz>>3)    ) = v128_64( bswap_64( l1 ) );
   *(buf + (numz>>3) + 1) = v128_64( bswap_64( l0 ) );

   jh_2x64_core( sc, buf, numz + 16 );

   for ( u=0; u < 8; u++ )
       buf[u] = sc->H[u+8];

    v128_memcpy( dst256, buf, 8 );
}

void
jh256_2x64_update( jh_2x64_context *cc, const void *data, size_t len)
{
   jh_2x64_core(cc, data, len);
}

void
jh256_2x64_close( jh_2x64_context *cc, void *dst)
{
   jh_2x64_close(cc, 0, 0, dst, 8 );
}

void jh256_2x64_ctx( jh_2x64_context *cc, void *dst, const void *data,
                      size_t len )
{
   jh256_2x64_init( cc );
   jh256_2x64_update( cc, data, len );;
   jh256_2x64_close( cc, dst );
}

void
jh512_2x64_update( jh_2x64_context *cc, const void *data, size_t len)
{
   jh_2x64_core(cc, data, len);
}

void
jh512_2x64_close( jh_2x64_context *cc, void *dst)
{
   jh_2x64_close(cc, 0, 0, dst, 16 );
}

void jh512_2x64_ctx( jh_2x64_context *cc, void *dst, const void *data, size_t len )
{
   jh512_2x64_init( cc );
   jh512_2x64_update( cc, data, len);
   jh512_2x64_close( cc, dst);
}
