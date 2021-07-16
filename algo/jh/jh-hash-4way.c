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

#ifdef __AVX2__

#include <stddef.h>
#include <string.h>

#include "jh-hash-4way.h"

#ifdef __cplusplus
extern "C"{
#endif

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define Sb_8W(x0, x1, x2, x3, c) \
do { \
   __m512i cc = _mm512_set1_epi64( c ); \
    x3 = mm512_not( x3 ); \
    x0 = mm512_xorandnot( x0, x2, cc ); \
    tmp = mm512_xorand( cc, x0, x1 ); \
    x0 = mm512_xorand( x0, x2, x3 ); \
    x3 = mm512_xorandnot( x3, x1, x2 ); \
    x1 = mm512_xorand( x1, x0, x2 ); \
    x2 = mm512_xorandnot( x2, x3, x0 ); \
    x0 = mm512_xoror( x0, x1, x3 ); \
    x3 = mm512_xorand( x3, x1, x2 ); \
    x1 = mm512_xorand( x1, tmp, x0 ); \
    x2 = _mm512_xor_si512( x2, tmp ); \
} while (0)

#define Lb_8W(x0, x1, x2, x3, x4, x5, x6, x7) \
do { \
    x4 = _mm512_xor_si512( x4, x1 ); \
    x5 = _mm512_xor_si512( x5, x2 ); \
    x6 = mm512_xor3( x6, x3, x0 ); \
    x7 = _mm512_xor_si512( x7, x0 ); \
    x0 = _mm512_xor_si512( x0, x5 ); \
    x1 = _mm512_xor_si512( x1, x6 ); \
    x2 = mm512_xor3( x2, x7, x4 ); \
    x3 = _mm512_xor_si512( x3, x4 ); \
} while (0)

#endif

#define Sb(x0, x1, x2, x3, c) \
do { \
   __m256i cc = _mm256_set1_epi64x( c ); \
    x3 = mm256_not( x3 ); \
    x0 = _mm256_xor_si256( x0, _mm256_andnot_si256( x2, cc ) ); \
    tmp = _mm256_xor_si256( cc, _mm256_and_si256( x0, x1 ) ); \
    x0 = _mm256_xor_si256( x0, _mm256_and_si256( x2, x3 ) ); \
    x3 = _mm256_xor_si256( x3, _mm256_andnot_si256( x1, x2 ) ); \
    x1 = _mm256_xor_si256( x1, _mm256_and_si256( x0, x2 ) ); \
    x2 = _mm256_xor_si256( x2, _mm256_andnot_si256( x3, x0 ) ); \
    x0 = _mm256_xor_si256( x0, _mm256_or_si256( x1, x3 ) ); \
    x3 = _mm256_xor_si256( x3, _mm256_and_si256( x1, x2 ) ); \
    x1 = _mm256_xor_si256( x1, _mm256_and_si256( tmp, x0 ) ); \
    x2 = _mm256_xor_si256( x2, tmp ); \
} while (0)

#define Lb(x0, x1, x2, x3, x4, x5, x6, x7) \
do { \
    x4 = _mm256_xor_si256( x4, x1 ); \
    x5 = _mm256_xor_si256( x5, x2 ); \
    x6 = _mm256_xor_si256( x6, _mm256_xor_si256( x3, x0 ) ); \
    x7 = _mm256_xor_si256( x7, x0 ); \
    x0 = _mm256_xor_si256( x0, x5 ); \
    x1 = _mm256_xor_si256( x1, x6 ); \
    x2 = _mm256_xor_si256( x2, _mm256_xor_si256( x7, x4 ) ); \
    x3 = _mm256_xor_si256( x3, x4 ); \
} while (0)

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

// Big endian version

/*
static const sph_u64 C[] = {
	C64e(0x72d5dea2df15f867), C64e(0x7b84150ab7231557),
	C64e(0x81abd6904d5a87f6), C64e(0x4e9f4fc5c3d12b40),
	C64e(0xea983ae05c45fa9c), C64e(0x03c5d29966b2999a),
	C64e(0x660296b4f2bb538a), C64e(0xb556141a88dba231),
	C64e(0x03a35a5c9a190edb), C64e(0x403fb20a87c14410),
	C64e(0x1c051980849e951d), C64e(0x6f33ebad5ee7cddc),
	C64e(0x10ba139202bf6b41), C64e(0xdc786515f7bb27d0),
	C64e(0x0a2c813937aa7850), C64e(0x3f1abfd2410091d3),
	C64e(0x422d5a0df6cc7e90), C64e(0xdd629f9c92c097ce),
	C64e(0x185ca70bc72b44ac), C64e(0xd1df65d663c6fc23),
	C64e(0x976e6c039ee0b81a), C64e(0x2105457e446ceca8),
	C64e(0xeef103bb5d8e61fa), C64e(0xfd9697b294838197),
	C64e(0x4a8e8537db03302f), C64e(0x2a678d2dfb9f6a95),
	C64e(0x8afe7381f8b8696c), C64e(0x8ac77246c07f4214),
	C64e(0xc5f4158fbdc75ec4), C64e(0x75446fa78f11bb80),
	C64e(0x52de75b7aee488bc), C64e(0x82b8001e98a6a3f4),
	C64e(0x8ef48f33a9a36315), C64e(0xaa5f5624d5b7f989),
	C64e(0xb6f1ed207c5ae0fd), C64e(0x36cae95a06422c36),
	C64e(0xce2935434efe983d), C64e(0x533af974739a4ba7),
	C64e(0xd0f51f596f4e8186), C64e(0x0e9dad81afd85a9f),
	C64e(0xa7050667ee34626a), C64e(0x8b0b28be6eb91727),
	C64e(0x47740726c680103f), C64e(0xe0a07e6fc67e487b),
	C64e(0x0d550aa54af8a4c0), C64e(0x91e3e79f978ef19e),
	C64e(0x8676728150608dd4), C64e(0x7e9e5a41f3e5b062),
	C64e(0xfc9f1fec4054207a), C64e(0xe3e41a00cef4c984),
	C64e(0x4fd794f59dfa95d8), C64e(0x552e7e1124c354a5),
	C64e(0x5bdf7228bdfe6e28), C64e(0x78f57fe20fa5c4b2),
	C64e(0x05897cefee49d32e), C64e(0x447e9385eb28597f),
	C64e(0x705f6937b324314a), C64e(0x5e8628f11dd6e465),
	C64e(0xc71b770451b920e7), C64e(0x74fe43e823d4878a),
	C64e(0x7d29e8a3927694f2), C64e(0xddcb7a099b30d9c1),
	C64e(0x1d1b30fb5bdc1be0), C64e(0xda24494ff29c82bf),
	C64e(0xa4e7ba31b470bfff), C64e(0x0d324405def8bc48),
	C64e(0x3baefc3253bbd339), C64e(0x459fc3c1e0298ba0),
	C64e(0xe5c905fdf7ae090f), C64e(0x947034124290f134),
	C64e(0xa271b701e344ed95), C64e(0xe93b8e364f2f984a),
	C64e(0x88401d63a06cf615), C64e(0x47c1444b8752afff),
	C64e(0x7ebb4af1e20ac630), C64e(0x4670b6c5cc6e8ce6),
	C64e(0xa4d5a456bd4fca00), C64e(0xda9d844bc83e18ae),
	C64e(0x7357ce453064d1ad), C64e(0xe8a6ce68145c2567),
	C64e(0xa3da8cf2cb0ee116), C64e(0x33e906589a94999a),
	C64e(0x1f60b220c26f847b), C64e(0xd1ceac7fa0d18518),
	C64e(0x32595ba18ddd19d3), C64e(0x509a1cc0aaa5b446),
	C64e(0x9f3d6367e4046bba), C64e(0xf6ca19ab0b56ee7e),
	C64e(0x1fb179eaa9282174), C64e(0xe9bdf7353b3651ee),
	C64e(0x1d57ac5a7550d376), C64e(0x3a46c2fea37d7001),
	C64e(0xf735c1af98a4d842), C64e(0x78edec209e6b6779),
	C64e(0x41836315ea3adba8), C64e(0xfac33b4d32832c83),
	C64e(0xa7403b1f1c2747f3), C64e(0x5940f034b72d769a),
	C64e(0xe73e4e6cd2214ffd), C64e(0xb8fd8d39dc5759ef),
	C64e(0x8d9b0c492b49ebda), C64e(0x5ba2d74968f3700d),
	C64e(0x7d3baed07a8d5584), C64e(0xf5a5e9f0e4f88e65),
	C64e(0xa0b8a2f436103b53), C64e(0x0ca8079e753eec5a),
	C64e(0x9168949256e8884f), C64e(0x5bb05c55f8babc4c),
	C64e(0xe3bb3b99f387947b), C64e(0x75daf4d6726b1c5d),
	C64e(0x64aeac28dc34b36d), C64e(0x6c34a550b828db71),
	C64e(0xf861e2f2108d512a), C64e(0xe3db643359dd75fc),
	C64e(0x1cacbcf143ce3fa2), C64e(0x67bbd13c02e843b0),
	C64e(0x330a5bca8829a175), C64e(0x7f34194db416535c),
	C64e(0x923b94c30e794d1e), C64e(0x797475d7b6eeaf3f),
	C64e(0xeaa8d4f7be1a3921), C64e(0x5cf47e094c232751),
	C64e(0x26a32453ba323cd2), C64e(0x44a3174a6da6d5ad),
	C64e(0xb51d3ea6aff2c908), C64e(0x83593d98916b3c56),
	C64e(0x4cf87ca17286604d), C64e(0x46e23ecc086ec7f6),
	C64e(0x2f9833b3b1bc765e), C64e(0x2bd666a5efc4e62a),
	C64e(0x06f4b6e8bec1d436), C64e(0x74ee8215bcef2163),
	C64e(0xfdc14e0df453c969), C64e(0xa77d5ac406585826),
	C64e(0x7ec1141606e0fa16), C64e(0x7e90af3d28639d3f),
	C64e(0xd2c9f2e3009bd20c), C64e(0x5faace30b7d40c30),
	C64e(0x742a5116f2e03298), C64e(0x0deb30d8e3cef89a),
	C64e(0x4bc59e7bb5f17992), C64e(0xff51e66e048668d3),
	C64e(0x9b234d57e6966731), C64e(0xcce6a6f3170a7505),
	C64e(0xb17681d913326cce), C64e(0x3c175284f805a262),
	C64e(0xf42bcbb378471547), C64e(0xff46548223936a48),
	C64e(0x38df58074e5e6565), C64e(0xf2fc7c89fc86508e),
	C64e(0x31702e44d00bca86), C64e(0xf04009a23078474e),
	C64e(0x65a0ee39d1f73883), C64e(0xf75ee937e42c3abd),
	C64e(0x2197b2260113f86f), C64e(0xa344edd1ef9fdee7),
	C64e(0x8ba0df15762592d9), C64e(0x3c85f7f612dc42be),
	C64e(0xd8a7ec7cab27b07e), C64e(0x538d7ddaaa3ea8de),
	C64e(0xaa25ce93bd0269d8), C64e(0x5af643fd1a7308f9),
	C64e(0xc05fefda174a19a5), C64e(0x974d66334cfd216a),
	C64e(0x35b49831db411570), C64e(0xea1e0fbbedcd549b),
	C64e(0x9ad063a151974072), C64e(0xf6759dbf91476fe2)
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

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define S_8W(x0, x1, x2, x3, cb, r)   do { \
      Sb_8W(x0 ## h, x1 ## h, x2 ## h, x3 ## h, cb ## hi(r)); \
      Sb_8W(x0 ## l, x1 ## l, x2 ## l, x3 ## l, cb ## lo(r)); \
   } while (0)

#define L_8W(x0, x1, x2, x3, x4, x5, x6, x7)   do { \
      Lb_8W(x0 ## h, x1 ## h, x2 ## h, x3 ## h, \
         x4 ## h, x5 ## h, x6 ## h, x7 ## h); \
      Lb_8W(x0 ## l, x1 ## l, x2 ## l, x3 ## l, \
         x4 ## l, x5 ## l, x6 ## l, x7 ## l); \
   } while (0)

#define Wz_8W(x, c, n) \
do { \
   __m512i t = _mm512_slli_epi64( _mm512_and_si512(x ## h, (c)), (n) ); \
   x ## h = mm512_orand( t, _mm512_srli_epi64( x ## h, (n) ), (c) ); \
   t = _mm512_slli_epi64( _mm512_and_si512(x ## l, (c)), (n) ); \
   x ## l = mm512_orand( t, (x ## l >> (n)), (c) ); \
} while (0)


#define W80(x)   Wz_8W(x, m512_const1_64( 0x5555555555555555 ),  1 )
#define W81(x)   Wz_8W(x, m512_const1_64( 0x3333333333333333 ),  2 )
#define W82(x)   Wz_8W(x, m512_const1_64( 0x0F0F0F0F0F0F0F0F ),  4 )
#define W83(x)   Wz_8W(x, m512_const1_64( 0x00FF00FF00FF00FF ),  8 ) 
#define W84(x)   Wz_8W(x, m512_const1_64( 0x0000FFFF0000FFFF ), 16 )
#define W85(x)   Wz_8W(x, m512_const1_64( 0x00000000FFFFFFFF ), 32 )
#define W86(x) \
do { \
   __m512i t = x ## h; \
   x ## h = x ## l; \
   x ## l = t; \
} while (0)

#define DECL_STATE_8W \
   __m512i h0h, h1h, h2h, h3h, h4h, h5h, h6h, h7h; \
   __m512i h0l, h1l, h2l, h3l, h4l, h5l, h6l, h7l; \
   __m512i tmp;

#endif

#define Wz(x, c, n) \
do { \
   __m256i t = _mm256_slli_epi64( _mm256_and_si256(x ## h, (c)), (n) ); \
   x ## h = _mm256_or_si256( _mm256_and_si256( \
                                _mm256_srli_epi64(x ## h, (n)), (c)), t ); \
   t = _mm256_slli_epi64( _mm256_and_si256(x ## l, (c)), (n) ); \
   x ## l = _mm256_or_si256( _mm256_and_si256((x ## l >> (n)), (c)), t ); \
} while (0)

#define W0(x)   Wz(x, m256_const1_64( 0x5555555555555555 ),  1 )
#define W1(x)   Wz(x, m256_const1_64( 0x3333333333333333 ),  2 )
#define W2(x)   Wz(x, m256_const1_64( 0x0F0F0F0F0F0F0F0F ),  4 )
#define W3(x)   Wz(x, m256_const1_64( 0x00FF00FF00FF00FF ),  8 ) 
#define W4(x)   Wz(x, m256_const1_64( 0x0000FFFF0000FFFF ), 16 )
#define W5(x)   Wz(x, m256_const1_64( 0x00000000FFFFFFFF ), 32 )
#define W6(x) \
do { \
   __m256i t = x ## h; \
   x ## h = x ## l; \
   x ## l = t; \
} while (0)

#define DECL_STATE \
	__m256i h0h, h1h, h2h, h3h, h4h, h5h, h6h, h7h; \
	__m256i h0l, h1l, h2l, h3l, h4l, h5l, h6l, h7l; \
	__m256i tmp;


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

#endif

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
   h3l = _mm256_xor_si256( h3l, m3l ); \

#define INPUT_BUF2 \
   h4h = _mm256_xor_si256( h4h, m0h ); \
   h4l = _mm256_xor_si256( h4l, m0l ); \
   h5h = _mm256_xor_si256( h5h, m1h ); \
   h5l = _mm256_xor_si256( h5l, m1l ); \
   h6h = _mm256_xor_si256( h6h, m2h ); \
   h6l = _mm256_xor_si256( h6l, m2l ); \
   h7h = _mm256_xor_si256( h7h, m3h ); \
   h7l = _mm256_xor_si256( h7l, m3l ); \

/*
static const sph_u64 IV256[] = {
	C64e(0xeb98a3412c20d3eb), C64e(0x92cdbe7b9cb245c1),
	C64e(0x1c93519160d4c7fa), C64e(0x260082d67e508a03),
	C64e(0xa4239e267726b945), C64e(0xe0fb1a48d41a9477),
	C64e(0xcdb5ab26026b177a), C64e(0x56f024420fff2fa8),
	C64e(0x71a396897f2e4d75), C64e(0x1d144908f77de262),
	C64e(0x277695f776248f94), C64e(0x87d5b6574780296c),
	C64e(0x5c5e272dac8e0d6c), C64e(0x518450c657057a0f),
	C64e(0x7be4d367702412ea), C64e(0x89e3ab13d31cd769)
};


static const sph_u64 IV512[] = {
	C64e(0x6fd14b963e00aa17), C64e(0x636a2e057a15d543),
	C64e(0x8a225e8d0c97ef0b), C64e(0xe9341259f2b3c361),
	C64e(0x891da0c1536f801e), C64e(0x2aa9056bea2b6d80),
	C64e(0x588eccdb2075baa6), C64e(0xa90f3a76baf83bf7),
	C64e(0x0169e60541e34a69), C64e(0x46b58a8e2e6fe65a),
	C64e(0x1047a7d0c1843c24), C64e(0x3b6e71b12d5ac199),
	C64e(0xcf57f6ec9db1f856), C64e(0xa706887c5716b156),
	C64e(0xe3c2fcdfe68517fb), C64e(0x545a4678cc8cdd4b)
};
*/


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define SL_8W(ro)   SLu_8W(r + ro, ro)

#define SLu_8W(r, ro)   do { \
      S_8W(h0, h2, h4, h6, Ceven_, r); \
      S_8W(h1, h3, h5, h7, Codd_, r); \
      L_8W(h0, h2, h4, h6, h1, h3, h5, h7); \
      W8 ## ro(h1); \
      W8 ## ro(h3); \
      W8 ## ro(h5); \
      W8 ## ro(h7); \
   } while (0)

#endif

#define SL(ro)   SLu(r + ro, ro)

#define SLu(r, ro)   do { \
		S(h0, h2, h4, h6, Ceven_, r); \
		S(h1, h3, h5, h7, Codd_, r); \
		L(h0, h2, h4, h6, h1, h3, h5, h7); \
		W ## ro(h1); \
		W ## ro(h3); \
		W ## ro(h5); \
		W ## ro(h7); \
	} while (0)


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

#define E8_8W   do { \
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
	} while (0)

#endif  // AVX512


#define E8   do { \
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
   } while (0)

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

void jh256_8way_init( jh_8way_context *sc )
{
    // bswapped IV256
    sc->H[ 0] = m512_const1_64( 0xebd3202c41a398eb );
    sc->H[ 1] = m512_const1_64( 0xc145b29c7bbecd92 );
    sc->H[ 2] = m512_const1_64( 0xfac7d4609151931c );
    sc->H[ 3] = m512_const1_64( 0x038a507ed6820026 );
    sc->H[ 4] = m512_const1_64( 0x45b92677269e23a4 );
    sc->H[ 5] = m512_const1_64( 0x77941ad4481afbe0 );
    sc->H[ 6] = m512_const1_64( 0x7a176b0226abb5cd );
    sc->H[ 7] = m512_const1_64( 0xa82fff0f4224f056 );
    sc->H[ 8] = m512_const1_64( 0x754d2e7f8996a371 );
    sc->H[ 9] = m512_const1_64( 0x62e27df70849141d );
    sc->H[10] = m512_const1_64( 0x948f2476f7957627 );
    sc->H[11] = m512_const1_64( 0x6c29804757b6d587 );
    sc->H[12] = m512_const1_64( 0x6c0d8eac2d275e5c );
    sc->H[13] = m512_const1_64( 0x0f7a0557c6508451 );
    sc->H[14] = m512_const1_64( 0xea12247067d3e47b );
    sc->H[15] = m512_const1_64( 0x69d71cd313abe389 );
    sc->ptr = 0;
    sc->block_count = 0;
}

void jh512_8way_init( jh_8way_context *sc )
{
    // bswapped IV512
    sc->H[ 0] = m512_const1_64( 0x17aa003e964bd16f );
    sc->H[ 1] = m512_const1_64( 0x43d5157a052e6a63 );
    sc->H[ 2] = m512_const1_64( 0x0bef970c8d5e228a );
    sc->H[ 3] = m512_const1_64( 0x61c3b3f2591234e9 );
    sc->H[ 4] = m512_const1_64( 0x1e806f53c1a01d89 );
    sc->H[ 5] = m512_const1_64( 0x806d2bea6b05a92a );
    sc->H[ 6] = m512_const1_64( 0xa6ba7520dbcc8e58 );
    sc->H[ 7] = m512_const1_64( 0xf73bf8ba763a0fa9 );
    sc->H[ 8] = m512_const1_64( 0x694ae34105e66901 );
    sc->H[ 9] = m512_const1_64( 0x5ae66f2e8e8ab546 );
    sc->H[10] = m512_const1_64( 0x243c84c1d0a74710 );
    sc->H[11] = m512_const1_64( 0x99c15a2db1716e3b );
    sc->H[12] = m512_const1_64( 0x56f8b19decf657cf );
    sc->H[13] = m512_const1_64( 0x56b116577c8806a7 );
    sc->H[14] = m512_const1_64( 0xfb1785e6dffcc2e3 );
    sc->H[15] = m512_const1_64( 0x4bdd8ccc78465a54 );
    sc->ptr = 0;
    sc->block_count = 0;
}

static void
jh_8way_core( jh_8way_context *sc, const void *data, size_t len )
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
jh_8way_close( jh_8way_context *sc, unsigned ub, unsigned n, void *dst,
               size_t out_size_w32 )
{
   __m512i buf[16*4];
   __m512i *dst512 = (__m512i*)dst;
   size_t numz, u;
   uint64_t l0, l1;

   buf[0] = m512_const1_64( 0x80ULL );

   if ( sc->ptr == 0 )
       numz = 48;
   else
       numz = 112 - sc->ptr;

   memset_zero_512( buf+1, (numz>>3) - 1 );

   l0 = ( sc->block_count << 9 ) + ( sc->ptr << 3 );
   l1 = ( sc->block_count >> 55 );
   *(buf + (numz>>3)    ) = _mm512_set1_epi64( bswap_64( l1 ) );
   *(buf + (numz>>3) + 1) = _mm512_set1_epi64( bswap_64( l0 ) );

   jh_8way_core( sc, buf, numz + 16 );

   for ( u=0; u < 8; u++ )
       buf[u] = sc->H[u+8];

    memcpy_512( dst512, buf, 8 );
}

void
jh256_8way_update(void *cc, const void *data, size_t len)
{
   jh_8way_core(cc, data, len);
}

void
jh256_8way_close(void *cc, void *dst)
{
   jh_8way_close(cc, 0, 0, dst, 8);
}

void
jh512_8way_update(void *cc, const void *data, size_t len)
{
   jh_8way_core(cc, data, len);
}

void
jh512_8way_close(void *cc, void *dst)
{
   jh_8way_close(cc, 0, 0, dst, 16);
}

#endif

void jh256_4way_init( jh_4way_context *sc )
{
    // bswapped IV256
    sc->H[ 0] = m256_const1_64( 0xebd3202c41a398eb );
    sc->H[ 1] = m256_const1_64( 0xc145b29c7bbecd92 );
    sc->H[ 2] = m256_const1_64( 0xfac7d4609151931c );
    sc->H[ 3] = m256_const1_64( 0x038a507ed6820026 );
    sc->H[ 4] = m256_const1_64( 0x45b92677269e23a4 );
    sc->H[ 5] = m256_const1_64( 0x77941ad4481afbe0 );
    sc->H[ 6] = m256_const1_64( 0x7a176b0226abb5cd );
    sc->H[ 7] = m256_const1_64( 0xa82fff0f4224f056 );
    sc->H[ 8] = m256_const1_64( 0x754d2e7f8996a371 );
    sc->H[ 9] = m256_const1_64( 0x62e27df70849141d );
    sc->H[10] = m256_const1_64( 0x948f2476f7957627 );
    sc->H[11] = m256_const1_64( 0x6c29804757b6d587 );
    sc->H[12] = m256_const1_64( 0x6c0d8eac2d275e5c );
    sc->H[13] = m256_const1_64( 0x0f7a0557c6508451 );
    sc->H[14] = m256_const1_64( 0xea12247067d3e47b );
    sc->H[15] = m256_const1_64( 0x69d71cd313abe389 );
    sc->ptr = 0;
    sc->block_count = 0;
}

void jh512_4way_init( jh_4way_context *sc )
{
    // bswapped IV512
    sc->H[ 0] = m256_const1_64( 0x17aa003e964bd16f );
    sc->H[ 1] = m256_const1_64( 0x43d5157a052e6a63 );
    sc->H[ 2] = m256_const1_64( 0x0bef970c8d5e228a );
    sc->H[ 3] = m256_const1_64( 0x61c3b3f2591234e9 );
    sc->H[ 4] = m256_const1_64( 0x1e806f53c1a01d89 );
    sc->H[ 5] = m256_const1_64( 0x806d2bea6b05a92a );
    sc->H[ 6] = m256_const1_64( 0xa6ba7520dbcc8e58 );
    sc->H[ 7] = m256_const1_64( 0xf73bf8ba763a0fa9 );
    sc->H[ 8] = m256_const1_64( 0x694ae34105e66901 );
    sc->H[ 9] = m256_const1_64( 0x5ae66f2e8e8ab546 );
    sc->H[10] = m256_const1_64( 0x243c84c1d0a74710 );
    sc->H[11] = m256_const1_64( 0x99c15a2db1716e3b );
    sc->H[12] = m256_const1_64( 0x56f8b19decf657cf );
    sc->H[13] = m256_const1_64( 0x56b116577c8806a7 );
    sc->H[14] = m256_const1_64( 0xfb1785e6dffcc2e3 );
    sc->H[15] = m256_const1_64( 0x4bdd8ccc78465a54 );
    sc->ptr = 0;
    sc->block_count = 0;
}

static void
jh_4way_core( jh_4way_context *sc, const void *data, size_t len )
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
jh_4way_close( jh_4way_context *sc, unsigned ub, unsigned n, void *dst,
               size_t out_size_w32 )
{
   __m256i buf[16*4];
   __m256i *dst256 = (__m256i*)dst;
   size_t numz, u;
   uint64_t l0, l1;

   buf[0] = m256_const1_64( 0x80ULL );

   if ( sc->ptr == 0 )
       numz = 48;
   else
       numz = 112 - sc->ptr;

   memset_zero_256( buf+1, (numz>>3) - 1 );   

   l0 = ( sc->block_count << 9 ) + ( sc->ptr << 3 );
   l1 = ( sc->block_count >> 55 );
   *(buf + (numz>>3)    ) = _mm256_set1_epi64x( bswap_64( l1 ) );
   *(buf + (numz>>3) + 1) = _mm256_set1_epi64x( bswap_64( l0 ) );

   jh_4way_core( sc, buf, numz + 16 );

   for ( u=0; u < 8; u++ )
       buf[u] = sc->H[u+8];

    memcpy_256( dst256, buf, 8 );
}

void
jh256_4way_update(void *cc, const void *data, size_t len)
{
	jh_4way_core(cc, data, len);
}

void
jh256_4way_close(void *cc, void *dst)
{
	jh_4way_close(cc, 0, 0, dst, 8 );
}

void
jh512_4way_update(void *cc, const void *data, size_t len)
{
	jh_4way_core(cc, data, len);
}

void
jh512_4way_close(void *cc, void *dst)
{
	jh_4way_close(cc, 0, 0, dst, 16 );
}


#ifdef __cplusplus
}
#endif

#endif
