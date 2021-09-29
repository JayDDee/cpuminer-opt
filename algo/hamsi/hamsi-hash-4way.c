/* $Id: hamsi.c 251 2010-10-19 14:31:51Z tp $ */
/*
 * Hamsi implementation.
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
#include "hamsi-hash-4way.h"

#if defined(__AVX2__)

#ifdef __cplusplus
extern "C"{
#endif

/*
 * The SPH_HAMSI_EXPAND_* define how many input bits we handle in one
 * table lookup during message expansion (1 to 8, inclusive). If we note
 * w the number of bits per message word (w=32 for Hamsi-224/256, w=64
 * for Hamsi-384/512), r the size of a "row" in 32-bit words (r=8 for
 * Hamsi-224/256, r=16 for Hamsi-384/512), and n the expansion level,
 * then we will get t tables (where t=ceil(w/n)) of individual size
 * 2^n*r*4 (in bytes). The last table may be shorter (e.g. with w=32 and
 * n=5, there are 7 tables, but the last one uses only two bits on
 * input, not five).
 *
 * Also, we read t rows of r words from RAM. Words in a given row are
 * concatenated in RAM in that order, so most of the cost is about
 * reading the first row word; comparatively, cache misses are thus
 * less expensive with Hamsi-512 (r=16) than with Hamsi-256 (r=8).
 *
 * When n=1, tables are "special" in that we omit the first entry of
 * each table (which always contains 0), so that total table size is
 * halved.
 *
 * We thus have the following (size1 is the cumulative table size of
 * Hamsi-224/256; size2 is for Hamsi-384/512; similarly, t1 and t2
 * are for Hamsi-224/256 and Hamsi-384/512, respectively).
 *
 *   n      size1      size2    t1    t2
 * ---------------------------------------
 *   1       1024       4096    32    64
 *   2       2048       8192    16    32
 *   3       2688      10880    11    22
 *   4       4096      16384     8    16
 *   5       6272      25600     7    13
 *   6      10368      41984     6    11
 *   7      16896      73856     5    10
 *   8      32768     131072     4     8
 *
 * So there is a trade-off: a lower n makes the tables fit better in
 * L1 cache, but increases the number of memory accesses. The optimal
 * value depends on the amount of available L1 cache and the relative
 * impact of a cache miss.
 *
 * Experimentally, in ideal benchmark conditions (which are not necessarily
 * realistic with regards to L1 cache contention), it seems that n=8 is
 * the best value on "big" architectures (those with 32 kB or more of L1
 * cache), while n=4 is better on "small" architectures. This was tested
 * on an Intel Core2 Q6600 (both 32-bit and 64-bit mode), a PowerPC G3
 * (32 kB L1 cache, hence "big"), and a MIPS-compatible Broadcom BCM3302
 * (8 kB L1 cache).
 *
 * Note: with n=1, the 32 tables (actually implemented as one big table)
 * are read entirely and sequentially, regardless of the input data,
 * thus avoiding any data-dependent table access pattern.
 */

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

//#include "hamsi-helper-4way.c"
/*
static const sph_u32 IV512[] = {
	SPH_C32(0x73746565), SPH_C32(0x6c706172), SPH_C32(0x6b204172),
	SPH_C32(0x656e6265), SPH_C32(0x72672031), SPH_C32(0x302c2062),
	SPH_C32(0x75732032), SPH_C32(0x3434362c), SPH_C32(0x20422d33),
	SPH_C32(0x30303120), SPH_C32(0x4c657576), SPH_C32(0x656e2d48),
	SPH_C32(0x65766572), SPH_C32(0x6c65652c), SPH_C32(0x2042656c),
	SPH_C32(0x6769756d)
};
*/
static const sph_u32 alpha_n[] = {
	SPH_C32(0xff00f0f0), SPH_C32(0xccccaaaa), SPH_C32(0xf0f0cccc),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccaaaa), SPH_C32(0xf0f0ff00),
	SPH_C32(0xaaaacccc), SPH_C32(0xf0f0ff00), SPH_C32(0xf0f0cccc),
	SPH_C32(0xaaaaff00), SPH_C32(0xccccff00), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xaaaaf0f0), SPH_C32(0xff00cccc), SPH_C32(0xccccf0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccaaaa), SPH_C32(0xff00f0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xf0f0cccc), SPH_C32(0xf0f0ff00),
	SPH_C32(0xccccaaaa), SPH_C32(0xf0f0ff00), SPH_C32(0xaaaacccc),
	SPH_C32(0xaaaaff00), SPH_C32(0xf0f0cccc), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xccccff00), SPH_C32(0xff00cccc), SPH_C32(0xaaaaf0f0),
	SPH_C32(0xff00aaaa), SPH_C32(0xccccf0f0)
};

static const sph_u32 alpha_f[] = {
	SPH_C32(0xcaf9639c), SPH_C32(0x0ff0f9c0), SPH_C32(0x639c0ff0),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0f9c0), SPH_C32(0x639ccaf9),
	SPH_C32(0xf9c00ff0), SPH_C32(0x639ccaf9), SPH_C32(0x639c0ff0),
	SPH_C32(0xf9c0caf9), SPH_C32(0x0ff0caf9), SPH_C32(0xf9c0639c),
	SPH_C32(0xf9c0639c), SPH_C32(0xcaf90ff0), SPH_C32(0x0ff0639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0f9c0), SPH_C32(0xcaf9639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x639c0ff0), SPH_C32(0x639ccaf9),
	SPH_C32(0x0ff0f9c0), SPH_C32(0x639ccaf9), SPH_C32(0xf9c00ff0),
	SPH_C32(0xf9c0caf9), SPH_C32(0x639c0ff0), SPH_C32(0xf9c0639c),
	SPH_C32(0x0ff0caf9), SPH_C32(0xcaf90ff0), SPH_C32(0xf9c0639c),
	SPH_C32(0xcaf9f9c0), SPH_C32(0x0ff0639c)
};


// imported from hamsi helper

/* Note: this table lists bits within each byte from least
   siginificant to most significant. */
static const sph_u32 T512[64][16] = {
	{ SPH_C32(0xef0b0270), SPH_C32(0x3afd0000), SPH_C32(0x5dae0000),
	  SPH_C32(0x69490000), SPH_C32(0x9b0f3c06), SPH_C32(0x4405b5f9),
	  SPH_C32(0x66140a51), SPH_C32(0x924f5d0a), SPH_C32(0xc96b0030),
	  SPH_C32(0xe7250000), SPH_C32(0x2f840000), SPH_C32(0x264f0000),
	  SPH_C32(0x08695bf9), SPH_C32(0x6dfcf137), SPH_C32(0x509f6984),
	  SPH_C32(0x9e69af68) },
	{ SPH_C32(0xc96b0030), SPH_C32(0xe7250000), SPH_C32(0x2f840000),
	  SPH_C32(0x264f0000), SPH_C32(0x08695bf9), SPH_C32(0x6dfcf137),
	  SPH_C32(0x509f6984), SPH_C32(0x9e69af68), SPH_C32(0x26600240),
	  SPH_C32(0xddd80000), SPH_C32(0x722a0000), SPH_C32(0x4f060000),
	  SPH_C32(0x936667ff), SPH_C32(0x29f944ce), SPH_C32(0x368b63d5),
	  SPH_C32(0x0c26f262) },
	{ SPH_C32(0x145a3c00), SPH_C32(0xb9e90000), SPH_C32(0x61270000),
	  SPH_C32(0xf1610000), SPH_C32(0xce613d6c), SPH_C32(0xb0493d78),
	  SPH_C32(0x47a96720), SPH_C32(0xe18e24c5), SPH_C32(0x23671400),
	  SPH_C32(0xc8b90000), SPH_C32(0xf4c70000), SPH_C32(0xfb750000),
	  SPH_C32(0x73cd2465), SPH_C32(0xf8a6a549), SPH_C32(0x02c40a3f),
	  SPH_C32(0xdc24e61f) },
	{ SPH_C32(0x23671400), SPH_C32(0xc8b90000), SPH_C32(0xf4c70000),
	  SPH_C32(0xfb750000), SPH_C32(0x73cd2465), SPH_C32(0xf8a6a549),
	  SPH_C32(0x02c40a3f), SPH_C32(0xdc24e61f), SPH_C32(0x373d2800),
	  SPH_C32(0x71500000), SPH_C32(0x95e00000), SPH_C32(0x0a140000),
	  SPH_C32(0xbdac1909), SPH_C32(0x48ef9831), SPH_C32(0x456d6d1f),
	  SPH_C32(0x3daac2da) },
	{ SPH_C32(0x54285c00), SPH_C32(0xeaed0000), SPH_C32(0xc5d60000),
	  SPH_C32(0xa1c50000), SPH_C32(0xb3a26770), SPH_C32(0x94a5c4e1),
	  SPH_C32(0x6bb0419d), SPH_C32(0x551b3782), SPH_C32(0x9cbb1800),
	  SPH_C32(0xb0d30000), SPH_C32(0x92510000), SPH_C32(0xed930000),
	  SPH_C32(0x593a4345), SPH_C32(0xe114d5f4), SPH_C32(0x430633da),
	  SPH_C32(0x78cace29) },
	{ SPH_C32(0x9cbb1800), SPH_C32(0xb0d30000), SPH_C32(0x92510000),
	  SPH_C32(0xed930000), SPH_C32(0x593a4345), SPH_C32(0xe114d5f4),
	  SPH_C32(0x430633da), SPH_C32(0x78cace29), SPH_C32(0xc8934400),
	  SPH_C32(0x5a3e0000), SPH_C32(0x57870000), SPH_C32(0x4c560000),
	  SPH_C32(0xea982435), SPH_C32(0x75b11115), SPH_C32(0x28b67247),
	  SPH_C32(0x2dd1f9ab) },
	{ SPH_C32(0x29449c00), SPH_C32(0x64e70000), SPH_C32(0xf24b0000),
	  SPH_C32(0xc2f30000), SPH_C32(0x0ede4e8f), SPH_C32(0x56c23745),
	  SPH_C32(0xf3e04259), SPH_C32(0x8d0d9ec4), SPH_C32(0x466d0c00),
	  SPH_C32(0x08620000), SPH_C32(0xdd5d0000), SPH_C32(0xbadd0000),
	  SPH_C32(0x6a927942), SPH_C32(0x441f2b93), SPH_C32(0x218ace6f),
	  SPH_C32(0xbf2c0be2) },
	{ SPH_C32(0x466d0c00), SPH_C32(0x08620000), SPH_C32(0xdd5d0000),
	  SPH_C32(0xbadd0000), SPH_C32(0x6a927942), SPH_C32(0x441f2b93),
	  SPH_C32(0x218ace6f), SPH_C32(0xbf2c0be2), SPH_C32(0x6f299000),
	  SPH_C32(0x6c850000), SPH_C32(0x2f160000), SPH_C32(0x782e0000),
	  SPH_C32(0x644c37cd), SPH_C32(0x12dd1cd6), SPH_C32(0xd26a8c36),
	  SPH_C32(0x32219526) },
	{ SPH_C32(0xf6800005), SPH_C32(0x3443c000), SPH_C32(0x24070000),
	  SPH_C32(0x8f3d0000), SPH_C32(0x21373bfb), SPH_C32(0x0ab8d5ae),
	  SPH_C32(0xcdc58b19), SPH_C32(0xd795ba31), SPH_C32(0xa67f0001),
	  SPH_C32(0x71378000), SPH_C32(0x19fc0000), SPH_C32(0x96db0000),
	  SPH_C32(0x3a8b6dfd), SPH_C32(0xebcaaef3), SPH_C32(0x2c6d478f),
	  SPH_C32(0xac8e6c88) },
	{ SPH_C32(0xa67f0001), SPH_C32(0x71378000), SPH_C32(0x19fc0000),
	  SPH_C32(0x96db0000), SPH_C32(0x3a8b6dfd), SPH_C32(0xebcaaef3),
	  SPH_C32(0x2c6d478f), SPH_C32(0xac8e6c88), SPH_C32(0x50ff0004),
	  SPH_C32(0x45744000), SPH_C32(0x3dfb0000), SPH_C32(0x19e60000),
	  SPH_C32(0x1bbc5606), SPH_C32(0xe1727b5d), SPH_C32(0xe1a8cc96),
	  SPH_C32(0x7b1bd6b9) },
	{ SPH_C32(0xf7750009), SPH_C32(0xcf3cc000), SPH_C32(0xc3d60000),
	  SPH_C32(0x04920000), SPH_C32(0x029519a9), SPH_C32(0xf8e836ba),
	  SPH_C32(0x7a87f14e), SPH_C32(0x9e16981a), SPH_C32(0xd46a0000),
	  SPH_C32(0x8dc8c000), SPH_C32(0xa5af0000), SPH_C32(0x4a290000),
	  SPH_C32(0xfc4e427a), SPH_C32(0xc9b4866c), SPH_C32(0x98369604),
	  SPH_C32(0xf746c320) },
	{ SPH_C32(0xd46a0000), SPH_C32(0x8dc8c000), SPH_C32(0xa5af0000),
	  SPH_C32(0x4a290000), SPH_C32(0xfc4e427a), SPH_C32(0xc9b4866c),
	  SPH_C32(0x98369604), SPH_C32(0xf746c320), SPH_C32(0x231f0009),
	  SPH_C32(0x42f40000), SPH_C32(0x66790000), SPH_C32(0x4ebb0000),
	  SPH_C32(0xfedb5bd3), SPH_C32(0x315cb0d6), SPH_C32(0xe2b1674a),
	  SPH_C32(0x69505b3a) },
	{ SPH_C32(0x774400f0), SPH_C32(0xf15a0000), SPH_C32(0xf5b20000),
	  SPH_C32(0x34140000), SPH_C32(0x89377e8c), SPH_C32(0x5a8bec25),
	  SPH_C32(0x0bc3cd1e), SPH_C32(0xcf3775cb), SPH_C32(0xf46c0050),
	  SPH_C32(0x96180000), SPH_C32(0x14a50000), SPH_C32(0x031f0000),
	  SPH_C32(0x42947eb8), SPH_C32(0x66bf7e19), SPH_C32(0x9ca470d2),
	  SPH_C32(0x8a341574) },
	{ SPH_C32(0xf46c0050), SPH_C32(0x96180000), SPH_C32(0x14a50000),
	  SPH_C32(0x031f0000), SPH_C32(0x42947eb8), SPH_C32(0x66bf7e19),
	  SPH_C32(0x9ca470d2), SPH_C32(0x8a341574), SPH_C32(0x832800a0),
	  SPH_C32(0x67420000), SPH_C32(0xe1170000), SPH_C32(0x370b0000),
	  SPH_C32(0xcba30034), SPH_C32(0x3c34923c), SPH_C32(0x9767bdcc),
	  SPH_C32(0x450360bf) },
	{ SPH_C32(0xe8870170), SPH_C32(0x9d720000), SPH_C32(0x12db0000),
	  SPH_C32(0xd4220000), SPH_C32(0xf2886b27), SPH_C32(0xa921e543),
	  SPH_C32(0x4ef8b518), SPH_C32(0x618813b1), SPH_C32(0xb4370060),
	  SPH_C32(0x0c4c0000), SPH_C32(0x56c20000), SPH_C32(0x5cae0000),
	  SPH_C32(0x94541f3f), SPH_C32(0x3b3ef825), SPH_C32(0x1b365f3d),
	  SPH_C32(0xf3d45758) },
	{ SPH_C32(0xb4370060), SPH_C32(0x0c4c0000), SPH_C32(0x56c20000),
	  SPH_C32(0x5cae0000), SPH_C32(0x94541f3f), SPH_C32(0x3b3ef825),
	  SPH_C32(0x1b365f3d), SPH_C32(0xf3d45758), SPH_C32(0x5cb00110),
	  SPH_C32(0x913e0000), SPH_C32(0x44190000), SPH_C32(0x888c0000),
	  SPH_C32(0x66dc7418), SPH_C32(0x921f1d66), SPH_C32(0x55ceea25),
	  SPH_C32(0x925c44e9) },
	{ SPH_C32(0x0c720000), SPH_C32(0x49e50f00), SPH_C32(0x42790000),
	  SPH_C32(0x5cea0000), SPH_C32(0x33aa301a), SPH_C32(0x15822514),
	  SPH_C32(0x95a34b7b), SPH_C32(0xb44b0090), SPH_C32(0xfe220000),
	  SPH_C32(0xa7580500), SPH_C32(0x25d10000), SPH_C32(0xf7600000),
	  SPH_C32(0x893178da), SPH_C32(0x1fd4f860), SPH_C32(0x4ed0a315),
	  SPH_C32(0xa123ff9f) },
	{ SPH_C32(0xfe220000), SPH_C32(0xa7580500), SPH_C32(0x25d10000),
	  SPH_C32(0xf7600000), SPH_C32(0x893178da), SPH_C32(0x1fd4f860),
	  SPH_C32(0x4ed0a315), SPH_C32(0xa123ff9f), SPH_C32(0xf2500000),
	  SPH_C32(0xeebd0a00), SPH_C32(0x67a80000), SPH_C32(0xab8a0000),
	  SPH_C32(0xba9b48c0), SPH_C32(0x0a56dd74), SPH_C32(0xdb73e86e),
	  SPH_C32(0x1568ff0f) },
	{ SPH_C32(0x45180000), SPH_C32(0xa5b51700), SPH_C32(0xf96a0000),
	  SPH_C32(0x3b480000), SPH_C32(0x1ecc142c), SPH_C32(0x231395d6),
	  SPH_C32(0x16bca6b0), SPH_C32(0xdf33f4df), SPH_C32(0xb83d0000),
	  SPH_C32(0x16710600), SPH_C32(0x379a0000), SPH_C32(0xf5b10000),
	  SPH_C32(0x228161ac), SPH_C32(0xae48f145), SPH_C32(0x66241616),
	  SPH_C32(0xc5c1eb3e) },
	{ SPH_C32(0xb83d0000), SPH_C32(0x16710600), SPH_C32(0x379a0000),
	  SPH_C32(0xf5b10000), SPH_C32(0x228161ac), SPH_C32(0xae48f145),
	  SPH_C32(0x66241616), SPH_C32(0xc5c1eb3e), SPH_C32(0xfd250000),
	  SPH_C32(0xb3c41100), SPH_C32(0xcef00000), SPH_C32(0xcef90000),
	  SPH_C32(0x3c4d7580), SPH_C32(0x8d5b6493), SPH_C32(0x7098b0a6),
	  SPH_C32(0x1af21fe1) },
	{ SPH_C32(0x75a40000), SPH_C32(0xc28b2700), SPH_C32(0x94a40000),
	  SPH_C32(0x90f50000), SPH_C32(0xfb7857e0), SPH_C32(0x49ce0bae),
	  SPH_C32(0x1767c483), SPH_C32(0xaedf667e), SPH_C32(0xd1660000),
	  SPH_C32(0x1bbc0300), SPH_C32(0x9eec0000), SPH_C32(0xf6940000),
	  SPH_C32(0x03024527), SPH_C32(0xcf70fcf2), SPH_C32(0xb4431b17),
	  SPH_C32(0x857f3c2b) },
	{ SPH_C32(0xd1660000), SPH_C32(0x1bbc0300), SPH_C32(0x9eec0000),
	  SPH_C32(0xf6940000), SPH_C32(0x03024527), SPH_C32(0xcf70fcf2),
	  SPH_C32(0xb4431b17), SPH_C32(0x857f3c2b), SPH_C32(0xa4c20000),
	  SPH_C32(0xd9372400), SPH_C32(0x0a480000), SPH_C32(0x66610000),
	  SPH_C32(0xf87a12c7), SPH_C32(0x86bef75c), SPH_C32(0xa324df94),
	  SPH_C32(0x2ba05a55) },
	{ SPH_C32(0x75c90003), SPH_C32(0x0e10c000), SPH_C32(0xd1200000),
	  SPH_C32(0xbaea0000), SPH_C32(0x8bc42f3e), SPH_C32(0x8758b757),
	  SPH_C32(0xbb28761d), SPH_C32(0x00b72e2b), SPH_C32(0xeecf0001),
	  SPH_C32(0x6f564000), SPH_C32(0xf33e0000), SPH_C32(0xa79e0000),
	  SPH_C32(0xbdb57219), SPH_C32(0xb711ebc5), SPH_C32(0x4a3b40ba),
	  SPH_C32(0xfeabf254) },
	{ SPH_C32(0xeecf0001), SPH_C32(0x6f564000), SPH_C32(0xf33e0000),
	  SPH_C32(0xa79e0000), SPH_C32(0xbdb57219), SPH_C32(0xb711ebc5),
	  SPH_C32(0x4a3b40ba), SPH_C32(0xfeabf254), SPH_C32(0x9b060002),
	  SPH_C32(0x61468000), SPH_C32(0x221e0000), SPH_C32(0x1d740000),
	  SPH_C32(0x36715d27), SPH_C32(0x30495c92), SPH_C32(0xf11336a7),
	  SPH_C32(0xfe1cdc7f) },
	{ SPH_C32(0x86790000), SPH_C32(0x3f390002), SPH_C32(0xe19ae000),
	  SPH_C32(0x98560000), SPH_C32(0x9565670e), SPH_C32(0x4e88c8ea),
	  SPH_C32(0xd3dd4944), SPH_C32(0x161ddab9), SPH_C32(0x30b70000),
	  SPH_C32(0xe5d00000), SPH_C32(0xf4f46000), SPH_C32(0x42c40000),
	  SPH_C32(0x63b83d6a), SPH_C32(0x78ba9460), SPH_C32(0x21afa1ea),
	  SPH_C32(0xb0a51834) },
	{ SPH_C32(0x30b70000), SPH_C32(0xe5d00000), SPH_C32(0xf4f46000),
	  SPH_C32(0x42c40000), SPH_C32(0x63b83d6a), SPH_C32(0x78ba9460),
	  SPH_C32(0x21afa1ea), SPH_C32(0xb0a51834), SPH_C32(0xb6ce0000),
	  SPH_C32(0xdae90002), SPH_C32(0x156e8000), SPH_C32(0xda920000),
	  SPH_C32(0xf6dd5a64), SPH_C32(0x36325c8a), SPH_C32(0xf272e8ae),
	  SPH_C32(0xa6b8c28d) },
	{ SPH_C32(0x14190000), SPH_C32(0x23ca003c), SPH_C32(0x50df0000),
	  SPH_C32(0x44b60000), SPH_C32(0x1b6c67b0), SPH_C32(0x3cf3ac75),
	  SPH_C32(0x61e610b0), SPH_C32(0xdbcadb80), SPH_C32(0xe3430000),
	  SPH_C32(0x3a4e0014), SPH_C32(0xf2c60000), SPH_C32(0xaa4e0000),
	  SPH_C32(0xdb1e42a6), SPH_C32(0x256bbe15), SPH_C32(0x123db156),
	  SPH_C32(0x3a4e99d7) },
	{ SPH_C32(0xe3430000), SPH_C32(0x3a4e0014), SPH_C32(0xf2c60000),
	  SPH_C32(0xaa4e0000), SPH_C32(0xdb1e42a6), SPH_C32(0x256bbe15),
	  SPH_C32(0x123db156), SPH_C32(0x3a4e99d7), SPH_C32(0xf75a0000),
	  SPH_C32(0x19840028), SPH_C32(0xa2190000), SPH_C32(0xeef80000),
	  SPH_C32(0xc0722516), SPH_C32(0x19981260), SPH_C32(0x73dba1e6),
	  SPH_C32(0xe1844257) },
	{ SPH_C32(0x54500000), SPH_C32(0x0671005c), SPH_C32(0x25ae0000),
	  SPH_C32(0x6a1e0000), SPH_C32(0x2ea54edf), SPH_C32(0x664e8512),
	  SPH_C32(0xbfba18c3), SPH_C32(0x7e715d17), SPH_C32(0xbc8d0000),
	  SPH_C32(0xfc3b0018), SPH_C32(0x19830000), SPH_C32(0xd10b0000),
	  SPH_C32(0xae1878c4), SPH_C32(0x42a69856), SPH_C32(0x0012da37),
	  SPH_C32(0x2c3b504e) },
	{ SPH_C32(0xbc8d0000), SPH_C32(0xfc3b0018), SPH_C32(0x19830000),
	  SPH_C32(0xd10b0000), SPH_C32(0xae1878c4), SPH_C32(0x42a69856),
	  SPH_C32(0x0012da37), SPH_C32(0x2c3b504e), SPH_C32(0xe8dd0000),
	  SPH_C32(0xfa4a0044), SPH_C32(0x3c2d0000), SPH_C32(0xbb150000),
	  SPH_C32(0x80bd361b), SPH_C32(0x24e81d44), SPH_C32(0xbfa8c2f4),
	  SPH_C32(0x524a0d59) },
	{ SPH_C32(0x69510000), SPH_C32(0xd4e1009c), SPH_C32(0xc3230000),
	  SPH_C32(0xac2f0000), SPH_C32(0xe4950bae), SPH_C32(0xcea415dc),
	  SPH_C32(0x87ec287c), SPH_C32(0xbce1a3ce), SPH_C32(0xc6730000),
	  SPH_C32(0xaf8d000c), SPH_C32(0xa4c10000), SPH_C32(0x218d0000),
	  SPH_C32(0x23111587), SPH_C32(0x7913512f), SPH_C32(0x1d28ac88),
	  SPH_C32(0x378dd173) },
	{ SPH_C32(0xc6730000), SPH_C32(0xaf8d000c), SPH_C32(0xa4c10000),
	  SPH_C32(0x218d0000), SPH_C32(0x23111587), SPH_C32(0x7913512f),
	  SPH_C32(0x1d28ac88), SPH_C32(0x378dd173), SPH_C32(0xaf220000),
	  SPH_C32(0x7b6c0090), SPH_C32(0x67e20000), SPH_C32(0x8da20000),
	  SPH_C32(0xc7841e29), SPH_C32(0xb7b744f3), SPH_C32(0x9ac484f4),
	  SPH_C32(0x8b6c72bd) },
	{ SPH_C32(0xcc140000), SPH_C32(0xa5630000), SPH_C32(0x5ab90780),
	  SPH_C32(0x3b500000), SPH_C32(0x4bd013ff), SPH_C32(0x879b3418),
	  SPH_C32(0x694348c1), SPH_C32(0xca5a87fe), SPH_C32(0x819e0000),
	  SPH_C32(0xec570000), SPH_C32(0x66320280), SPH_C32(0x95f30000),
	  SPH_C32(0x5da92802), SPH_C32(0x48f43cbc), SPH_C32(0xe65aa22d),
	  SPH_C32(0x8e67b7fa) },
	{ SPH_C32(0x819e0000), SPH_C32(0xec570000), SPH_C32(0x66320280),
	  SPH_C32(0x95f30000), SPH_C32(0x5da92802), SPH_C32(0x48f43cbc),
	  SPH_C32(0xe65aa22d), SPH_C32(0x8e67b7fa), SPH_C32(0x4d8a0000),
	  SPH_C32(0x49340000), SPH_C32(0x3c8b0500), SPH_C32(0xaea30000),
	  SPH_C32(0x16793bfd), SPH_C32(0xcf6f08a4), SPH_C32(0x8f19eaec),
	  SPH_C32(0x443d3004) },
	{ SPH_C32(0x78230000), SPH_C32(0x12fc0000), SPH_C32(0xa93a0b80),
	  SPH_C32(0x90a50000), SPH_C32(0x713e2879), SPH_C32(0x7ee98924),
	  SPH_C32(0xf08ca062), SPH_C32(0x636f8bab), SPH_C32(0x02af0000),
	  SPH_C32(0xb7280000), SPH_C32(0xba1c0300), SPH_C32(0x56980000),
	  SPH_C32(0xba8d45d3), SPH_C32(0x8048c667), SPH_C32(0xa95c149a),
	  SPH_C32(0xf4f6ea7b) },
	{ SPH_C32(0x02af0000), SPH_C32(0xb7280000), SPH_C32(0xba1c0300),
	  SPH_C32(0x56980000), SPH_C32(0xba8d45d3), SPH_C32(0x8048c667),
	  SPH_C32(0xa95c149a), SPH_C32(0xf4f6ea7b), SPH_C32(0x7a8c0000),
	  SPH_C32(0xa5d40000), SPH_C32(0x13260880), SPH_C32(0xc63d0000),
	  SPH_C32(0xcbb36daa), SPH_C32(0xfea14f43), SPH_C32(0x59d0b4f8),
	  SPH_C32(0x979961d0) },
	{ SPH_C32(0xac480000), SPH_C32(0x1ba60000), SPH_C32(0x45fb1380),
	  SPH_C32(0x03430000), SPH_C32(0x5a85316a), SPH_C32(0x1fb250b6),
	  SPH_C32(0xfe72c7fe), SPH_C32(0x91e478f6), SPH_C32(0x1e4e0000),
	  SPH_C32(0xdecf0000), SPH_C32(0x6df80180), SPH_C32(0x77240000),
	  SPH_C32(0xec47079e), SPH_C32(0xf4a0694e), SPH_C32(0xcda31812),
	  SPH_C32(0x98aa496e) },
	{ SPH_C32(0x1e4e0000), SPH_C32(0xdecf0000), SPH_C32(0x6df80180),
	  SPH_C32(0x77240000), SPH_C32(0xec47079e), SPH_C32(0xf4a0694e),
	  SPH_C32(0xcda31812), SPH_C32(0x98aa496e), SPH_C32(0xb2060000),
	  SPH_C32(0xc5690000), SPH_C32(0x28031200), SPH_C32(0x74670000),
	  SPH_C32(0xb6c236f4), SPH_C32(0xeb1239f8), SPH_C32(0x33d1dfec),
	  SPH_C32(0x094e3198) },
	{ SPH_C32(0xaec30000), SPH_C32(0x9c4f0001), SPH_C32(0x79d1e000),
	  SPH_C32(0x2c150000), SPH_C32(0x45cc75b3), SPH_C32(0x6650b736),
	  SPH_C32(0xab92f78f), SPH_C32(0xa312567b), SPH_C32(0xdb250000),
	  SPH_C32(0x09290000), SPH_C32(0x49aac000), SPH_C32(0x81e10000),
	  SPH_C32(0xcafe6b59), SPH_C32(0x42793431), SPH_C32(0x43566b76),
	  SPH_C32(0xe86cba2e) },
	{ SPH_C32(0xdb250000), SPH_C32(0x09290000), SPH_C32(0x49aac000),
	  SPH_C32(0x81e10000), SPH_C32(0xcafe6b59), SPH_C32(0x42793431),
	  SPH_C32(0x43566b76), SPH_C32(0xe86cba2e), SPH_C32(0x75e60000),
	  SPH_C32(0x95660001), SPH_C32(0x307b2000), SPH_C32(0xadf40000),
	  SPH_C32(0x8f321eea), SPH_C32(0x24298307), SPH_C32(0xe8c49cf9),
	  SPH_C32(0x4b7eec55) },
	{ SPH_C32(0x58430000), SPH_C32(0x807e0000), SPH_C32(0x78330001),
	  SPH_C32(0xc66b3800), SPH_C32(0xe7375cdc), SPH_C32(0x79ad3fdd),
	  SPH_C32(0xac73fe6f), SPH_C32(0x3a4479b1), SPH_C32(0x1d5a0000),
	  SPH_C32(0x2b720000), SPH_C32(0x488d0000), SPH_C32(0xaf611800),
	  SPH_C32(0x25cb2ec5), SPH_C32(0xc879bfd0), SPH_C32(0x81a20429),
	  SPH_C32(0x1e7536a6) },
	{ SPH_C32(0x1d5a0000), SPH_C32(0x2b720000), SPH_C32(0x488d0000),
	  SPH_C32(0xaf611800), SPH_C32(0x25cb2ec5), SPH_C32(0xc879bfd0),
	  SPH_C32(0x81a20429), SPH_C32(0x1e7536a6), SPH_C32(0x45190000),
	  SPH_C32(0xab0c0000), SPH_C32(0x30be0001), SPH_C32(0x690a2000),
	  SPH_C32(0xc2fc7219), SPH_C32(0xb1d4800d), SPH_C32(0x2dd1fa46),
	  SPH_C32(0x24314f17) },
	{ SPH_C32(0xa53b0000), SPH_C32(0x14260000), SPH_C32(0x4e30001e),
	  SPH_C32(0x7cae0000), SPH_C32(0x8f9e0dd5), SPH_C32(0x78dfaa3d),
	  SPH_C32(0xf73168d8), SPH_C32(0x0b1b4946), SPH_C32(0x07ed0000),
	  SPH_C32(0xb2500000), SPH_C32(0x8774000a), SPH_C32(0x970d0000),
	  SPH_C32(0x437223ae), SPH_C32(0x48c76ea4), SPH_C32(0xf4786222),
	  SPH_C32(0x9075b1ce) },
	{ SPH_C32(0x07ed0000), SPH_C32(0xb2500000), SPH_C32(0x8774000a),
	  SPH_C32(0x970d0000), SPH_C32(0x437223ae), SPH_C32(0x48c76ea4),
	  SPH_C32(0xf4786222), SPH_C32(0x9075b1ce), SPH_C32(0xa2d60000),
	  SPH_C32(0xa6760000), SPH_C32(0xc9440014), SPH_C32(0xeba30000),
	  SPH_C32(0xccec2e7b), SPH_C32(0x3018c499), SPH_C32(0x03490afa),
	  SPH_C32(0x9b6ef888) },
	{ SPH_C32(0x88980000), SPH_C32(0x1f940000), SPH_C32(0x7fcf002e),
	  SPH_C32(0xfb4e0000), SPH_C32(0xf158079a), SPH_C32(0x61ae9167),
	  SPH_C32(0xa895706c), SPH_C32(0xe6107494), SPH_C32(0x0bc20000),
	  SPH_C32(0xdb630000), SPH_C32(0x7e88000c), SPH_C32(0x15860000),
	  SPH_C32(0x91fd48f3), SPH_C32(0x7581bb43), SPH_C32(0xf460449e),
	  SPH_C32(0xd8b61463) },
	{ SPH_C32(0x0bc20000), SPH_C32(0xdb630000), SPH_C32(0x7e88000c),
	  SPH_C32(0x15860000), SPH_C32(0x91fd48f3), SPH_C32(0x7581bb43),
	  SPH_C32(0xf460449e), SPH_C32(0xd8b61463), SPH_C32(0x835a0000),
	  SPH_C32(0xc4f70000), SPH_C32(0x01470022), SPH_C32(0xeec80000),
	  SPH_C32(0x60a54f69), SPH_C32(0x142f2a24), SPH_C32(0x5cf534f2),
	  SPH_C32(0x3ea660f7) },
	{ SPH_C32(0x52500000), SPH_C32(0x29540000), SPH_C32(0x6a61004e),
	  SPH_C32(0xf0ff0000), SPH_C32(0x9a317eec), SPH_C32(0x452341ce),
	  SPH_C32(0xcf568fe5), SPH_C32(0x5303130f), SPH_C32(0x538d0000),
	  SPH_C32(0xa9fc0000), SPH_C32(0x9ef70006), SPH_C32(0x56ff0000),
	  SPH_C32(0x0ae4004e), SPH_C32(0x92c5cdf9), SPH_C32(0xa9444018),
	  SPH_C32(0x7f975691) },
	{ SPH_C32(0x538d0000), SPH_C32(0xa9fc0000), SPH_C32(0x9ef70006),
	  SPH_C32(0x56ff0000), SPH_C32(0x0ae4004e), SPH_C32(0x92c5cdf9),
	  SPH_C32(0xa9444018), SPH_C32(0x7f975691), SPH_C32(0x01dd0000),
	  SPH_C32(0x80a80000), SPH_C32(0xf4960048), SPH_C32(0xa6000000),
	  SPH_C32(0x90d57ea2), SPH_C32(0xd7e68c37), SPH_C32(0x6612cffd),
	  SPH_C32(0x2c94459e) },
	{ SPH_C32(0xe6280000), SPH_C32(0x4c4b0000), SPH_C32(0xa8550000),
	  SPH_C32(0xd3d002e0), SPH_C32(0xd86130b8), SPH_C32(0x98a7b0da),
	  SPH_C32(0x289506b4), SPH_C32(0xd75a4897), SPH_C32(0xf0c50000),
	  SPH_C32(0x59230000), SPH_C32(0x45820000), SPH_C32(0xe18d00c0),
	  SPH_C32(0x3b6d0631), SPH_C32(0xc2ed5699), SPH_C32(0xcbe0fe1c),
	  SPH_C32(0x56a7b19f) },
	{ SPH_C32(0xf0c50000), SPH_C32(0x59230000), SPH_C32(0x45820000),
	  SPH_C32(0xe18d00c0), SPH_C32(0x3b6d0631), SPH_C32(0xc2ed5699),
	  SPH_C32(0xcbe0fe1c), SPH_C32(0x56a7b19f), SPH_C32(0x16ed0000),
	  SPH_C32(0x15680000), SPH_C32(0xedd70000), SPH_C32(0x325d0220),
	  SPH_C32(0xe30c3689), SPH_C32(0x5a4ae643), SPH_C32(0xe375f8a8),
	  SPH_C32(0x81fdf908) },
	{ SPH_C32(0xb4310000), SPH_C32(0x77330000), SPH_C32(0xb15d0000),
	  SPH_C32(0x7fd004e0), SPH_C32(0x78a26138), SPH_C32(0xd116c35d),
	  SPH_C32(0xd256d489), SPH_C32(0x4e6f74de), SPH_C32(0xe3060000),
	  SPH_C32(0xbdc10000), SPH_C32(0x87130000), SPH_C32(0xbff20060),
	  SPH_C32(0x2eba0a1a), SPH_C32(0x8db53751), SPH_C32(0x73c5ab06),
	  SPH_C32(0x5bd61539) },
	{ SPH_C32(0xe3060000), SPH_C32(0xbdc10000), SPH_C32(0x87130000),
	  SPH_C32(0xbff20060), SPH_C32(0x2eba0a1a), SPH_C32(0x8db53751),
	  SPH_C32(0x73c5ab06), SPH_C32(0x5bd61539), SPH_C32(0x57370000),
	  SPH_C32(0xcaf20000), SPH_C32(0x364e0000), SPH_C32(0xc0220480),
	  SPH_C32(0x56186b22), SPH_C32(0x5ca3f40c), SPH_C32(0xa1937f8f),
	  SPH_C32(0x15b961e7) },
	{ SPH_C32(0x02f20000), SPH_C32(0xa2810000), SPH_C32(0x873f0000),
	  SPH_C32(0xe36c7800), SPH_C32(0x1e1d74ef), SPH_C32(0x073d2bd6),
	  SPH_C32(0xc4c23237), SPH_C32(0x7f32259e), SPH_C32(0xbadd0000),
	  SPH_C32(0x13ad0000), SPH_C32(0xb7e70000), SPH_C32(0xf7282800),
	  SPH_C32(0xdf45144d), SPH_C32(0x361ac33a), SPH_C32(0xea5a8d14),
	  SPH_C32(0x2a2c18f0) },
	{ SPH_C32(0xbadd0000), SPH_C32(0x13ad0000), SPH_C32(0xb7e70000),
	  SPH_C32(0xf7282800), SPH_C32(0xdf45144d), SPH_C32(0x361ac33a),
	  SPH_C32(0xea5a8d14), SPH_C32(0x2a2c18f0), SPH_C32(0xb82f0000),
	  SPH_C32(0xb12c0000), SPH_C32(0x30d80000), SPH_C32(0x14445000),
	  SPH_C32(0xc15860a2), SPH_C32(0x3127e8ec), SPH_C32(0x2e98bf23),
	  SPH_C32(0x551e3d6e) },
	{ SPH_C32(0x1e6c0000), SPH_C32(0xc4420000), SPH_C32(0x8a2e0000),
	  SPH_C32(0xbcb6b800), SPH_C32(0x2c4413b6), SPH_C32(0x8bfdd3da),
	  SPH_C32(0x6a0c1bc8), SPH_C32(0xb99dc2eb), SPH_C32(0x92560000),
	  SPH_C32(0x1eda0000), SPH_C32(0xea510000), SPH_C32(0xe8b13000),
	  SPH_C32(0xa93556a5), SPH_C32(0xebfb6199), SPH_C32(0xb15c2254),
	  SPH_C32(0x33c5244f) },
	{ SPH_C32(0x92560000), SPH_C32(0x1eda0000), SPH_C32(0xea510000),
	  SPH_C32(0xe8b13000), SPH_C32(0xa93556a5), SPH_C32(0xebfb6199),
	  SPH_C32(0xb15c2254), SPH_C32(0x33c5244f), SPH_C32(0x8c3a0000),
	  SPH_C32(0xda980000), SPH_C32(0x607f0000), SPH_C32(0x54078800),
	  SPH_C32(0x85714513), SPH_C32(0x6006b243), SPH_C32(0xdb50399c),
	  SPH_C32(0x8a58e6a4) },
	{ SPH_C32(0x033d0000), SPH_C32(0x08b30000), SPH_C32(0xf33a0000),
	  SPH_C32(0x3ac20007), SPH_C32(0x51298a50), SPH_C32(0x6b6e661f),
	  SPH_C32(0x0ea5cfe3), SPH_C32(0xe6da7ffe), SPH_C32(0xa8da0000),
	  SPH_C32(0x96be0000), SPH_C32(0x5c1d0000), SPH_C32(0x07da0002),
	  SPH_C32(0x7d669583), SPH_C32(0x1f98708a), SPH_C32(0xbb668808),
	  SPH_C32(0xda878000) },
	{ SPH_C32(0xa8da0000), SPH_C32(0x96be0000), SPH_C32(0x5c1d0000),
	  SPH_C32(0x07da0002), SPH_C32(0x7d669583), SPH_C32(0x1f98708a),
	  SPH_C32(0xbb668808), SPH_C32(0xda878000), SPH_C32(0xabe70000),
	  SPH_C32(0x9e0d0000), SPH_C32(0xaf270000), SPH_C32(0x3d180005),
	  SPH_C32(0x2c4f1fd3), SPH_C32(0x74f61695), SPH_C32(0xb5c347eb),
	  SPH_C32(0x3c5dfffe) },
	{ SPH_C32(0x01930000), SPH_C32(0xe7820000), SPH_C32(0xedfb0000),
	  SPH_C32(0xcf0c000b), SPH_C32(0x8dd08d58), SPH_C32(0xbca3b42e),
	  SPH_C32(0x063661e1), SPH_C32(0x536f9e7b), SPH_C32(0x92280000),
	  SPH_C32(0xdc850000), SPH_C32(0x57fa0000), SPH_C32(0x56dc0003),
	  SPH_C32(0xbae92316), SPH_C32(0x5aefa30c), SPH_C32(0x90cef752),
	  SPH_C32(0x7b1675d7) },
	{ SPH_C32(0x92280000), SPH_C32(0xdc850000), SPH_C32(0x57fa0000),
	  SPH_C32(0x56dc0003), SPH_C32(0xbae92316), SPH_C32(0x5aefa30c),
	  SPH_C32(0x90cef752), SPH_C32(0x7b1675d7), SPH_C32(0x93bb0000),
	  SPH_C32(0x3b070000), SPH_C32(0xba010000), SPH_C32(0x99d00008),
	  SPH_C32(0x3739ae4e), SPH_C32(0xe64c1722), SPH_C32(0x96f896b3),
	  SPH_C32(0x2879ebac) },
	{ SPH_C32(0x5fa80000), SPH_C32(0x56030000), SPH_C32(0x43ae0000),
	  SPH_C32(0x64f30013), SPH_C32(0x257e86bf), SPH_C32(0x1311944e),
	  SPH_C32(0x541e95bf), SPH_C32(0x8ea4db69), SPH_C32(0x00440000),
	  SPH_C32(0x7f480000), SPH_C32(0xda7c0000), SPH_C32(0x2a230001),
	  SPH_C32(0x3badc9cc), SPH_C32(0xa9b69c87), SPH_C32(0x030a9e60),
	  SPH_C32(0xbe0a679e) },
	{ SPH_C32(0x00440000), SPH_C32(0x7f480000), SPH_C32(0xda7c0000),
	  SPH_C32(0x2a230001), SPH_C32(0x3badc9cc), SPH_C32(0xa9b69c87),
	  SPH_C32(0x030a9e60), SPH_C32(0xbe0a679e), SPH_C32(0x5fec0000),
	  SPH_C32(0x294b0000), SPH_C32(0x99d20000), SPH_C32(0x4ed00012),
	  SPH_C32(0x1ed34f73), SPH_C32(0xbaa708c9), SPH_C32(0x57140bdf),
	  SPH_C32(0x30aebcf7) },
	{ SPH_C32(0xee930000), SPH_C32(0xd6070000), SPH_C32(0x92c10000),
	  SPH_C32(0x2b9801e0), SPH_C32(0x9451287c), SPH_C32(0x3b6cfb57),
	  SPH_C32(0x45312374), SPH_C32(0x201f6a64), SPH_C32(0x7b280000),
	  SPH_C32(0x57420000), SPH_C32(0xa9e50000), SPH_C32(0x634300a0),
	  SPH_C32(0x9edb442f), SPH_C32(0x6d9995bb), SPH_C32(0x27f83b03),
	  SPH_C32(0xc7ff60f0) },
	{ SPH_C32(0x7b280000), SPH_C32(0x57420000), SPH_C32(0xa9e50000),
	  SPH_C32(0x634300a0), SPH_C32(0x9edb442f), SPH_C32(0x6d9995bb),
	  SPH_C32(0x27f83b03), SPH_C32(0xc7ff60f0), SPH_C32(0x95bb0000),
	  SPH_C32(0x81450000), SPH_C32(0x3b240000), SPH_C32(0x48db0140),
	  SPH_C32(0x0a8a6c53), SPH_C32(0x56f56eec), SPH_C32(0x62c91877),
	  SPH_C32(0xe7e00a94) }
};

#define s0   m0
#define s1   c0
#define s2   m1
#define s3   c1
#define s4   c2
#define s5   m2
#define s6   c3
#define s7   m3
#define s8   m4
#define s9   c4
#define sA   m5
#define sB   c5
#define sC   c6
#define sD   m6
#define sE   c7
#define sF   m7


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Hamsi 8 way AVX512 

#define INPUT_BIG8 \
do { \
  __m512i db = *buf; \
  const uint64_t *tp = (uint64_t*)&T512[0][0];  \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = m512_zero; \
  for ( int u = 0; u < 64; u++ ) \
  { \
     __m512i dm = _mm512_and_si512( db, m512_one_64 ) ; \
     dm = mm512_negate_32( _mm512_or_si512( dm, \
                                          _mm512_slli_epi64( dm, 32 ) ) ); \
     m0 = mm512_xorand( m0, dm, m512_const1_64( tp[0] ) ); \
     m1 = mm512_xorand( m1, dm, m512_const1_64( tp[1] ) ); \
     m2 = mm512_xorand( m2, dm, m512_const1_64( tp[2] ) ); \
     m3 = mm512_xorand( m3, dm, m512_const1_64( tp[3] ) ); \
     m4 = mm512_xorand( m4, dm, m512_const1_64( tp[4] ) ); \
     m5 = mm512_xorand( m5, dm, m512_const1_64( tp[5] ) ); \
     m6 = mm512_xorand( m6, dm, m512_const1_64( tp[6] ) ); \
     m7 = mm512_xorand( m7, dm, m512_const1_64( tp[7] ) ); \
     tp += 8; \
     db = _mm512_srli_epi64( db, 1 ); \
  } \
} while (0)

#define SBOX8( a, b, c, d ) \
do { \
  __m512i t; \
  t = a; \
  a = mm512_xorand( d, a, c ); \
  c = mm512_xor3( a, b, c ); \
  b = mm512_xoror( b, d, t ); \
  t = _mm512_xor_si512( t, c ); \
  d = mm512_xoror( a, b, t ); \
  t = mm512_xorand( t, a, b ); \
  b = mm512_xor3( b, d, t ); \
  a = c; \
  c = b; \
  b = d; \
  d = mm512_not( t ); \
} while (0)

#define L8( a, b, c, d ) \
do { \
   a = mm512_rol_32( a, 13 ); \
   c = mm512_rol_32( c,  3 ); \
   b = mm512_xor3( a, b, c ); \
   d = mm512_xor3( d, c, _mm512_slli_epi32( a, 3 ) ); \
   b = mm512_rol_32( b, 1 ); \
   d = mm512_rol_32( d, 7 ); \
   a = mm512_xor3( a, b, d ); \
   c = mm512_xor3( c, d, _mm512_slli_epi32( b, 7 ) ); \
   a = mm512_rol_32( a,  5 ); \
   c = mm512_rol_32( c, 22 ); \
} while (0)

#define DECL_STATE_BIG8 \
   __m512i c0, c1, c2, c3, c4, c5, c6, c7; \

#define READ_STATE_BIG8(sc) \
do { \
   c0 = sc->h[0x0]; \
   c1 = sc->h[0x1]; \
   c2 = sc->h[0x2]; \
   c3 = sc->h[0x3]; \
   c4 = sc->h[0x4]; \
   c5 = sc->h[0x5]; \
   c6 = sc->h[0x6]; \
   c7 = sc->h[0x7]; \
} while (0)

#define WRITE_STATE_BIG8(sc) \
do { \
   sc->h[0x0] = c0; \
   sc->h[0x1] = c1; \
   sc->h[0x2] = c2; \
   sc->h[0x3] = c3; \
   sc->h[0x4] = c4; \
   sc->h[0x5] = c5; \
   sc->h[0x6] = c6; \
   sc->h[0x7] = c7; \
} while (0)


#define ROUND_BIG8( alpha ) \
do { \
   __m512i t0, t1, t2, t3; \
   s0 = _mm512_xor_si512( s0, alpha[ 0] ); \
   s1 = _mm512_xor_si512( s1, alpha[ 1] ); \
   s2 = _mm512_xor_si512( s2, alpha[ 2] ); \
   s3 = _mm512_xor_si512( s3, alpha[ 3] ); \
   s4 = _mm512_xor_si512( s4, alpha[ 4] ); \
   s5 = _mm512_xor_si512( s5, alpha[ 5] ); \
   s6 = _mm512_xor_si512( s6, alpha[ 6] ); \
   s7 = _mm512_xor_si512( s7, alpha[ 7] ); \
   s8 = _mm512_xor_si512( s8, alpha[ 8] ); \
   s9 = _mm512_xor_si512( s9, alpha[ 9] ); \
   sA = _mm512_xor_si512( sA, alpha[10] ); \
   sB = _mm512_xor_si512( sB, alpha[11] ); \
   sC = _mm512_xor_si512( sC, alpha[12] ); \
   sD = _mm512_xor_si512( sD, alpha[13] ); \
   sE = _mm512_xor_si512( sE, alpha[14] ); \
   sF = _mm512_xor_si512( sF, alpha[15] ); \
\
  SBOX8( s0, s4, s8, sC ); \
  SBOX8( s1, s5, s9, sD ); \
  SBOX8( s2, s6, sA, sE ); \
  SBOX8( s3, s7, sB, sF ); \
\
  t1 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s4, 4 ), \
                                        _mm512_bslli_epi128( s5, 4 ) ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( sD, 4 ), \
                                        _mm512_bslli_epi128( sE, 4 ) ); \
  L8( s0, t1, s9, t3 ); \
  s4 = _mm512_mask_blend_epi32( 0xaaaa, s4, _mm512_bslli_epi128( t1, 4 ) ); \
  s5 = _mm512_mask_blend_epi32( 0x5555, s5, _mm512_bsrli_epi128( t1, 4 ) ); \
  sD = _mm512_mask_blend_epi32( 0xaaaa, sD, _mm512_bslli_epi128( t3, 4 ) ); \
  sE = _mm512_mask_blend_epi32( 0x5555, sE, _mm512_bsrli_epi128( t3, 4 ) ); \
\
  t1 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s5, 4 ), \
                                        _mm512_bslli_epi128( s6, 4 ) ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( sE, 4 ), \
                                        _mm512_bslli_epi128( sF, 4 ) ); \
  L8( s1, t1, sA, t3 ); \
  s5 = _mm512_mask_blend_epi32( 0xaaaa, s5, _mm512_bslli_epi128( t1, 4 ) ); \
  s6 = _mm512_mask_blend_epi32( 0x5555, s6, _mm512_bsrli_epi128( t1, 4 ) ); \
  sE = _mm512_mask_blend_epi32( 0xaaaa, sE, _mm512_bslli_epi128( t3, 4 ) ); \
  sF = _mm512_mask_blend_epi32( 0x5555, sF, _mm512_bsrli_epi128( t3, 4 ) ); \
\
  t1 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s6, 4 ), \
                                        _mm512_bslli_epi128( s7, 4 ) ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( sF, 4 ), \
                                        _mm512_bslli_epi128( sC, 4 ) ); \
  L8( s2, t1, sB, t3 ); \
  s6 = _mm512_mask_blend_epi32( 0xaaaa, s6, _mm512_bslli_epi128( t1, 4 ) ); \
  s7 = _mm512_mask_blend_epi32( 0x5555, s7, _mm512_bsrli_epi128( t1, 4 ) ); \
  sF = _mm512_mask_blend_epi32( 0xaaaa, sF, _mm512_bslli_epi128( t3, 4 ) ); \
  sC = _mm512_mask_blend_epi32( 0x5555, sC, _mm512_bsrli_epi128( t3, 4 ) ); \
\
  t1 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s7, 4 ), \
                                        _mm512_bslli_epi128( s4, 4 ) ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( sC, 4 ), \
                                        _mm512_bslli_epi128( sD, 4 ) ); \
  L8( s3, t1, s8, t3 ); \
  s7 = _mm512_mask_blend_epi32( 0xaaaa, s7, _mm512_bslli_epi128( t1, 4 ) ); \
  s4 = _mm512_mask_blend_epi32( 0x5555, s4, _mm512_bsrli_epi128( t1, 4 ) ); \
  sC = _mm512_mask_blend_epi32( 0xaaaa, sC, _mm512_bslli_epi128( t3, 4 ) ); \
  sD = _mm512_mask_blend_epi32( 0x5555, sD, _mm512_bsrli_epi128( t3, 4 ) ); \
\
  t0 = _mm512_mask_blend_epi32( 0xaaaa, s0, _mm512_bslli_epi128( s8, 4 ) ); \
  t1 = _mm512_mask_blend_epi32( 0xaaaa, s1, s9 ); \
  t2 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s2, 4 ), sA ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s3, 4 ), \
                                        _mm512_bslli_epi128( sB, 4 ) ); \
  L8( t0, t1, t2, t3 ); \
  s0 = _mm512_mask_blend_epi32( 0x5555, s0, t0 ); \
  s8 = _mm512_mask_blend_epi32( 0x5555, s8, _mm512_bsrli_epi128( t0, 4 ) ); \
  s1 = _mm512_mask_blend_epi32( 0x5555, s1, t1 ); \
  s9 = _mm512_mask_blend_epi32( 0xaaaa, s9, t1 ); \
  s2 = _mm512_mask_blend_epi32( 0xaaaa, s2, _mm512_bslli_epi128( t2, 4 ) ); \
  sA = _mm512_mask_blend_epi32( 0xaaaa, sA, t2 ); \
  s3 = _mm512_mask_blend_epi32( 0xaaaa, s3, _mm512_bslli_epi128( t3, 4 ) ); \
  sB = _mm512_mask_blend_epi32( 0x5555, sB, _mm512_bsrli_epi128( t3, 4 ) ); \
\
  t0 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s4, 4 ), sC ); \
  t1 = _mm512_mask_blend_epi32( 0xaaaa, _mm512_bsrli_epi128( s5, 4 ), \
                                        _mm512_bslli_epi128( sD, 4 ) ); \
  t2 = _mm512_mask_blend_epi32( 0xaaaa, s6, _mm512_bslli_epi128( sE, 4 ) ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, s7, sF ); \
  L8( t0, t1, t2, t3 ); \
  s4 = _mm512_mask_blend_epi32( 0xaaaa, s4, _mm512_bslli_epi128( t0, 4 ) ); \
  sC = _mm512_mask_blend_epi32( 0xaaaa, sC, t0 ); \
  s5 = _mm512_mask_blend_epi32( 0xaaaa, s5, _mm512_bslli_epi128( t1, 4 ) ); \
  sD = _mm512_mask_blend_epi32( 0x5555, sD, _mm512_bsrli_epi128( t1, 4 ) ); \
  s6 = _mm512_mask_blend_epi32( 0x5555, s6, t2 ); \
  sE = _mm512_mask_blend_epi32( 0x5555, sE, _mm512_bsrli_epi128( t2, 4 ) ); \
  s7 = _mm512_mask_blend_epi32( 0x5555, s7, t3 ); \
  sF = _mm512_mask_blend_epi32( 0xaaaa, sF, t3 ); \
} while (0)

#define P_BIG8 \
do { \
   __m512i alpha[16]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = m512_const1_64( ( (uint64_t*)alpha_n )[i] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)1 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)2 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)3 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)4 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)5 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG8( alpha ); \
} while (0)

#define PF_BIG8 \
do { \
   __m512i alpha[16]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = m512_const1_64( ( (uint64_t*)alpha_f )[i] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)1 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)2 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)3 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)4 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)5 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)6 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)7 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)8 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)9 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)10 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = m512_const1_64( ( (uint64_t)11 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG8( alpha ); \
} while (0)

#define T_BIG8 \
do { /* order is important */ \
   c7 = sc->h[ 0x7 ] = _mm512_xor_si512( sc->h[ 0x7 ], sB ); \
   c6 = sc->h[ 0x6 ] = _mm512_xor_si512( sc->h[ 0x6 ], sA ); \
   c5 = sc->h[ 0x5 ] = _mm512_xor_si512( sc->h[ 0x5 ], s9 ); \
   c4 = sc->h[ 0x4 ] = _mm512_xor_si512( sc->h[ 0x4 ], s8 ); \
   c3 = sc->h[ 0x3 ] = _mm512_xor_si512( sc->h[ 0x3 ], s3 ); \
   c2 = sc->h[ 0x2 ] = _mm512_xor_si512( sc->h[ 0x2 ], s2 ); \
   c1 = sc->h[ 0x1 ] = _mm512_xor_si512( sc->h[ 0x1 ], s1 ); \
   c0 = sc->h[ 0x0 ] = _mm512_xor_si512( sc->h[ 0x0 ], s0 ); \
} while (0)

void hamsi_8way_big( hamsi_8way_big_context *sc, __m512i *buf, size_t num )
{
   DECL_STATE_BIG8
   uint32_t tmp = num << 6;

   sc->count_low = SPH_T32( sc->count_low + tmp );
   sc->count_high += (sph_u32)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_BIG8( sc );
   while ( num-- > 0 )
   {
      __m512i m0, m1, m2, m3, m4, m5, m6, m7;

      INPUT_BIG8;
      P_BIG8;
      T_BIG8;
      buf++;
   }
   WRITE_STATE_BIG8( sc );
}

void hamsi_8way_big_final( hamsi_8way_big_context *sc, __m512i *buf )
{
   __m512i m0, m1, m2, m3, m4, m5, m6, m7;
   DECL_STATE_BIG8
   READ_STATE_BIG8( sc );
   INPUT_BIG8;
   PF_BIG8;
   T_BIG8;
   WRITE_STATE_BIG8( sc );
}


void hamsi512_8way_init( hamsi_8way_big_context *sc )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;

   sc->h[0] = m512_const1_64( 0x6c70617273746565 );
   sc->h[1] = m512_const1_64( 0x656e62656b204172 );
   sc->h[2] = m512_const1_64( 0x302c206272672031 );
   sc->h[3] = m512_const1_64( 0x3434362c75732032 );
   sc->h[4] = m512_const1_64( 0x3030312020422d33 );
   sc->h[5] = m512_const1_64( 0x656e2d484c657576 );
   sc->h[6] = m512_const1_64( 0x6c65652c65766572 );
   sc->h[7] = m512_const1_64( 0x6769756d2042656c );
}

void hamsi512_8way_update( hamsi_8way_big_context *sc, const void *data,
                           size_t len )
{
   __m512i *vdata = (__m512i*)data;

   hamsi_8way_big( sc, vdata, len>>3 );
   vdata += ( (len& ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_512( sc->buf, vdata, len>>3 );
   sc->partial_len = len;
}

void hamsi512_8way_close( hamsi_8way_big_context *sc, void *dst )
{
   __m512i pad[1];
   uint32_t ch, cl;

   sph_enc32be( &ch, sc->count_high );
   sph_enc32be( &cl, sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = _mm512_set1_epi64( ((uint64_t)cl << 32 ) | (uint64_t)ch );
   sc->buf[0] = m512_const1_64( 0x80 );
   hamsi_8way_big( sc, sc->buf, 1 );
   hamsi_8way_big_final( sc, pad );

   mm512_block_bswap_32( (__m512i*)dst, sc->h );
}

#endif // AVX512

// Hamsi 4 way AVX2

#define INPUT_BIG \
do { \
  __m256i db = *buf; \
  const uint64_t *tp = (uint64_t*)&T512[0][0];  \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = m256_zero; \
  for ( int u = 0; u < 64; u++ ) \
  { \
     __m256i dm = _mm256_and_si256( db, m256_one_64 ) ; \
     dm = mm256_negate_32( _mm256_or_si256( dm, \
                         _mm256_slli_epi64( dm, 32 ) ) ); \
     m0 = _mm256_xor_si256( m0, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[0] ) ) ); \
     m1 = _mm256_xor_si256( m1, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[1] ) ) ); \
     m2 = _mm256_xor_si256( m2, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[2] ) ) ); \
     m3 = _mm256_xor_si256( m3, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[3] ) ) ); \
     m4 = _mm256_xor_si256( m4, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[4] ) ) ); \
     m5 = _mm256_xor_si256( m5, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[5] ) ) ); \
     m6 = _mm256_xor_si256( m6, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[6] ) ) ); \
     m7 = _mm256_xor_si256( m7, _mm256_and_si256( dm, \
                                          m256_const1_64( tp[7] ) ) ); \
     tp += 8; \
     db = _mm256_srli_epi64( db, 1 ); \
  } \
} while (0)

#define SBOX( a, b, c, d ) \
do { \
  __m256i t; \
  t = a; \
  a = _mm256_and_si256( a, c ); \
  a = _mm256_xor_si256( a, d ); \
  c = _mm256_xor_si256( c, b ); \
  c = _mm256_xor_si256( c, a ); \
  d = _mm256_or_si256( d, t ); \
  d = _mm256_xor_si256( d, b ); \
  t = _mm256_xor_si256( t, c ); \
  b = d; \
  d = _mm256_or_si256( d, t ); \
  d = _mm256_xor_si256( d, a ); \
  a = _mm256_and_si256( a, b ); \
  t = _mm256_xor_si256( t, a ); \
  b = _mm256_xor_si256( b, d ); \
  b = _mm256_xor_si256( b, t ); \
  a = c; \
  c = b; \
  b = d; \
  d = mm256_not( t ); \
} while (0)

#define L( a, b, c, d ) \
do { \
   a = mm256_rol_32( a, 13 ); \
   c = mm256_rol_32( c,  3 ); \
   b = _mm256_xor_si256( b, _mm256_xor_si256( a, c ) ); \
   d = _mm256_xor_si256( d, _mm256_xor_si256( c, \
                                              _mm256_slli_epi32( a, 3 ) ) ); \
   b = mm256_rol_32( b, 1 ); \
   d = mm256_rol_32( d, 7 ); \
   a = _mm256_xor_si256( a, _mm256_xor_si256( b, d ) ); \
   c = _mm256_xor_si256( c, _mm256_xor_si256( d, \
                                              _mm256_slli_epi32( b, 7 ) ) ); \
   a = mm256_rol_32( a,  5 ); \
   c = mm256_rol_32( c, 22 ); \
} while (0)

#define DECL_STATE_BIG \
   __m256i c0, c1, c2, c3, c4, c5, c6, c7; \

#define READ_STATE_BIG(sc) \
do { \
   c0 = sc->h[0x0]; \
   c1 = sc->h[0x1]; \
   c2 = sc->h[0x2]; \
   c3 = sc->h[0x3]; \
   c4 = sc->h[0x4]; \
   c5 = sc->h[0x5]; \
   c6 = sc->h[0x6]; \
   c7 = sc->h[0x7]; \
} while (0)

#define WRITE_STATE_BIG(sc) \
do { \
   sc->h[0x0] = c0; \
   sc->h[0x1] = c1; \
   sc->h[0x2] = c2; \
   sc->h[0x3] = c3; \
   sc->h[0x4] = c4; \
   sc->h[0x5] = c5; \
   sc->h[0x6] = c6; \
   sc->h[0x7] = c7; \
} while (0)

/*
#define s0   m0
#define s1   c0
#define s2   m1
#define s3   c1
#define s4   c2
#define s5   m2
#define s6   c3
#define s7   m3
#define s8   m4
#define s9   c4
#define sA   m5
#define sB   c5
#define sC   c6
#define sD   m6
#define sE   c7
#define sF   m7
*/

#define ROUND_BIG( alpha ) \
do { \
   __m256i t0, t1, t2, t3; \
   s0 = _mm256_xor_si256( s0, alpha[ 0] ); \
   s1 = _mm256_xor_si256( s1, alpha[ 1] ); \
   s2 = _mm256_xor_si256( s2, alpha[ 2] ); \
   s3 = _mm256_xor_si256( s3, alpha[ 3] ); \
   s4 = _mm256_xor_si256( s4, alpha[ 4] ); \
   s5 = _mm256_xor_si256( s5, alpha[ 5] ); \
   s6 = _mm256_xor_si256( s6, alpha[ 6] ); \
   s7 = _mm256_xor_si256( s7, alpha[ 7] ); \
   s8 = _mm256_xor_si256( s8, alpha[ 8] ); \
   s9 = _mm256_xor_si256( s9, alpha[ 9] ); \
   sA = _mm256_xor_si256( sA, alpha[10] ); \
   sB = _mm256_xor_si256( sB, alpha[11] ); \
   sC = _mm256_xor_si256( sC, alpha[12] ); \
   sD = _mm256_xor_si256( sD, alpha[13] ); \
   sE = _mm256_xor_si256( sE, alpha[14] ); \
   sF = _mm256_xor_si256( sF, alpha[15] ); \
\
  SBOX( s0, s4, s8, sC ); \
  SBOX( s1, s5, s9, sD ); \
  SBOX( s2, s6, sA, sE ); \
  SBOX( s3, s7, sB, sF ); \
\
  t1 = _mm256_blend_epi32( _mm256_bsrli_epi128( s4, 4 ), \
                           _mm256_bslli_epi128( s5, 4 ), 0xAA ); \
  t3 = _mm256_blend_epi32( _mm256_bsrli_epi128( sD, 4 ), \
                           _mm256_bslli_epi128( sE, 4 ), 0xAA ); \
  L( s0, t1, s9, t3 ); \
  s4 = _mm256_blend_epi32( s4, _mm256_bslli_epi128( t1, 4 ), 0xAA );\
  s5 = _mm256_blend_epi32( s5, _mm256_bsrli_epi128( t1, 4 ), 0x55 );\
  sD = _mm256_blend_epi32( sD, _mm256_bslli_epi128( t3, 4 ), 0xAA );\
  sE = _mm256_blend_epi32( sE, _mm256_bsrli_epi128( t3, 4 ), 0x55 );\
\
  t1 = _mm256_blend_epi32( _mm256_bsrli_epi128( s5, 4 ), \
                           _mm256_bslli_epi128( s6, 4 ), 0xAA ); \
  t3 = _mm256_blend_epi32( _mm256_bsrli_epi128( sE, 4 ), \
                           _mm256_bslli_epi128( sF, 4 ), 0xAA ); \
  L( s1, t1, sA, t3 ); \
  s5 = _mm256_blend_epi32( s5, _mm256_bslli_epi128( t1, 4 ), 0xAA );\
  s6 = _mm256_blend_epi32( s6, _mm256_bsrli_epi128( t1, 4 ), 0x55 );\
  sE = _mm256_blend_epi32( sE, _mm256_bslli_epi128( t3, 4 ), 0xAA );\
  sF = _mm256_blend_epi32( sF, _mm256_bsrli_epi128( t3, 4 ), 0x55 );\
\
  t1 = _mm256_blend_epi32( _mm256_bsrli_epi128( s6, 4 ), \
                           _mm256_bslli_epi128( s7, 4 ), 0xAA ); \
  t3 = _mm256_blend_epi32( _mm256_bsrli_epi128( sF, 4 ), \
                           _mm256_bslli_epi128( sC, 4 ), 0xAA ); \
  L( s2, t1, sB, t3 ); \
  s6 = _mm256_blend_epi32( s6, _mm256_bslli_epi128( t1, 4 ), 0xAA );\
  s7 = _mm256_blend_epi32( s7, _mm256_bsrli_epi128( t1, 4 ), 0x55 );\
  sF = _mm256_blend_epi32( sF, _mm256_bslli_epi128( t3, 4 ), 0xAA );\
  sC = _mm256_blend_epi32( sC, _mm256_bsrli_epi128( t3, 4 ), 0x55 );\
\
  t1 = _mm256_blend_epi32( _mm256_bsrli_epi128( s7, 4 ), \
                           _mm256_bslli_epi128( s4, 4 ), 0xAA ); \
  t3 = _mm256_blend_epi32( _mm256_bsrli_epi128( sC, 4 ), \
                           _mm256_bslli_epi128( sD, 4 ), 0xAA ); \
  L( s3, t1, s8, t3 ); \
  s7 = _mm256_blend_epi32( s7, _mm256_bslli_epi128( t1, 4 ), 0xAA );\
  s4 = _mm256_blend_epi32( s4, _mm256_bsrli_epi128( t1, 4 ), 0x55 );\
  sC = _mm256_blend_epi32( sC, _mm256_bslli_epi128( t3, 4 ), 0xAA );\
  sD = _mm256_blend_epi32( sD, _mm256_bsrli_epi128( t3, 4 ), 0x55 );\
\
  t0 = _mm256_blend_epi32( s0, _mm256_bslli_epi128( s8, 4 ), 0xAA ); \
  t1 = _mm256_blend_epi32( s1, s9, 0xAA ); \
  t2 = _mm256_blend_epi32( _mm256_bsrli_epi128( s2, 4 ), sA, 0xAA ); \
  t3 = _mm256_blend_epi32( _mm256_bsrli_epi128( s3, 4 ), \
                           _mm256_bslli_epi128( sB, 4 ), 0xAA ); \
  L( t0, t1, t2, t3 ); \
  s0 = _mm256_blend_epi32( s0, t0, 0x55 ); \
  s8 = _mm256_blend_epi32( s8, _mm256_bsrli_epi128( t0, 4 ), 0x55 ); \
  s1 = _mm256_blend_epi32( s1, t1, 0x55 ); \
  s9 = _mm256_blend_epi32( s9, t1, 0xAA ); \
  s2 = _mm256_blend_epi32( s2, _mm256_bslli_epi128( t2, 4 ), 0xAA ); \
  sA = _mm256_blend_epi32( sA, t2, 0xAA ); \
  s3 = _mm256_blend_epi32( s3, _mm256_bslli_epi128( t3, 4 ), 0xAA ); \
  sB = _mm256_blend_epi32( sB, _mm256_bsrli_epi128( t3, 4 ), 0x55 ); \
\
  t0 = _mm256_blend_epi32( _mm256_bsrli_epi128( s4, 4 ), sC, 0xAA ); \
  t1 = _mm256_blend_epi32( _mm256_bsrli_epi128( s5, 4 ), \
                           _mm256_bslli_epi128( sD, 4 ), 0xAA ); \
  t2 = _mm256_blend_epi32( s6, _mm256_bslli_epi128( sE, 4 ), 0xAA ); \
  t3 = _mm256_blend_epi32( s7, sF, 0xAA ); \
  L( t0, t1, t2, t3 ); \
  s4 = _mm256_blend_epi32( s4, _mm256_bslli_epi128( t0, 4 ), 0xAA ); \
  sC = _mm256_blend_epi32( sC, t0, 0xAA ); \
  s5 = _mm256_blend_epi32( s5, _mm256_bslli_epi128( t1, 4 ), 0xAA ); \
  sD = _mm256_blend_epi32( sD, _mm256_bsrli_epi128( t1, 4 ), 0x55 ); \
  s6 = _mm256_blend_epi32( s6, t2, 0x55 ); \
  sE = _mm256_blend_epi32( sE, _mm256_bsrli_epi128( t2, 4 ), 0x55 ); \
  s7 = _mm256_blend_epi32( s7, t3, 0x55 ); \
  sF = _mm256_blend_epi32( sF, t3, 0xAA ); \
} while (0)

#define P_BIG \
do { \
   __m256i alpha[16]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = m256_const1_64( ( (uint64_t*)alpha_n )[i] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)1 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)2 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)3 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)4 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)5 << 32 ) \
                            ^ ( (uint64_t*)alpha_n )[0] ); \
   ROUND_BIG( alpha ); \
} while (0)

#define PF_BIG \
do { \
   __m256i alpha[16]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = m256_const1_64( ( (uint64_t*)alpha_f )[i] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)1 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)2 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)3 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)4 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)5 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)6 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)7 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)8 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)9 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)10 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = m256_const1_64( ( (uint64_t)11 << 32 ) \
                            ^ ( (uint64_t*)alpha_f )[0] ); \
   ROUND_BIG( alpha ); \
} while (0)

#define T_BIG \
do { /* order is important */ \
   c7 = sc->h[ 0x7 ] = _mm256_xor_si256( sc->h[ 0x7 ], sB ); \
   c6 = sc->h[ 0x6 ] = _mm256_xor_si256( sc->h[ 0x6 ], sA ); \
   c5 = sc->h[ 0x5 ] = _mm256_xor_si256( sc->h[ 0x5 ], s9 ); \
   c4 = sc->h[ 0x4 ] = _mm256_xor_si256( sc->h[ 0x4 ], s8 ); \
   c3 = sc->h[ 0x3 ] = _mm256_xor_si256( sc->h[ 0x3 ], s3 ); \
   c2 = sc->h[ 0x2 ] = _mm256_xor_si256( sc->h[ 0x2 ], s2 ); \
   c1 = sc->h[ 0x1 ] = _mm256_xor_si256( sc->h[ 0x1 ], s1 ); \
   c0 = sc->h[ 0x0 ] = _mm256_xor_si256( sc->h[ 0x0 ], s0 ); \
} while (0)

void hamsi_big( hamsi_4way_big_context *sc, __m256i *buf, size_t num )
{
   DECL_STATE_BIG
   sph_u32 tmp;

   tmp = SPH_T32( (sph_u32)num << 6 );
   sc->count_low = SPH_T32( sc->count_low + tmp );
   sc->count_high += (sph_u32)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_BIG( sc );
   while ( num-- > 0 )
   {
      __m256i m0, m1, m2, m3, m4, m5, m6, m7;

      INPUT_BIG;
      P_BIG;
      T_BIG;
      buf++;
   }
   WRITE_STATE_BIG( sc );
}

void hamsi_big_final( hamsi_4way_big_context *sc, __m256i *buf )
{
   __m256i m0, m1, m2, m3, m4, m5, m6, m7;
   DECL_STATE_BIG
   READ_STATE_BIG( sc );
   INPUT_BIG;
   PF_BIG;
   T_BIG;
   WRITE_STATE_BIG( sc );
}

void hamsi512_4way_init( hamsi_4way_big_context *sc )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;

   sc->h[0] = m256_const1_64( 0x6c70617273746565 );
   sc->h[1] = m256_const1_64( 0x656e62656b204172 );
   sc->h[2] = m256_const1_64( 0x302c206272672031 );
   sc->h[3] = m256_const1_64( 0x3434362c75732032 );
   sc->h[4] = m256_const1_64( 0x3030312020422d33 );
   sc->h[5] = m256_const1_64( 0x656e2d484c657576 );
   sc->h[6] = m256_const1_64( 0x6c65652c65766572 );
   sc->h[7] = m256_const1_64( 0x6769756d2042656c );
}

void hamsi512_4way_update( hamsi_4way_big_context *sc, const void *data,
      size_t len )
{
   __m256i *vdata = (__m256i*)data;

   hamsi_big( sc, vdata, len>>3 );
   vdata += ( (len& ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_256( sc->buf, vdata, len>>3 );
   sc->partial_len = len;
}

void hamsi512_4way_close( hamsi_4way_big_context *sc, void *dst )
{
   __m256i pad[1];
   uint32_t ch, cl;

   sph_enc32be( &ch, sc->count_high );
   sph_enc32be( &cl, sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = _mm256_set1_epi64x( ((uint64_t)cl << 32 ) | (uint64_t)ch );
   sc->buf[0] = m256_const1_64( 0x80 );
   hamsi_big( sc, sc->buf, 1 );
   hamsi_big_final( sc, pad );

   mm256_block_bswap_32( (__m256i*)dst, sc->h );
}

#ifdef __cplusplus
}
#endif
#endif
