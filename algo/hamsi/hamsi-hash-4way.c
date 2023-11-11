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
#include <stdio.h>
#include "hamsi-hash-4way.h"

static const uint32_t HAMSI_IV512[] __attribute__ ((aligned (32))) =
{
	 0x73746565, 0x6c706172, 0x6b204172, 0x656e6265,
    0x72672031, 0x302c2062, 0x75732032, 0x3434362c,
    0x20422d33, 0x30303120, 0x4c657576, 0x656e2d48,
	 0x65766572, 0x6c65652c, 0x2042656c, 0x6769756d
};

static const uint32_t alpha_n[] __attribute__ ((aligned (32))) =
{
	0xff00f0f0, 0xccccaaaa, 0xf0f0cccc, 0xff00aaaa,
   0xccccaaaa, 0xf0f0ff00, 0xaaaacccc, 0xf0f0ff00,
   0xf0f0cccc, 0xaaaaff00, 0xccccff00, 0xaaaaf0f0,
	0xaaaaf0f0, 0xff00cccc, 0xccccf0f0,	0xff00aaaa,
   0xccccaaaa, 0xff00f0f0,	0xff00aaaa, 0xf0f0cccc,
   0xf0f0ff00,	0xccccaaaa, 0xf0f0ff00, 0xaaaacccc,
	0xaaaaff00, 0xf0f0cccc, 0xaaaaf0f0,	0xccccff00,
   0xff00cccc, 0xaaaaf0f0,	0xff00aaaa, 0xccccf0f0
};

static const uint32_t alpha_f[] __attribute__ ((aligned (32))) =
{
	0xcaf9639c, 0x0ff0f9c0, 0x639c0ff0,	0xcaf9f9c0,
   0x0ff0f9c0, 0x639ccaf9,	0xf9c00ff0, 0x639ccaf9,
   0x639c0ff0,	0xf9c0caf9, 0x0ff0caf9, 0xf9c0639c,
	0xf9c0639c, 0xcaf90ff0, 0x0ff0639c,	0xcaf9f9c0,
   0x0ff0f9c0, 0xcaf9639c,	0xcaf9f9c0, 0x639c0ff0,
   0x639ccaf9,	0x0ff0f9c0, 0x639ccaf9, 0xf9c00ff0,
	0xf9c0caf9, 0x639c0ff0, 0xf9c0639c,	0x0ff0caf9,
   0xcaf90ff0, 0xf9c0639c,	0xcaf9f9c0, 0x0ff0639c
};

// imported from hamsi helper

/* Note: this table lists bits within each byte from least
   siginificant to most significant. */
static const uint32_t T512[64][16] __attribute__ ((aligned (32))) =
{
	{  0xef0b0270, 0x3afd0000, 0x5dae0000, 0x69490000,
      0x9b0f3c06, 0x4405b5f9, 0x66140a51, 0x924f5d0a,
      0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
	   0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68 },
	{  0xc96b0030, 0xe7250000, 0x2f840000, 0x264f0000,
      0x08695bf9, 0x6dfcf137, 0x509f6984, 0x9e69af68,
      0x26600240, 0xddd80000, 0x722a0000, 0x4f060000,
	   0x936667ff, 0x29f944ce, 0x368b63d5, 0x0c26f262 },
	{  0x145a3c00, 0xb9e90000, 0x61270000, 0xf1610000,
      0xce613d6c, 0xb0493d78, 0x47a96720, 0xe18e24c5,
      0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
	   0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f },
	{  0x23671400, 0xc8b90000, 0xf4c70000, 0xfb750000,
      0x73cd2465, 0xf8a6a549, 0x02c40a3f, 0xdc24e61f,
      0x373d2800, 0x71500000, 0x95e00000, 0x0a140000,
	   0xbdac1909, 0x48ef9831, 0x456d6d1f, 0x3daac2da },
	{  0x54285c00, 0xeaed0000, 0xc5d60000, 0xa1c50000,
      0xb3a26770, 0x94a5c4e1, 0x6bb0419d, 0x551b3782,
      0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
	   0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29 },
	{  0x9cbb1800, 0xb0d30000, 0x92510000, 0xed930000,
      0x593a4345, 0xe114d5f4, 0x430633da, 0x78cace29,
      0xc8934400, 0x5a3e0000, 0x57870000, 0x4c560000,
	   0xea982435, 0x75b11115, 0x28b67247, 0x2dd1f9ab },
	{  0x29449c00, 0x64e70000, 0xf24b0000, 0xc2f30000,
      0x0ede4e8f, 0x56c23745, 0xf3e04259, 0x8d0d9ec4,
      0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
	   0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2 },
	{  0x466d0c00, 0x08620000, 0xdd5d0000, 0xbadd0000,
      0x6a927942, 0x441f2b93, 0x218ace6f, 0xbf2c0be2,
      0x6f299000, 0x6c850000, 0x2f160000, 0x782e0000,
	   0x644c37cd, 0x12dd1cd6, 0xd26a8c36, 0x32219526 },
	{  0xf6800005, 0x3443c000, 0x24070000, 0x8f3d0000,
      0x21373bfb, 0x0ab8d5ae, 0xcdc58b19, 0xd795ba31,
      0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
	   0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88 },
	{  0xa67f0001, 0x71378000, 0x19fc0000, 0x96db0000,
      0x3a8b6dfd, 0xebcaaef3, 0x2c6d478f, 0xac8e6c88,
      0x50ff0004, 0x45744000, 0x3dfb0000, 0x19e60000,
	   0x1bbc5606, 0xe1727b5d, 0xe1a8cc96, 0x7b1bd6b9 },
	{  0xf7750009, 0xcf3cc000, 0xc3d60000, 0x04920000,
      0x029519a9, 0xf8e836ba, 0x7a87f14e, 0x9e16981a,
      0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
	   0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320 },
	{  0xd46a0000, 0x8dc8c000, 0xa5af0000, 0x4a290000,
      0xfc4e427a, 0xc9b4866c, 0x98369604, 0xf746c320,
      0x231f0009, 0x42f40000, 0x66790000, 0x4ebb0000,
	   0xfedb5bd3, 0x315cb0d6, 0xe2b1674a, 0x69505b3a },
	{  0x774400f0, 0xf15a0000, 0xf5b20000, 0x34140000,
      0x89377e8c, 0x5a8bec25, 0x0bc3cd1e, 0xcf3775cb,
      0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
	   0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574 },
	{  0xf46c0050, 0x96180000, 0x14a50000, 0x031f0000,
      0x42947eb8, 0x66bf7e19, 0x9ca470d2, 0x8a341574,
      0x832800a0, 0x67420000, 0xe1170000, 0x370b0000,
	   0xcba30034, 0x3c34923c, 0x9767bdcc, 0x450360bf },
	{  0xe8870170, 0x9d720000, 0x12db0000, 0xd4220000,
      0xf2886b27, 0xa921e543, 0x4ef8b518, 0x618813b1,
      0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
	   0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758 },
	{  0xb4370060, 0x0c4c0000, 0x56c20000, 0x5cae0000,
      0x94541f3f, 0x3b3ef825, 0x1b365f3d, 0xf3d45758,
      0x5cb00110, 0x913e0000, 0x44190000, 0x888c0000,
	   0x66dc7418, 0x921f1d66, 0x55ceea25, 0x925c44e9 },
	{  0x0c720000, 0x49e50f00, 0x42790000, 0x5cea0000,
      0x33aa301a, 0x15822514, 0x95a34b7b, 0xb44b0090,
      0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
	   0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f },
	{  0xfe220000, 0xa7580500, 0x25d10000, 0xf7600000,
      0x893178da, 0x1fd4f860, 0x4ed0a315, 0xa123ff9f,
      0xf2500000, 0xeebd0a00, 0x67a80000, 0xab8a0000,
	   0xba9b48c0, 0x0a56dd74, 0xdb73e86e, 0x1568ff0f },
	{  0x45180000, 0xa5b51700, 0xf96a0000, 0x3b480000,
      0x1ecc142c, 0x231395d6, 0x16bca6b0, 0xdf33f4df,
      0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
	   0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e },
	{  0xb83d0000, 0x16710600, 0x379a0000, 0xf5b10000,
      0x228161ac, 0xae48f145, 0x66241616, 0xc5c1eb3e,
      0xfd250000, 0xb3c41100, 0xcef00000, 0xcef90000,
	   0x3c4d7580, 0x8d5b6493, 0x7098b0a6, 0x1af21fe1 },
	{  0x75a40000, 0xc28b2700, 0x94a40000, 0x90f50000,
      0xfb7857e0, 0x49ce0bae, 0x1767c483, 0xaedf667e,
      0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
	   0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b },
	{  0xd1660000, 0x1bbc0300, 0x9eec0000, 0xf6940000,
      0x03024527, 0xcf70fcf2, 0xb4431b17, 0x857f3c2b,
      0xa4c20000, 0xd9372400, 0x0a480000, 0x66610000,
	   0xf87a12c7, 0x86bef75c, 0xa324df94, 0x2ba05a55 },
	{  0x75c90003, 0x0e10c000, 0xd1200000, 0xbaea0000,
      0x8bc42f3e, 0x8758b757, 0xbb28761d, 0x00b72e2b,
      0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
	   0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254 },
	{  0xeecf0001, 0x6f564000, 0xf33e0000, 0xa79e0000,
      0xbdb57219, 0xb711ebc5, 0x4a3b40ba, 0xfeabf254,
      0x9b060002, 0x61468000, 0x221e0000, 0x1d740000,
	   0x36715d27, 0x30495c92, 0xf11336a7, 0xfe1cdc7f },
	{  0x86790000, 0x3f390002, 0xe19ae000, 0x98560000,
      0x9565670e, 0x4e88c8ea,	0xd3dd4944, 0x161ddab9,
      0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
	   0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834 },
	{  0x30b70000, 0xe5d00000, 0xf4f46000, 0x42c40000,
      0x63b83d6a, 0x78ba9460, 0x21afa1ea, 0xb0a51834,
      0xb6ce0000,	0xdae90002, 0x156e8000, 0xda920000,
	   0xf6dd5a64, 0x36325c8a, 0xf272e8ae, 0xa6b8c28d },
	{  0x14190000, 0x23ca003c, 0x50df0000, 0x44b60000,
      0x1b6c67b0, 0x3cf3ac75, 0x61e610b0, 0xdbcadb80,
      0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
	   0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7 },
	{  0xe3430000, 0x3a4e0014, 0xf2c60000, 0xaa4e0000,
      0xdb1e42a6, 0x256bbe15, 0x123db156, 0x3a4e99d7,
      0xf75a0000, 0x19840028, 0xa2190000, 0xeef80000,
	   0xc0722516, 0x19981260, 0x73dba1e6, 0xe1844257 },
	{  0x54500000, 0x0671005c, 0x25ae0000, 0x6a1e0000,
      0x2ea54edf, 0x664e8512, 0xbfba18c3, 0x7e715d17,
      0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
	   0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e },
	{  0xbc8d0000, 0xfc3b0018, 0x19830000, 0xd10b0000,
      0xae1878c4, 0x42a69856, 0x0012da37, 0x2c3b504e,
      0xe8dd0000, 0xfa4a0044, 0x3c2d0000, 0xbb150000,
	   0x80bd361b, 0x24e81d44, 0xbfa8c2f4, 0x524a0d59 },
	{  0x69510000, 0xd4e1009c, 0xc3230000, 0xac2f0000,
      0xe4950bae, 0xcea415dc, 0x87ec287c, 0xbce1a3ce,
      0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
	   0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173 },
	{  0xc6730000, 0xaf8d000c, 0xa4c10000, 0x218d0000,
      0x23111587, 0x7913512f, 0x1d28ac88, 0x378dd173,
      0xaf220000, 0x7b6c0090, 0x67e20000, 0x8da20000,
	   0xc7841e29, 0xb7b744f3, 0x9ac484f4, 0x8b6c72bd },
	{  0xcc140000, 0xa5630000, 0x5ab90780, 0x3b500000,
      0x4bd013ff, 0x879b3418, 0x694348c1, 0xca5a87fe,
      0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
	   0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa },
	{  0x819e0000, 0xec570000, 0x66320280, 0x95f30000,
      0x5da92802, 0x48f43cbc, 0xe65aa22d, 0x8e67b7fa,
      0x4d8a0000, 0x49340000, 0x3c8b0500, 0xaea30000,
	   0x16793bfd, 0xcf6f08a4, 0x8f19eaec, 0x443d3004 },
	{  0x78230000, 0x12fc0000, 0xa93a0b80, 0x90a50000,
      0x713e2879, 0x7ee98924, 0xf08ca062, 0x636f8bab,
      0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
	   0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b },
	{  0x02af0000, 0xb7280000, 0xba1c0300, 0x56980000,
      0xba8d45d3, 0x8048c667, 0xa95c149a, 0xf4f6ea7b,
      0x7a8c0000, 0xa5d40000, 0x13260880, 0xc63d0000,
	   0xcbb36daa, 0xfea14f43, 0x59d0b4f8, 0x979961d0 },
	{  0xac480000, 0x1ba60000, 0x45fb1380, 0x03430000,
      0x5a85316a, 0x1fb250b6, 0xfe72c7fe, 0x91e478f6,
      0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
	   0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e },
	{  0x1e4e0000, 0xdecf0000, 0x6df80180, 0x77240000,
      0xec47079e, 0xf4a0694e, 0xcda31812, 0x98aa496e,
      0xb2060000, 0xc5690000, 0x28031200, 0x74670000,
	   0xb6c236f4, 0xeb1239f8, 0x33d1dfec, 0x094e3198 },
	{  0xaec30000, 0x9c4f0001, 0x79d1e000, 0x2c150000,
      0x45cc75b3, 0x6650b736, 0xab92f78f, 0xa312567b,
      0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
	   0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e },
	{  0xdb250000, 0x09290000, 0x49aac000, 0x81e10000,
      0xcafe6b59, 0x42793431, 0x43566b76, 0xe86cba2e,
      0x75e60000, 0x95660001, 0x307b2000, 0xadf40000,
	   0x8f321eea, 0x24298307, 0xe8c49cf9, 0x4b7eec55 },
	{  0x58430000, 0x807e0000, 0x78330001, 0xc66b3800,
      0xe7375cdc, 0x79ad3fdd, 0xac73fe6f, 0x3a4479b1,
      0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
	   0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6 },
	{  0x1d5a0000, 0x2b720000, 0x488d0000, 0xaf611800,
      0x25cb2ec5, 0xc879bfd0, 0x81a20429, 0x1e7536a6,
      0x45190000, 0xab0c0000, 0x30be0001, 0x690a2000,
	   0xc2fc7219, 0xb1d4800d, 0x2dd1fa46, 0x24314f17 },
	{  0xa53b0000, 0x14260000, 0x4e30001e, 0x7cae0000,
      0x8f9e0dd5, 0x78dfaa3d, 0xf73168d8, 0x0b1b4946,
      0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
	   0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce },
	{  0x07ed0000, 0xb2500000, 0x8774000a, 0x970d0000,
      0x437223ae, 0x48c76ea4, 0xf4786222, 0x9075b1ce,
      0xa2d60000, 0xa6760000, 0xc9440014, 0xeba30000,
	   0xccec2e7b, 0x3018c499, 0x03490afa, 0x9b6ef888 },
	{  0x88980000, 0x1f940000, 0x7fcf002e, 0xfb4e0000,
      0xf158079a, 0x61ae9167, 0xa895706c, 0xe6107494,
      0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
	   0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463 },
	{  0x0bc20000, 0xdb630000, 0x7e88000c, 0x15860000,
      0x91fd48f3, 0x7581bb43, 0xf460449e, 0xd8b61463,
      0x835a0000, 0xc4f70000, 0x01470022, 0xeec80000,
	   0x60a54f69, 0x142f2a24, 0x5cf534f2, 0x3ea660f7 },
	{  0x52500000, 0x29540000, 0x6a61004e, 0xf0ff0000,
      0x9a317eec, 0x452341ce, 0xcf568fe5, 0x5303130f,
      0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
	   0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691 },
	{  0x538d0000, 0xa9fc0000, 0x9ef70006, 0x56ff0000,
      0x0ae4004e, 0x92c5cdf9, 0xa9444018, 0x7f975691,
      0x01dd0000, 0x80a80000, 0xf4960048, 0xa6000000,
	   0x90d57ea2, 0xd7e68c37, 0x6612cffd, 0x2c94459e },
	{  0xe6280000, 0x4c4b0000, 0xa8550000, 0xd3d002e0,
      0xd86130b8, 0x98a7b0da, 0x289506b4, 0xd75a4897,
      0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
	   0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f },
	{  0xf0c50000, 0x59230000, 0x45820000, 0xe18d00c0,
      0x3b6d0631, 0xc2ed5699, 0xcbe0fe1c, 0x56a7b19f, 
      0x16ed0000, 0x15680000, 0xedd70000, 0x325d0220,
	   0xe30c3689, 0x5a4ae643, 0xe375f8a8, 0x81fdf908 },
	{  0xb4310000, 0x77330000, 0xb15d0000, 0x7fd004e0,
      0x78a26138, 0xd116c35d, 0xd256d489, 0x4e6f74de,
      0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
	   0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539 },
	{  0xe3060000, 0xbdc10000, 0x87130000, 0xbff20060,
      0x2eba0a1a, 0x8db53751, 0x73c5ab06, 0x5bd61539,
      0x57370000, 0xcaf20000, 0x364e0000, 0xc0220480,
	   0x56186b22, 0x5ca3f40c, 0xa1937f8f, 0x15b961e7 },
	{  0x02f20000, 0xa2810000, 0x873f0000, 0xe36c7800,
      0x1e1d74ef, 0x073d2bd6, 0xc4c23237, 0x7f32259e,
      0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
	   0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0 },
	{  0xbadd0000, 0x13ad0000, 0xb7e70000, 0xf7282800,
      0xdf45144d, 0x361ac33a, 0xea5a8d14, 0x2a2c18f0,
      0xb82f0000, 0xb12c0000, 0x30d80000, 0x14445000,
	   0xc15860a2, 0x3127e8ec, 0x2e98bf23, 0x551e3d6e },
	{  0x1e6c0000, 0xc4420000, 0x8a2e0000, 0xbcb6b800,
      0x2c4413b6, 0x8bfdd3da, 0x6a0c1bc8, 0xb99dc2eb,
      0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
	   0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f },
	{  0x92560000, 0x1eda0000, 0xea510000, 0xe8b13000,
      0xa93556a5, 0xebfb6199, 0xb15c2254, 0x33c5244f,
      0x8c3a0000, 0xda980000, 0x607f0000, 0x54078800,
	   0x85714513, 0x6006b243, 0xdb50399c, 0x8a58e6a4 },
	{  0x033d0000, 0x08b30000, 0xf33a0000, 0x3ac20007,
      0x51298a50, 0x6b6e661f, 0x0ea5cfe3, 0xe6da7ffe,
      0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
	   0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000 },
	{  0xa8da0000, 0x96be0000, 0x5c1d0000, 0x07da0002,
      0x7d669583, 0x1f98708a, 0xbb668808, 0xda878000,
      0xabe70000, 0x9e0d0000, 0xaf270000, 0x3d180005,
	   0x2c4f1fd3, 0x74f61695, 0xb5c347eb, 0x3c5dfffe },
	{  0x01930000, 0xe7820000, 0xedfb0000, 0xcf0c000b,
      0x8dd08d58, 0xbca3b42e, 0x063661e1, 0x536f9e7b,
      0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
	   0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7 },
	{  0x92280000, 0xdc850000, 0x57fa0000, 0x56dc0003,
      0xbae92316, 0x5aefa30c, 0x90cef752, 0x7b1675d7,
      0x93bb0000, 0x3b070000, 0xba010000, 0x99d00008,
	   0x3739ae4e, 0xe64c1722, 0x96f896b3, 0x2879ebac },
	{  0x5fa80000, 0x56030000, 0x43ae0000, 0x64f30013,
      0x257e86bf, 0x1311944e, 0x541e95bf, 0x8ea4db69,
      0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
	   0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e },
	{  0x00440000, 0x7f480000, 0xda7c0000, 0x2a230001,
      0x3badc9cc, 0xa9b69c87, 0x030a9e60, 0xbe0a679e,
      0x5fec0000, 0x294b0000, 0x99d20000, 0x4ed00012,
	   0x1ed34f73, 0xbaa708c9, 0x57140bdf, 0x30aebcf7 },
	{  0xee930000, 0xd6070000, 0x92c10000, 0x2b9801e0,
      0x9451287c, 0x3b6cfb57, 0x45312374, 0x201f6a64,
      0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
	   0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0 },
	{  0x7b280000, 0x57420000, 0xa9e50000, 0x634300a0,
      0x9edb442f, 0x6d9995bb, 0x27f83b03, 0xc7ff60f0,
      0x95bb0000, 0x81450000, 0x3b240000, 0x48db0140,
	   0x0a8a6c53, 0x56f56eec, 0x62c91877, 0xe7e00a94 }
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

#define S00   M0
#define S01   M1
#define S02   C0
#define S03   C1
#define S04   M2
#define S05   M3
#define S06   C2
#define S07   C3
#define S08   C4
#define S09   C5
#define S0A   M4
#define S0B   M5
#define S0C   C6
#define S0D   C7
#define S0E   M6
#define S0F   M7
#define S10   M8
#define S11   M9
#define S12   C8
#define S13   C9
#define S14   MA
#define S15   MB
#define S16   CA
#define S17   CB
#define S18   CC
#define S19   CD
#define S1A   MC
#define S1B   MD
#define S1C   CE
#define S1D   CF
#define S1E   ME
#define S1F   MF


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Hamsi 8 way AVX512 

// Intel docs say _mm512_movepi64_mask & _mm512_cmplt_epi64_mask have same
// timig. However, when tested hashing X13 on i9-9940x using cmplt with zero
// had a 3% faster overall hashrate than than using movepi. 

#define INPUT_BIG8 \
{ \
  __m512i db = _mm512_ror_epi64( *buf, 1 ); \
  const __m512i zero = m512_zero; \
  const uint64_t *tp = (const uint64_t*)T512; \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = zero; \
  for ( int i = 0; i < 64*8; i += 8, db = _mm512_ror_epi64( db, 1 ) ) \
  { \
     const __mmask8 dm = _mm512_cmplt_epi64_mask( db, zero ); \
     m0 = _mm512_mask_xor_epi64( m0, dm, m0, v512_64( tp[i+0] ) ); \
     m1 = _mm512_mask_xor_epi64( m1, dm, m1, v512_64( tp[i+1] ) ); \
     m2 = _mm512_mask_xor_epi64( m2, dm, m2, v512_64( tp[i+2] ) ); \
     m3 = _mm512_mask_xor_epi64( m3, dm, m3, v512_64( tp[i+3] ) ); \
     m4 = _mm512_mask_xor_epi64( m4, dm, m4, v512_64( tp[i+4] ) ); \
     m5 = _mm512_mask_xor_epi64( m5, dm, m5, v512_64( tp[i+5] ) ); \
     m6 = _mm512_mask_xor_epi64( m6, dm, m6, v512_64( tp[i+6] ) ); \
     m7 = _mm512_mask_xor_epi64( m7, dm, m7, v512_64( tp[i+7] ) ); \
  } \
}

#define SBOX8( a, b, c, d ) \
{ \
  __m512i tb, td; \
  td = mm512_xorand( d, a, c ); \
  c = mm512_xor3( c, td, b ); \
  tb = mm512_xoror( b, d, a ); \
  a = _mm512_xor_si512( a, c ); \
  b = mm512_xoror( td, tb, a ); \
  td = mm512_xorand( a, td, tb ); \
  a = c; \
  c = mm512_xor3( tb, b, td ); \
  d = mm512_not( td ); \
}


/*
#define SBOX8( a, b, c, d ) \
do { \
  __m512i t = mm512_xorand( d, a, c ); \
  c = mm512_xor3( c, t, b ); \
  b = mm512_xoror( b, d, a ); \
  a = _mm512_xor_si512( a, c ); \
  d = mm512_xoror( t, b, a ); \
  t = mm512_xorand( a, t, b ); \
  a = c; \
  c = mm512_xor3( b, d, t ); \
  b = d; \
  d = mm512_not( t ); \
} while (0)
*/

#define L8( a, b, c, d ) \
   a = mm512_rol_32( a, 13 ); \
   c = mm512_rol_32( c,  3 ); \
   d = mm512_xor3( d, c, _mm512_slli_epi32( a, 3 ) ); \
   b = mm512_xor3( a, b, c ); \
   d = mm512_rol_32( d, 7 ); \
   b = mm512_rol_32( b, 1 ); \
   c = mm512_xor3( c, d, _mm512_slli_epi32( b, 7 ) ); \
   a = mm512_xor3( a, b, d ); \
   c = mm512_rol_32( c, 22 ); \
   a = mm512_rol_32( a,  5 );

#define DECL_STATE_BIG8 \
   __m512i c0, c1, c2, c3, c4, c5, c6, c7; \

#define READ_STATE_BIG8(sc) \
do { \
   c0 = sc->h[0]; \
   c1 = sc->h[1]; \
   c2 = sc->h[2]; \
   c3 = sc->h[3]; \
   c4 = sc->h[4]; \
   c5 = sc->h[5]; \
   c6 = sc->h[6]; \
   c7 = sc->h[7]; \
} while (0)

#define WRITE_STATE_BIG8(sc) \
do { \
   sc->h[0] = c0; \
   sc->h[1] = c1; \
   sc->h[2] = c2; \
   sc->h[3] = c3; \
   sc->h[4] = c4; \
   sc->h[5] = c5; \
   sc->h[6] = c6; \
   sc->h[7] = c7; \
} while (0)

#define ROUND_BIG8( alpha ) \
do { \
   __m512i t0, t1, t2, t3, t4, t5; \
   s0 = _mm512_xor_si512( s0, alpha[ 0] ); /* m0 */ \
   s1 = _mm512_xor_si512( s1, alpha[ 1] ); /* c0 */ \
   s2 = _mm512_xor_si512( s2, alpha[ 2] ); /* m1 */ \
   s3 = _mm512_xor_si512( s3, alpha[ 3] ); /* c1 */ \
   s4 = _mm512_xor_si512( s4, alpha[ 4] ); /* c2 */ \
   s5 = _mm512_xor_si512( s5, alpha[ 5] ); /* m2 */ \
   s6 = _mm512_xor_si512( s6, alpha[ 6] ); /* c3 */ \
   s7 = _mm512_xor_si512( s7, alpha[ 7] ); /* m3 */ \
   s8 = _mm512_xor_si512( s8, alpha[ 8] ); /* m4 */ \
   s9 = _mm512_xor_si512( s9, alpha[ 9] ); /* c4 */ \
   sA = _mm512_xor_si512( sA, alpha[10] ); /* m5 */ \
   sB = _mm512_xor_si512( sB, alpha[11] ); /* c5 */ \
   sC = _mm512_xor_si512( sC, alpha[12] ); /* c6 */ \
   sD = _mm512_xor_si512( sD, alpha[13] ); /* m6 */ \
   sE = _mm512_xor_si512( sE, alpha[14] ); /* c7 */ \
   sF = _mm512_xor_si512( sF, alpha[15] ); /* m7 */ \
\
  SBOX8( s0, s4, s8, sC ); /* ( m0, c2, m4, c6 ) */ \
  SBOX8( s1, s5, s9, sD ); /* ( c0, m2, c4, m6 ) */ \
  SBOX8( s2, s6, sA, sE ); /* ( m1, c3, m5, c7 ) */ \
  SBOX8( s3, s7, sB, sF ); /* ( c1, m3, c5, m7 ) */ \
  s4 = mm512_swap64_32( s4 ); \
  s5 = mm512_swap64_32( s5 ); \
  sD = mm512_swap64_32( sD ); \
  sE = mm512_swap64_32( sE ); \
  t0 = _mm512_mask_blend_epi32( 0xaaaa, s4, s5 ); \
  t1 = _mm512_mask_blend_epi32( 0xaaaa, sD, sE ); \
  L8( s0, t0, s9, t1 ); \
  s6 = mm512_swap64_32( s6 ); \
  sF = mm512_swap64_32( sF ); \
  t2 = _mm512_mask_blend_epi32( 0xaaaa, s5, s6 ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, sE, sF ); \
  L8( s1, t2, sA, t3 ); \
  s5 = _mm512_mask_blend_epi32( 0x5555, t0, t2 ); \
  sE = _mm512_mask_blend_epi32( 0x5555, t1, t3 ); \
\
  s7 = mm512_swap64_32( s7 ); \
  sC = mm512_swap64_32( sC ); \
  t4 = _mm512_mask_blend_epi32( 0xaaaa, s6, s7 ); \
  t5 = _mm512_mask_blend_epi32( 0xaaaa, sF, sC ); \
  L8( s2, t4, sB, t5 ); \
  s6 = _mm512_mask_blend_epi32( 0x5555, t2, t4 ); \
  sF = _mm512_mask_blend_epi32( 0x5555, t3, t5 ); \
  s6 = mm512_swap64_32( s6 ); \
  sF = mm512_swap64_32( sF ); \
\
  t2 = _mm512_mask_blend_epi32( 0xaaaa, s7, s4 ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, sC, sD ); \
  L8( s3, t2, s8, t3 ); \
  s7 = _mm512_mask_blend_epi32( 0x5555, t4, t2 ); \
  s4 = _mm512_mask_blend_epi32( 0xaaaa, t0, t2 ); \
  sC = _mm512_mask_blend_epi32( 0x5555, t5, t3 ); \
  sD = _mm512_mask_blend_epi32( 0xaaaa, t1, t3 ); \
  s7 = mm512_swap64_32( s7 ); \
  sC = mm512_swap64_32( sC ); \
\
  t0 = _mm512_mask_blend_epi32( 0xaaaa, s0, mm512_swap64_32( s8 ) ); \
  t1 = _mm512_mask_blend_epi32( 0xaaaa, s1, s9 ); \
  t2 = _mm512_mask_blend_epi32( 0xaaaa, mm512_swap64_32( s2 ), sA ); \
  t3 = _mm512_mask_blend_epi32( 0x5555, s3, sB ); \
  t3 = mm512_swap64_32( t3 ); \
  L8( t0, t1, t2, t3 ); \
  t3 = mm512_swap64_32( t3 ); \
  s0 = _mm512_mask_blend_epi32( 0x5555, s0, t0 ); \
  s8 = _mm512_mask_blend_epi32( 0x5555, s8, mm512_swap64_32( t0 ) ); \
  s1 = _mm512_mask_blend_epi32( 0x5555, s1, t1 ); \
  s9 = _mm512_mask_blend_epi32( 0xaaaa, s9, t1 ); \
  s2 = _mm512_mask_blend_epi32( 0xaaaa, s2, mm512_swap64_32( t2 ) ); \
  sA = _mm512_mask_blend_epi32( 0xaaaa, sA, t2 ); \
  s3 = _mm512_mask_blend_epi32( 0xaaaa, s3, t3 ); \
  sB = _mm512_mask_blend_epi32( 0x5555, sB, t3 ); \
\
  t0 = _mm512_mask_blend_epi32( 0xaaaa, s4, sC ); \
  t1 = _mm512_mask_blend_epi32( 0xaaaa, s5, sD ); \
  t2 = _mm512_mask_blend_epi32( 0xaaaa, s6, sE ); \
  t3 = _mm512_mask_blend_epi32( 0xaaaa, s7, sF ); \
  L8( t0, t1, t2, t3 ); \
  s4 = _mm512_mask_blend_epi32( 0x5555, s4, t0 ); \
  sC = _mm512_mask_blend_epi32( 0xaaaa, sC, t0 ); \
  s5 = _mm512_mask_blend_epi32( 0x5555, s5, t1 ); \
  sD = _mm512_mask_blend_epi32( 0xaaaa, sD, t1 ); \
  s6 = _mm512_mask_blend_epi32( 0x5555, s6, t2 ); \
  sE = _mm512_mask_blend_epi32( 0xaaaa, sE, t2 ); \
  s7 = _mm512_mask_blend_epi32( 0x5555, s7, t3 ); \
  sF = _mm512_mask_blend_epi32( 0xaaaa, sF, t3 ); \
  s4 = mm512_swap64_32( s4 ); \
  s5 = mm512_swap64_32( s5 ); \
  sD = mm512_swap64_32( sD ); \
  sE = mm512_swap64_32( sE ); \
} while (0)

#define P_BIG8 \
do { \
   __m512i alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_n )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v512_64( ( (uint64_t*)alpha_n )[i] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (1ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (2ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (3ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (4ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (5ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
} while (0)

#define PF_BIG8 \
do { \
   __m512i alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_f )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v512_64( ( (uint64_t*)alpha_f )[i] ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 1ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 2ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 3ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 4ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 5ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 6ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 7ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 8ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( ( 9ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (10ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
   alpha[0] = v512_64( (11ULL << 32) ^ A0 ); \
   ROUND_BIG8( alpha ); \
} while (0)

#define T_BIG8 \
do { /* order is important */ \
   c7 = sc->h[ 7 ] = _mm512_xor_si512( sc->h[ 7 ], sB ); /* c5 */ \
   c6 = sc->h[ 6 ] = _mm512_xor_si512( sc->h[ 6 ], sA ); /* m5 */ \
   c5 = sc->h[ 5 ] = _mm512_xor_si512( sc->h[ 5 ], s9 ); /* c4 */ \
   c4 = sc->h[ 4 ] = _mm512_xor_si512( sc->h[ 4 ], s8 ); /* m4 */ \
   c3 = sc->h[ 3 ] = _mm512_xor_si512( sc->h[ 3 ], s3 ); /* c1 */ \
   c2 = sc->h[ 2 ] = _mm512_xor_si512( sc->h[ 2 ], s2 ); /* m1 */ \
   c1 = sc->h[ 1 ] = _mm512_xor_si512( sc->h[ 1 ], s1 ); /* c0 */ \
   c0 = sc->h[ 0 ] = _mm512_xor_si512( sc->h[ 0 ], s0 ); /* m0 */ \
} while (0)

///////////////////////
//
//  Found to be slower than running 8x64 twice.

// Hamsi 16 way 32 bit.

#define DECL_STATE_16X32 \
   __m512i C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, CA, CB, CC, CD, CE, CF; \

#define READ_STATE_16X32(sc) \
   C0 = sc->h[ 0]; \
   C1 = sc->h[ 1]; \
   C2 = sc->h[ 2]; \
   C3 = sc->h[ 3]; \
   C4 = sc->h[ 4]; \
   C5 = sc->h[ 5]; \
   C6 = sc->h[ 6]; \
   C7 = sc->h[ 7]; \
   C8 = sc->h[ 8]; \
   C9 = sc->h[ 9]; \
   CA = sc->h[10]; \
   CB = sc->h[11]; \
   CC = sc->h[12]; \
   CD = sc->h[13]; \
   CE = sc->h[14]; \
   CF = sc->h[15];

#define WRITE_STATE_16X32(sc) \
   sc->h[ 0] = C0; \
   sc->h[ 1] = C1; \
   sc->h[ 2] = C2; \
   sc->h[ 3] = C3; \
   sc->h[ 4] = C4; \
   sc->h[ 5] = C5; \
   sc->h[ 6] = C6; \
   sc->h[ 7] = C7; \
   sc->h[ 8] = C8; \
   sc->h[ 9] = C9; \
   sc->h[10] = CA; \
   sc->h[11] = CB; \
   sc->h[12] = CC; \
   sc->h[13] = CD; \
   sc->h[14] = CE; \
   sc->h[15] = CF;


#define INPUT_16X32 \
{ \
  const __m512i zero = (const __m512i)_mm512_setzero_si512(); \
  const uint64_t *tp = (const uint64_t*)T512; \
  M0 = M1 = M2 = M3 = M4 = M5 = M6 = M7 = \
  M8 = M9 = MA = MB = MC = MD = ME = MF = zero; \
  __m512i db = _mm512_ror_epi32( buf[0], 1 ); \
  for ( int u = 0; u < 32; u++ ) \
  { \
    const __mmask16 dm = (const __mmask16)_mm512_cmplt_epi32_mask( db, zero );\
    M0 = _mm512_mask_xor_epi32( M0, dm, M0,\
                        v512_32( (const uint32_t)(tp[0] & 0xffffffffull) ) );\
    M1 = _mm512_mask_xor_epi32( M1, dm, M1, \
                        v512_32( (const uint32_t)(tp[0] >> 32) ) ); \
    M2 = _mm512_mask_xor_epi32( M2, dm, M2, \
                        v512_32( (const uint32_t)(tp[1] & 0xffffffffull) ) );\
    M3 = _mm512_mask_xor_epi32( M3, dm, M3, \
                        v512_32( (const uint32_t)(tp[1] >> 32) ) ); \
    M4 = _mm512_mask_xor_epi32( M4, dm, M4, \
                        v512_32( (const uint32_t)(tp[2] & 0xffffffffull) ) );\
    M5 = _mm512_mask_xor_epi32( M5, dm, M5, \
                        v512_32( (const uint32_t)(tp[2] >> 32) ) ); \
    M6 = _mm512_mask_xor_epi32( M6, dm, M6, \
                        v512_32( (const uint32_t)(tp[3] & 0xffffffffull) ) );\
    M7 = _mm512_mask_xor_epi32( M7, dm, M7, \
                        v512_32( (const uint32_t)(tp[3] >> 32) ) ); \
    M8 = _mm512_mask_xor_epi32( M8, dm, M8, \
                        v512_32( (const uint32_t)(tp[4] & 0xffffffffull) ) );\
    M9 = _mm512_mask_xor_epi32( M9, dm, M9, \
                        v512_32( (const uint32_t)(tp[4] >> 32) ) ); \
    MA = _mm512_mask_xor_epi32( MA, dm, MA, \
                        v512_32( (const uint32_t)(tp[5] & 0xffffffffull) ) );\
    MB = _mm512_mask_xor_epi32( MB, dm, MB, \
                        v512_32( (const uint32_t)(tp[5] >> 32) ) ); \
    MC = _mm512_mask_xor_epi32( MC, dm, MC, \
                        v512_32( (const uint32_t)(tp[6] & 0xffffffffull) ) );\
    MD = _mm512_mask_xor_epi32( MD, dm, MD, \
                        v512_32( (const uint32_t)(tp[6] >> 32) ) ); \
    ME = _mm512_mask_xor_epi32( ME, dm, ME, \
                        v512_32( (const uint32_t)(tp[7] & 0xffffffffull) ) );\
    MF = _mm512_mask_xor_epi32( MF, dm, MF, \
                        v512_32( (const uint32_t)(tp[7] >> 32) ) ); \
    db = _mm512_ror_epi32( db, 1 ); \
    tp += 8; \
  } \
  db = _mm512_ror_epi32( buf[1], 1 ); \
  for ( int u = 0; u < 32; u++ ) \
  { \
    const __mmask16 dm = (const __mmask16)_mm512_cmplt_epi32_mask( db, zero ); \
    M0 = _mm512_mask_xor_epi32( M0, dm, M0,\
                        v512_32( (const uint32_t)(tp[0] & 0xffffffffull) ) );\
    M1 = _mm512_mask_xor_epi32( M1, dm, M1, \
                        v512_32( (const uint32_t)(tp[0] >> 32) ) ); \
    M2 = _mm512_mask_xor_epi32( M2, dm, M2, \
                        v512_32( (const uint32_t)(tp[1] & 0xffffffffull) ) );\
    M3 = _mm512_mask_xor_epi32( M3, dm, M3, \
                        v512_32( (const uint32_t)(tp[1] >> 32) ) ); \
    M4 = _mm512_mask_xor_epi32( M4, dm, M4, \
                        v512_32( (const uint32_t)(tp[2] & 0xffffffffull) ) );\
    M5 = _mm512_mask_xor_epi32( M5, dm, M5, \
                        v512_32( (const uint32_t)(tp[2] >> 32) ) ); \
    M6 = _mm512_mask_xor_epi32( M6, dm, M6, \
                        v512_32( (const uint32_t)(tp[3] & 0xffffffffull) ) );\
    M7 = _mm512_mask_xor_epi32( M7, dm, M7, \
                        v512_32( (const uint32_t)(tp[3] >> 32) ) ); \
    M8 = _mm512_mask_xor_epi32( M8, dm, M8, \
                        v512_32( (const uint32_t)(tp[4] & 0xffffffffull) ) );\
    M9 = _mm512_mask_xor_epi32( M9, dm, M9, \
                        v512_32( (const uint32_t)(tp[4] >> 32) ) ); \
    MA = _mm512_mask_xor_epi32( MA, dm, MA, \
                        v512_32( (const uint32_t)(tp[5] & 0xffffffffull) ) );\
    MB = _mm512_mask_xor_epi32( MB, dm, MB, \
                        v512_32( (const uint32_t)(tp[5] >> 32) ) ); \
    MC = _mm512_mask_xor_epi32( MC, dm, MC, \
                        v512_32( (const uint32_t)(tp[6] & 0xffffffffull) ) );\
    MD = _mm512_mask_xor_epi32( MD, dm, MD, \
                        v512_32( (const uint32_t)(tp[6] >> 32) ) ); \
    ME = _mm512_mask_xor_epi32( ME, dm, ME, \
                        v512_32( (const uint32_t)(tp[7] & 0xffffffffull) ) );\
    MF = _mm512_mask_xor_epi32( MF, dm, MF, \
                        v512_32( (const uint32_t)(tp[7] >> 32) ) ); \
    db = _mm512_ror_epi32( db, 1 ); \
    tp += 8; \
  } \
}


#define SBOX_16X32 SBOX8
#define L_16X32    L8

#define ROUND_16X32( alpha ) \
{ \
   S00 = _mm512_xor_si512( S00, alpha[ 0] ); \
   S01 = _mm512_xor_si512( S01, alpha[ 1] ); \
   S02 = _mm512_xor_si512( S02, alpha[ 2] ); \
   S03 = _mm512_xor_si512( S03, alpha[ 3] ); \
   S04 = _mm512_xor_si512( S04, alpha[ 4] ); \
   S05 = _mm512_xor_si512( S05, alpha[ 5] ); \
   S06 = _mm512_xor_si512( S06, alpha[ 6] ); \
   S07 = _mm512_xor_si512( S07, alpha[ 7] ); \
   S08 = _mm512_xor_si512( S08, alpha[ 8] ); \
   S09 = _mm512_xor_si512( S09, alpha[ 9] ); \
   S0A = _mm512_xor_si512( S0A, alpha[10] ); \
   S0B = _mm512_xor_si512( S0B, alpha[11] ); \
   S0C = _mm512_xor_si512( S0C, alpha[12] ); \
   S0D = _mm512_xor_si512( S0D, alpha[13] ); \
   S0E = _mm512_xor_si512( S0E, alpha[14] ); \
   S0F = _mm512_xor_si512( S0F, alpha[15] ); \
   S10 = _mm512_xor_si512( S10, alpha[16] ); \
   S11 = _mm512_xor_si512( S11, alpha[17] ); \
   S12 = _mm512_xor_si512( S12, alpha[18] ); \
   S13 = _mm512_xor_si512( S13, alpha[19] ); \
   S14 = _mm512_xor_si512( S14, alpha[20] ); \
   S15 = _mm512_xor_si512( S15, alpha[21] ); \
   S16 = _mm512_xor_si512( S16, alpha[22] ); \
   S17 = _mm512_xor_si512( S17, alpha[23] ); \
   S18 = _mm512_xor_si512( S18, alpha[24] ); \
   S19 = _mm512_xor_si512( S19, alpha[25] ); \
   S1A = _mm512_xor_si512( S1A, alpha[26] ); \
   S1B = _mm512_xor_si512( S1B, alpha[27] ); \
   S1C = _mm512_xor_si512( S1C, alpha[28] ); \
   S1D = _mm512_xor_si512( S1D, alpha[29] ); \
   S1E = _mm512_xor_si512( S1E, alpha[30] ); \
   S1F = _mm512_xor_si512( S1F, alpha[31] ); \
   SBOX_16X32( S00, S08, S10, S18 ); \
   SBOX_16X32( S01, S09, S11, S19 ); \
   SBOX_16X32( S02, S0A, S12, S1A ); \
   SBOX_16X32( S03, S0B, S13, S1B ); \
   SBOX_16X32( S04, S0C, S14, S1C ); \
   SBOX_16X32( S05, S0D, S15, S1D ); \
   SBOX_16X32( S06, S0E, S16, S1E ); \
   SBOX_16X32( S07, S0F, S17, S1F ); \
   L_16X32( S00, S09, S12, S1B ); \
   L_16X32( S01, S0A, S13, S1C ); \
   L_16X32( S02, S0B, S14, S1D ); \
   L_16X32( S03, S0C, S15, S1E ); \
   L_16X32( S04, S0D, S16, S1F ); \
   L_16X32( S05, S0E, S17, S18 ); \
   L_16X32( S06, S0F, S10, S19 ); \
   L_16X32( S07, S08, S11, S1A ); \
   L_16X32( S00, S02, S05, S07 ); \
   L_16X32( S10, S13, S15, S16 ); \
   L_16X32( S09, S0B, S0C, S0E ); \
   L_16X32( S19, S1A, S1C, S1F ); \
}

#define P_16X32 \
{ \
   __m512i alpha[32]; \
   const uint32_t A1 = ( (const uint32_t*)alpha_n )[1]; \
   for( int i = 0; i < 32; i++ ) \
      alpha[i] = v512_32( ( (uint32_t*)alpha_n )[i] ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 1 ^ (A1) ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 2 ^ (A1) ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 3 ^ (A1) ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 4 ^ (A1) ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 5 ^ (A1) ); \
   ROUND_16X32( alpha ); \
}

#define PF_16X32 \
{ \
   __m512i alpha[32]; \
   const uint32_t A1 = ( (const uint32_t*)alpha_f )[1]; \
   for( int i = 0; i < 32; i++ ) \
      alpha[i] = v512_32( ( (uint32_t*)alpha_f )[i] ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  1 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  2 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  3 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  4 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  5 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  6 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  7 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  8 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32(  9 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 10 ^ A1 ); \
   ROUND_16X32( alpha ); \
   alpha[1] = v512_32( 11 ^ A1 ); \
   ROUND_16X32( alpha ); \
}

#define T_16X32 \
      /* order is important */ \
      CF = sc->h[15] = _mm512_xor_si512( sc->h[15], S17 ); \
      CE = sc->h[14] = _mm512_xor_si512( sc->h[14], S16 ); \
      CD = sc->h[13] = _mm512_xor_si512( sc->h[13], S15 ); \
      CC = sc->h[12] = _mm512_xor_si512( sc->h[12], S14 ); \
      CB = sc->h[11] = _mm512_xor_si512( sc->h[11], S13 ); \
      CA = sc->h[10] = _mm512_xor_si512( sc->h[10], S12 ); \
      C9 = sc->h[ 9] = _mm512_xor_si512( sc->h[ 9], S11 ); \
      C8 = sc->h[ 8] = _mm512_xor_si512( sc->h[ 8], S10 ); \
      C7 = sc->h[ 7] = _mm512_xor_si512( sc->h[ 7], S07 ); \
      C6 = sc->h[ 6] = _mm512_xor_si512( sc->h[ 6], S06 ); \
      C5 = sc->h[ 5] = _mm512_xor_si512( sc->h[ 5], S05 ); \
      C4 = sc->h[ 4] = _mm512_xor_si512( sc->h[ 4], S04 ); \
      C3 = sc->h[ 3] = _mm512_xor_si512( sc->h[ 3], S03 ); \
      C2 = sc->h[ 2] = _mm512_xor_si512( sc->h[ 2], S02 ); \
      C1 = sc->h[ 1] = _mm512_xor_si512( sc->h[ 1], S01 ); \
      C0 = sc->h[ 0] = _mm512_xor_si512( sc->h[ 0], S00 );

void hamsi_16x32_big( hamsi_16x32_big_context *sc, __m512i *buf, size_t num )
{
   DECL_STATE_16X32
   uint32_t tmp = num << 6;

   sc->count_low =  sc->count_low + tmp;
   sc->count_high += (uint32_t)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_16X32( sc );
   while ( num-- > 0 )
   {
      __m512i M0, M1, M2, M3, M4, M5, M6, M7;
      __m512i M8, M9, MA, MB, MC, MD, ME, MF;
      INPUT_16X32;
      P_16X32;
      T_16X32;
      buf += 2;
   }
   WRITE_STATE_16X32( sc );
}

void hamsi_16x32_big_final( hamsi_16x32_big_context *sc, __m512i *buf )
{
   DECL_STATE_16X32
   READ_STATE_16X32( sc );
   __m512i M0, M1, M2, M3, M4, M5, M6, M7;
   __m512i M8, M9, MA, MB, MC, MD, ME, MF;
   INPUT_16X32;
   PF_16X32;
   T_16X32;
   WRITE_STATE_16X32( sc );
}

void hamsi512_16x32_init( hamsi512_16x32_context *sc )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;
   sc->h[ 0] = v512_32( HAMSI_IV512[ 0] );
   sc->h[ 1] = v512_32( HAMSI_IV512[ 1] );
   sc->h[ 2] = v512_32( HAMSI_IV512[ 2] );
   sc->h[ 3] = v512_32( HAMSI_IV512[ 3] );
   sc->h[ 4] = v512_32( HAMSI_IV512[ 4] );
   sc->h[ 5] = v512_32( HAMSI_IV512[ 5] );
   sc->h[ 6] = v512_32( HAMSI_IV512[ 6] );
   sc->h[ 7] = v512_32( HAMSI_IV512[ 7] );
   sc->h[ 8] = v512_32( HAMSI_IV512[ 8] );
   sc->h[ 9] = v512_32( HAMSI_IV512[ 9] );
   sc->h[10] = v512_32( HAMSI_IV512[10] );
   sc->h[11] = v512_32( HAMSI_IV512[11] );
   sc->h[12] = v512_32( HAMSI_IV512[12] );
   sc->h[13] = v512_32( HAMSI_IV512[13] );
   sc->h[14] = v512_32( HAMSI_IV512[14] );
   sc->h[15] = v512_32( HAMSI_IV512[15] );
}

void hamsi512_16x32_update( hamsi512_16x32_context *sc, const void *data,
                           size_t len )
{
   __m512i *vdata = (__m512i*)data;

   hamsi_16x32_big( sc, vdata, len>>3 );
   vdata += ( (len & ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_512( sc->buf, vdata, len>>3 );
   sc->partial_len = len;
}

void hamsi512_16x32_close( hamsi512_16x32_context *sc, void *dst )
{
   __m512i pad[2];
   uint32_t ch, cl;

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v512_32( ch );
   pad[1] = v512_32( cl );
   sc->buf[0] = v512_32( 0x80 );
   sc->buf[1] = _mm512_setzero_si512();
   hamsi_16x32_big( sc, sc->buf, 1 );
   hamsi_16x32_big_final( sc, pad );

   mm512_block_bswap_32( (__m512i*)dst, sc->h );
   mm512_block_bswap_32( (__m512i*)dst + 8, sc->h + 8 );
}

void hamsi512_16x32_full( hamsi512_16x32_context *sc, void *dst,
                            const void *data, size_t len )
{
   // init
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;
   sc->h[ 0] = v512_32( HAMSI_IV512[ 0] );
   sc->h[ 1] = v512_32( HAMSI_IV512[ 1] );
   sc->h[ 2] = v512_32( HAMSI_IV512[ 2] );
   sc->h[ 3] = v512_32( HAMSI_IV512[ 3] );
   sc->h[ 4] = v512_32( HAMSI_IV512[ 4] );
   sc->h[ 5] = v512_32( HAMSI_IV512[ 5] );
   sc->h[ 6] = v512_32( HAMSI_IV512[ 6] );
   sc->h[ 7] = v512_32( HAMSI_IV512[ 7] );
   sc->h[ 8] = v512_32( HAMSI_IV512[ 8] );
   sc->h[ 9] = v512_32( HAMSI_IV512[ 9] );
   sc->h[10] = v512_32( HAMSI_IV512[10] );
   sc->h[11] = v512_32( HAMSI_IV512[11] );
   sc->h[12] = v512_32( HAMSI_IV512[12] );
   sc->h[13] = v512_32( HAMSI_IV512[13] );
   sc->h[14] = v512_32( HAMSI_IV512[14] );
   sc->h[15] = v512_32( HAMSI_IV512[15] );

   // update
   __m512i *vdata = (__m512i*)data;

   hamsi_16x32_big( sc, vdata, len>>3 );
   vdata += ( (len & ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_512( sc->buf, vdata, len>>3 );
   sc->partial_len = len;

   // close   
   __m512i pad[2];
   uint32_t ch, cl;

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v512_32( ch );
   pad[1] = v512_32( cl );
   sc->buf[0] = v512_32( 0x80 );
   sc->buf[1] = _mm512_setzero_si512();
   hamsi_16x32_big( sc, sc->buf, 1 );
   hamsi_16x32_big_final( sc, pad );

   mm512_block_bswap_32( (__m512i*)dst, sc->h );
   mm512_block_bswap_32( (__m512i*)dst + 8, sc->h + 8 );
}

//
//
//
/////////////////////////////////


void hamsi_8way_big( hamsi_8way_big_context *sc, __m512i *buf, size_t num )
{
   DECL_STATE_BIG8
   uint32_t tmp = num << 6;

   sc->count_low =  sc->count_low + tmp;
   sc->count_high += (uint32_t)( (num >> 13) >> 13 );
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
   uint64_t *iv = (uint64_t*)HAMSI_IV512;

   sc->h[0] = v512_64( iv[0] );
   sc->h[1] = v512_64( iv[1] );
   sc->h[2] = v512_64( iv[2] );
   sc->h[3] = v512_64( iv[3] );
   sc->h[4] = v512_64( iv[4] );
   sc->h[5] = v512_64( iv[5] );
   sc->h[6] = v512_64( iv[6] );
   sc->h[7] = v512_64( iv[7] );
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
   
   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v512_64( ((uint64_t)cl << 32 ) | (uint64_t)ch );
   sc->buf[0] = v512_64( 0x80 );
   hamsi_8way_big( sc, sc->buf, 1 );
   hamsi_8way_big_final( sc, pad );

   mm512_block_bswap_32( (__m512i*)dst, sc->h );
}

#endif // AVX512

#if defined (__AVX2__)

// Hamsi 4 way AVX2

#if defined(__AVX512VL__)

#define INPUT_BIG \
do { \
  __m256i db = _mm256_ror_epi64( *buf, 1 ); \
  const __m256i zero = m256_zero; \
  const uint64_t *tp = (const uint64_t*)T512; \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = zero; \
  for ( int i = 0; i < 64*8; i+=8, db = _mm256_ror_epi64( db, 1 ) ) \
  { \
     const __mmask8 dm = _mm256_cmplt_epi64_mask( db, zero ); \
     m0 = _mm256_mask_xor_epi64( m0, dm, m0, v256_64( tp[i+0] ) ); \
     m1 = _mm256_mask_xor_epi64( m1, dm, m1, v256_64( tp[i+1] ) ); \
     m2 = _mm256_mask_xor_epi64( m2, dm, m2, v256_64( tp[i+2] ) ); \
     m3 = _mm256_mask_xor_epi64( m3, dm, m3, v256_64( tp[i+3] ) ); \
     m4 = _mm256_mask_xor_epi64( m4, dm, m4, v256_64( tp[i+4] ) ); \
     m5 = _mm256_mask_xor_epi64( m5, dm, m5, v256_64( tp[i+5] ) ); \
     m6 = _mm256_mask_xor_epi64( m6, dm, m6, v256_64( tp[i+6] ) ); \
     m7 = _mm256_mask_xor_epi64( m7, dm, m7, v256_64( tp[i+7] ) ); \
  } \
} while (0)

// v3 ternary logic, 8 instructions, 2 local vars
#define SBOX( a, b, c, d ) \
{ \
  __m256i tb, td; \
  td = mm256_xorand( d, a, c ); \
  tb = mm256_xoror( b, d, a ); \
  c = mm256_xor3( c, td, b ); \
  a = _mm256_xor_si256( a, c ); \
  b = mm256_xoror( td, tb, a ); \
  d = _mm256_ternarylogic_epi64( a, td, tb, 0x87 );/* mm256_not( mm256_xorand( a, td, tb ) ); */ \
  a = c; \
  c = _mm256_ternarylogic_epi64( tb, b, d, 0x69 ); /*mm256_not( mm256_xor3( tb, b, d ) );*/ \
}

#else

#define INPUT_BIG \
do { \
  __m256i db = *buf; \
  const __m256i zero = m256_zero; \
  const uint64_t *tp = (const uint64_t*)T512;  \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = zero; \
  for ( int i = 63; i >= 0; i-- ) \
  { \
     __m256i dm = _mm256_cmpgt_epi64( zero, _mm256_slli_epi64( db, i ) ); \
     m0 = _mm256_xor_si256( m0, _mm256_and_si256( dm, v256_64( tp[0] ) ) ); \
     m1 = _mm256_xor_si256( m1, _mm256_and_si256( dm, v256_64( tp[1] ) ) ); \
     m2 = _mm256_xor_si256( m2, _mm256_and_si256( dm, v256_64( tp[2] ) ) ); \
     m3 = _mm256_xor_si256( m3, _mm256_and_si256( dm, v256_64( tp[3] ) ) ); \
     m4 = _mm256_xor_si256( m4, _mm256_and_si256( dm, v256_64( tp[4] ) ) ); \
     m5 = _mm256_xor_si256( m5, _mm256_and_si256( dm, v256_64( tp[5] ) ) ); \
     m6 = _mm256_xor_si256( m6, _mm256_and_si256( dm, v256_64( tp[6] ) ) ); \
     m7 = _mm256_xor_si256( m7, _mm256_and_si256( dm, v256_64( tp[7] ) ) ); \
     tp += 8; \
  } \
} while (0)

// v3 no ternary logic, 15 instructions, 9 TL equivalent instructions
#define SBOX( a, b, c, d ) \
{ \
  __m256i tb, td; \
  td = mm256_xorand( d, a, c ); \
  tb = mm256_xoror( b, d, a ); \
  c = mm256_xor3( c, td, b ); \
  a = _mm256_xor_si256( a, c ); \
  b = mm256_xoror( td, tb, a ); \
  td = mm256_xorand( a, td, tb ); \
  a = c; \
  c = mm256_xor3( tb, b, td ); \
  d = mm256_not( td ); \
}

#endif

/*
/ v2, 16 instructions, 10 TL equivalent instructions
#define SBOX( a, b, c, d ) \
{ \
  __m256i t = mm256_xorand( d, a, c ); \
  c = mm256_xor3( t, b, c ); \
  b = mm256_xoror( b, d, a); \
  a = _mm256_xor_si256( a, c ); \
  d = mm256_xoror( t, b, a ); \
  t = mm256_xorand( a, t, b ); \
  a = c; \
  c = mm256_xor3( b, d, t ); \
  b = d; \
  d = mm256_not( t ); \
}
*/

#define L( a, b, c, d ) \
do { \
   a = mm256_rol_32( a, 13 ); \
   c = mm256_rol_32( c,  3 ); \
   b = mm256_xor3( a, b, c ); \
   d = mm256_xor3( d, c, _mm256_slli_epi32( a, 3 ) ); \
   b = mm256_rol_32( b, 1 ); \
   d = mm256_rol_32( d, 7 ); \
   a = mm256_xor3( a, b, d ); \
   c = mm256_xor3( c, d, _mm256_slli_epi32( b, 7 ) ); \
   a = mm256_rol_32( a,  5 ); \
   c = mm256_rol_32( c, 22 ); \
} while (0)

/*
// original, 18 instructions
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
  a = c; \
  c = _mm256_xor_si256( b, d ); \
  c = _mm256_xor_si256( c, t ); \
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
*/

#define DECL_STATE_BIG \
   __m256i c0, c1, c2, c3, c4, c5, c6, c7; \

#define READ_STATE_BIG(sc) \
do { \
   c0 = sc->h[0]; \
   c1 = sc->h[1]; \
   c2 = sc->h[2]; \
   c3 = sc->h[3]; \
   c4 = sc->h[4]; \
   c5 = sc->h[5]; \
   c6 = sc->h[6]; \
   c7 = sc->h[7]; \
} while (0)

#define WRITE_STATE_BIG(sc) \
do { \
   sc->h[0] = c0; \
   sc->h[1] = c1; \
   sc->h[2] = c2; \
   sc->h[3] = c3; \
   sc->h[4] = c4; \
   sc->h[5] = c5; \
   sc->h[6] = c6; \
   sc->h[7] = c7; \
} while (0)

#define ROUND_BIG( alpha ) \
do { \
   __m256i t0, t1, t2, t3, t4, t5; \
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
  s4 = mm256_swap64_32( s4 ); \
  s5 = mm256_swap64_32( s5 ); \
  sD = mm256_swap64_32( sD ); \
  sE = mm256_swap64_32( sE ); \
  t0 = _mm256_blend_epi32( s4, s5, 0xaa ); \
  t1 = _mm256_blend_epi32( sD, sE, 0xaa ); \
  L( s0, t0, s9, t1 ); \
\
  s6 = mm256_swap64_32( s6 ); \
  sF = mm256_swap64_32( sF ); \
  t2 = _mm256_blend_epi32( s5, s6, 0xaa ); \
  t3 = _mm256_blend_epi32( sE, sF, 0xaa ); \
  L( s1, t2, sA, t3 ); \
  s5 = _mm256_blend_epi32( t0, t2, 0x55 ); \
  sE = _mm256_blend_epi32( t1, t3, 0x55 ); \
\
  s7 = mm256_swap64_32( s7 ); \
  sC = mm256_swap64_32( sC ); \
  t4 = _mm256_blend_epi32( s6, s7, 0xaa ); \
  t5 = _mm256_blend_epi32( sF, sC, 0xaa ); \
  L( s2, t4, sB, t5 ); \
  s6 = _mm256_blend_epi32( t2, t4, 0x55 ); \
  sF = _mm256_blend_epi32( t3, t5, 0x55 ); \
  s6 = mm256_swap64_32( s6 ); \
  sF = mm256_swap64_32( sF ); \
\
  t2 = _mm256_blend_epi32( s7, s4, 0xaa ); \
  t3 = _mm256_blend_epi32( sC, sD, 0xaa ); \
  L( s3, t2, s8, t3 ); \
  s7 = _mm256_blend_epi32( t4, t2, 0x55 ); \
  s4 = _mm256_blend_epi32( t0, t2, 0xaa ); \
  sC = _mm256_blend_epi32( t5, t3, 0x55 ); \
  sD = _mm256_blend_epi32( t1, t3, 0xaa ); \
  s7 = mm256_swap64_32( s7 ); \
  sC = mm256_swap64_32( sC ); \
\
  t0 = _mm256_blend_epi32( s0, mm256_swap64_32( s8 ), 0xaa ); \
  t1 = _mm256_blend_epi32( s1, s9, 0xaa ); \
  t2 = _mm256_blend_epi32( mm256_swap64_32( s2 ), sA, 0xaa ); \
  t3 = _mm256_blend_epi32( s3, sB, 0x55 ); \
  t3 = mm256_swap64_32( t3 ); \
  L( t0, t1, t2, t3 ); \
  t3 = mm256_swap64_32( t3 ); \
  s0 = _mm256_blend_epi32( s0, t0, 0x55 ); \
  s8 = _mm256_blend_epi32( s8, mm256_swap64_32( t0 ), 0x55 ); \
  s1 = _mm256_blend_epi32( s1, t1, 0x55 ); \
  s9 = _mm256_blend_epi32( s9, t1, 0xaa ); \
  s2 = _mm256_blend_epi32( s2, mm256_swap64_32( t2 ), 0xaa ); \
  sA = _mm256_blend_epi32( sA, t2, 0xaa ); \
  s3 = _mm256_blend_epi32( s3, t3, 0xaa ); \
  sB = _mm256_blend_epi32( sB, t3, 0x55 ); \
\
  t0 = _mm256_blend_epi32( s4, sC, 0xaa ); \
  t1 = _mm256_blend_epi32( s5, sD, 0xaa ); \
  t2 = _mm256_blend_epi32( s6, sE, 0xaa ); \
  t3 = _mm256_blend_epi32( s7, sF, 0xaa ); \
  L( t0, t1, t2, t3 ); \
  s4 = _mm256_blend_epi32( s4, t0, 0x55 ); \
  sC = _mm256_blend_epi32( sC, t0, 0xaa ); \
  s5 = _mm256_blend_epi32( s5, t1, 0x55 ); \
  sD = _mm256_blend_epi32( sD, t1, 0xaa ); \
  s6 = _mm256_blend_epi32( s6, t2, 0x55 ); \
  sE = _mm256_blend_epi32( sE, t2, 0xaa ); \
  s7 = _mm256_blend_epi32( s7, t3, 0x55 ); \
  sF = _mm256_blend_epi32( sF, t3, 0xaa ); \
  s4 = mm256_swap64_32( s4 ); \
  s5 = mm256_swap64_32( s5 ); \
  sD = mm256_swap64_32( sD ); \
  sE = mm256_swap64_32( sE ); \
} while (0)

#define P_BIG \
do { \
   __m256i alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_n )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v256_64( ( (uint64_t*)alpha_n )[i] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (1ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (2ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (3ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (4ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (5ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
} while (0)

#define PF_BIG \
do { \
   __m256i alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_f )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v256_64( ( (uint64_t*)alpha_f )[i] ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 1ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 2ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 3ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 4ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 5ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 6ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 7ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 8ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( ( 9ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (10ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
   alpha[0] = v256_64( (11ULL << 32) ^ A0 ); \
   ROUND_BIG( alpha ); \
} while (0)

#define T_BIG \
do { /* order is important */ \
   c7 = sc->h[ 7 ] = _mm256_xor_si256( sc->h[ 7 ], sB ); \
   c6 = sc->h[ 6 ] = _mm256_xor_si256( sc->h[ 6 ], sA ); \
   c5 = sc->h[ 5 ] = _mm256_xor_si256( sc->h[ 5 ], s9 ); \
   c4 = sc->h[ 4 ] = _mm256_xor_si256( sc->h[ 4 ], s8 ); \
   c3 = sc->h[ 3 ] = _mm256_xor_si256( sc->h[ 3 ], s3 ); \
   c2 = sc->h[ 2 ] = _mm256_xor_si256( sc->h[ 2 ], s2 ); \
   c1 = sc->h[ 1 ] = _mm256_xor_si256( sc->h[ 1 ], s1 ); \
   c0 = sc->h[ 0 ] = _mm256_xor_si256( sc->h[ 0 ], s0 ); \
} while (0)


// Hamsi-512 8x32

// Experimental untested


#define DECL_STATE_8X32 \
   __m256i C0, C1, C2, C3, C4, C5, C6, C7, C8, C9, CA, CB, CC, CD, CE, CF; \

#define READ_STATE_8X32(sc) \
   C0 = sc->h[ 0]; \
   C1 = sc->h[ 1]; \
   C2 = sc->h[ 2]; \
   C3 = sc->h[ 3]; \
   C4 = sc->h[ 4]; \
   C5 = sc->h[ 5]; \
   C6 = sc->h[ 6]; \
   C7 = sc->h[ 7]; \
   C8 = sc->h[ 8]; \
   C9 = sc->h[ 9]; \
   CA = sc->h[10]; \
   CB = sc->h[11]; \
   CC = sc->h[12]; \
   CD = sc->h[13]; \
   CE = sc->h[14]; \
   CF = sc->h[15];

#define WRITE_STATE_8X32(sc) \
   sc->h[ 0] = C0; \
   sc->h[ 1] = C1; \
   sc->h[ 2] = C2; \
   sc->h[ 3] = C3; \
   sc->h[ 4] = C4; \
   sc->h[ 5] = C5; \
   sc->h[ 6] = C6; \
   sc->h[ 7] = C7; \
   sc->h[ 8] = C8; \
   sc->h[ 9] = C9; \
   sc->h[10] = CA; \
   sc->h[11] = CB; \
   sc->h[12] = CC; \
   sc->h[13] = CD; \
   sc->h[14] = CE; \
   sc->h[15] = CF;

#if defined(__AVX512VL__)

#define INPUT_8X32 \
{ \
  const __m256i zero = _mm256_setzero_si256(); \
  const uint32_t *tp = (const uint32_t*)T512; \
  M0 = M1 = M2 = M3 = M4 = M5 = M6 = M7 = \
  M8 = M9 = MA = MB = MC = MD = ME = MF = zero; \
  __m256i db = _mm256_ror_epi32( buf[0], 1 ); \
  for ( int u = 0; u < 32; u++ ) \
  { \
     __mmask8 dm = _mm256_cmplt_epi32_mask( db, zero ); \
     M0 = _mm256_mask_xor_epi32( M0, dm, M0, v256_32( tp[ 0] ) ); \
     M1 = _mm256_mask_xor_epi32( M1, dm, M1, v256_32( tp[ 1] ) ); \
     M2 = _mm256_mask_xor_epi32( M2, dm, M2, v256_32( tp[ 2] ) ); \
     M3 = _mm256_mask_xor_epi32( M3, dm, M3, v256_32( tp[ 3] ) ); \
     M4 = _mm256_mask_xor_epi32( M4, dm, M4, v256_32( tp[ 4] ) ); \
     M5 = _mm256_mask_xor_epi32( M5, dm, M5, v256_32( tp[ 5] ) ); \
     M6 = _mm256_mask_xor_epi32( M6, dm, M6, v256_32( tp[ 6] ) ); \
     M7 = _mm256_mask_xor_epi32( M7, dm, M7, v256_32( tp[ 7] ) ); \
     M8 = _mm256_mask_xor_epi32( M8, dm, M8, v256_32( tp[ 8] ) ); \
     M9 = _mm256_mask_xor_epi32( M9, dm, M9, v256_32( tp[ 9] ) ); \
     MA = _mm256_mask_xor_epi32( MA, dm, MA, v256_32( tp[10] ) ); \
     MB = _mm256_mask_xor_epi32( MB, dm, MB, v256_32( tp[11] ) ); \
     MC = _mm256_mask_xor_epi32( MC, dm, MC, v256_32( tp[12] ) ); \
     MD = _mm256_mask_xor_epi32( MD, dm, MD, v256_32( tp[13] ) ); \
     ME = _mm256_mask_xor_epi32( ME, dm, ME, v256_32( tp[14] ) ); \
     MF = _mm256_mask_xor_epi32( MF, dm, MF, v256_32( tp[15] ) ); \
     db = _mm256_ror_epi32( db, 1 ); \
     tp += 16; \
  } \
  db = _mm256_ror_epi32( buf[1], 1 ); \
  for ( int u = 0; u < 32; u++ ) \
  { \
     __mmask8 dm = _mm256_cmplt_epi32_mask( db, zero ); \
     M0 = _mm256_mask_xor_epi32( M0, dm, M0, v256_32( tp[ 0] ) ); \
     M1 = _mm256_mask_xor_epi32( M1, dm, M1, v256_32( tp[ 1] ) ); \
     M2 = _mm256_mask_xor_epi32( M2, dm, M2, v256_32( tp[ 2] ) ); \
     M3 = _mm256_mask_xor_epi32( M3, dm, M3, v256_32( tp[ 3] ) ); \
     M4 = _mm256_mask_xor_epi32( M4, dm, M4, v256_32( tp[ 4] ) ); \
     M5 = _mm256_mask_xor_epi32( M5, dm, M5, v256_32( tp[ 5] ) ); \
     M6 = _mm256_mask_xor_epi32( M6, dm, M6, v256_32( tp[ 6] ) ); \
     M7 = _mm256_mask_xor_epi32( M7, dm, M7, v256_32( tp[ 7] ) ); \
     M8 = _mm256_mask_xor_epi32( M8, dm, M8, v256_32( tp[ 8] ) ); \
     M9 = _mm256_mask_xor_epi32( M9, dm, M9, v256_32( tp[ 9] ) ); \
     MA = _mm256_mask_xor_epi32( MA, dm, MA, v256_32( tp[10] ) ); \
     MB = _mm256_mask_xor_epi32( MB, dm, MB, v256_32( tp[11] ) ); \
     MC = _mm256_mask_xor_epi32( MC, dm, MC, v256_32( tp[12] ) ); \
     MD = _mm256_mask_xor_epi32( MD, dm, MD, v256_32( tp[13] ) ); \
     ME = _mm256_mask_xor_epi32( ME, dm, ME, v256_32( tp[14] ) ); \
     MF = _mm256_mask_xor_epi32( MF, dm, MF, v256_32( tp[15] ) ); \
     db = _mm256_ror_epi32( db, 1 ); \
     tp += 16; \
  } \
}

#else

#define INPUT_8X32 \
{ \
  const __m256i zero = _mm256_setzero_si256(); \
  const uint32_t *tp = (const uint32_t*)T512; \
  M0 = M1 = M2 = M3 = M4 = M5 = M6 = M7 = \
  M8 = M9 = MA = MB = MC = MD = ME = MF = zero; \
  __m256i db = buf[0]; \
  for ( int u = 31; u >= 0; u-- ) \
  { \
     __m256i dm = _mm256_cmpgt_epi32( zero, _mm256_slli_epi32( db, u ) ); \
     M0 = _mm256_xor_si256( M0, _mm256_and_si256( dm, v256_32( tp[ 0] ) ) ); \
     M1 = _mm256_xor_si256( M1, _mm256_and_si256( dm, v256_32( tp[ 1] ) ) ); \
     M2 = _mm256_xor_si256( M2, _mm256_and_si256( dm, v256_32( tp[ 2] ) ) ); \
     M3 = _mm256_xor_si256( M3, _mm256_and_si256( dm, v256_32( tp[ 3] ) ) ); \
     M4 = _mm256_xor_si256( M4, _mm256_and_si256( dm, v256_32( tp[ 4] ) ) ); \
     M5 = _mm256_xor_si256( M5, _mm256_and_si256( dm, v256_32( tp[ 5] ) ) ); \
     M6 = _mm256_xor_si256( M6, _mm256_and_si256( dm, v256_32( tp[ 6] ) ) ); \
     M7 = _mm256_xor_si256( M7, _mm256_and_si256( dm, v256_32( tp[ 7] ) ) ); \
     M8 = _mm256_xor_si256( M8, _mm256_and_si256( dm, v256_32( tp[ 8] ) ) ); \
     M9 = _mm256_xor_si256( M9, _mm256_and_si256( dm, v256_32( tp[ 9] ) ) ); \
     MA = _mm256_xor_si256( MA, _mm256_and_si256( dm, v256_32( tp[10] ) ) ); \
     MB = _mm256_xor_si256( MB, _mm256_and_si256( dm, v256_32( tp[11] ) ) ); \
     MC = _mm256_xor_si256( MC, _mm256_and_si256( dm, v256_32( tp[12] ) ) ); \
     MD = _mm256_xor_si256( MD, _mm256_and_si256( dm, v256_32( tp[13] ) ) ); \
     ME = _mm256_xor_si256( ME, _mm256_and_si256( dm, v256_32( tp[14] ) ) ); \
     MF = _mm256_xor_si256( MF, _mm256_and_si256( dm, v256_32( tp[15] ) ) ); \
     tp += 16; \
  } \
  db = buf[1]; \
  for ( int u = 31; u >= 0; u-- ) \
  { \
     __m256i dm = _mm256_cmpgt_epi32( zero, _mm256_slli_epi32( db, u ) ); \
     M0 = _mm256_xor_si256( M0, _mm256_and_si256( dm, v256_32( tp[ 0] ) ) ); \
     M1 = _mm256_xor_si256( M1, _mm256_and_si256( dm, v256_32( tp[ 1] ) ) ); \
     M2 = _mm256_xor_si256( M2, _mm256_and_si256( dm, v256_32( tp[ 2] ) ) ); \
     M3 = _mm256_xor_si256( M3, _mm256_and_si256( dm, v256_32( tp[ 3] ) ) ); \
     M4 = _mm256_xor_si256( M4, _mm256_and_si256( dm, v256_32( tp[ 4] ) ) ); \
     M5 = _mm256_xor_si256( M5, _mm256_and_si256( dm, v256_32( tp[ 5] ) ) ); \
     M6 = _mm256_xor_si256( M6, _mm256_and_si256( dm, v256_32( tp[ 6] ) ) ); \
     M7 = _mm256_xor_si256( M7, _mm256_and_si256( dm, v256_32( tp[ 7] ) ) ); \
     M8 = _mm256_xor_si256( M8, _mm256_and_si256( dm, v256_32( tp[ 8] ) ) ); \
     M9 = _mm256_xor_si256( M9, _mm256_and_si256( dm, v256_32( tp[ 9] ) ) ); \
     MA = _mm256_xor_si256( MA, _mm256_and_si256( dm, v256_32( tp[10] ) ) ); \
     MB = _mm256_xor_si256( MB, _mm256_and_si256( dm, v256_32( tp[11] ) ) ); \
     MC = _mm256_xor_si256( MC, _mm256_and_si256( dm, v256_32( tp[12] ) ) ); \
     MD = _mm256_xor_si256( MD, _mm256_and_si256( dm, v256_32( tp[13] ) ) ); \
     ME = _mm256_xor_si256( ME, _mm256_and_si256( dm, v256_32( tp[14] ) ) ); \
     MF = _mm256_xor_si256( MF, _mm256_and_si256( dm, v256_32( tp[15] ) ) ); \
     tp += 16; \
  } \
}

#endif

#define SBOX_8X32    SBOX
#define L_8X32       L

#define ROUND_8X32( rc, alpha ) \
{ \
   S00 = _mm256_xor_si256( S00, v256_32( alpha[ 0] ) ); \
   S01 = _mm256_xor_si256( S01, v256_32( (alpha[ 1]) ^ (rc) ) ); \
   S02 = _mm256_xor_si256( S02, v256_32( alpha[ 2] ) ); \
   S03 = _mm256_xor_si256( S03, v256_32( alpha[ 3] ) ); \
   S04 = _mm256_xor_si256( S04, v256_32( alpha[ 4] ) ); \
   S05 = _mm256_xor_si256( S05, v256_32( alpha[ 5] ) ); \
   S06 = _mm256_xor_si256( S06, v256_32( alpha[ 6] ) ); \
   S07 = _mm256_xor_si256( S07, v256_32( alpha[ 7] ) ); \
   S08 = _mm256_xor_si256( S08, v256_32( alpha[ 8] ) ); \
   S09 = _mm256_xor_si256( S09, v256_32( alpha[ 9] ) ); \
   S0A = _mm256_xor_si256( S0A, v256_32( alpha[10] ) ); \
   S0B = _mm256_xor_si256( S0B, v256_32( alpha[11] ) ); \
   S0C = _mm256_xor_si256( S0C, v256_32( alpha[12] ) ); \
   S0D = _mm256_xor_si256( S0D, v256_32( alpha[13] ) ); \
   S0E = _mm256_xor_si256( S0E, v256_32( alpha[14] ) ); \
   S0F = _mm256_xor_si256( S0F, v256_32( alpha[15] ) ); \
   S10 = _mm256_xor_si256( S10, v256_32( alpha[16] ) ); \
   S11 = _mm256_xor_si256( S11, v256_32( alpha[17] ) ); \
   S12 = _mm256_xor_si256( S12, v256_32( alpha[18] ) ); \
   S13 = _mm256_xor_si256( S13, v256_32( alpha[19] ) ); \
   S14 = _mm256_xor_si256( S14, v256_32( alpha[20] ) ); \
   S15 = _mm256_xor_si256( S15, v256_32( alpha[21] ) ); \
   S16 = _mm256_xor_si256( S16, v256_32( alpha[22] ) ); \
   S17 = _mm256_xor_si256( S17, v256_32( alpha[23] ) ); \
   S18 = _mm256_xor_si256( S18, v256_32( alpha[24] ) ); \
   S19 = _mm256_xor_si256( S19, v256_32( alpha[25] ) ); \
   S1A = _mm256_xor_si256( S1A, v256_32( alpha[26] ) ); \
   S1B = _mm256_xor_si256( S1B, v256_32( alpha[27] ) ); \
   S1C = _mm256_xor_si256( S1C, v256_32( alpha[28] ) ); \
   S1D = _mm256_xor_si256( S1D, v256_32( alpha[29] ) ); \
   S1E = _mm256_xor_si256( S1E, v256_32( alpha[30] ) ); \
   S1F = _mm256_xor_si256( S1F, v256_32( alpha[31] ) ); \
   SBOX_8X32( S00, S08, S10, S18 ); \
   SBOX_8X32( S01, S09, S11, S19 ); \
   SBOX_8X32( S02, S0A, S12, S1A ); \
   SBOX_8X32( S03, S0B, S13, S1B ); \
   SBOX_8X32( S04, S0C, S14, S1C ); \
   SBOX_8X32( S05, S0D, S15, S1D ); \
   SBOX_8X32( S06, S0E, S16, S1E ); \
   SBOX_8X32( S07, S0F, S17, S1F ); \
   L_8X32( S00, S09, S12, S1B ); \
   L_8X32( S01, S0A, S13, S1C ); \
   L_8X32( S02, S0B, S14, S1D ); \
   L_8X32( S03, S0C, S15, S1E ); \
   L_8X32( S04, S0D, S16, S1F ); \
   L_8X32( S05, S0E, S17, S18 ); \
   L_8X32( S06, S0F, S10, S19 ); \
   L_8X32( S07, S08, S11, S1A ); \
   L_8X32( S00, S02, S05, S07 ); \
   L_8X32( S10, S13, S15, S16 ); \
   L_8X32( S09, S0B, S0C, S0E ); \
   L_8X32( S19, S1A, S1C, S1F ); \
}

#define P_8X32 \
      ROUND_8X32( 0, alpha_n ); \
      ROUND_8X32( 1, alpha_n ); \
      ROUND_8X32( 2, alpha_n ); \
      ROUND_8X32( 3, alpha_n ); \
      ROUND_8X32( 4, alpha_n ); \
      ROUND_8X32( 5, alpha_n );

#define PF_8X32 \
      ROUND_8X32(  0, alpha_f ); \
      ROUND_8X32(  1, alpha_f ); \
      ROUND_8X32(  2, alpha_f ); \
      ROUND_8X32(  3, alpha_f ); \
      ROUND_8X32(  4, alpha_f ); \
      ROUND_8X32(  5, alpha_f ); \
      ROUND_8X32(  6, alpha_f ); \
      ROUND_8X32(  7, alpha_f ); \
      ROUND_8X32(  8, alpha_f ); \
      ROUND_8X32(  9, alpha_f ); \
      ROUND_8X32( 10, alpha_f ); \
      ROUND_8X32( 11, alpha_f );

#define T_8X32 \
      /* order is important */ \
      CF = sc->h[15] = _mm256_xor_si256( sc->h[15], S17 ); \
      CE = sc->h[14] = _mm256_xor_si256( sc->h[14], S16 ); \
      CD = sc->h[13] = _mm256_xor_si256( sc->h[13], S15 ); \
      CC = sc->h[12] = _mm256_xor_si256( sc->h[12], S14 ); \
      CB = sc->h[11] = _mm256_xor_si256( sc->h[11], S13 ); \
      CA = sc->h[10] = _mm256_xor_si256( sc->h[10], S12 ); \
      C9 = sc->h[ 9] = _mm256_xor_si256( sc->h[ 9], S11 ); \
      C8 = sc->h[ 8] = _mm256_xor_si256( sc->h[ 8], S10 ); \
      C7 = sc->h[ 7] = _mm256_xor_si256( sc->h[ 7], S07 ); \
      C6 = sc->h[ 6] = _mm256_xor_si256( sc->h[ 6], S06 ); \
      C5 = sc->h[ 5] = _mm256_xor_si256( sc->h[ 5], S05 ); \
      C4 = sc->h[ 4] = _mm256_xor_si256( sc->h[ 4], S04 ); \
      C3 = sc->h[ 3] = _mm256_xor_si256( sc->h[ 3], S03 ); \
      C2 = sc->h[ 2] = _mm256_xor_si256( sc->h[ 2], S02 ); \
      C1 = sc->h[ 1] = _mm256_xor_si256( sc->h[ 1], S01 ); \
      C0 = sc->h[ 0] = _mm256_xor_si256( sc->h[ 0], S00 );


void hamsi_8x32_big( hamsi_8x32_big_context *sc, __m256i *buf, size_t num )
{
   DECL_STATE_8X32
   uint32_t tmp;

   tmp = (uint32_t)num << 6;
   sc->count_low = sc->count_low + tmp;
   sc->count_high += (uint32_t)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_8X32( sc );
   while ( num-- > 0 )
   {
      __m256i M0, M1, M2, M3, M4, M5, M6, M7;
      __m256i M8, M9, MA, MB, MC, MD, ME, MF;
      INPUT_8X32;
      P_8X32;
      T_8X32;
      buf += 2;
   }
   WRITE_STATE_8X32( sc );
}

void hamsi_8x32_big_final( hamsi_8x32_big_context *sc, __m256i *buf )
{
   __m256i M0, M1, M2, M3, M4, M5, M6, M7;
   __m256i M8, M9, MA, MB, MC, MD, ME, MF;

   DECL_STATE_8X32
   READ_STATE_8X32( sc );
   INPUT_8X32;
   PF_8X32;
   T_8X32;
   WRITE_STATE_8X32( sc );
}

void hamsi512_8x32_init( hamsi512_8x32_context *sc )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;

   sc->h[ 0] = v256_32( HAMSI_IV512[ 0] );
   sc->h[ 1] = v256_32( HAMSI_IV512[ 1] );
   sc->h[ 2] = v256_32( HAMSI_IV512[ 2] );
   sc->h[ 3] = v256_32( HAMSI_IV512[ 3] );
   sc->h[ 4] = v256_32( HAMSI_IV512[ 4] );
   sc->h[ 5] = v256_32( HAMSI_IV512[ 5] );
   sc->h[ 6] = v256_32( HAMSI_IV512[ 6] );
   sc->h[ 7] = v256_32( HAMSI_IV512[ 7] );
   sc->h[ 8] = v256_32( HAMSI_IV512[ 8] );
   sc->h[ 9] = v256_32( HAMSI_IV512[ 9] );
   sc->h[10] = v256_32( HAMSI_IV512[10] );
   sc->h[11] = v256_32( HAMSI_IV512[11] );
   sc->h[12] = v256_32( HAMSI_IV512[12] );
   sc->h[13] = v256_32( HAMSI_IV512[13] );
   sc->h[14] = v256_32( HAMSI_IV512[14] );
   sc->h[15] = v256_32( HAMSI_IV512[15] );
}

void hamsi512_8x32_update( hamsi512_8x32_context *sc, const void *data,
      size_t len )
{
   __m256i *vdata = (__m256i*)data;
   
   hamsi_8x32_big( sc, vdata, len >> 3 );
   vdata += ( (len & ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_256( sc->buf, vdata, len>> 3 );
   sc->partial_len = len;
}

void hamsi512_8x32_close( hamsi512_8x32_context *sc, void *dst )
{
   __m256i pad[2];
   uint32_t ch, cl;

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v256_32( ch );
   pad[1] = v256_32( cl );
   sc->buf[0] = v256_32( 0x80 );
   sc->buf[1] = _mm256_setzero_si256();
   hamsi_8x32_big( sc, sc->buf, 1 );
   hamsi_8x32_big_final( sc, pad );

   mm256_block_bswap_32( (__m256i*)dst, sc->h );
   mm256_block_bswap_32( (__m256i*)dst + 8, sc->h + 8 );
}

void hamsi512_8x32_full( hamsi512_8x32_context *sc, void * dst, 
                         const void *data, size_t len )
{
   // init
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;

   sc->h[ 0] = v256_32( HAMSI_IV512[ 0] );
   sc->h[ 1] = v256_32( HAMSI_IV512[ 1] );
   sc->h[ 2] = v256_32( HAMSI_IV512[ 2] );
   sc->h[ 3] = v256_32( HAMSI_IV512[ 3] );
   sc->h[ 4] = v256_32( HAMSI_IV512[ 4] );
   sc->h[ 5] = v256_32( HAMSI_IV512[ 5] );
   sc->h[ 6] = v256_32( HAMSI_IV512[ 6] );
   sc->h[ 7] = v256_32( HAMSI_IV512[ 7] );
   sc->h[ 8] = v256_32( HAMSI_IV512[ 8] );
   sc->h[ 9] = v256_32( HAMSI_IV512[ 9] );
   sc->h[10] = v256_32( HAMSI_IV512[10] );
   sc->h[11] = v256_32( HAMSI_IV512[11] );
   sc->h[12] = v256_32( HAMSI_IV512[12] );
   sc->h[13] = v256_32( HAMSI_IV512[13] );
   sc->h[14] = v256_32( HAMSI_IV512[14] );
   sc->h[15] = v256_32( HAMSI_IV512[15] );

   //update
   __m256i *vdata = (__m256i*)data;

   hamsi_8x32_big( sc, vdata, len >> 3 );
   vdata += ( (len & ~(size_t)7) >> 3 );
   len &= (size_t)7;
   memcpy_256( sc->buf, vdata, len>> 3 );
   sc->partial_len = len;

   // close
   __m256i pad[2];
   uint32_t ch, cl;

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v256_32( ch );
   pad[1] = v256_32( cl );
   sc->buf[0] = v256_32( 0x80 );
   sc->buf[1] = _mm256_setzero_si256();
   hamsi_8x32_big( sc, sc->buf, 1 );
   hamsi_8x32_big_final( sc, pad );

   mm256_block_bswap_32( (__m256i*)dst, sc->h );
   mm256_block_bswap_32( (__m256i*)dst + 8, sc->h + 8 );
}


////////////

void hamsi_big( hamsi_4way_big_context *sc, __m256i *buf, size_t num )
{
   DECL_STATE_BIG
   uint32_t tmp;

   tmp = (uint32_t)num << 6;
   sc->count_low = sc->count_low + tmp;
   sc->count_high += (uint32_t)( (num >> 13) >> 13 );
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
   uint64_t *iv = (uint64_t*)HAMSI_IV512;
   sc->h[0] = v256_64( iv[0] );
   sc->h[1] = v256_64( iv[1] );
   sc->h[2] = v256_64( iv[2] );
   sc->h[3] = v256_64( iv[3] );
   sc->h[4] = v256_64( iv[4] );
   sc->h[5] = v256_64( iv[5] );
   sc->h[6] = v256_64( iv[6] );
   sc->h[7] = v256_64( iv[7] );
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

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad[0] = v256_64( ((uint64_t)cl << 32 ) | (uint64_t)ch );
   sc->buf[0] = v256_64( 0x80 );
   hamsi_big( sc, sc->buf, 1 );
   hamsi_big_final( sc, pad );

   mm256_block_bswap_32( (__m256i*)dst, sc->h );
}

#endif

#if defined(__SSE4_2__) || defined(__ARM_NEON)

#define DECL_STATE_2x64 \
   v128u64_t c0, c1, c2, c3, c4, c5, c6, c7; \

#define READ_STATE_2x64(sc) \
   c0 = sc->h[0]; \
   c1 = sc->h[1]; \
   c2 = sc->h[2]; \
   c3 = sc->h[3]; \
   c4 = sc->h[4]; \
   c5 = sc->h[5]; \
   c6 = sc->h[6]; \
   c7 = sc->h[7];

#define WRITE_STATE_2x64(sc) \
   sc->h[0] = c0; \
   sc->h[1] = c1; \
   sc->h[2] = c2; \
   sc->h[3] = c3; \
   sc->h[4] = c4; \
   sc->h[5] = c5; \
   sc->h[6] = c6; \
   sc->h[7] = c7;

#define INPUT_2x64 \
{ \
  v128u64_t db = *buf; \
  const v128u64_t zero = v128_64( 0ull ); \
  const uint64_t *tp = (const uint64_t*)T512;  \
  m0 = m1 = m2 = m3 = m4 = m5 = m6 = m7 = zero; \
  for ( int i = 63; i >= 0; i-- ) \
  { \
     v128u64_t dm = v128_cmpgt64( zero, v128_sl64( db, i ) ); \
     m0 = v128_xor( m0, v128_and( dm, v128_64( tp[0] ) ) ); \
     m1 = v128_xor( m1, v128_and( dm, v128_64( tp[1] ) ) ); \
     m2 = v128_xor( m2, v128_and( dm, v128_64( tp[2] ) ) ); \
     m3 = v128_xor( m3, v128_and( dm, v128_64( tp[3] ) ) ); \
     m4 = v128_xor( m4, v128_and( dm, v128_64( tp[4] ) ) ); \
     m5 = v128_xor( m5, v128_and( dm, v128_64( tp[5] ) ) ); \
     m6 = v128_xor( m6, v128_and( dm, v128_64( tp[6] ) ) ); \
     m7 = v128_xor( m7, v128_and( dm, v128_64( tp[7] ) ) ); \
     tp += 8; \
  } \
}

// v3 no ternary logic, 15 instructions, 9 TL equivalent instructions
#define SBOX_2x64( a, b, c, d ) \
{ \
  v128u64_t tb, td; \
  td = v128_xorand( d, a, c ); \
  tb = v128_xoror( b, d, a ); \
  c = v128_xor3( c, td, b ); \
  a = v128_xor( a, c ); \
  b = v128_xoror( td, tb, a ); \
  td = v128_xorand( a, td, tb ); \
  a = c; \
  c = v128_xor3( tb, b, td ); \
  d = v128_not( td ); \
}

#define L_2x64( a, b, c, d ) \
{ \
   a = v128_rol32( a, 13 ); \
   c = v128_rol32( c,  3 ); \
   b = v128_xor3( a, b, c ); \
   d = v128_xor3( d, c, v128_sl32( a, 3 ) ); \
   b = v128_rol32( b, 1 ); \
   d = v128_rol32( d, 7 ); \
   a = v128_xor3( a, b, d ); \
   c = v128_xor3( c, d, v128_sl32( b, 7 ) ); \
   a = v128_rol32( a,  5 ); \
   c = v128_rol32( c, 22 ); \
}

#define ROUND_2x64( alpha ) \
{ \
   v128u64_t t0, t1, t2, t3, t4, t5; \
   const v128_t mask = v128_64( 0x00000000ffffffff ); \
   s0 = v128_xor( s0, alpha[ 0] ); \
   s1 = v128_xor( s1, alpha[ 1] ); \
   s2 = v128_xor( s2, alpha[ 2] ); \
   s3 = v128_xor( s3, alpha[ 3] ); \
   s4 = v128_xor( s4, alpha[ 4] ); \
   s5 = v128_xor( s5, alpha[ 5] ); \
   s6 = v128_xor( s6, alpha[ 6] ); \
   s7 = v128_xor( s7, alpha[ 7] ); \
   s8 = v128_xor( s8, alpha[ 8] ); \
   s9 = v128_xor( s9, alpha[ 9] ); \
   sA = v128_xor( sA, alpha[10] ); \
   sB = v128_xor( sB, alpha[11] ); \
   sC = v128_xor( sC, alpha[12] ); \
   sD = v128_xor( sD, alpha[13] ); \
   sE = v128_xor( sE, alpha[14] ); \
   sF = v128_xor( sF, alpha[15] ); \
\
  SBOX_2x64( s0, s4, s8, sC ); \
  SBOX_2x64( s1, s5, s9, sD ); \
  SBOX_2x64( s2, s6, sA, sE ); \
  SBOX_2x64( s3, s7, sB, sF ); \
\
  s4 = v128_swap64_32( s4 ); \
  s5 = v128_swap64_32( s5 ); \
  sD = v128_swap64_32( sD ); \
  sE = v128_swap64_32( sE ); \
  t0 = v128_blendv( s5, s4, mask ); \
  t1 = v128_blendv( sE, sD, mask ); \
  L_2x64( s0, t0, s9, t1 ); \
\
  s6 = v128_swap64_32( s6 ); \
  sF = v128_swap64_32( sF ); \
  t2 = v128_blendv( s6, s5, mask ); \
  t3 = v128_blendv( sF, sE, mask ); \
  L_2x64( s1, t2, sA, t3 ); \
  s5 = v128_blendv( t0, t2, mask ); \
  sE = v128_blendv( t1, t3, mask ); \
\
  s7 = v128_swap64_32( s7 ); \
  sC = v128_swap64_32( sC ); \
  t4 = v128_blendv( s7, s6, mask ); \
  t5 = v128_blendv( sC, sF, mask ); \
  L_2x64( s2, t4, sB, t5 ); \
  s6 = v128_blendv( t2, t4, mask ); \
  sF = v128_blendv( t3, t5, mask ); \
  s6 = v128_swap64_32( s6 ); \
  sF = v128_swap64_32( sF ); \
\
  t2 = v128_blendv( s4, s7, mask ); \
  t3 = v128_blendv( sD, sC, mask ); \
  L_2x64( s3, t2, s8, t3 ); \
  s7 = v128_blendv( t4, t2, mask ); \
  s4 = v128_blendv( t2, t0, mask ); \
  sC = v128_blendv( t5, t3, mask ); \
  sD = v128_blendv( t3, t1, mask ); \
  s7 = v128_swap64_32( s7 ); \
  sC = v128_swap64_32( sC ); \
\
  t0 = v128_blendv( v128_swap64_32( s8 ), s0, mask ); \
  t1 = v128_blendv( s9, s1, mask ); \
  t2 = v128_blendv( sA, v128_swap64_32( s2 ), mask ); \
  t3 = v128_blendv( s3, sB, mask ); \
  t3 = v128_swap64_32( t3 ); \
  L_2x64( t0, t1, t2, t3 ); \
  t3 = v128_swap64_32( t3 ); \
  s0 = v128_blendv( s0, t0, mask ); \
  s8 = v128_blendv( s8, v128_swap64_32( t0 ), mask ); \
  s1 = v128_blendv( s1, t1, mask ); \
  s9 = v128_blendv( t1, s9, mask ); \
  s2 = v128_blendv( v128_swap64_32( t2 ), s2, mask ); \
  sA = v128_blendv( t2, sA, mask ); \
  s3 = v128_blendv( t3, s3, mask ); \
  sB = v128_blendv( sB, t3, mask ); \
\
  t0 = v128_blendv( sC, s4, mask ); \
  t1 = v128_blendv( sD, s5, mask ); \
  t2 = v128_blendv( sE, s6, mask ); \
  t3 = v128_blendv( sF, s7, mask ); \
  L_2x64( t0, t1, t2, t3 ); \
  s4 = v128_blendv( s4, t0, mask ); \
  sC = v128_blendv( t0, sC, mask ); \
  s5 = v128_blendv( s5, t1, mask ); \
  sD = v128_blendv( t1, sD, mask ); \
  s6 = v128_blendv( s6, t2, mask ); \
  sE = v128_blendv( t2, sE, mask ); \
  s7 = v128_blendv( s7, t3, mask ); \
  sF = v128_blendv( t3, sF, mask ); \
  s4 = v128_swap64_32( s4 ); \
  s5 = v128_swap64_32( s5 ); \
  sD = v128_swap64_32( sD ); \
  sE = v128_swap64_32( sE ); \
}

#define P_2x64 \
{ \
   v128u64_t alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_n )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v128_64( ( (uint64_t*)alpha_n )[i] ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (1ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (2ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (3ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (4ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (5ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
}

#define PF_2x64 \
{ \
   v128u64_t alpha[16]; \
   const uint64_t A0 = ( (uint64_t*)alpha_f )[0]; \
   for( int i = 0; i < 16; i++ ) \
      alpha[i] = v128_64( ( (uint64_t*)alpha_f )[i] ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 1ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 2ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 3ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 4ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 5ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 6ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 7ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 8ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( ( 9ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (10ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
   alpha[0] = v128_64( (11ULL << 32) ^ A0 ); \
   ROUND_2x64( alpha ); \
}

#define T_2x64 \
{ /* order is important */ \
   c7 = sc->h[ 7 ] = v128_xor( sc->h[ 7 ], sB ); \
   c6 = sc->h[ 6 ] = v128_xor( sc->h[ 6 ], sA ); \
   c5 = sc->h[ 5 ] = v128_xor( sc->h[ 5 ], s9 ); \
   c4 = sc->h[ 4 ] = v128_xor( sc->h[ 4 ], s8 ); \
   c3 = sc->h[ 3 ] = v128_xor( sc->h[ 3 ], s3 ); \
   c2 = sc->h[ 2 ] = v128_xor( sc->h[ 2 ], s2 ); \
   c1 = sc->h[ 1 ] = v128_xor( sc->h[ 1 ], s1 ); \
   c0 = sc->h[ 0 ] = v128_xor( sc->h[ 0 ], s0 ); \
}

void hamsi64_big( hamsi_2x64_context *sc, v128_t *buf, size_t num )
{
   DECL_STATE_2x64;
   uint32_t tmp;

   tmp = (uint32_t)num << 6;
   sc->count_low = sc->count_low + tmp;
   sc->count_high += (uint32_t)( (num >> 13) >> 13 );
   if ( sc->count_low < tmp )
      sc->count_high++;

   READ_STATE_2x64( sc );
   while ( num-- > 0 )
   {
      v128_t m0, m1, m2, m3, m4, m5, m6, m7;

      INPUT_2x64;
      P_2x64;
      T_2x64;
      buf++;
   }
   WRITE_STATE_2x64( sc );
}

void hamsi64_big_final( hamsi_2x64_context *sc, v128_t *buf )
{
   v128u64_t m0, m1, m2, m3, m4, m5, m6, m7;
   DECL_STATE_2x64;
   READ_STATE_2x64( sc );
   INPUT_2x64;
   PF_2x64;
   T_2x64;
   WRITE_STATE_2x64( sc );
}

void hamsi512_2x64_init( hamsi_2x64_context *sc )
{
   sc->partial_len = 0;
   sc->count_high = sc->count_low = 0;
   uint64_t * iv = (uint64_t*)HAMSI_IV512;
   sc->h[0] = v128_64( iv[0] );
   sc->h[1] = v128_64( iv[1] );
   sc->h[2] = v128_64( iv[2] );
   sc->h[3] = v128_64( iv[3] );
   sc->h[4] = v128_64( iv[4] );
   sc->h[5] = v128_64( iv[5] );
   sc->h[6] = v128_64( iv[6] );
   sc->h[7] = v128_64( iv[7] );
}

void hamsi512_2x64_update( hamsi_2x64_context *sc, const void *data,
      size_t len )
{
   v128_t *vdata = (v128_t*)data;

   hamsi64_big( sc, vdata, len>>3 );
   vdata += ( (len& ~(size_t)7) >> 3 );
   len &= (size_t)7;
   v128_memcpy( sc->buf, vdata, len>>3 );
   sc->partial_len = len;
}

void hamsi512_2x64_close( hamsi_2x64_context *sc, void *dst )
{
   v128u32_t pad;
   uint32_t ch, cl;

   ch = bswap_32( sc->count_high );
   cl = bswap_32( sc->count_low + ( sc->partial_len << 3 ) );
   pad = v128_64( ((uint64_t)cl << 32 ) | (uint64_t)ch );
   sc->buf[0] = v128_64( 0x80 );
   hamsi64_big( sc, sc->buf, 1 );
   hamsi64_big_final( sc, &pad );

   v128_block_bswap32( (v128_t*)dst, sc->h );
}

void hamsi512_2x64_ctx( hamsi512_2x64_context *sc, void *dst, const void *data, 
                        size_t len )
{
   hamsi512_2x64_init( sc );
   hamsi512_2x64_update( sc, data, len );
   hamsi512_2x64_close( sc, dst );
}

void hamsi512_2x64( void *dst, const void *data, size_t len )
{
   hamsi512_2x64_context sc;
   hamsi512_2x64_init( &sc );
   hamsi512_2x64_update( &sc, data, len );
   hamsi512_2x64_close( &sc, dst );
}   

#endif   // SSE4.2 or NEON
