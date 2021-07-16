/* $Id: haval.c 227 2010-06-16 17:28:38Z tp $ */
/*
 * HAVAL implementation.
 *
 * The HAVAL reference paper is of questionable clarity with regards to
 * some details such as endianness of bits within a byte, bytes within
 * a 32-bit word, or the actual ordering of words within a stream of
 * words. This implementation has been made compatible with the reference
 * implementation available on: http://labs.calyptix.com/haval.php
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
#include "haval-hash-4way.h"

// won't compile with sse4.2, not a problem, it's only used with AVX2 4 way.
//#if defined (__SSE4_2__)
#if defined(__AVX__)

#ifdef __cplusplus
extern "C"{
#endif

//#if SPH_SMALL_FOOTPRINT && !defined SPH_SMALL_FOOTPRINT_HAVAL
#define SPH_SMALL_FOOTPRINT_HAVAL   1
//#endif

#define F1(x6, x5, x4, x3, x2, x1, x0) \
   _mm_xor_si128( x0, \
       _mm_xor_si128( _mm_and_si128(_mm_xor_si128( x0, x4 ), x1 ), \
                      _mm_xor_si128( _mm_and_si128( x2, x5 ), \
                                     _mm_and_si128( x3, x6 ) ) ) ) \

#define F2(x6, x5, x4, x3, x2, x1, x0) \
   _mm_xor_si128( \
      _mm_and_si128( x2, \
         _mm_xor_si128( _mm_andnot_si128( x3, x1 ), \
                        _mm_xor_si128( _mm_and_si128( x4, x5 ), \
                                       _mm_xor_si128( x6, x0 ) ) ) ), \
         _mm_xor_si128( \
             _mm_and_si128( x4, _mm_xor_si128( x1, x5 ) ), \
             _mm_xor_si128( _mm_and_si128( x3, x5 ), x0 ) ) ) \

#define F3(x6, x5, x4, x3, x2, x1, x0) \
  _mm_xor_si128( \
    _mm_and_si128( x3, \
      _mm_xor_si128( _mm_and_si128( x1, x2 ), \
                     _mm_xor_si128( x6, x0 ) ) ), \
      _mm_xor_si128( _mm_xor_si128(_mm_and_si128( x1, x4 ), \
                                   _mm_and_si128( x2, x5 ) ), x0 ) )

#define F4(x6, x5, x4, x3, x2, x1, x0) \
  _mm_xor_si128( \
     _mm_xor_si128( \
        _mm_and_si128( x3, \
           _mm_xor_si128( _mm_xor_si128( _mm_and_si128( x1, x2 ), \
                                         _mm_or_si128( x4, x6 ) ), x5 ) ), \
        _mm_and_si128( x4, \
           _mm_xor_si128( _mm_xor_si128( _mm_and_si128( mm128_not(x2), x5 ), \
                          _mm_xor_si128( x1, x6 ) ), x0 ) ) ), \
     _mm_xor_si128( _mm_and_si128( x2, x6 ), x0 ) )


#define F5(x6, x5, x4, x3, x2, x1, x0) \
   _mm_xor_si128( \
       _mm_and_si128( x0, \
            mm128_not( _mm_xor_si128( \
                    _mm_and_si128( _mm_and_si128( x1, x2 ), x3 ), x5 ) ) ), \
      _mm_xor_si128( _mm_xor_si128( _mm_and_si128( x1, x4 ), \
                                    _mm_and_si128( x2, x5 ) ), \
                                    _mm_and_si128( x3, x6 ) ) )

/*
 * The macros below integrate the phi() permutations, depending on the
 * pass and the total number of passes.
 */

#define FP3_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x1, x0, x3, x5, x6, x2, x4)
#define FP3_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x4, x2, x1, x0, x5, x3, x6)
#define FP3_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x6, x1, x2, x3, x4, x5, x0)

#define FP4_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x2, x6, x1, x4, x5, x3, x0)
#define FP4_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x3, x5, x2, x0, x1, x6, x4)
#define FP4_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x1, x4, x3, x6, x0, x2, x5)
#define FP4_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x6, x4, x0, x5, x2, x1, x3)

#define FP5_1(x6, x5, x4, x3, x2, x1, x0) \
	F1(x3, x4, x1, x0, x5, x2, x6)
#define FP5_2(x6, x5, x4, x3, x2, x1, x0) \
	F2(x6, x2, x1, x0, x3, x4, x5)
#define FP5_3(x6, x5, x4, x3, x2, x1, x0) \
	F3(x2, x6, x0, x4, x3, x1, x5)
#define FP5_4(x6, x5, x4, x3, x2, x1, x0) \
	F4(x1, x5, x3, x2, x0, x4, x6)
#define FP5_5(x6, x5, x4, x3, x2, x1, x0) \
	F5(x2, x5, x0, x6, x4, x3, x1)

/*
 * One step, for "n" passes, pass number "p" (1 <= p <= n), using
 * input word number "w" and step constant "c".
 */
#define STEP(n, p, x7, x6, x5, x4, x3, x2, x1, x0, w, c) \
do { \
   __m128i t = FP ## n ## _ ## p(x6, x5, x4, x3, x2, x1, x0); \
   x7 = _mm_add_epi32( _mm_add_epi32( mm128_ror_32( t, 7 ), \
                                      mm128_ror_32( x7, 11 ) ), \
                       _mm_add_epi32( w, _mm_set1_epi32( c ) ) ); \
} while (0)

/*
 * PASSy(n, in) computes pass number "y", for a total of "n", using the
 * one-argument macro "in" to access input words. Current state is assumed
 * to be held in variables "s0" to "s7".
 */

//#if SPH_SMALL_FOOTPRINT_HAVAL

#define PASS1(n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(pass_count + 0), SPH_C32(0x00000000)); \
			STEP(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(pass_count + 1), SPH_C32(0x00000000)); \
			STEP(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(pass_count + 2), SPH_C32(0x00000000)); \
			STEP(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(pass_count + 3), SPH_C32(0x00000000)); \
			STEP(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(pass_count + 4), SPH_C32(0x00000000)); \
			STEP(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(pass_count + 5), SPH_C32(0x00000000)); \
			STEP(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(pass_count + 6), SPH_C32(0x00000000)); \
			STEP(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(pass_count + 7), SPH_C32(0x00000000)); \
   		} \
	} while (0)

#define PASSG(p, n, in)   do { \
		unsigned pass_count; \
		for (pass_count = 0; pass_count < 32; pass_count += 8) { \
			STEP(n, p, s7, s6, s5, s4, s3, s2, s1, s0, \
				in(MP ## p[pass_count + 0]), \
				RK ## p[pass_count + 0]); \
			STEP(n, p, s6, s5, s4, s3, s2, s1, s0, s7, \
				in(MP ## p[pass_count + 1]), \
				RK ## p[pass_count + 1]); \
			STEP(n, p, s5, s4, s3, s2, s1, s0, s7, s6, \
				in(MP ## p[pass_count + 2]), \
				RK ## p[pass_count + 2]); \
			STEP(n, p, s4, s3, s2, s1, s0, s7, s6, s5, \
				in(MP ## p[pass_count + 3]), \
				RK ## p[pass_count + 3]); \
			STEP(n, p, s3, s2, s1, s0, s7, s6, s5, s4, \
				in(MP ## p[pass_count + 4]), \
				RK ## p[pass_count + 4]); \
			STEP(n, p, s2, s1, s0, s7, s6, s5, s4, s3, \
				in(MP ## p[pass_count + 5]), \
				RK ## p[pass_count + 5]); \
			STEP(n, p, s1, s0, s7, s6, s5, s4, s3, s2, \
				in(MP ## p[pass_count + 6]), \
				RK ## p[pass_count + 6]); \
			STEP(n, p, s0, s7, s6, s5, s4, s3, s2, s1, \
				in(MP ## p[pass_count + 7]), \
				RK ## p[pass_count + 7]); \
   		} \
	} while (0)

#define PASS2(n, in)    PASSG(2, n, in)
#define PASS3(n, in)    PASSG(3, n, in)
#define PASS4(n, in)    PASSG(4, n, in)
#define PASS5(n, in)    PASSG(5, n, in)

static const unsigned MP2[32] = {
	 5, 14, 26, 18, 11, 28,  7, 16,
	 0, 23, 20, 22,  1, 10,  4,  8,
	30,  3, 21,  9, 17, 24, 29,  6,
	19, 12, 15, 13,  2, 25, 31, 27
};

static const unsigned MP3[32] = {
	19,  9,  4, 20, 28, 17,  8, 22,
	29, 14, 25, 12, 24, 30, 16, 26,
	31, 15,  7,  3,  1,  0, 18, 27,
	13,  6, 21, 10, 23, 11,  5,  2
};

static const unsigned MP4[32] = {
	24,  4,  0, 14,  2,  7, 28, 23,
	26,  6, 30, 20, 18, 25, 19,  3,
	22, 11, 31, 21,  8, 27, 12,  9,
	 1, 29,  5, 15, 17, 10, 16, 13
};

static const unsigned MP5[32] = {
	27,  3, 21, 26, 17, 11, 20, 29,
	19,  0, 12,  7, 13,  8, 31, 10,
	 5,  9, 14, 30, 18,  6, 28, 24,
	 2, 23, 16, 22,  4,  1, 25, 15
};

static const sph_u32 RK2[32] = {
	SPH_C32(0x452821E6), SPH_C32(0x38D01377),
	SPH_C32(0xBE5466CF), SPH_C32(0x34E90C6C),
	SPH_C32(0xC0AC29B7), SPH_C32(0xC97C50DD),
	SPH_C32(0x3F84D5B5), SPH_C32(0xB5470917),
	SPH_C32(0x9216D5D9), SPH_C32(0x8979FB1B),
	SPH_C32(0xD1310BA6), SPH_C32(0x98DFB5AC),
	SPH_C32(0x2FFD72DB), SPH_C32(0xD01ADFB7),
	SPH_C32(0xB8E1AFED), SPH_C32(0x6A267E96),
	SPH_C32(0xBA7C9045), SPH_C32(0xF12C7F99),
	SPH_C32(0x24A19947), SPH_C32(0xB3916CF7),
	SPH_C32(0x0801F2E2), SPH_C32(0x858EFC16),
	SPH_C32(0x636920D8), SPH_C32(0x71574E69),
	SPH_C32(0xA458FEA3), SPH_C32(0xF4933D7E),
	SPH_C32(0x0D95748F), SPH_C32(0x728EB658),
	SPH_C32(0x718BCD58), SPH_C32(0x82154AEE),
	SPH_C32(0x7B54A41D), SPH_C32(0xC25A59B5)
};

static const sph_u32 RK3[32] = {
	SPH_C32(0x9C30D539), SPH_C32(0x2AF26013),
	SPH_C32(0xC5D1B023), SPH_C32(0x286085F0),
	SPH_C32(0xCA417918), SPH_C32(0xB8DB38EF),
	SPH_C32(0x8E79DCB0), SPH_C32(0x603A180E),
	SPH_C32(0x6C9E0E8B), SPH_C32(0xB01E8A3E),
	SPH_C32(0xD71577C1), SPH_C32(0xBD314B27),
	SPH_C32(0x78AF2FDA), SPH_C32(0x55605C60),
	SPH_C32(0xE65525F3), SPH_C32(0xAA55AB94),
	SPH_C32(0x57489862), SPH_C32(0x63E81440),
	SPH_C32(0x55CA396A), SPH_C32(0x2AAB10B6),
	SPH_C32(0xB4CC5C34), SPH_C32(0x1141E8CE),
	SPH_C32(0xA15486AF), SPH_C32(0x7C72E993),
	SPH_C32(0xB3EE1411), SPH_C32(0x636FBC2A),
	SPH_C32(0x2BA9C55D), SPH_C32(0x741831F6),
	SPH_C32(0xCE5C3E16), SPH_C32(0x9B87931E),
	SPH_C32(0xAFD6BA33), SPH_C32(0x6C24CF5C)
};

static const sph_u32 RK4[32] = {
	SPH_C32(0x7A325381), SPH_C32(0x28958677),
	SPH_C32(0x3B8F4898), SPH_C32(0x6B4BB9AF),
	SPH_C32(0xC4BFE81B), SPH_C32(0x66282193),
	SPH_C32(0x61D809CC), SPH_C32(0xFB21A991),
	SPH_C32(0x487CAC60), SPH_C32(0x5DEC8032),
	SPH_C32(0xEF845D5D), SPH_C32(0xE98575B1),
	SPH_C32(0xDC262302), SPH_C32(0xEB651B88),
	SPH_C32(0x23893E81), SPH_C32(0xD396ACC5),
	SPH_C32(0x0F6D6FF3), SPH_C32(0x83F44239),
	SPH_C32(0x2E0B4482), SPH_C32(0xA4842004),
	SPH_C32(0x69C8F04A), SPH_C32(0x9E1F9B5E),
	SPH_C32(0x21C66842), SPH_C32(0xF6E96C9A),
	SPH_C32(0x670C9C61), SPH_C32(0xABD388F0),
	SPH_C32(0x6A51A0D2), SPH_C32(0xD8542F68),
	SPH_C32(0x960FA728), SPH_C32(0xAB5133A3),
	SPH_C32(0x6EEF0B6C), SPH_C32(0x137A3BE4)
};

static const sph_u32 RK5[32] = {
	SPH_C32(0xBA3BF050), SPH_C32(0x7EFB2A98),
	SPH_C32(0xA1F1651D), SPH_C32(0x39AF0176),
	SPH_C32(0x66CA593E), SPH_C32(0x82430E88),
	SPH_C32(0x8CEE8619), SPH_C32(0x456F9FB4),
	SPH_C32(0x7D84A5C3), SPH_C32(0x3B8B5EBE),
	SPH_C32(0xE06F75D8), SPH_C32(0x85C12073),
	SPH_C32(0x401A449F), SPH_C32(0x56C16AA6),
	SPH_C32(0x4ED3AA62), SPH_C32(0x363F7706),
	SPH_C32(0x1BFEDF72), SPH_C32(0x429B023D),
	SPH_C32(0x37D0D724), SPH_C32(0xD00A1248),
	SPH_C32(0xDB0FEAD3), SPH_C32(0x49F1C09B),
	SPH_C32(0x075372C9), SPH_C32(0x80991B7B),
	SPH_C32(0x25D479D8), SPH_C32(0xF6E8DEF7),
	SPH_C32(0xE3FE501A), SPH_C32(0xB6794C3B),
	SPH_C32(0x976CE0BD), SPH_C32(0x04C006BA),
	SPH_C32(0xC1A94FB6), SPH_C32(0x409F60C4)
};

#define SAVE_STATE \
   __m128i u0, u1, u2, u3, u4, u5, u6, u7; \
   do { \
      u0 = s0; \
      u1 = s1; \
      u2 = s2; \
      u3 = s3; \
      u4 = s4; \
      u5 = s5; \
      u6 = s6; \
      u7 = s7; \
   } while (0)

#define UPDATE_STATE \
do { \
   s0 = _mm_add_epi32( s0, u0 ); \
   s1 = _mm_add_epi32( s1, u1 ); \
   s2 = _mm_add_epi32( s2, u2 ); \
   s3 = _mm_add_epi32( s3, u3 ); \
   s4 = _mm_add_epi32( s4, u4 ); \
   s5 = _mm_add_epi32( s5, u5 ); \
   s6 = _mm_add_epi32( s6, u6 ); \
   s7 = _mm_add_epi32( s7, u7 ); \
} while (0)

/*
 * COREn(in) performs the core HAVAL computation for "n" passes, using
 * the one-argument macro "in" to access the input words. Running state
 * is held in variable "s0" to "s7".
 */
/*
#define CORE3(in)  do { \
		SAVE_STATE; \
		PASS1(3, in); \
		PASS2(3, in); \
		PASS3(3, in); \
		UPDATE_STATE; \
	} while (0)

#define CORE4(in)  do { \
		SAVE_STATE; \
		PASS1(4, in); \
		PASS2(4, in); \
		PASS3(4, in); \
		PASS4(4, in); \
		UPDATE_STATE; \
	} while (0)
*/
#define CORE5(in)  do { \
		SAVE_STATE; \
		PASS1(5, in); \
		PASS2(5, in); \
		PASS3(5, in); \
		PASS4(5, in); \
		PASS5(5, in); \
		UPDATE_STATE; \
	} while (0)

/*
 * DSTATE declares the state variables "s0" to "s7".
 */
#define DSTATE   __m128i s0, s1, s2, s3, s4, s5, s6, s7

/*
 * RSTATE fills the state variables from the context "sc".
 */
#define RSTATE \
do { \
   s0 = sc->s0; \
   s1 = sc->s1; \
   s2 = sc->s2; \
   s3 = sc->s3; \
   s4 = sc->s4; \
   s5 = sc->s5; \
   s6 = sc->s6; \
   s7 = sc->s7; \
} while (0)

/*
 * WSTATE updates the context "sc" from the state variables.
 */
#define WSTATE \
do { \
   sc->s0 = s0; \
   sc->s1 = s1; \
   sc->s2 = s2; \
   sc->s3 = s3; \
   sc->s4 = s4; \
   sc->s5 = s5; \
   sc->s6 = s6; \
   sc->s7 = s7; \
} while (0)

/*
 * Initialize a context. "olen" is the output length, in 32-bit words
 * (between 4 and 8, inclusive). "passes" is the number of passes
 * (3, 4 or 5).
 */
static void
haval_4way_init( haval_4way_context *sc, unsigned olen, unsigned passes )
{
   sc->s0 = _mm_set1_epi32( 0x243F6A88UL );
   sc->s1 = _mm_set1_epi32( 0x85A308D3UL );
   sc->s2 = _mm_set1_epi32( 0x13198A2EUL );
   sc->s3 = _mm_set1_epi32( 0x03707344UL );
   sc->s4 = _mm_set1_epi32( 0xA4093822UL );
   sc->s5 = _mm_set1_epi32( 0x299F31D0UL );
   sc->s6 = _mm_set1_epi32( 0x082EFA98UL );
   sc->s7 = _mm_set1_epi32( 0xEC4E6C89UL );
   sc->olen = olen;
   sc->passes = passes;
   sc->count_high = 0;
   sc->count_low = 0;
	
}

#define IN_PREPARE(indata) const __m128i *const load_ptr = (indata)

#define INW(i)   load_ptr[ i ] 

/*
 * Write out HAVAL output. The output length is tailored to the requested
 * length.
 */
static void
haval_4way_out( haval_4way_context *sc, void *dst )
{
   __m128i *buf = (__m128i*)dst;
   DSTATE;
   RSTATE;

   buf[0] = s0;
   buf[1] = s1;
   buf[2] = s2;
   buf[3] = s3;
   buf[4] = s4;
   buf[5] = s5;
   buf[6] = s6;
   buf[7] = s7;
}

/*
 * The main core functions inline the code with the COREx() macros. We
 * use a helper file, included three times, which avoids code copying.
 */
/*
#undef PASSES
#define PASSES   3
#include "haval-helper.c"

#undef PASSES
#define PASSES   4
#include "haval-helper.c"
*/

#undef PASSES
#define PASSES   5
#include "haval-4way-helper.c"

/* ====================================================================== */

#define API(xxx, y) \
void \
haval ## xxx ## _ ## y ## _4way_init(void *cc) \
{ \
	haval_4way_init(cc, xxx >> 5, y); \
} \
 \
void \
haval ## xxx ## _ ## y ## _4way_update (void *cc, const void *data, size_t len) \
{ \
	haval ## y ## _4way_update(cc, data, len); \
} \
 \
void \
haval ## xxx ## _ ## y ## _4way_close(void *cc, void *dst) \
{ \
	haval ## y ## _4way_close(cc, dst); \
} \

API(256, 5)

#define RVAL \
do { \
   s0 = val[0]; \
   s1 = val[1]; \
   s2 = val[2]; \
   s3 = val[3]; \
   s4 = val[4]; \
   s5 = val[5]; \
   s6 = val[6]; \
   s7 = val[7]; \
} while (0)

#define WVAL \
do { \
   val[0] = s0; \
   val[1] = s1; \
   val[2] = s2; \
   val[3] = s3; \
   val[4] = s4; \
   val[5] = s5; \
   val[6] = s6; \
   val[7] = s7; \
} while (0)

#define INMSG(i)   msg[i]

#if defined(__AVX2__)

// Haval-256 8 way 32 bit avx2

#if defined (__AVX512VL__)

// ( ~( a ^ b ) ) & c
#define mm256_andnotxor( a, b, c ) \
   _mm256_ternarylogic_epi32( a, b, c, 0x82  )

#else

#define mm256_andnotxor( a, b, c ) \
   _mm256_andnot_si256( _mm256_xor_si256( a, b ), c )

#endif

#define F1_8W(x6, x5, x4, x3, x2, x1, x0) \
 mm256_xor3( x0, mm256_andxor( x1, x0, x4 ), \
                 _mm256_xor_si256( _mm256_and_si256( x2, x5 ), \
                                   _mm256_and_si256( x3, x6 ) ) ) \

#define F2_8W(x6, x5, x4, x3, x2, x1, x0) \
   mm256_xor3( mm256_andxor( x2, _mm256_andnot_si256( x3, x1 ), \
                       mm256_xor3( _mm256_and_si256( x4, x5 ), x6, x0 )  ), \
               mm256_andxor( x4, x1, x5 ), \
               mm256_xorand( x0, x3, x5 ) ) \

#define F3_8W(x6, x5, x4, x3, x2, x1, x0) \
  mm256_xor3( x0, \
              _mm256_and_si256( x3, \
                         mm256_xor3( _mm256_and_si256( x1, x2 ), x6, x0 ) ), \
              _mm256_xor_si256( _mm256_and_si256( x1, x4 ), \
                                _mm256_and_si256( x2, x5 ) ) )

#define F4_8W(x6, x5, x4, x3, x2, x1, x0) \
  mm256_xor3( \
      mm256_andxor( x3, x5, \
                    _mm256_xor_si256( _mm256_and_si256( x1, x2 ), \
                                      _mm256_or_si256( x4, x6 ) ) ), \
      _mm256_and_si256( x4, \
                        mm256_xor3( x0, _mm256_andnot_si256( x2, x5 ), \
                                    _mm256_xor_si256( x1, x6 ) ) ), \
      mm256_xorand( x0, x2, x6 ) )

#define F5_8W(x6, x5, x4, x3, x2, x1, x0) \
   _mm256_xor_si256( \
         mm256_andnotxor( mm256_and3( x1, x2, x3 ), x5, x0 ), \
         mm256_xor3( _mm256_and_si256( x1, x4 ), \
                     _mm256_and_si256( x2, x5 ), \
                     _mm256_and_si256( x3, x6 ) ) )

#define FP3_1_8W(x6, x5, x4, x3, x2, x1, x0) \
   F1_8W(x1, x0, x3, x5, x6, x2, x4)
#define FP3_2_8W(x6, x5, x4, x3, x2, x1, x0) \
   F2_8W(x4, x2, x1, x0, x5, x3, x6)
#define FP3_3_8W(x6, x5, x4, x3, x2, x1, x0) \
   F3_8W(x6, x1, x2, x3, x4, x5, x0)

#define FP4_1_8W(x6, x5, x4, x3, x2, x1, x0) \
   F1_8W(x2, x6, x1, x4, x5, x3, x0)
#define FP4_2_8W(x6, x5, x4, x3, x2, x1, x0) \
   F2_8W(x3, x5, x2, x0, x1, x6, x4)
#define FP4_3_8W(x6, x5, x4, x3, x2, x1, x0) \
   F3_8W(x1, x4, x3, x6, x0, x2, x5)
#define FP4_4_8W(x6, x5, x4, x3, x2, x1, x0) \
   F4_8W(x6, x4, x0, x5, x2, x1, x3)

#define FP5_1_8W(x6, x5, x4, x3, x2, x1, x0) \
   F1_8W(x3, x4, x1, x0, x5, x2, x6)
#define FP5_2_8W(x6, x5, x4, x3, x2, x1, x0) \
   F2_8W(x6, x2, x1, x0, x3, x4, x5)
#define FP5_3_8W(x6, x5, x4, x3, x2, x1, x0) \
   F3_8W(x2, x6, x0, x4, x3, x1, x5)
#define FP5_4_8W(x6, x5, x4, x3, x2, x1, x0) \
   F4_8W(x1, x5, x3, x2, x0, x4, x6)
#define FP5_5_8W(x6, x5, x4, x3, x2, x1, x0) \
   F5_8W(x2, x5, x0, x6, x4, x3, x1)

#define STEP_8W(n, p, x7, x6, x5, x4, x3, x2, x1, x0, w, c) \
do { \
   __m256i t = FP ## n ## _ ## p ## _8W(x6, x5, x4, x3, x2, x1, x0); \
   x7 = _mm256_add_epi32( _mm256_add_epi32( mm256_ror_32( t, 7 ), \
                                      mm256_ror_32( x7, 11 ) ), \
                       _mm256_add_epi32( w, _mm256_set1_epi32( c ) ) ); \
} while (0)

#define PASS1_8W(n, in)   do { \
      unsigned pass_count; \
      for (pass_count = 0; pass_count < 32; pass_count += 8) { \
         STEP_8W(n, 1, s7, s6, s5, s4, s3, s2, s1, s0, \
            in(pass_count + 0), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s6, s5, s4, s3, s2, s1, s0, s7, \
            in(pass_count + 1), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s5, s4, s3, s2, s1, s0, s7, s6, \
            in(pass_count + 2), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s4, s3, s2, s1, s0, s7, s6, s5, \
            in(pass_count + 3), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s3, s2, s1, s0, s7, s6, s5, s4, \
            in(pass_count + 4), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s2, s1, s0, s7, s6, s5, s4, s3, \
            in(pass_count + 5), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s1, s0, s7, s6, s5, s4, s3, s2, \
            in(pass_count + 6), SPH_C32(0x00000000)); \
         STEP_8W(n, 1, s0, s7, s6, s5, s4, s3, s2, s1, \
            in(pass_count + 7), SPH_C32(0x00000000)); \
         } \
   } while (0)

#define PASSG_8W(p, n, in)   do { \
      unsigned pass_count; \
      for (pass_count = 0; pass_count < 32; pass_count += 8) { \
         STEP_8W(n, p, s7, s6, s5, s4, s3, s2, s1, s0, \
            in(MP ## p[pass_count + 0]), \
            RK ## p[pass_count + 0]); \
         STEP_8W(n, p, s6, s5, s4, s3, s2, s1, s0, s7, \
            in(MP ## p[pass_count + 1]), \
            RK ## p[pass_count + 1]); \
         STEP_8W(n, p, s5, s4, s3, s2, s1, s0, s7, s6, \
            in(MP ## p[pass_count + 2]), \
            RK ## p[pass_count + 2]); \
         STEP_8W(n, p, s4, s3, s2, s1, s0, s7, s6, s5, \
            in(MP ## p[pass_count + 3]), \
            RK ## p[pass_count + 3]); \
         STEP_8W(n, p, s3, s2, s1, s0, s7, s6, s5, s4, \
            in(MP ## p[pass_count + 4]), \
            RK ## p[pass_count + 4]); \
         STEP_8W(n, p, s2, s1, s0, s7, s6, s5, s4, s3, \
            in(MP ## p[pass_count + 5]), \
            RK ## p[pass_count + 5]); \
         STEP_8W(n, p, s1, s0, s7, s6, s5, s4, s3, s2, \
            in(MP ## p[pass_count + 6]), \
            RK ## p[pass_count + 6]); \
         STEP_8W(n, p, s0, s7, s6, s5, s4, s3, s2, s1, \
            in(MP ## p[pass_count + 7]), \
            RK ## p[pass_count + 7]); \
         } \
   } while (0)

#define PASS2_8W(n, in)    PASSG_8W(2, n, in)
#define PASS3_8W(n, in)    PASSG_8W(3, n, in)
#define PASS4_8W(n, in)    PASSG_8W(4, n, in)
#define PASS5_8W(n, in)    PASSG_8W(5, n, in)

#define SAVE_STATE_8W \
   __m256i u0, u1, u2, u3, u4, u5, u6, u7; \
   do { \
      u0 = s0; \
      u1 = s1; \
      u2 = s2; \
      u3 = s3; \
      u4 = s4; \
      u5 = s5; \
      u6 = s6; \
      u7 = s7; \
   } while (0)

#define UPDATE_STATE_8W \
do { \
   s0 = _mm256_add_epi32( s0, u0 ); \
   s1 = _mm256_add_epi32( s1, u1 ); \
   s2 = _mm256_add_epi32( s2, u2 ); \
   s3 = _mm256_add_epi32( s3, u3 ); \
   s4 = _mm256_add_epi32( s4, u4 ); \
   s5 = _mm256_add_epi32( s5, u5 ); \
   s6 = _mm256_add_epi32( s6, u6 ); \
   s7 = _mm256_add_epi32( s7, u7 ); \
} while (0)

#define CORE_8W5(in)  do { \
      SAVE_STATE_8W; \
      PASS1_8W(5, in); \
      PASS2_8W(5, in); \
      PASS3_8W(5, in); \
      PASS4_8W(5, in); \
      PASS5_8W(5, in); \
      UPDATE_STATE_8W; \
   } while (0)

#define DSTATE_8W   __m256i s0, s1, s2, s3, s4, s5, s6, s7

#define RSTATE_8W \
do { \
   s0 = sc->s0; \
   s1 = sc->s1; \
   s2 = sc->s2; \
   s3 = sc->s3; \
   s4 = sc->s4; \
   s5 = sc->s5; \
   s6 = sc->s6; \
   s7 = sc->s7; \
} while (0)

#define WSTATE_8W \
do { \
   sc->s0 = s0; \
   sc->s1 = s1; \
   sc->s2 = s2; \
   sc->s3 = s3; \
   sc->s4 = s4; \
   sc->s5 = s5; \
   sc->s6 = s6; \
   sc->s7 = s7; \
} while (0)

static void
haval_8way_init( haval_8way_context *sc, unsigned olen, unsigned passes )
{
   sc->s0 = m256_const1_32( 0x243F6A88UL );
   sc->s1 = m256_const1_32( 0x85A308D3UL );
   sc->s2 = m256_const1_32( 0x13198A2EUL );
   sc->s3 = m256_const1_32( 0x03707344UL );
   sc->s4 = m256_const1_32( 0xA4093822UL );
   sc->s5 = m256_const1_32( 0x299F31D0UL );
   sc->s6 = m256_const1_32( 0x082EFA98UL );
   sc->s7 = m256_const1_32( 0xEC4E6C89UL );
   sc->olen = olen;
   sc->passes = passes;
   sc->count_high = 0;
   sc->count_low = 0;

}
#define IN_PREPARE_8W(indata) const __m256i *const load_ptr_8w = (indata)

#define INW_8W(i)   load_ptr_8w[ i ] 

static void
haval_8way_out( haval_8way_context *sc, void *dst )
{
   __m256i *buf = (__m256i*)dst;
   DSTATE_8W;
   RSTATE_8W;

   buf[0] = s0;
   buf[1] = s1;
   buf[2] = s2;
   buf[3] = s3;
   buf[4] = s4;
   buf[5] = s5;
   buf[6] = s6;
   buf[7] = s7;
}

#undef PASSES
#define PASSES   5
#include "haval-8way-helper.c"

#define API_8W(xxx, y) \
void \
haval ## xxx ## _ ## y ## _8way_init(void *cc) \
{ \
   haval_8way_init(cc, xxx >> 5, y); \
} \
 \
void \
haval ## xxx ## _ ## y ## _8way_update (void *cc, const void *data, size_t len) \
{ \
   haval ## y ## _8way_update(cc, data, len); \
} \
 \
void \
haval ## xxx ## _ ## y ## _8way_close(void *cc, void *dst) \
{ \
   haval ## y ## _8way_close(cc, dst); \
} \

API_8W(256, 5)

#define RVAL_8W \
do { \
   s0 = val[0]; \
   s1 = val[1]; \
   s2 = val[2]; \
   s3 = val[3]; \
   s4 = val[4]; \
   s5 = val[5]; \
   s6 = val[6]; \
   s7 = val[7]; \
} while (0)

#define WVAL_8W \
do { \
   val[0] = s0; \
   val[1] = s1; \
   val[2] = s2; \
   val[3] = s3; \
   val[4] = s4; \
   val[5] = s5; \
   val[6] = s6; \
   val[7] = s7; \
} while (0)

#define INMSG_8W(i)   msg[i]



#endif // AVX2

#ifdef __cplusplus
}
#endif	
#endif
