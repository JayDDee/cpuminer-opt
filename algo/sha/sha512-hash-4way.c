/* $Id: sha2big.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * SHA-384 / SHA-512 implementation.
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
#include "sha512-hash.h"

/*
static const uit64_t H512[8] =
{
 0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
 0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179
};
*/

static const uint64_t K512[80] =
{
 0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
 0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
 0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
 0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
 0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
 0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
 0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
 0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
 0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
 0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
 0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
 0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
 0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
 0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
 0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
 0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
 0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
 0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
 0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
 0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
};

#if defined(__AVX__) && defined(__SHA512__)

// SHA-512 implemented using SHA512 CPU extension.

// Experimental. Not supported. Not tested. Not reviewed. Compile tested only.
// Modelled after noloader sha256 implementation, replacing 4x32 bit
// instructions with equivalent 4x64 bit instructions and increasing rounds
// to 80.

// Needs GCC-14 for compilation.
// Needs Intel Lunarlake or Arrowlake CPU, or AMD Zen-6? for execution.

void sha512_opt_transform_be( uint64_t *state_out, const void *input,
                              const uint64_t *state_in )
{
    __m256i STATE0, STATE1;
    __m256i MSG, TMP;
    __m256i TMSG0, TMSG1, TMSG2, TMSG3;
    __m256i ABEF_SAVE, CDGH_SAVE;

    // Load initial values
    TMP = _mm256_load_si256( (__m256i*) &state_in[0] );
    STATE1 = _mm256_load_si256( (__m256i*) &state_in[4] );
    TMP = _mm256_permute4x64_epi64( TMP, 0xB1 );             // CDAB
    STATE1 = _mm256_permute4x64_epi64( STATE1, 0x1B );       // EFGH
    STATE0 = _mm256_permute2x128_si256( TMP, STATE1, 0x21 ); // ABEF
    STATE1 = _mm256_blend_epi32( STATE1, TMP, 0xF0 );        // CDGH

    // Save initial state
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    TMSG0 = _mm256_load_si256( (const __m256i*) (input+0) );
    TMSG0 = mm256_bswap_64( TMSG0 );
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 0 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128 (MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );

    // Rounds 4-7
    TMSG1 = _mm256_load_si256( (const __m256i*) (input+16) );
    TMSG1 = mm256_bswap_64( TMSG1 );
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 1 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                        _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 8-11
    TMSG2 = _mm256_load_si256( (const __m256i*) (input+32) );
    TMSG2 = mm256_bswap_64( TMSG2 );
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 2 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 12-15
    TMSG3 = _mm256_load_si256( (const __m256i*) (input+48) );
    TMSG3 = mm256_bswap_64( TMSG3 );
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 3 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_shuffle2_64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi32( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );
    
    // Rounds 16-19
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 4 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 20-23
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 5 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 24-27
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 6 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi32( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );
    
    // Rounds 28-31
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 7 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 32-35
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 8 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 36-39
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 9 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 40-43
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 10 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 44-47
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 11 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 48-51
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 12 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 52-55
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 13 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 56-59
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 14 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 60-63
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 15 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );
    
    // Rounds 64-67
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 16 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 68-71
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 17 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );

    // Rounds 72-75
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 18 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );

    // Rounds 76-79
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 19 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0,
                                       _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1,
                                       _mm256_castsi256_si128( MSG ) );

    // Add initial state
    STATE0 = _mm256_add_epi64( STATE0, ABEF_SAVE );
    STATE1 = _mm256_add_epi64( STATE1, CDGH_SAVE );

    TMP = _mm256_permute4x64_epi64( STATE0, 0x1B );          // FEBA
    STATE1 = _mm256_permute4x64_epi64( STATE1, 0xB1 );       // DCHG
    STATE0 = _mm256_blend_epi32( TMP, STATE1, 0xF0 );        // DCBA
    STATE1 = _mm256_permute2x128_si256( STATE1, TMP, 0x21 ); // ABEF

    // Save state
    _mm256_store_si256((__m256i*) &state_out[0], STATE0 );
    _mm256_store_si256((__m256i*) &state_out[4], STATE1 );
}

void sha512_opt_transform_le( uint64_t *state_out, const void *input,
                              const uint64_t *state_in )
{
    __m256i STATE0, STATE1;
    __m256i MSG, TMP;
    __m256i TMSG0, TMSG1, TMSG2, TMSG3;
    __m256i ABEF_SAVE, CDGH_SAVE;

    // Load initial values
    TMP = _mm256_load_si256( (__m256i*) &state_in[0] );
    STATE1 = _mm256_load_si256( (__m256i*) &state_in[4] );
    TMP = _mm256_permute4x64_epi64( TMP, 0xB1 );             // CDAB
    STATE1 = _mm256_permute4x64_epi64( STATE1, 0x1B );       // EFGH
    STATE0 = _mm256_permute2x128_si256( TMP, STATE1, 0x21 ); // ABEF
    STATE1 = _mm256_blend_epi32( STATE1, TMP, 0xF0 );        // CDGH

    // Save initial state
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    TMSG0 = _mm256_load_si256( (const __m256i*) (input+0) );
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 0 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );

    // Rounds 4-7
    TMSG1 = _mm256_load_si256( (const __m256i*) (input+16) );
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 1 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 8-11
    TMSG2 = _mm256_load_si256( (const __m256i*) (input+32) );
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 2 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 12-15
    TMSG3 = _mm256_load_si256( (const __m256i*) (input+48) );
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 3 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_shuffle2_64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi32( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 16-19
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 4 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 20-23
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 5 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 24-27
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 6 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi32( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 28-31
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 7 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 32-35
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 8 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 36-39
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 9 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 40-43
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 10 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 44-47
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 11 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 48-51
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 12 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 52-55
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 13 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG0 = _mm256_sha512msg1_epi64( TMSG0, _mm256_castsi256_si128( TMSG1 ) );

    // Rounds 56-59
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 14 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG1 = _mm256_sha512msg1_epi64( TMSG1, _mm256_castsi256_si128( TMSG2 ) );

    // Rounds 60-63
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 15 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG3, TMSG2, 1 );
    TMSG0 = _mm256_add_epi64( TMSG0, TMP );
    TMSG0 = _mm256_sha512msg2_epi64( TMSG0, TMSG3 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG2 = _mm256_sha512msg1_epi64( TMSG2, _mm256_castsi256_si128( TMSG3 ) );

    // Rounds 64-67
    MSG = _mm256_add_epi64( TMSG0, casti_m256i( K512, 16 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG0, TMSG3, 1 );
    TMSG1 = _mm256_add_epi64( TMSG1, TMP );
    TMSG1 = _mm256_sha512msg2_epi64( TMSG1, TMSG0 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );
    TMSG3 = _mm256_sha512msg1_epi64( TMSG3, _mm256_castsi256_si128( TMSG0 ) );

    // Rounds 68-71
    MSG = _mm256_add_epi64( TMSG1, casti_m256i( K512, 17 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG1, TMSG0, 1 );
    TMSG2 = _mm256_add_epi64( TMSG2, TMP );
    TMSG2 = _mm256_sha512msg2_epi64( TMSG2, TMSG1 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );

    // Rounds 72-75
    MSG = _mm256_add_epi64( TMSG2, casti_m256i( K512, 18 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    TMP = mm256_alignr64( TMSG2, TMSG1, 1 );
    TMSG3 = _mm256_add_epi64( TMSG3, TMP );
    TMSG3 = _mm256_sha512msg2_epi64( TMSG3, TMSG2 );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );

    // Rounds 76-79
    MSG = _mm256_add_epi64( TMSG3, casti_m256i( K512, 19 ) );
    STATE1 = _mm256_sha512rnds2_epi64( STATE1, STATE0, _mm256_castsi256_si128( MSG ) );
    MSG = _mm256_permute4x64_epi64( MSG, 0x0E );
    STATE0 = _mm256_sha512rnds2_epi64( STATE0, STATE1, _mm256_castsi256_si128( MSG ) );

    // Add initial state
    STATE0 = _mm256_add_epi64( STATE0, ABEF_SAVE );
    STATE1 = _mm256_add_epi64( STATE1, CDGH_SAVE );

    TMP = _mm256_permute4x64_epi64( STATE0, 0x1B );          // FEBA
    STATE1 = _mm256_permute4x64_epi64( STATE1, 0xB1 );       // DCHG
    STATE0 = _mm256_blend_epi32( TMP, STATE1, 0xF0 );        // DCBA
    STATE1 = _mm256_permute2x128_si256( STATE1, TMP, 0x21 ); // ABEF

    // Save state
    _mm256_store_si256((__m256i*) &state_out[0], STATE0 );
    _mm256_store_si256((__m256i*) &state_out[4], STATE1 );
}


#endif

/*
#if defined(__ARM_FEATURE_NEON) && defined(__ARM_FEATURE_SHA512)

uint64x2_t sha512_compile_test( uint64x2_t test )
{
   test = vsha512hq_u64( test, test, test );
   test = vsha512h2q_u64( test, test, test );
   test = vsha512su0q_u64( test, test );
   test = vsha512su1q_u64( test, test, test );
   return test;
}

#endif
*/

#if defined(SIMD512)

// SHA-512 8 way 64 bit

#define CH8W( X, Y, Z )    _mm512_ternarylogic_epi64( X, Y, Z, 0xca )

#define MAJ8W( X, Y, Z )   _mm512_ternarylogic_epi64( X, Y, Z, 0xe8 )

#define BSG8W_5_0( x )     mm512_xor3( _mm512_ror_epi64( x, 28 ), \
                                       _mm512_ror_epi64( x, 34 ), \
                                       _mm512_ror_epi64( x, 39 ) )

#define BSG8W_5_1( x )     mm512_xor3( _mm512_ror_epi64( x, 14 ), \
                                       _mm512_ror_epi64( x, 18 ), \
                                       _mm512_ror_epi64( x, 41 ) )

#define SSG8W_5_0( x )     mm512_xor3( _mm512_ror_epi64( x,  1 ), \
                                       _mm512_ror_epi64( x,  8 ), \
                                       _mm512_srli_epi64( x, 7 ) ) 

#define SSG8W_5_1( x )     mm512_xor3( _mm512_ror_epi64( x, 19 ), \
                                       _mm512_ror_epi64( x, 61 ), \
                                       _mm512_srli_epi64( x, 6 ) )

#define SHA3_8WAY_STEP( A, B, C, D, E, F, G, H, i ) \
do { \
  __m512i T0 = _mm512_add_epi64( v512_64( K512[i] ), W[ i ] ); \
  __m512i T1 = BSG8W_5_1( E ); \
  __m512i T2 = BSG8W_5_0( A ); \
  T0 = _mm512_add_epi64( T0, CH8W( E, F, G ) ); \
  T1 = _mm512_add_epi64( T1, H ); \
  T2 = _mm512_add_epi64( T2, MAJ8W( A, B, C ) ); \
  T1 = _mm512_add_epi64( T1, T0 ); \
  D  = _mm512_add_epi64( D,  T1 ); \
  H  = _mm512_add_epi64( T1, T2 ); \
} while (0)

static void
sha512_8x64_round( sha512_8x64_context *ctx,  __m512i *in, __m512i r[8] )
{
   int i;
   register __m512i A, B, C, D, E, F, G, H;
   __m512i W[80];

   mm512_block_bswap_64( W  , in );
   mm512_block_bswap_64( W+8, in+8 );

   for ( i = 16; i < 80; i++ )
      W[i] = mm512_add4_64( SSG8W_5_0( W[i-15] ), SSG8W_5_1( W[i-2] ),
                             W[ i- 7 ], W[ i-16 ] );

   if ( ctx->initialized )
   {
      A = r[0];
      B = r[1];
      C = r[2];
      D = r[3];
      E = r[4];
      F = r[5];
      G = r[6];
      H = r[7];
   }
   else
   {
      A = v512_64( 0x6A09E667F3BCC908 );
      B = v512_64( 0xBB67AE8584CAA73B );
      C = v512_64( 0x3C6EF372FE94F82B );
      D = v512_64( 0xA54FF53A5F1D36F1 );
      E = v512_64( 0x510E527FADE682D1 );
      F = v512_64( 0x9B05688C2B3E6C1F );
      G = v512_64( 0x1F83D9ABFB41BD6B );
      H = v512_64( 0x5BE0CD19137E2179 );
   }

   for ( i = 0; i < 80; i += 8 )
   {
      SHA3_8WAY_STEP( A, B, C, D, E, F, G, H, i + 0 );
      SHA3_8WAY_STEP( H, A, B, C, D, E, F, G, i + 1 );
      SHA3_8WAY_STEP( G, H, A, B, C, D, E, F, i + 2 );
      SHA3_8WAY_STEP( F, G, H, A, B, C, D, E, i + 3 );
      SHA3_8WAY_STEP( E, F, G, H, A, B, C, D, i + 4 );
      SHA3_8WAY_STEP( D, E, F, G, H, A, B, C, i + 5 );
      SHA3_8WAY_STEP( C, D, E, F, G, H, A, B, i + 6 );
      SHA3_8WAY_STEP( B, C, D, E, F, G, H, A, i + 7 );
   }

   if ( ctx->initialized )
   {
      r[0] = _mm512_add_epi64( r[0], A );
      r[1] = _mm512_add_epi64( r[1], B );
      r[2] = _mm512_add_epi64( r[2], C );
      r[3] = _mm512_add_epi64( r[3], D );
      r[4] = _mm512_add_epi64( r[4], E );
      r[5] = _mm512_add_epi64( r[5], F );
      r[6] = _mm512_add_epi64( r[6], G );
      r[7] = _mm512_add_epi64( r[7], H );
   }
   else
   {
      ctx->initialized = true;
      r[0] = _mm512_add_epi64( A, v512_64( 0x6A09E667F3BCC908 ) );
      r[1] = _mm512_add_epi64( B, v512_64( 0xBB67AE8584CAA73B ) );
      r[2] = _mm512_add_epi64( C, v512_64( 0x3C6EF372FE94F82B ) );
      r[3] = _mm512_add_epi64( D, v512_64( 0xA54FF53A5F1D36F1 ) );
      r[4] = _mm512_add_epi64( E, v512_64( 0x510E527FADE682D1 ) );
      r[5] = _mm512_add_epi64( F, v512_64( 0x9B05688C2B3E6C1F ) );
      r[6] = _mm512_add_epi64( G, v512_64( 0x1F83D9ABFB41BD6B ) );
      r[7] = _mm512_add_epi64( H, v512_64( 0x5BE0CD19137E2179 ) );
   }
}

void sha512_8x64_init( sha512_8x64_context *sc )
{
   sc->initialized = false;
   sc->count = 0;
}

void sha512_8x64_update( sha512_8x64_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   size_t ptr;
   const int buf_size = 128;

   ptr = (unsigned)sc->count & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_512( sc->buf + (ptr>>3), vdata, clen>>3 );
      vdata = vdata + (clen>>3);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha512_8x64_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      sc->count += clen;
   }
}

void sha512_8x64_close( sha512_8x64_context *sc, void *dst )
{
    unsigned ptr;
    const int buf_size = 128;
    const int pad = buf_size - 16;

    ptr = (unsigned)sc->count & (buf_size - 1U);
    sc->buf[ ptr>>3 ] = v512_64( 0x80 );
    ptr += 8;
    if ( ptr > pad )
    {
         memset_zero_512( sc->buf + (ptr>>3), (buf_size - ptr) >> 3 );
         sha512_8x64_round( sc, sc->buf, sc->val );
         memset_zero_512( sc->buf, pad >> 3 );
    }
    else
         memset_zero_512( sc->buf + (ptr>>3), (pad - ptr) >> 3 );

    sc->buf[ pad >> 3 ] = v512_64( bswap_64( sc->count >> 61 ) );
    sc->buf[ ( pad+8 ) >> 3 ] = v512_64( bswap_64( sc->count <<  3 ) );
    sha512_8x64_round( sc, sc->buf, sc->val );

    mm512_block_bswap_64( dst, sc->val );
}

void sha512_8x64_ctx( sha512_8x64_context *sc, void *dst, const void *data,
                      size_t len )
{
 sha512_8x64_init( sc);
 sha512_8x64_update( sc, data,len );
 sha512_8x64_close( sc, dst );
}

#endif   // AVX512

#if defined(__AVX2__)

// SHA-512 4 way 64 bit

#define BSG5_0( x )     mm256_xor3( mm256_ror_64( x, 28 ), \
                                    mm256_ror_64( x, 34 ), \
                                    mm256_ror_64( x, 39 ) )

#define BSG5_1( x )     mm256_xor3( mm256_ror_64( x, 14 ), \
                                    mm256_ror_64( x, 18 ), \
                                    mm256_ror_64( x, 41 ) )

#define SSG5_0( x )     mm256_xor3( mm256_ror_64( x,  1 ), \
                                    mm256_ror_64( x,  8 ), \
                                    _mm256_srli_epi64( x, 7 ) ) 

#define SSG5_1( x )     mm256_xor3( mm256_ror_64( x, 19 ), \
                                    mm256_ror_64( x, 61 ), \
                                    _mm256_srli_epi64( x, 6 ) )

#define CH(X, Y, Z) \
   _mm256_xor_si256( _mm256_and_si256( _mm256_xor_si256( Y, Z ), X ), Z ) 

#define MAJ(X, Y, Z) \
  _mm256_xor_si256( Y, _mm256_and_si256( (X_xor_Y = _mm256_xor_si256( X, Y )), \
                                         Y_xor_Z ) )

#define SHA3_4WAY_STEP( A, B, C, D, E, F, G, H, i ) \
do { \
  __m256i T0 = _mm256_add_epi64( v256_64( K512[i] ), W[i] ); \
  __m256i T1 = BSG5_1( E ); \
  __m256i T2 = BSG5_0( A ); \
  T0 = _mm256_add_epi64( T0, CH( E, F, G ) ); \
  T1 = _mm256_add_epi64( T1, H ); \
  T2 = _mm256_add_epi64( T2, MAJ( A, B, C ) ); \
  T1 = _mm256_add_epi64( T1, T0 ); \
  Y_xor_Z = X_xor_Y; \
  D  = _mm256_add_epi64( D,  T1 ); \
  H  = _mm256_add_epi64( T1, T2 ); \
} while (0)

static void
sha512_4x64_round( sha512_4x64_context *ctx,  __m256i *in, __m256i r[8] )
{
   int i;
   register __m256i A, B, C, D, E, F, G, H;
   __m256i X_xor_Y, Y_xor_Z;
   __m256i W[80];

   mm256_block_bswap_64( W  , in );
   mm256_block_bswap_64( W+8, in+8 );

   for ( i = 16; i < 80; i++ )
       W[i] = mm256_add4_64( SSG5_0( W[i-15] ), SSG5_1( W[i-2] ),
                             W[ i- 7 ], W[ i-16 ] );

   if ( ctx->initialized )
   {
      A = r[0];
      B = r[1];
      C = r[2];
      D = r[3];
      E = r[4];
      F = r[5];
      G = r[6];
      H = r[7];
   }
   else
   {
      A = v256_64( 0x6A09E667F3BCC908 );
      B = v256_64( 0xBB67AE8584CAA73B );
      C = v256_64( 0x3C6EF372FE94F82B );
      D = v256_64( 0xA54FF53A5F1D36F1 );
      E = v256_64( 0x510E527FADE682D1 );
      F = v256_64( 0x9B05688C2B3E6C1F );
      G = v256_64( 0x1F83D9ABFB41BD6B );
      H = v256_64( 0x5BE0CD19137E2179 );
   }

   Y_xor_Z = _mm256_xor_si256( B, C );

   for ( i = 0; i < 80; i += 8 )
   {
      SHA3_4WAY_STEP( A, B, C, D, E, F, G, H, i + 0 );
      SHA3_4WAY_STEP( H, A, B, C, D, E, F, G, i + 1 );
      SHA3_4WAY_STEP( G, H, A, B, C, D, E, F, i + 2 );
      SHA3_4WAY_STEP( F, G, H, A, B, C, D, E, i + 3 );
      SHA3_4WAY_STEP( E, F, G, H, A, B, C, D, i + 4 );
      SHA3_4WAY_STEP( D, E, F, G, H, A, B, C, i + 5 );
      SHA3_4WAY_STEP( C, D, E, F, G, H, A, B, i + 6 );
      SHA3_4WAY_STEP( B, C, D, E, F, G, H, A, i + 7 );
   }

   if ( ctx->initialized )
   {
      r[0] = _mm256_add_epi64( r[0], A );
      r[1] = _mm256_add_epi64( r[1], B );
      r[2] = _mm256_add_epi64( r[2], C );
      r[3] = _mm256_add_epi64( r[3], D );
      r[4] = _mm256_add_epi64( r[4], E );
      r[5] = _mm256_add_epi64( r[5], F );
      r[6] = _mm256_add_epi64( r[6], G );
      r[7] = _mm256_add_epi64( r[7], H );
   }
   else
   {
      ctx->initialized = true;
      r[0] = _mm256_add_epi64( A, v256_64( 0x6A09E667F3BCC908 ) );
      r[1] = _mm256_add_epi64( B, v256_64( 0xBB67AE8584CAA73B ) );
      r[2] = _mm256_add_epi64( C, v256_64( 0x3C6EF372FE94F82B ) );
      r[3] = _mm256_add_epi64( D, v256_64( 0xA54FF53A5F1D36F1 ) );
      r[4] = _mm256_add_epi64( E, v256_64( 0x510E527FADE682D1 ) );
      r[5] = _mm256_add_epi64( F, v256_64( 0x9B05688C2B3E6C1F ) );
      r[6] = _mm256_add_epi64( G, v256_64( 0x1F83D9ABFB41BD6B ) );
      r[7] = _mm256_add_epi64( H, v256_64( 0x5BE0CD19137E2179 ) );
   }
}

void sha512_4x64_init( sha512_4x64_context *sc )
{
   sc->initialized = false;
   sc->count = 0;
}

void sha512_4x64_update( sha512_4x64_context *sc, const void *data, size_t len )
{
   __m256i *vdata = (__m256i*)data;
   size_t ptr;
   const int buf_size = 128;

   ptr = (unsigned)sc->count & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>3), vdata, clen>>3 );
      vdata = vdata + (clen>>3);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha512_4x64_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      sc->count += clen;
   }
}

void sha512_4x64_close( sha512_4x64_context *sc, void *dst )
{
    unsigned ptr;
    const int buf_size = 128;
    const int pad = buf_size - 16;

    ptr = (unsigned)sc->count & (buf_size - 1U);
    sc->buf[ ptr>>3 ] = v256_64( 0x80 );
    ptr += 8;
    if ( ptr > pad )
    {
         memset_zero_256( sc->buf + (ptr>>3), (buf_size - ptr) >> 3 );
         sha512_4x64_round( sc, sc->buf, sc->val );
         memset_zero_256( sc->buf, pad >> 3 );
    }
    else
         memset_zero_256( sc->buf + (ptr>>3), (pad - ptr) >> 3 );

    sc->buf[ pad >> 3 ] = v256_64( bswap_64( sc->count >> 61 ) );
    sc->buf[ ( pad+8 ) >> 3 ] = v256_64( bswap_64( sc->count <<  3 ) );
    sha512_4x64_round( sc, sc->buf, sc->val );

    mm256_block_bswap_64( dst, sc->val );
}

void sha512_4x64_ctx( sha512_4x64_context *sc, void *dst, const void *data,
                      size_t len )
{
 sha512_4x64_init( sc);
 sha512_4x64_update( sc, data,len );
 sha512_4x64_close( sc, dst );
}



#endif  // __AVX2__
        

// SHA512 2 way 64 SSE2 or NEON

#define BSG5_0_2x64( x )     v128_xor3( v128_ror64( x, 28 ), \
                                        v128_ror64( x, 34 ), \
                                        v128_ror64( x, 39 ) )

#define BSG5_1_2x64( x )     v128_xor3( v128_ror64( x, 14 ), \
                                        v128_ror64( x, 18 ), \
                                        v128_ror64( x, 41 ) )

#define SSG5_0_2x64( x )     v128_xor3( v128_ror64( x,  1 ), \
                                        v128_ror64( x,  8 ), \
                                        v128_sr64(  x,  7 ) )

#define SSG5_1_2x64( x )     v128_xor3( v128_ror64( x, 19 ), \
                                        v128_ror64( x, 61 ), \
                                        v128_sr64(  x,  6 ) )

#define CH_2x64(X, Y, Z) \
   v128_xor( v128_and( v128_xor( Y, Z ), X ), Z )

#define MAJ_2x64(X, Y, Z) \
  v128_xor( Y, v128_and( (X_xor_Y = v128_xor( X, Y ) ), Y_xor_Z ) )

#define SHA3_2x64_STEP( A, B, C, D, E, F, G, H, i ) \
do { \
  v128u64_t T0 = v128_add64( v128_64( K512[i] ), W[i] ); \
  v128u64_t T1 = BSG5_1_2x64( E ); \
  v128u64_t T2 = BSG5_0_2x64( A ); \
  T0 = v128_add64( T0, CH_2x64( E, F, G ) ); \
  T1 = v128_add64( T1, H ); \
  T2 = v128_add64( T2, MAJ_2x64( A, B, C ) ); \
  T1 = v128_add64( T1, T0 ); \
  Y_xor_Z = X_xor_Y; \
  D  = v128_add64( D,  T1 ); \
  H  = v128_add64( T1, T2 ); \
} while (0)

static void
sha512_2x64_round( sha512_2x64_context *ctx, v128u64_t *in, v128u64_t r[8] )
{
   int i;
   register v128u64_t A, B, C, D, E, F, G, H;
   v128u64_t X_xor_Y, Y_xor_Z;
   v128u64_t W[80];

   v128_block_bswap64( W  , in );
   v128_block_bswap64( W+8, in+8 );

   for ( i = 16; i < 80; i++ )
       W[i] = v128_add4_64( SSG5_0_2x64( W[i-15] ), SSG5_1_2x64( W[i-2] ),
                             W[ i- 7 ], W[ i-16 ] );

   A = r[0];
   B = r[1];
   C = r[2];
   D = r[3];
   E = r[4];
   F = r[5];
   G = r[6];
   H = r[7];

   Y_xor_Z = v128_xor( B, C );

   for ( i = 0; i < 80; i += 8 )
   {
      SHA3_2x64_STEP( A, B, C, D, E, F, G, H, i + 0 );
      SHA3_2x64_STEP( H, A, B, C, D, E, F, G, i + 1 );
      SHA3_2x64_STEP( G, H, A, B, C, D, E, F, i + 2 );
      SHA3_2x64_STEP( F, G, H, A, B, C, D, E, i + 3 );
      SHA3_2x64_STEP( E, F, G, H, A, B, C, D, i + 4 );
      SHA3_2x64_STEP( D, E, F, G, H, A, B, C, i + 5 );
      SHA3_2x64_STEP( C, D, E, F, G, H, A, B, i + 6 );
      SHA3_2x64_STEP( B, C, D, E, F, G, H, A, i + 7 );
   }

   r[0] = v128_add64( r[0], A );
   r[1] = v128_add64( r[1], B );
   r[2] = v128_add64( r[2], C );
   r[3] = v128_add64( r[3], D );
   r[4] = v128_add64( r[4], E );
   r[5] = v128_add64( r[5], F );
   r[6] = v128_add64( r[6], G );
   r[7] = v128_add64( r[7], H );
}

void sha512_2x64_init( sha512_2x64_context *sc )
{
   sc->val[0] = v128_64( 0x6A09E667F3BCC908 );
   sc->val[1] = v128_64( 0xBB67AE8584CAA73B );
   sc->val[2] = v128_64( 0x3C6EF372FE94F82B );
   sc->val[3] = v128_64( 0xA54FF53A5F1D36F1 );
   sc->val[4] = v128_64( 0x510E527FADE682D1 );
   sc->val[5] = v128_64( 0x9B05688C2B3E6C1F );
   sc->val[6] = v128_64( 0x1F83D9ABFB41BD6B );
   sc->val[7] = v128_64( 0x5BE0CD19137E2179 );
   sc->count = 0;
   sc->initialized = true;
}

void sha512_2x64_update( sha512_2x64_context *sc, const void *data, size_t len )
{
   v128u64_t *vdata = (v128u64_t*)data;
   size_t ptr;
   const int buf_size = 128;

   ptr = (unsigned)sc->count & (buf_size - 1U);
   while ( len > 0 )
   {
      size_t clen;
      clen = buf_size - ptr;
      if ( clen > len )
         clen = len;
      v128_memcpy( sc->buf + (ptr>>3), vdata, clen>>3 );
      vdata = vdata + (clen>>3);
      ptr += clen;
      len -= clen;
      if ( ptr == buf_size )
      {
         sha512_2x64_round( sc, sc->buf, sc->val );
         ptr = 0;
      }
      sc->count += clen;
   }
}

void sha512_2x64_close( sha512_2x64_context *sc, void *dst )
{
    unsigned ptr;
    const int buf_size = 128;
    const int pad = buf_size - 16;

    ptr = (unsigned)sc->count & (buf_size - 1U);
    sc->buf[ ptr>>3 ] = v128_64( 0x80 );
    ptr += 8;
    if ( ptr > pad )
    {
         v128_memset_zero( sc->buf + (ptr>>3), (buf_size - ptr) >> 3 );
         sha512_2x64_round( sc, sc->buf, sc->val );
         v128_memset_zero( sc->buf, pad >> 3 );
    }
    else
         v128_memset_zero( sc->buf + (ptr>>3), (pad - ptr) >> 3 );

    sc->buf[ pad >> 3 ] = v128_64( bswap_64( sc->count >> 61 ) );
    sc->buf[ ( pad+8 ) >> 3 ] = v128_64( bswap_64( sc->count << 3 ) );
    sha512_2x64_round( sc, sc->buf, sc->val );

    v128_block_bswap64( castp_v128u64( dst ), sc->val );
}

void sha512_2x64( void *dst, const void *data, size_t len )
{
   sha512_2x64_context sc;
   sha512_2x64_init( &sc );
   sha512_2x64_update( &sc, data, len );
   sha512_2x64_close( &sc, dst );
}

void sha512_2x64_ctx( sha512_2x64_context *sc, void *dst, const void *data,
                      size_t len )
{
   sha512_2x64_init( sc );
   sha512_2x64_update( sc, data, len );
   sha512_2x64_close( sc, dst );
}


