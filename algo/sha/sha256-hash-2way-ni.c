/*   Intel SHA extensions using C intrinsics               */
/*   Written and place in public domain by Jeffrey Walton  */
/*   Based on code from Intel, and by Sean Gulley for      */
/*   the miTLS project.                                    */

// A stripped down version with byte swapping removed. 

#if defined(__SHA__)

#include "sha256-hash.h"

void sha256_ni2way_transform_le( uint32_t *out_X, uint32_t*out_Y,
                              const void *msg_X, const void *msg_Y,
                              const uint32_t *in_X, const uint32_t *in_Y )
{
    __m128i STATE0_X, STATE1_X, STATE0_Y, STATE1_Y;
    __m128i MSG_X, MSG_Y, TMP_X, TMP_Y;
    __m128i TMSG0_X, TMSG1_X, TMSG2_X, TMSG3_X;
    __m128i TMSG0_Y, TMSG1_Y, TMSG2_Y, TMSG3_Y;
    __m128i ABEF_SAVE_X, CDGH_SAVE_X,ABEF_SAVE_Y, CDGH_SAVE_Y;

    // Load initial values
    TMP_X = _mm_load_si128((__m128i*) &in_X[0]);
    STATE1_X = _mm_load_si128((__m128i*) &in_X[4]);
    TMP_Y = _mm_load_si128((__m128i*) &in_Y[0]);
    STATE1_Y = _mm_load_si128((__m128i*) &in_Y[4]);

    TMP_X = _mm_shuffle_epi32(TMP_X, 0xB1); // CDAB
    TMP_Y = _mm_shuffle_epi32(TMP_Y, 0xB1); // CDAB
    STATE1_X = _mm_shuffle_epi32(STATE1_X, 0x1B); // EFGH
    STATE1_Y = _mm_shuffle_epi32(STATE1_Y, 0x1B); // EFGH
    STATE0_X = _mm_alignr_epi8(TMP_X, STATE1_X, 8); // ABEF
    STATE0_Y = _mm_alignr_epi8(TMP_Y, STATE1_Y, 8); // ABEF
    STATE1_X = _mm_blend_epi16(STATE1_X, TMP_X, 0xF0); // CDGH
    STATE1_Y = _mm_blend_epi16(STATE1_Y, TMP_Y, 0xF0); // CDGH

    // Save current hash
    ABEF_SAVE_X = STATE0_X;
    ABEF_SAVE_Y = STATE0_Y;
    CDGH_SAVE_X = STATE1_X;
    CDGH_SAVE_Y = STATE1_Y;

    // Rounds 0-3
    TMSG0_X = _mm_load_si128((const __m128i*) (msg_X));
    TMSG0_Y = _mm_load_si128((const __m128i*) (msg_Y));
    TMP_X = _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL);
    MSG_X = _mm_add_epi32( TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 4-7
    TMSG1_X = _mm_load_si128((const __m128i*) (msg_X+16));
    TMSG1_Y = _mm_load_si128((const __m128i*) (msg_Y+16));
    TMP_X = _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 8-11
    TMSG2_X = _mm_load_si128((const __m128i*) (msg_X+32));
    TMSG2_Y = _mm_load_si128((const __m128i*) (msg_Y+32));
    TMP_X = _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 12-15
    TMSG3_X = _mm_load_si128((const __m128i*) (msg_X+48));
    TMSG3_Y = _mm_load_si128((const __m128i*) (msg_Y+48));
    TMP_X = _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 16-19
    TMP_X = _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 20-23
    TMP_X = _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 24-27
    TMP_X = _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 28-31
    TMP_X = _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 32-35
    TMP_X = _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 36-39
    TMP_X = _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 40-43
    TMP_X = _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 44-47
    TMP_X = _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 48-51
    TMP_X = _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 52-55
    TMP_X = _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 56-59
    TMP_X = _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 60-63
    TMP_X = _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Add values back to state
    STATE0_X = _mm_add_epi32(STATE0_X, ABEF_SAVE_X);
    STATE1_X = _mm_add_epi32(STATE1_X, CDGH_SAVE_X);
    STATE0_Y = _mm_add_epi32(STATE0_Y, ABEF_SAVE_Y);
    STATE1_Y = _mm_add_epi32(STATE1_Y, CDGH_SAVE_Y);

    TMP_X = _mm_shuffle_epi32(STATE0_X, 0x1B); // FEBA
    TMP_Y = _mm_shuffle_epi32(STATE0_Y, 0x1B); // FEBA
    STATE1_X = _mm_shuffle_epi32(STATE1_X, 0xB1); // DCHG
    STATE1_Y = _mm_shuffle_epi32(STATE1_Y, 0xB1); // DCHG
    STATE0_X = _mm_blend_epi16(TMP_X, STATE1_X, 0xF0); // DCBA
    STATE0_Y = _mm_blend_epi16(TMP_Y, STATE1_Y, 0xF0); // DCBA
    STATE1_X = _mm_alignr_epi8(STATE1_X, TMP_X, 8); // ABEF
    STATE1_Y = _mm_alignr_epi8(STATE1_Y, TMP_Y, 8); // ABEF

    // Save state
    _mm_store_si128((__m128i*) &out_X[0], STATE0_X);
    _mm_store_si128((__m128i*) &out_X[4], STATE1_X);
    _mm_store_si128((__m128i*) &out_Y[0], STATE0_Y);
    _mm_store_si128((__m128i*) &out_Y[4], STATE1_Y);
}

void sha256_ni2way_transform_be( uint32_t *out_X, uint32_t*out_Y,
                              const void *msg_X, const void *msg_Y,
                              const uint32_t *in_X, const uint32_t *in_Y )
{
    __m128i STATE0_X, STATE1_X, STATE0_Y, STATE1_Y;
    __m128i MSG_X, MSG_Y, TMP_X, TMP_Y, MASK;
    __m128i TMSG0_X, TMSG1_X, TMSG2_X, TMSG3_X;
    __m128i TMSG0_Y, TMSG1_Y, TMSG2_Y, TMSG3_Y;
    __m128i ABEF_SAVE_X, CDGH_SAVE_X, ABEF_SAVE_Y, CDGH_SAVE_Y;

    // Load initial values
    TMP_X = _mm_load_si128((__m128i*) &in_X[0]);
    STATE1_X = _mm_load_si128((__m128i*) &in_X[4]);
    TMP_Y = _mm_load_si128((__m128i*) &in_Y[0]);
    STATE1_Y = _mm_load_si128((__m128i*) &in_Y[4]);
    MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP_X = _mm_shuffle_epi32(TMP_X, 0xB1); // CDAB
    TMP_Y = _mm_shuffle_epi32(TMP_Y, 0xB1); // CDAB
    STATE1_X = _mm_shuffle_epi32(STATE1_X, 0x1B); // EFGH
    STATE1_Y = _mm_shuffle_epi32(STATE1_Y, 0x1B); // EFGH
    STATE0_X = _mm_alignr_epi8(TMP_X, STATE1_X, 8); // ABEF
    STATE0_Y = _mm_alignr_epi8(TMP_Y, STATE1_Y, 8); // ABEF
    STATE1_X = _mm_blend_epi16(STATE1_X, TMP_X, 0xF0); // CDGH
    STATE1_Y = _mm_blend_epi16(STATE1_Y, TMP_Y, 0xF0); // CDGH

    // Save current hash
    ABEF_SAVE_X = STATE0_X;
    ABEF_SAVE_Y = STATE0_Y;
    CDGH_SAVE_X = STATE1_X;
    CDGH_SAVE_Y = STATE1_Y;

    // Rounds 0-3
    TMSG0_X = _mm_load_si128((const __m128i*) (msg_X));
    TMSG0_Y = _mm_load_si128((const __m128i*) (msg_Y));
    TMP_X = _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL);
    TMSG0_X = _mm_shuffle_epi8( TMSG0_X, MASK );
    TMSG0_Y = _mm_shuffle_epi8( TMSG0_Y, MASK );
    MSG_X = _mm_add_epi32( TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 4-7
    TMSG1_X = _mm_load_si128((const __m128i*) (msg_X+16));
    TMSG1_Y = _mm_load_si128((const __m128i*) (msg_Y+16));
    TMP_X = _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL);
    TMSG1_X = _mm_shuffle_epi8( TMSG1_X, MASK );
    TMSG1_Y = _mm_shuffle_epi8( TMSG1_Y, MASK );
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 8-11
    TMSG2_X = _mm_load_si128((const __m128i*) (msg_X+32));
    TMSG2_Y = _mm_load_si128((const __m128i*) (msg_Y+32));
    TMP_X = _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL);
    TMSG2_X = _mm_shuffle_epi8( TMSG2_X, MASK );
    TMSG2_Y = _mm_shuffle_epi8( TMSG2_Y, MASK );
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 12-15
    TMSG3_X = _mm_load_si128((const __m128i*) (msg_X+48));
    TMSG3_Y = _mm_load_si128((const __m128i*) (msg_Y+48));
    TMP_X = _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL);
    TMSG3_X = _mm_shuffle_epi8( TMSG3_X, MASK );
    TMSG3_Y = _mm_shuffle_epi8( TMSG3_Y, MASK );
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 16-19
    TMP_X = _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 20-23
    TMP_X = _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 24-27
    TMP_X = _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 28-31
    TMP_X = _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 32-35
    TMP_X = _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 36-39
    TMP_X = _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG0_X = _mm_sha256msg1_epu32(TMSG0_X, TMSG1_X);
    TMSG0_Y = _mm_sha256msg1_epu32(TMSG0_Y, TMSG1_Y);

    // Rounds 40-43
    TMP_X = _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG1_X = _mm_sha256msg1_epu32(TMSG1_X, TMSG2_X);
    TMSG1_Y = _mm_sha256msg1_epu32(TMSG1_Y, TMSG2_Y);

    // Rounds 44-47
    TMP_X = _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG3_X, TMSG2_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG3_Y, TMSG2_Y, 4);
    TMSG0_X = _mm_add_epi32(TMSG0_X, TMP_X);
    TMSG0_Y = _mm_add_epi32(TMSG0_Y, TMP_Y);
    TMSG0_X = _mm_sha256msg2_epu32(TMSG0_X, TMSG3_X);
    TMSG0_Y = _mm_sha256msg2_epu32(TMSG0_Y, TMSG3_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG2_X = _mm_sha256msg1_epu32(TMSG2_X, TMSG3_X);
    TMSG2_Y = _mm_sha256msg1_epu32(TMSG2_Y, TMSG3_Y);

    // Rounds 48-51
    TMP_X = _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL);
    MSG_X = _mm_add_epi32(TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG0_X, TMSG3_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG0_Y, TMSG3_Y, 4);
    TMSG1_X = _mm_add_epi32(TMSG1_X, TMP_X);
    TMSG1_Y = _mm_add_epi32(TMSG1_Y, TMP_Y);
    TMSG1_X = _mm_sha256msg2_epu32(TMSG1_X, TMSG0_X);
    TMSG1_Y = _mm_sha256msg2_epu32(TMSG1_Y, TMSG0_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);
    TMSG3_X = _mm_sha256msg1_epu32(TMSG3_X, TMSG0_X);
    TMSG3_Y = _mm_sha256msg1_epu32(TMSG3_Y, TMSG0_Y);

    // Rounds 52-55
    TMP_X = _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL);
    MSG_X = _mm_add_epi32(TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32(TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG1_X, TMSG0_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG1_Y, TMSG0_Y, 4);
    TMSG2_X = _mm_add_epi32(TMSG2_X, TMP_X);
    TMSG2_Y = _mm_add_epi32(TMSG2_Y, TMP_Y);
    TMSG2_X = _mm_sha256msg2_epu32(TMSG2_X, TMSG1_X);
    TMSG2_Y = _mm_sha256msg2_epu32(TMSG2_Y, TMSG1_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 56-59
    TMP_X = _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL);
    MSG_X = _mm_add_epi32(TMSG2_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG2_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    TMP_X = _mm_alignr_epi8(TMSG2_X, TMSG1_X, 4);
    TMP_Y = _mm_alignr_epi8(TMSG2_Y, TMSG1_Y, 4);
    TMSG3_X = _mm_add_epi32(TMSG3_X, TMP_X);
    TMSG3_Y = _mm_add_epi32(TMSG3_Y, TMP_Y);
    TMSG3_X = _mm_sha256msg2_epu32(TMSG3_X, TMSG2_X);
    TMSG3_Y = _mm_sha256msg2_epu32(TMSG3_Y, TMSG2_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Rounds 60-63
    TMP_X = _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL);
    MSG_X = _mm_add_epi32(TMSG3_X, TMP_X);
    MSG_Y = _mm_add_epi32(TMSG3_Y, TMP_X);
    STATE1_X = _mm_sha256rnds2_epu32(STATE1_X, STATE0_X, MSG_X);
    STATE1_Y = _mm_sha256rnds2_epu32(STATE1_Y, STATE0_Y, MSG_Y);
    MSG_X = _mm_shuffle_epi32(MSG_X, 0x0E);
    MSG_Y = _mm_shuffle_epi32(MSG_Y, 0x0E);
    STATE0_X = _mm_sha256rnds2_epu32(STATE0_X, STATE1_X, MSG_X);
    STATE0_Y = _mm_sha256rnds2_epu32(STATE0_Y, STATE1_Y, MSG_Y);

    // Add values back to state
    STATE0_X = _mm_add_epi32(STATE0_X, ABEF_SAVE_X);
    STATE1_X = _mm_add_epi32(STATE1_X, CDGH_SAVE_X);
    STATE0_Y = _mm_add_epi32(STATE0_Y, ABEF_SAVE_Y);
    STATE1_Y = _mm_add_epi32(STATE1_Y, CDGH_SAVE_Y);

    TMP_X = _mm_shuffle_epi32(STATE0_X, 0x1B); // FEBA
    TMP_Y = _mm_shuffle_epi32(STATE0_Y, 0x1B); // FEBA
    STATE1_X = _mm_shuffle_epi32(STATE1_X, 0xB1); // DCHG
    STATE1_Y = _mm_shuffle_epi32(STATE1_Y, 0xB1); // DCHG
    STATE0_X = _mm_blend_epi16(TMP_X, STATE1_X, 0xF0); // DCBA
    STATE0_Y = _mm_blend_epi16(TMP_Y, STATE1_Y, 0xF0); // DCBA
    STATE1_X = _mm_alignr_epi8(STATE1_X, TMP_X, 8); // ABEF
    STATE1_Y = _mm_alignr_epi8(STATE1_Y, TMP_Y, 8); // ABEF

    // Save state
    _mm_store_si128((__m128i*) &out_X[0], STATE0_X);
    _mm_store_si128((__m128i*) &out_X[4], STATE1_X);
    _mm_store_si128((__m128i*) &out_Y[0], STATE0_Y);
    _mm_store_si128((__m128i*) &out_Y[4], STATE1_Y);
}


#endif

