#include "sha256-hash.h"

static const uint32_t SHA256_IV[8] =
{
   0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
   0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
};

#if defined(__SHA__)

void sha256_opt_transform_le( uint32_t *state_out, const void *input,
                              const uint32_t *state_in )
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i TMSG0, TMSG1, TMSG2, TMSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    // Load initial values
    TMP = _mm_load_si128((__m128i*) &state_in[0]);
    STATE1 = _mm_load_si128((__m128i*) &state_in[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1); // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B); // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8); // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

    // Save current hash
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    TMSG0 = _mm_load_si128((const __m128i*) (input+0));
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    TMSG1 = _mm_load_si128((const __m128i*) (input+16));
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);


    // Rounds 8-11
    TMSG2 = _mm_load_si128((const __m128i*) (input+32));
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 12-15
    TMSG3 = _mm_load_si128((const __m128i*) (input+48));
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 16-19
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 20-23
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

    // Rounds 24-27
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 28-31
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 32-35
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 36-39
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

    // Rounds 40-43
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 44-47
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 48-51
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 52-55
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Add values back to state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP = _mm_shuffle_epi32(STATE0, 0x1B); // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1); // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8); // ABEF

    // Save state
    _mm_store_si128((__m128i*) &state_out[0], STATE0);
    _mm_store_si128((__m128i*) &state_out[4], STATE1);
}


void sha256_opt_transform_be( uint32_t *state_out, const void *input,
                           const uint32_t *state_in )
{
    __m128i STATE0, STATE1;
    __m128i MSG, TMP, MASK;
    __m128i TMSG0, TMSG1, TMSG2, TMSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;

    // Load initial values
    TMP = _mm_load_si128((__m128i*) &state_in[0]);
    STATE1 = _mm_load_si128((__m128i*) &state_in[4]);
    MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    TMP = _mm_shuffle_epi32(TMP, 0xB1); // CDAB
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B); // EFGH
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8); // ABEF
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); // CDGH

    // Save current hash
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Rounds 0-3
    TMSG0 = _mm_load_si128((const __m128i*) (input+0));
    TMSG0 = _mm_shuffle_epi8( TMSG0, MASK );
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 4-7
    TMSG1 = _mm_load_si128((const __m128i*) (input+16));
    TMSG1 = _mm_shuffle_epi8(TMSG1, MASK);
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);
    // Rounds 8-11
    TMSG2 = _mm_load_si128((const __m128i*) (input+32));
    TMSG2 = _mm_shuffle_epi8(TMSG2, MASK);
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 12-15
    TMSG3 = _mm_load_si128((const __m128i*) (input+48));
    TMSG3 = _mm_shuffle_epi8(TMSG3, MASK);
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 16-19
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 20-23
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

    // Rounds 24-27
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 28-31
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 32-35
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 36-39
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG0 = _mm_sha256msg1_epu32(TMSG0, TMSG1);

    // Rounds 40-43
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG1 = _mm_sha256msg1_epu32(TMSG1, TMSG2);

    // Rounds 44-47
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG3, TMSG2, 4);
    TMSG0 = _mm_add_epi32(TMSG0, TMP);
    TMSG0 = _mm_sha256msg2_epu32(TMSG0, TMSG3);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG2 = _mm_sha256msg1_epu32(TMSG2, TMSG3);

    // Rounds 48-51
    MSG = _mm_add_epi32(TMSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG0, TMSG3, 4);
    TMSG1 = _mm_add_epi32(TMSG1, TMP);
    TMSG1 = _mm_sha256msg2_epu32(TMSG1, TMSG0);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);
    TMSG3 = _mm_sha256msg1_epu32(TMSG3, TMSG0);

    // Rounds 52-55
    MSG = _mm_add_epi32(TMSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG1, TMSG0, 4);
    TMSG2 = _mm_add_epi32(TMSG2, TMP);
    TMSG2 = _mm_sha256msg2_epu32(TMSG2, TMSG1);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 56-59
    MSG = _mm_add_epi32(TMSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    TMP = _mm_alignr_epi8(TMSG2, TMSG1, 4);
    TMSG3 = _mm_add_epi32(TMSG3, TMP);
    TMSG3 = _mm_sha256msg2_epu32(TMSG3, TMSG2);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Rounds 60-63
    MSG = _mm_add_epi32(TMSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
    STATE1 = _mm_sha256rnds2_epu32(STATE1, STATE0, MSG);
    MSG = _mm_shuffle_epi32(MSG, 0x0E);
    STATE0 = _mm_sha256rnds2_epu32(STATE0, STATE1, MSG);

    // Add values back to state
    STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
    STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

    TMP = _mm_shuffle_epi32(STATE0, 0x1B); // FEBA
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1); // DCHG
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); // DCBA
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8); // ABEF

    // Save state
    _mm_store_si128((__m128i*) &state_out[0], STATE0);
    _mm_store_si128((__m128i*) &state_out[4], STATE1);
}

// 2 way double buffered

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

// The next 2 functions work together to seperate the low frequency data
// (outer loop) from the high frequency data containing the nonce (inner loop)
// when hashing the second block (tail) of the first sha256 hash.
// The goal is to avoid any redundant processing in final. Prehash is almost
// 4 rounds total, only missing the final addition of the nonce.
// Nonce must be set to zero for prehash.
void sha256_ni_prehash_3rounds( uint32_t *ostate, const void *msg,
                                uint32_t *sstate, const uint32_t *istate )
{
   __m128i STATE0, STATE1, MSG, TMP;

   // Load initial values
   TMP    = casti_m128i( istate, 0 );
   STATE1 = casti_m128i( istate, 1 );

   TMP    = _mm_shuffle_epi32( TMP, 0xB1 );       // CDAB
   STATE1 = _mm_shuffle_epi32( STATE1, 0x1B );    // EFGH
   STATE0 = _mm_alignr_epi8( TMP, STATE1, 8 );    // ABEF
   STATE1 = _mm_blend_epi16( STATE1, TMP, 0xF0 ); // CDGH

   // Save current hash
   casti_m128i( sstate, 0 ) = STATE0;
   casti_m128i( sstate, 1 ) = STATE1;

   // Rounds 0 to 3
   MSG = casti_m128i( msg, 0 );
   TMP = _mm_set_epi64x( 0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL );
   MSG = _mm_add_epi32( MSG, TMP );
   STATE1 = _mm_sha256rnds2_epu32( STATE1, STATE0, MSG );
   MSG = _mm_shuffle_epi32( MSG, 0x0E );
   casti_m128i( ostate, 0 ) = _mm_sha256rnds2_epu32( STATE0, STATE1, MSG );
   casti_m128i( ostate, 1 ) = STATE1;
}

void sha256_ni2way_final_rounds( uint32_t *out_X, uint32_t *out_Y,
                 const void *msg_X, const void *msg_Y,
                 const uint32_t *state_mid_X, const uint32_t *state_mid_Y,
                 const uint32_t *state_save_X, const uint32_t *state_save_Y )
{
    __m128i STATE0_X, STATE1_X, STATE0_Y, STATE1_Y;
    __m128i MSG_X, MSG_Y, TMP_X, TMP_Y;
    __m128i TMSG0_X, TMSG1_X, TMSG2_X, TMSG3_X;
    __m128i TMSG0_Y, TMSG1_Y, TMSG2_Y, TMSG3_Y;

    STATE0_X = casti_m128i( state_mid_X, 0 );
    STATE1_X = casti_m128i( state_mid_X, 1 );
    STATE0_Y = casti_m128i( state_mid_Y, 0 );
    STATE1_Y = casti_m128i( state_mid_Y, 1 );

    // Add the nonces (msg[0] lane 3) to A & E (STATE0 lanes 1 & 3)
    TMSG0_X = casti_m128i( msg_X, 0 );
    TMSG0_Y = casti_m128i( msg_Y, 0 );
    TMP_X = mm128_xim_32( TMSG0_X, TMSG0_X, 0xd5 );
    TMP_Y = mm128_xim_32( TMSG0_Y, TMSG0_Y, 0xd5 );
    STATE0_X = _mm_add_epi32( STATE0_X, TMP_X );
    STATE0_Y = _mm_add_epi32( STATE0_Y, TMP_Y );

    // Rounds 4 to 7
    TMSG1_X = casti_m128i( msg_X, 1 );
    TMSG1_Y = casti_m128i( msg_Y, 1 );
    TMP_X = _mm_set_epi64x( 0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL );
    MSG_X = _mm_add_epi32( TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG0_X = _mm_sha256msg1_epu32( TMSG0_X, TMSG1_X );
    TMSG0_Y = _mm_sha256msg1_epu32( TMSG0_Y, TMSG1_Y );

    // Rounds 8 to 11, skip TMSG2, it's zero until round 22
    MSG_X = _mm_set_epi64x( 0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_X );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_X );

    // Rounds 12 to 15
    TMSG3_X = casti_m128i( msg_X, 3 );
    TMSG3_Y = casti_m128i( msg_Y, 3 );
    TMP_X = _mm_set_epi64x( 0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL );
    MSG_X = _mm_add_epi32( TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMSG0_X = _mm_sha256msg2_epu32( TMSG0_X, TMSG3_X );
    TMSG0_Y = _mm_sha256msg2_epu32( TMSG0_Y, TMSG3_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );

    // Rounds 16 to 19
    TMP_X = _mm_set_epi64x( 0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL );
    MSG_X = _mm_add_epi32( TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG0_X, TMSG3_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG0_Y, TMSG3_Y, 4 );
    TMSG1_X = _mm_add_epi32( TMSG1_X, TMP_X );
    TMSG1_Y = _mm_add_epi32( TMSG1_Y, TMP_Y );
    TMSG1_X = _mm_sha256msg2_epu32( TMSG1_X, TMSG0_X );
    TMSG1_Y = _mm_sha256msg2_epu32( TMSG1_Y, TMSG0_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG3_X = _mm_sha256msg1_epu32( TMSG3_X, TMSG0_X );
    TMSG3_Y = _mm_sha256msg1_epu32( TMSG3_Y, TMSG0_Y );

    // Rounds 20 to 23
    TMP_X = _mm_set_epi64x( 0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL );
    MSG_X = _mm_add_epi32( TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMSG2_X = _mm_alignr_epi8( TMSG1_X, TMSG0_X, 4 );
    TMSG2_Y = _mm_alignr_epi8( TMSG1_Y, TMSG0_Y, 4 );
    TMSG2_X = _mm_sha256msg2_epu32( TMSG2_X, TMSG1_X );
    TMSG2_Y = _mm_sha256msg2_epu32( TMSG2_Y, TMSG1_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG0_X = _mm_sha256msg1_epu32( TMSG0_X, TMSG1_X );
    TMSG0_Y = _mm_sha256msg1_epu32( TMSG0_Y, TMSG1_Y );

    // Rounds 24 to 27
    TMP_X = _mm_set_epi64x( 0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL );
    MSG_X = _mm_add_epi32( TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG2_X, TMSG1_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG2_Y, TMSG1_Y, 4 );
    TMSG3_X = _mm_add_epi32( TMSG3_X, TMP_X );
    TMSG3_Y = _mm_add_epi32( TMSG3_Y, TMP_Y );
    TMSG3_X = _mm_sha256msg2_epu32( TMSG3_X, TMSG2_X );
    TMSG3_Y = _mm_sha256msg2_epu32( TMSG3_Y, TMSG2_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG1_X = _mm_sha256msg1_epu32( TMSG1_X, TMSG2_X );
    TMSG1_Y = _mm_sha256msg1_epu32( TMSG1_Y, TMSG2_Y );

    // Rounds 28 to 31
    TMP_X = _mm_set_epi64x( 0x1429296706CA6351ULL,  0xD5A79147C6E00BF3ULL );
    MSG_X = _mm_add_epi32( TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG3_X, TMSG2_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG3_Y, TMSG2_Y, 4 );
    TMSG0_X = _mm_add_epi32( TMSG0_X, TMP_X );
    TMSG0_Y = _mm_add_epi32( TMSG0_Y, TMP_Y );
    TMSG0_X = _mm_sha256msg2_epu32( TMSG0_X, TMSG3_X );
    TMSG0_Y = _mm_sha256msg2_epu32( TMSG0_Y, TMSG3_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG2_X = _mm_sha256msg1_epu32( TMSG2_X, TMSG3_X );
    TMSG2_Y = _mm_sha256msg1_epu32( TMSG2_Y, TMSG3_Y );

    // Rounds 32 to 35
    TMP_X = _mm_set_epi64x( 0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL );
    MSG_X = _mm_add_epi32( TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG0_X, TMSG3_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG0_Y, TMSG3_Y, 4 );
    TMSG1_X = _mm_add_epi32( TMSG1_X, TMP_X );
    TMSG1_Y = _mm_add_epi32( TMSG1_Y, TMP_Y );
    TMSG1_X = _mm_sha256msg2_epu32( TMSG1_X, TMSG0_X );
    TMSG1_Y = _mm_sha256msg2_epu32( TMSG1_Y, TMSG0_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG3_X = _mm_sha256msg1_epu32( TMSG3_X, TMSG0_X );
    TMSG3_Y = _mm_sha256msg1_epu32( TMSG3_Y, TMSG0_Y );

    // Rounds 36 to 39
    TMP_X = _mm_set_epi64x( 0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL );
    MSG_X = _mm_add_epi32( TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG1_X, TMSG0_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG1_Y, TMSG0_Y, 4 );
    TMSG2_X = _mm_add_epi32( TMSG2_X, TMP_X );
    TMSG2_Y = _mm_add_epi32( TMSG2_Y, TMP_Y );
    TMSG2_X = _mm_sha256msg2_epu32( TMSG2_X, TMSG1_X );
    TMSG2_Y = _mm_sha256msg2_epu32( TMSG2_Y, TMSG1_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG0_X = _mm_sha256msg1_epu32( TMSG0_X, TMSG1_X );
    TMSG0_Y = _mm_sha256msg1_epu32( TMSG0_Y, TMSG1_Y );

    // Rounds 40 to 43
    TMP_X = _mm_set_epi64x( 0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL );
    MSG_X = _mm_add_epi32( TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG2_X, TMSG1_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG2_Y, TMSG1_Y, 4 );
    TMSG3_X = _mm_add_epi32( TMSG3_X, TMP_X );
    TMSG3_Y = _mm_add_epi32( TMSG3_Y, TMP_Y );
    TMSG3_X = _mm_sha256msg2_epu32( TMSG3_X, TMSG2_X );
    TMSG3_Y = _mm_sha256msg2_epu32( TMSG3_Y, TMSG2_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG1_X = _mm_sha256msg1_epu32( TMSG1_X, TMSG2_X );
    TMSG1_Y = _mm_sha256msg1_epu32( TMSG1_Y, TMSG2_Y );

    // Rounds 44 to 47
    TMP_X = _mm_set_epi64x( 0x106AA070F40E3585ULL, 0xD6990624D192E819ULL );
    MSG_X = _mm_add_epi32( TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG3_X, TMSG2_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG3_Y, TMSG2_Y, 4 );
    TMSG0_X = _mm_add_epi32( TMSG0_X, TMP_X );
    TMSG0_Y = _mm_add_epi32( TMSG0_Y, TMP_Y );
    TMSG0_X = _mm_sha256msg2_epu32( TMSG0_X, TMSG3_X );
    TMSG0_Y = _mm_sha256msg2_epu32( TMSG0_Y, TMSG3_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG2_X = _mm_sha256msg1_epu32( TMSG2_X, TMSG3_X );
    TMSG2_Y = _mm_sha256msg1_epu32( TMSG2_Y, TMSG3_Y );

    // Rounds 48 to 51
    TMP_X = _mm_set_epi64x( 0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL );
    MSG_X = _mm_add_epi32( TMSG0_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG0_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG0_X, TMSG3_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG0_Y, TMSG3_Y, 4 );
    TMSG1_X = _mm_add_epi32( TMSG1_X, TMP_X );
    TMSG1_Y = _mm_add_epi32( TMSG1_Y, TMP_Y );
    TMSG1_X = _mm_sha256msg2_epu32( TMSG1_X, TMSG0_X );
    TMSG1_Y = _mm_sha256msg2_epu32( TMSG1_Y, TMSG0_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );
    TMSG3_X = _mm_sha256msg1_epu32( TMSG3_X, TMSG0_X );
    TMSG3_Y = _mm_sha256msg1_epu32( TMSG3_Y, TMSG0_Y );

    // Rounds 52 to 55
    TMP_X = _mm_set_epi64x( 0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL );
    MSG_X = _mm_add_epi32( TMSG1_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG1_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG1_X, TMSG0_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG1_Y, TMSG0_Y, 4 );
    TMSG2_X = _mm_add_epi32( TMSG2_X, TMP_X );
    TMSG2_Y = _mm_add_epi32( TMSG2_Y, TMP_Y );
    TMSG2_X = _mm_sha256msg2_epu32( TMSG2_X, TMSG1_X );
    TMSG2_Y = _mm_sha256msg2_epu32( TMSG2_Y, TMSG1_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );

    // Rounds 56 to 59
    TMP_X = _mm_set_epi64x( 0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL );
    MSG_X = _mm_add_epi32( TMSG2_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG2_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    TMP_X = _mm_alignr_epi8( TMSG2_X, TMSG1_X, 4 );
    TMP_Y = _mm_alignr_epi8( TMSG2_Y, TMSG1_Y, 4 );
    TMSG3_X = _mm_add_epi32( TMSG3_X, TMP_X );
    TMSG3_Y = _mm_add_epi32( TMSG3_Y, TMP_Y );
    TMSG3_X = _mm_sha256msg2_epu32( TMSG3_X, TMSG2_X );
    TMSG3_Y = _mm_sha256msg2_epu32( TMSG3_Y, TMSG2_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );

    // Rounds 60 to 63
    TMP_X = _mm_set_epi64x( 0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL );
    MSG_X = _mm_add_epi32( TMSG3_X, TMP_X );
    MSG_Y = _mm_add_epi32( TMSG3_Y, TMP_X );
    STATE1_X = _mm_sha256rnds2_epu32( STATE1_X, STATE0_X, MSG_X );
    STATE1_Y = _mm_sha256rnds2_epu32( STATE1_Y, STATE0_Y, MSG_Y );
    MSG_X = _mm_shuffle_epi32( MSG_X, 0x0E );
    MSG_Y = _mm_shuffle_epi32( MSG_Y, 0x0E );
    STATE0_X = _mm_sha256rnds2_epu32( STATE0_X, STATE1_X, MSG_X );
    STATE0_Y = _mm_sha256rnds2_epu32( STATE0_Y, STATE1_Y, MSG_Y );

    // Add saved state to new state
    STATE0_X = _mm_add_epi32( STATE0_X, casti_m128i( state_save_X, 0 ) );
    STATE1_X = _mm_add_epi32( STATE1_X, casti_m128i( state_save_X, 1 ) );
    STATE0_Y = _mm_add_epi32( STATE0_Y, casti_m128i( state_save_Y, 0 ) );
    STATE1_Y = _mm_add_epi32( STATE1_Y, casti_m128i( state_save_Y, 1 ) );

    // Unshuffle & save state    
    TMP_X = _mm_shuffle_epi32( STATE0_X, 0x1B );                        // FEBA
    TMP_Y = _mm_shuffle_epi32( STATE0_Y, 0x1B );
    STATE1_X = _mm_shuffle_epi32( STATE1_X, 0xB1 );                     // DCHG
    STATE1_Y = _mm_shuffle_epi32( STATE1_Y, 0xB1 );
    casti_m128i( out_X, 0 ) = _mm_blend_epi16( TMP_X, STATE1_X, 0xF0 ); // DCBA
    casti_m128i( out_Y, 0 ) = _mm_blend_epi16( TMP_Y, STATE1_Y, 0xF0 );
    casti_m128i( out_X, 1 ) = _mm_alignr_epi8( STATE1_X, TMP_X, 8 );    // ABEF
    casti_m128i( out_Y, 1 ) = _mm_alignr_epi8( STATE1_Y, TMP_Y, 8 );
}

#endif


void sha256_ctx_init( sha256_context *ctx )
{
   memcpy( ctx->state, SHA256_IV, sizeof SHA256_IV );
   ctx->count = 0;
}

void sha256_update( sha256_context *ctx, const void *data, size_t len )
{
   int ptr = ctx->count & 0x3f;
   const uint8_t *src = data;

   ctx->count += (uint64_t)len;

   if ( len < 64 - ptr )
   {
      memcpy( ctx->buf + ptr, src, len );
      return;
   }

   memcpy( ctx->buf + ptr, src, 64 - ptr );
   sha256_transform_be( ctx->state, (uint32_t*)ctx->buf, ctx->state );
   src += 64 - ptr;
   len -= 64 - ptr;

   while ( len >= 64 )
   {
      sha256_transform_be( ctx->state, (uint32_t*)src, ctx->state );
      src += 64;
      len -= 64;
   }

   memcpy( ctx->buf, src, len );
}

void sha256_final( sha256_context *ctx, void *hash )
{
   int ptr = ctx->count & 0x3f;

   ctx->buf[ ptr++ ] = 0x80;
   
   if ( ptr > 56 )
   {
      memset( ctx->buf + ptr, 0, 64 - ptr );
      sha256_transform_be( ctx->state, (uint32_t*)ctx->buf, ctx->state );
      memset( ctx->buf, 0, 56 );
   }
   else
      memset( ctx->buf + ptr, 0, 56 - ptr );

   *(uint64_t*)(&ctx->buf[56]) = bswap_64( ctx->count << 3 );   

   sha256_transform_be( ctx->state, (uint32_t*)ctx->buf, ctx->state );

   for ( int i = 0; i < 8; i++ )
      ( (uint32_t*)hash )[i] = bswap_32( ctx->state[i] );
}

void sha256_full( void *hash, const void *data, size_t len )
{
   sha256_context ctx;
   sha256_ctx_init( &ctx );
   sha256_update( &ctx, data, len );
   sha256_final( &ctx, hash );
}

