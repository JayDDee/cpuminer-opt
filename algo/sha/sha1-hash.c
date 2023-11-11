#include "simd-utils.h"
#include <stdint.h>
#include "sha1-hash.h"

#if defined(__x86_64__) && defined(__SHA__)

#define sha1_opt_rounds( state_out, data, state_in ) \
{ \
    __m128i ABCD, ABCD_SAVE, E0, E0_SAVE, E1; \
    __m128i MSG0, MSG1, MSG2, MSG3; \
\
    ABCD = _mm_load_si128( (const __m128i*) state_in ); \
    E0 = _mm_set_epi32( state_in[4], 0, 0, 0 ); \
    ABCD = _mm_shuffle_epi32( ABCD, 0x1B ); \
\
    ABCD_SAVE = ABCD; \
    E0_SAVE = E0; \
\
    /* Rounds 0-3 */ \
    MSG0 = load_msg( data, 0 ); \
    E0 = _mm_add_epi32( E0, MSG0 ); \
    E1 = ABCD; \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 0 ); \
\
    /* Rounds 4-7 */ \
    MSG1 = load_msg( data, 1 ); \
    E1 = _mm_sha1nexte_epu32( E1, MSG1 ); \
    E0 = ABCD; \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 0 ); \
    MSG0 = _mm_sha1msg1_epu32( MSG0, MSG1 ); \
\
    /* Rounds 8-11 */ \
    MSG2 = load_msg( data, 2 ); \
    E0 = _mm_sha1nexte_epu32( E0, MSG2 ); \
    E1 = ABCD; \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 0 ); \
    MSG1 = _mm_sha1msg1_epu32( MSG1, MSG2 ); \
    MSG0 = _mm_xor_si128( MSG0, MSG2 ); \
\
    /* Rounds 12-15 */ \
    MSG3 = load_msg( data, 3 ); \
    E1 = _mm_sha1nexte_epu32( E1, MSG3 ); \
    E0 = ABCD; \
    MSG0 = _mm_sha1msg2_epu32( MSG0, MSG3 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 0 ); \
    MSG2 = _mm_sha1msg1_epu32( MSG2, MSG3 ); \
    MSG1 = _mm_xor_si128( MSG1, MSG3 ); \
\
    /* Rounds 16-19 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG0 ); \
    E1 = ABCD; \
    MSG1 = _mm_sha1msg2_epu32( MSG1, MSG0 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 0 ); \
    MSG3 = _mm_sha1msg1_epu32( MSG3, MSG0 ); \
    MSG2 = _mm_xor_si128( MSG2, MSG0 ); \
\
    /* Rounds 20-23 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG1 ); \
    E0 = ABCD; \
    MSG2 = _mm_sha1msg2_epu32( MSG2, MSG1 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 1 ); \
    MSG0 = _mm_sha1msg1_epu32( MSG0, MSG1 ); \
    MSG3 = _mm_xor_si128( MSG3, MSG1 ); \
\
    /* Rounds 24-27 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG2 ); \
    E1 = ABCD; \
    MSG3 = _mm_sha1msg2_epu32( MSG3, MSG2 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 1 ); \
    MSG1 = _mm_sha1msg1_epu32( MSG1, MSG2 ); \
    MSG0 = _mm_xor_si128( MSG0, MSG2 ); \
\
    /* Rounds 28-31 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG3 ); \
    E0 = ABCD; \
    MSG0 = _mm_sha1msg2_epu32( MSG0, MSG3 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 1 ); \
    MSG2 = _mm_sha1msg1_epu32( MSG2, MSG3 ); \
    MSG1 = _mm_xor_si128( MSG1, MSG3 ); \
\
    /* Rounds 32-35 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG0 ); \
    E1 = ABCD; \
    MSG1 = _mm_sha1msg2_epu32( MSG1, MSG0 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 1 ); \
    MSG3 = _mm_sha1msg1_epu32( MSG3, MSG0 ); \
    MSG2 = _mm_xor_si128( MSG2, MSG0 ); \
\
    /* Rounds 36-39 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG1 ); \
    E0 = ABCD; \
    MSG2 = _mm_sha1msg2_epu32( MSG2, MSG1 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 1 ); \
    MSG0 = _mm_sha1msg1_epu32( MSG0, MSG1 ); \
    MSG3 = _mm_xor_si128( MSG3, MSG1 ); \
\
    /* Rounds 40-43 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG2 ); \
    E1 = ABCD; \
    MSG3 = _mm_sha1msg2_epu32( MSG3, MSG2 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 2 ); \
    MSG1 = _mm_sha1msg1_epu32( MSG1, MSG2 ); \
    MSG0 = _mm_xor_si128( MSG0, MSG2 ); \
\
    /* Rounds 44-47 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG3 ); \
    E0 = ABCD; \
    MSG0 = _mm_sha1msg2_epu32( MSG0, MSG3 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 2 ); \
    MSG2 = _mm_sha1msg1_epu32( MSG2, MSG3 ); \
    MSG1 = _mm_xor_si128( MSG1, MSG3 ); \
\
    /* Rounds 48-51 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG0 ); \
    E1 = ABCD; \
    MSG1 = _mm_sha1msg2_epu32( MSG1, MSG0 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 2 ); \
    MSG3 = _mm_sha1msg1_epu32( MSG3, MSG0 ); \
    MSG2 = _mm_xor_si128( MSG2, MSG0 ); \
    E0 = _mm_sha1nexte_epu32( E0, MSG0 ); \
    E1 = ABCD; \
    MSG1 = _mm_sha1msg2_epu32( MSG1, MSG0 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 2 ); \
    MSG3 = _mm_sha1msg1_epu32( MSG3, MSG0 ); \
    MSG2 = _mm_xor_si128( MSG2, MSG0 ); \
\
    /* Rounds 52-55 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG1 ); \
    E0 = ABCD; \
    MSG2 = _mm_sha1msg2_epu32( MSG2, MSG1 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 2 ); \
    MSG0 = _mm_sha1msg1_epu32( MSG0, MSG1 ); \
    MSG3 = _mm_xor_si128( MSG3, MSG1 ); \
\
    /* Rounds 56-59 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG2 ); \
    E1 = ABCD; \
    MSG3 = _mm_sha1msg2_epu32( MSG3, MSG2 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 2 ); \
    MSG1 = _mm_sha1msg1_epu32( MSG1, MSG2 ); \
    MSG0 = _mm_xor_si128( MSG0, MSG2 ); \
\
    /* Rounds 60-63 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG3 ); \
    E0 = ABCD; \
    MSG0 = _mm_sha1msg2_epu32( MSG0, MSG3 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 3 ); \
    MSG2 = _mm_sha1msg1_epu32( MSG2, MSG3 ); \
    MSG1 = _mm_xor_si128( MSG1, MSG3 ); \
\
    /* Rounds 64-67 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG0 ); \
    E1 = ABCD; \
    MSG1 = _mm_sha1msg2_epu32( MSG1, MSG0 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 3 ); \
    MSG3 = _mm_sha1msg1_epu32( MSG3, MSG0 ); \
    MSG2 = _mm_xor_si128( MSG2, MSG0 ); \
\
    /* Rounds 68-71 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG1 ); \
    E0 = ABCD; \
    MSG2 = _mm_sha1msg2_epu32( MSG2, MSG1 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 3 ); \
    MSG3 = _mm_xor_si128( MSG3, MSG1 ); \
\
    /* Rounds 72-75 */ \
    E0 = _mm_sha1nexte_epu32( E0, MSG2 ); \
    E1 = ABCD; \
    MSG3 = _mm_sha1msg2_epu32( MSG3, MSG2 ); \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E0, 3 ); \
\
    /* Rounds 76-79 */ \
    E1 = _mm_sha1nexte_epu32( E1, MSG3 ); \
    E0 = ABCD; \
    ABCD = _mm_sha1rnds4_epu32( ABCD, E1, 3 ); \
\
    /* Combine state */ \
    E0 = _mm_sha1nexte_epu32( E0, E0_SAVE ); \
    ABCD = _mm_add_epi32( ABCD, ABCD_SAVE ); \
\
    /* Save state */ \
    ABCD = _mm_shuffle_epi32( ABCD, 0x1B ); \
    _mm_store_si128( (__m128i*) state_out, ABCD ); \
    state_out[4] = _mm_extract_epi32( E0, 3 ); \
}


void sha1_x86_sha_transform_le( uint32_t *state_out, const void *input,
                                const uint32_t *state_in )
{
#define load_msg( m, i ) casti_v128( m, i )
   sha1_opt_rounds( state_out, input, state_in );
#undef load_msg
}

void sha1_x86_sha_transform_be( uint32_t *state_out, const void *input,
                                const uint32_t *state_in )
{
   const __m128i MASK = _mm_set_epi64x( 0x0001020304050607ULL,
                                        0x08090a0b0c0d0e0fULL );
#define load_msg( m, i ) _mm_shuffle_epi8( casti_v128( m, i ), MASK )
   sha1_opt_rounds( state_out, input, state_in );
#undef load_msg
}

#endif

#if defined(__aarch64__) && defined(__ARM_FEATURE_SHA2)

#define sha1_neon_rounds( state_out, data, state_in ) \
{ \
    uint32x4_t ABCD, ABCD_SAVED; \
    uint32x4_t TMP0, TMP1; \
    uint32x4_t MSG0, MSG1, MSG2, MSG3; \
    uint32_t   E0, E0_SAVED, E1; \
\
    /* Load state */ \
    ABCD = vld1q_u32( &state_in[0] ); \
    E0 = state_in[4]; \
\
    /* Save state */ \
    ABCD_SAVED = ABCD; \
    E0_SAVED = E0; \
\
    MSG0 = load_msg( data, 0 ); \
    MSG1 = load_msg( data, 1 ); \
    MSG2 = load_msg( data, 2 ); \
    MSG3 = load_msg( data, 3 ); \
\
    TMP0 = vaddq_u32( MSG0, vdupq_n_u32( 0x5A827999 ) ); \
    TMP1 = vaddq_u32( MSG1, vdupq_n_u32( 0x5A827999 ) ); \
\
    /* Rounds 0-3 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1cq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG2, vdupq_n_u32( 0x5A827999 ) ); \
    MSG0 = vsha1su0q_u32( MSG0, MSG1, MSG2 ); \
\
    /* Rounds 4-7 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1cq_u32(ABCD, E1, TMP1); \
    TMP1 = vaddq_u32( MSG3, vdupq_n_u32( 0x5A827999 ) ); \
    MSG0 = vsha1su1q_u32( MSG0, MSG3 ); \
    MSG1 = vsha1su0q_u32( MSG1, MSG2, MSG3 ); \
\
    /* Rounds 8-11 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1cq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG0, vdupq_n_u32( 0x5A827999 ) ); \
    MSG1 = vsha1su1q_u32( MSG1, MSG0 ); \
    MSG2 = vsha1su0q_u32( MSG2, MSG3, MSG0 ); \
\
    /* Rounds 12-15 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1cq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG1, vdupq_n_u32( 0x6ED9EBA1 ) ); \
    MSG2 = vsha1su1q_u32( MSG2, MSG1 ); \
    MSG3 = vsha1su0q_u32( MSG3, MSG0, MSG1 ); \
\
    /* Rounds 16-19 */\
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1cq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG2, vdupq_n_u32( 0x6ED9EBA1 ) ); \
    MSG3 = vsha1su1q_u32( MSG3, MSG2 ); \
    MSG0 = vsha1su0q_u32( MSG0, MSG1, MSG2 ); \
\
    /* Rounds 20-23 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG3, vdupq_n_u32( 0x6ED9EBA1 ) ); \
    MSG0 = vsha1su1q_u32( MSG0, MSG3 ); \
    MSG1 = vsha1su0q_u32( MSG1, MSG2, MSG3 ); \
\
    /* Rounds 24-27 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG0, vdupq_n_u32( 0x6ED9EBA1 ) ); \
    MSG1 = vsha1su1q_u32( MSG1, MSG0 ); \
    MSG2 = vsha1su0q_u32( MSG2, MSG3, MSG0 ); \
\
    /* Rounds 28-31 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG1, vdupq_n_u32( 0x6ED9EBA1 ) ); \
    MSG2 = vsha1su1q_u32( MSG2, MSG1 ); \
    MSG3 = vsha1su0q_u32( MSG3, MSG0, MSG1 ); \
\
    /* Rounds 32-35 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG2, vdupq_n_u32( 0x8F1BBCDC ) ); \
    MSG3 = vsha1su1q_u32( MSG3, MSG2 ); \
    MSG0 = vsha1su0q_u32( MSG0, MSG1, MSG2 ); \
\
    /* Rounds 36-39 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG3, vdupq_n_u32( 0x8F1BBCDC ) ); \
    MSG0 = vsha1su1q_u32( MSG0, MSG3 ); \
    MSG1 = vsha1su0q_u32( MSG1, MSG2, MSG3 ); \
\
    /* Rounds 40-43 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1mq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG0, vdupq_n_u32( 0x8F1BBCDC ) ); \
    MSG1 = vsha1su1q_u32( MSG1, MSG0 ); \
    MSG2 = vsha1su0q_u32( MSG2, MSG3, MSG0 ); \
\
    /* Rounds 44-47 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1mq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG1, vdupq_n_u32( 0x8F1BBCDC ) ); \
    MSG2 = vsha1su1q_u32( MSG2, MSG1 ); \
    MSG3 = vsha1su0q_u32( MSG3, MSG0, MSG1 ); \
\
    /* Rounds 48-51 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1mq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG2, vdupq_n_u32( 0x8F1BBCDC ) ); \
    MSG3 = vsha1su1q_u32( MSG3, MSG2 ); \
    MSG0 = vsha1su0q_u32( MSG0, MSG1, MSG2 ); \
\
    /* Rounds 52-55 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1mq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG3, vdupq_n_u32( 0xCA62C1D6 ) ); \
    MSG0 = vsha1su1q_u32( MSG0, MSG3 ); \
    MSG1 = vsha1su0q_u32( MSG1, MSG2, MSG3 ); \
\
    /* Rounds 56-59 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1mq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32( MSG0, vdupq_n_u32( 0xCA62C1D6 ) ); \
    MSG1 = vsha1su1q_u32( MSG1, MSG0 ); \
    MSG2 = vsha1su0q_u32( MSG2, MSG3, MSG0 ); \
\
    /* Rounds 60-63 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG1, vdupq_n_u32( 0xCA62C1D6 ) ); \
    MSG2 = vsha1su1q_u32( MSG2, MSG1 ); \
    MSG3 = vsha1su0q_u32( MSG3, MSG0, MSG1 ); \
\
    /* Rounds 64-67 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E0, TMP0 ); \
    TMP0 = vaddq_u32(MSG2, vdupq_n_u32( 0xCA62C1D6 ) ); \
    MSG3 = vsha1su1q_u32( MSG3, MSG2 ); \
    MSG0 = vsha1su0q_u32( MSG0, MSG1, MSG2 ); \
\
    /* Rounds 68-71 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
    TMP1 = vaddq_u32( MSG3, vdupq_n_u32( 0xCA62C1D6 ) ); \
    MSG0 = vsha1su1q_u32( MSG0, MSG3 ); \
\
    /* Rounds 72-75 */ \
    E1 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E0, TMP0 ); \
\
    /* Rounds 76-79 */ \
    E0 = vsha1h_u32( vgetq_lane_u32( ABCD, 0 ) ); \
    ABCD = vsha1pq_u32( ABCD, E1, TMP1 ); \
\
    /* Combine state */ \
    E0 += E0_SAVED; \
    ABCD = vaddq_u32( ABCD_SAVED, ABCD ); \
\
    /* Save state */ \
    vst1q_u32( &state_out[0], ABCD ); \
    state_out[4] = E0; \
}

void sha1_neon_sha_transform_be( uint32_t *state_out, const void *input,
                                 const uint32_t *state_in )
{
#define load_msg( m, i )  v128_bswap32( casti_v128( m, i ) );
   sha1_neon_rounds( state_out, input, state_in );
#undef load_msg
}

void sha1_neon_sha_transform_le( uint32_t *state_out, const void *input,
                                 const uint32_t *state_in )
{
#define load_msg( m, i )  casti_v128( m, i );
   sha1_neon_rounds( state_out, input, state_in );
#undef load_msg
}

#endif      
