/* Two nonces' clhash, the 32 iterations interleaved so one lane's stalls are
 * filled with the other lane's work. Body #included from verus_clhash_iter.h,
 * shared verbatim with the single-lane path. Enabled by VRS_LANES in
 * verus-gate.c, which carries the measurements. */
#include "verus-simd.h"
#if defined(VERUS_HAVE_SIMD)

#include "verus_clhash.h"
#include <string.h>

void verusclhash_2way( void *random0, const unsigned char buf0[64],
                       void *random1, const unsigned char buf1[64],
                       uint64_t keymask,
                       uint32_t *fixrand0, uint32_t *fixrandex0,
                       u128 *g_prand0, u128 *g_prandex0,
                       uint32_t *fixrand1, uint32_t *fixrandex1,
                       u128 *g_prand1, u128 *g_prandex1,
                       uint64_t out[2] )
{
   __m128i *rs0 = (__m128i*)random0;
   __m128i *rs1 = (__m128i*)random1;
   const __m128i *b0 = (const __m128i*)buf0;
   const __m128i *b1 = (const __m128i*)buf1;

   const __m128i pbuf_copy0[4] = { _mm_xor_si128( b0[0], b0[2] ),
                                   _mm_xor_si128( b0[1], b0[3] ), b0[2], b0[3] };
   const __m128i pbuf_copy1[4] = { _mm_xor_si128( b1[0], b1[2] ),
                                   _mm_xor_si128( b1[1], b1[3] ), b1[2], b1[3] };

   __m128i acc0 = _mm_load_si128( rs0 + ( keymask + 2 ) );
   __m128i acc1 = _mm_load_si128( rs1 + ( keymask + 2 ) );

   /* each block supplies the names verus_clhash_iter.h reads, as plain locals */
   for ( int64_t i = 0; i < 32; i++ )
   {
      {
         __m128i *randomsource     = rs0;
         const uint64_t keyMask    = keymask;
         const __m128i *pbuf_copy  = pbuf_copy0;
         uint32_t *fixrand         = fixrand0;
         uint32_t *fixrandex       = fixrandex0;
         u128 *g_prand             = g_prand0;
         u128 *g_prandex           = g_prandex0;
         __m128i acc               = acc0;
#        include "verus_clhash_iter.h"
         acc0 = acc;
      }
      {
         __m128i *randomsource     = rs1;
         const uint64_t keyMask    = keymask;
         const __m128i *pbuf_copy  = pbuf_copy1;
         uint32_t *fixrand         = fixrand1;
         uint32_t *fixrandex       = fixrandex1;
         u128 *g_prand             = g_prand1;
         u128 *g_prandex           = g_prandex1;
         __m128i acc               = acc1;
#        include "verus_clhash_iter.h"
         acc1 = acc;
      }
   }

   out[0] = precompReduction64( _mm_xor_si128( acc0, lazyLengthHash( 1024, 64 ) ) );
   out[1] = precompReduction64( _mm_xor_si128( acc1, lazyLengthHash( 1024, 64 ) ) );
}

#endif /* VERUS_HAVE_SIMD */
