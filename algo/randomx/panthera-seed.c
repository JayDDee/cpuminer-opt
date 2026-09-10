/* Panthera (Scala) seed post-processing.
 *
 * Panthera is RandomX with its own constants PLUS two extra stages applied to
 * the initial seed: yespower, then KangarooTwelve. They run where tempHash is
 * derived from an INPUT -- between the blake2b of that input and the
 * scratchpad fill -- and never on the in-loop blake2b of the register file.
 * randomx.cpp calls this through RANDOMX_SEED_HOOK, which config/panthera.h
 * defines and which expands to nothing for every other core.
 *
 * BUFFER SEMANTICS ARE CONSENSUS. seed is 64 bytes and each stage writes only
 * 32, so the result is
 *     k12( yespower( blake2b(input) ) )   in bytes 0..31
 *     blake2b(input) unchanged            in bytes 32..63
 * and initScratchpad then reads all 64. Treating the seed as 32 bytes, or
 * zeroing the tail, changes the hash. Upstream reaches this by passing the
 * same pointer as both source and destination; that aliasing is deliberate.
 */

#include <stdint.h>
#include <stddef.h>

#include "algo/yespower/yespower.h"
#include "algo/k12/KangarooTwelve.h"

void randomx_panthera_seed( void *seed, size_t len )
{
   /* N and r are Panthera's, from its yespower_k12_blake3.c. pers is NULL. */
   static const yespower_params_t params =
      { YESPOWER_1_0, 2048, 8, NULL, 0 };

   /* yespower_tls_ref, not yespower_tls: the optimised entry point indexes
    * the global work_restart[] by thread id to poll for an early abort, and
    * this hook runs deep inside the core with no thread id to give it --
    * work_restart is also a pointer that is NULL during registration, so the
    * self-test would fault. The reference implementation touches neither.
    * Writes 32 bytes; bytes 32..63 of seed are left alone by design. */
   yespower_tls_ref( (const uint8_t *)seed, len, &params,
                     (yespower_binary_t *)seed, 0 );

   /* 32-byte output, no customisation string. Also writes only 32 bytes. */
   KangarooTwelve( (const unsigned char *)seed, len,
                   (unsigned char *)seed, 32, 0, 0 );
}
