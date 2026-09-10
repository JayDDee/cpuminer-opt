/*
 * Unity build of the vendored libsecp256k1 (MIT) for the curvehash PoW.
 *
 * WARNING: This is NO LONGER on the hot path. Mining runs curvehash-kernel.c, the
 * extracted k*G subset, which is the file that gets tuned. This TU is kept
 * because it is the *pristine* public API: curvehash_self_test() runs random
 * scalars through both and requires identical points, so the untouched
 * upstream library is the differential oracle for the code we tune.
 *
 * The field/scalar selection lives in secp256k1-config.h, shared with the
 * kernel so the oracle and the thing it checks cannot drift onto different
 * limb widths.
 */

#include "secp256k1-config.h"

#include "secp256k1/src/secp256k1.c"

/* Which config actually got compiled. The selection macros are visible only
 * inside this TU, so anything outside testing them reports the #else branch
 * and lies -- ask here instead. */
const char *curvehash_secp256k1_config( void )
{
   return CURVEHASH_SECP256K1_CONFIG;
}
