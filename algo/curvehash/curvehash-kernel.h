#ifndef CURVEHASH_KERNEL_H__
#define CURVEHASH_KERNEL_H__ 1

#include <stdbool.h>
#include <stdint.h>

/*
 * The k*G subset of libsecp256k1 that curvehash actually needs, extracted so it
 * can be TUNED. No vendored type appears in this interface: callers see bytes.
 *
 * The tunable parts -- the ecmult_gen table scan, the window width, the point
 * addition and the inversion -- all live behind this header, in code we own.
 * The vendored tree stays pristine and serves as the differential oracle; never
 * edit it in place.
 */

/* Build the generator table. Idempotent, not thread-safe -- call once from
 * registration, before any worker thread exists. false on allocation failure. */
bool curvehash_kernel_init( void );

/* WARNING:WARNING: NOT SAFE FOR SIGNING OR ANY SECRET SCALAR. WARNING:WARNING:
 *
 * This kernel multiplies in VARIABLE TIME, in TWO independent ways: it indexes
 * the precomputed table directly, so the scalar leaks through the data cache,
 * and it adds points with secp256k1_gej_add_ge_var, which branches on the point
 * values. That is correct for curvehash, whose scalar is SHA-256 of a public
 * block header -- there is no secret and no attacker to time.
 *
 * If anything in this tree ever needs secp256k1 for a signature, a key
 * derivation, or any private key, use the pristine vendored library
 * (secp256k1_unity.c / the public secp256k1_* API), NOT this header. Reusing
 * this for a real key is a key-extraction bug, not merely a slow path.
 *
 * Set -DCURVEHASH_FORCE_CT_ECMULT to build the constant-time scan instead, and
 * -DCURVEHASH_FORCE_CT_ADD to restore upstream's constant-time point addition.
 * All are correct and produce identical points; they differ only in timing.
 * curvehash_kernel_config() reports which ones a binary carries, and -D prints
 * it.
 */

/* sec32 -> 65-byte uncompressed SEC point, 0x04 || X || Y.
 *
 * Returns 0 if sec32 is not a valid scalar (zero, or >= the group order n),
 * leaving out65 untouched. That is ~2^-128 per nonce and consensus asserts it
 * cannot happen, but the caller must skip the nonce rather than fabricate a
 * digest. */
int curvehash_kg65( unsigned char out65[65], const unsigned char sec32[32] );

/*
 * Nonces hashed in lockstep, so their modular inversions can be batched.
 *
 * Each round of curvehash ends in one Jacobian -> affine conversion, i.e. one
 * modular inversion, which is ~20% of a nonce. Montgomery's trick turns N of
 * them into 1 inversion + ~3(N-1) multiplications. The 8 rounds are still
 * strictly serial *within* a nonce; the parallelism is across nonces.
 *
 * CURVEHASH_LANES = 1 disables batching and restores the one-nonce-at-a-time
 * path exactly, which is the A/B baseline.
 *
 * 16 comes from a measured sweep of 1/2/4/8/16 on both arches at full thread
 * count, where returns diminish but never reverse; 8 is within a few percent if
 * a target ever turns out to be register-pressured.
 */
#ifndef CURVEHASH_LANES
#define CURVEHASH_LANES 16
#endif
#define CURVEHASH_MAX_LANES 16

/* For each lane whose bit is set in *active, compute sec32[l]*G into out65[l].
 * A lane whose scalar is invalid has its bit CLEARED and out65[l] left alone --
 * lanes drop out independently, they do not poison the batch. */
void curvehash_kg65_batch( unsigned char out65[][65],
                           const unsigned char sec32[][32],
                           int lanes, uint32_t *active );

/* Which field/scalar config THIS TU compiled to. Must be asked here: the
 * selection macros are visible only inside the TU that compiled the library,
 * so anything outside testing them reports the fallback and lies. */
const char *curvehash_kernel_config( void );

#endif
