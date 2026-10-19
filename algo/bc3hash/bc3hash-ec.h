/* bc3hash's elliptic-curve kernel: sums of precomputed secp256k1 table points.
 *
 * Built on libsecp256k1's internals (vendored under secp256k1/, see
 * VENDOR.md), not its public API, so a sum of several points pays one
 * variable-time affine conversion, and several sums can share one. Plain C
 * types only: the C++ core includes this, not the library headers. */
#ifndef BC3HASH_EC_H__
#define BC3HASH_EC_H__ 1

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One table entry: an affine point in libsecp's 64-byte storage form. */
#define BC3EC_ENTRY_BYTES 64
/* Most points in one sum: 26 digits at the smallest window (10). */
#define BC3EC_MAX_POINTS 26
/* Most sums converted together. Each sum prefetches its entries (up to 16 x
 * 64 bytes at the default window), so 16 sums stay well within L1D. */
#ifndef BC3EC_MAX_SUMS
#define BC3EC_MAX_SUMS 16
#endif

/* Affine point, coordinates as little-endian 64-bit limbs in [0,p). */
typedef struct {
   uint64_t x[4], y[4];
} bc3ec_affine;

/* Writes count entries to row: entry j-1 = j * base, j = 1..count. If next is
 * not NULL it receives (count + 1) * base. Returns 0, or -1 if base is not on
 * the curve, -2 on allocation failure. */
int bc3ec_row( void *row, unsigned count, const bc3ec_affine *base,
               bc3ec_affine *next );

/* out[s] = the sum of the n[s] entries in pts[s], for s < sums (at most
 * BC3EC_MAX_SUMS); every n[s] must be at least 1. Returns 0, or -1 if a sum is
 * the point at infinity or sums is out of range. */
int bc3ec_sum( bc3ec_affine *out, const void *const pts[][BC3EC_MAX_POINTS],
               const unsigned *n, unsigned sums );

/* The library configuration this TU compiled to. */
const char *bc3ec_config( void );

#ifdef __cplusplus
}
#endif

#endif
