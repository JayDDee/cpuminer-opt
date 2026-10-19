#ifndef GR_CRYPTONIGHT_H__
#define GR_CRYPTONIGHT_H__ 1

#include <stddef.h>
#include <stdint.h>

/*
 * GhostRider CryptoNight variants (all CryptoNight variant 1 / "cnv1").
 *
 * The six variants differ only in scratchpad size, iteration count and the
 * addressing mask. The "lite" variants use the same allocation and iteration
 * count as their parent but address only the lower half of the scratchpad
 * (mask = MEM/2 - 16). See WyvernTKC cpuminer-gr cryptonight.h for the
 * authoritative parameters.
 *
 *   variant      MEMORY    iterations   mask
 *   turtlelite   256 KiB   2^16         MEM/2 - 16
 *   turtle       256 KiB   2^16         MEM   - 16
 *   darklite     512 KiB   2^17         MEM/2 - 16
 *   dark         512 KiB   2^17         MEM   - 16
 *   lite           1 MiB   2^18         MEM   - 16
 *   fast           2 MiB   2^18         MEM   - 16
 *
 * The trailing `variant` argument mirrors the reference signature; GhostRider
 * always passes 1.
 */
void cryptonightdark_hash      ( const void *input, void *output, uint32_t len, int variant );
void cryptonightdarklite_hash  ( const void *input, void *output, uint32_t len, int variant );
void cryptonightfast_hash      ( const void *input, void *output, uint32_t len, int variant );
void cryptonightlite_hash      ( const void *input, void *output, uint32_t len, int variant );
void cryptonightturtle_hash    ( const void *input, void *output, uint32_t len, int variant );
void cryptonightturtlelite_hash( const void *input, void *output, uint32_t len, int variant );

// Interleaved multi-way CryptoNight-v1: hashes GR_CN_LANES independent inputs
// at once to hide scratchpad memory latency. cn_variant indexes the CNAlgo
// order {dark, darklite, fast, lite, turtle, turtlelite} = 0..5. On AES-NI
// builds this is the interleaved hardware path; otherwise it loops the soft
// single-hash (correct, no latency win).
#define GR_CN_LANES 4
void cryptonight_4way( int cn_variant, const void *in[GR_CN_LANES],
                       void *out[GR_CN_LANES], uint32_t len );

// Release the per-thread scratchpads (call on thread teardown if desired).
void cryptonight_free_scratchpad( void );

// Human-readable description of the scratchpad memory backing actually obtained
// (huge pages vs malloc), valid after the first hash. For logging.
const char *cryptonight_scratchpad_backing( void );

#endif /* GR_CRYPTONIGHT_H__ */
