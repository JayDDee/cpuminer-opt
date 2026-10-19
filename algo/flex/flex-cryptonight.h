#ifndef FLEX_CRYPTONIGHT_H__
#define FLEX_CRYPTONIGHT_H__ 1

#include <stdint.h>

// Flex's own CryptoNight-v1 variant cores (ported verbatim from the Kylacoin
// cpuminer-flex reference, in algo/flex/cryptonote/). These differ from this
// repo's GhostRider CryptoNight cores (algo/gr/cryptonight.c): Flex finalizes
// with a 3-entry extra-hash set {blake, groestl, skein} selected by
// `state.b[0] & 2` (never JH), whereas GhostRider uses the standard 4-entry set
// selected by `& 3`. The two are therefore NOT interchangeable; Flex must use
// these. Memory sizes, iteration counts and the lite half-scratchpad addressing
// match GhostRider's, but the finalization makes the digests diverge.
//
// They reuse GhostRider's shared cryptonote/crypto primitives (oaes, aesb,
// keccak, blake256, groestl, skein); only the variant cores are Flex-specific.
//
// Signature mirrors the reference: (input, output, len, variant). Flex always
// passes variant = 1.
void flex_cryptonightdark_hash      ( const char *input, char *output, uint32_t len, int variant );
void flex_cryptonightdarklite_hash  ( const char *input, char *output, uint32_t len, int variant );
void flex_cryptonightfast_hash      ( const char *input, char *output, uint32_t len, int variant );
void flex_cryptonightlite_hash      ( const char *input, char *output, uint32_t len, int variant );
void flex_cryptonightturtle_hash    ( const char *input, char *output, uint32_t len, int variant );
void flex_cryptonightturtlelite_hash( const char *input, char *output, uint32_t len, int variant );

#endif /* FLEX_CRYPTONIGHT_H__ */
