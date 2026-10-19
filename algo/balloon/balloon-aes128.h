#ifndef BALLOON_AES128_H__
#define BALLOON_AES128_H__ 1

#include <stdint.h>
#include <stddef.h>

/* AES-128 for Balloon's index bitstream.
 *
 * Balloon derives its block-index stream from AES-128-CTR over an all-zero
 * plaintext with an all-zero IV, which is just the raw keystream
 *
 *     block i = AES-128-Enc( key, BE128(i) )        i = 0, 1, 2, ...
 *
 * The reference implementation gets this from OpenSSL's EVP_aes_128_ctr; this
 * tree links no OpenSSL, and it has no reusable AES-128 either
 * (algo/gr/cryptonight.c carries an AES-*256* key schedule and
 * simd-utils/simd-neon-aes.h provides round primitives, not a cipher).
 *
 * Deliberately a plain portable implementation, not a hardware-AES one. The
 * keystream depends only on the 32-byte salt, i.e. on header bytes 0-31, so it
 * is recomputed once per *block* (~25.6k AES blocks) and amortised over every
 * nonce mined against it. There is no hot path here to optimize, and one
 * variant means no cross-variant differential to maintain.
 *
 * That was measured, not assumed: building the whole index table costs about
 * one hash — 3.9 ms on an i7-11700F, 5.8 ms on a Cortex-A76 — against 20-40 s
 * of mining per rebuild, since the salt only changes when the previous block
 * hash does. Hardware AES would recover roughly 0.01% of thread time.       */

#define BALLOON_AES128_ROUNDS 10

typedef struct
{
   uint8_t rk[ BALLOON_AES128_ROUNDS + 1 ][16];   /* expanded round keys */
} balloon_aes128_ctx;

/* Key expansion. Only the first 16 bytes of `key` are used — matching OpenSSL,
 * which reads a 16-byte key for aes-128 even when handed the full 32-byte
 * SHA-256 digest Balloon derives it from.                                    */
void balloon_aes128_init( balloon_aes128_ctx *ctx, const uint8_t key[16] );

void balloon_aes128_encrypt_block( const balloon_aes128_ctx *ctx,
                                   const uint8_t in[16], uint8_t out[16] );

/* Write `outlen` bytes of keystream, counter starting at `counter`, where the
 * counter block is the 128-bit big-endian encoding of the counter (OpenSSL's
 * CTR convention: the whole 16-byte block is one big-endian integer).
 * `outlen` need not be a multiple of 16.                                     */
void balloon_aes128_keystream( const balloon_aes128_ctx *ctx, uint64_t counter,
                               uint8_t *out, size_t outlen );

#endif /* BALLOON_AES128_H__ */
