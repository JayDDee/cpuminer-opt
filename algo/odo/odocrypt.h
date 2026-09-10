#ifndef ODOCRYPT_H__
#define ODOCRYPT_H__ 1

#include <stdint.h>
#include <stddef.h>

// Odocrypt (DigiByte) — a self-mutating SPN block cipher whose S-boxes, P-boxes,
// rotations and round keys are regenerated every "shapechange" epoch from a
// 32-bit key (derived from the block time). Scalar C port of DigiByte Core's
// src/crypto/odocrypt.cpp (forward/Encrypt path only; Decrypt is test-only).

#define ODO_DIGEST_SIZE       80          // block size in bytes
#define ODO_ROUNDS            84
#define ODO_SMALL_SBOX_WIDTH  6
#define ODO_LARGE_SBOX_WIDTH  10
#define ODO_PBOX_SUBROUNDS    6
#define ODO_PBOX_M            3
#define ODO_ROTATION_COUNT    6
#define ODO_WORD_BITS         64
#define ODO_STATE_SIZE        10          // (ODO_DIGEST_SIZE*8)/ODO_WORD_BITS
#define ODO_SMALL_SBOX_COUNT  40          // (DIGEST_BITS)/(6+10)
#define ODO_LARGE_SBOX_COUNT  10          // == ODO_STATE_SIZE

typedef struct
{
   uint64_t mask[ODO_PBOX_SUBROUNDS][ODO_STATE_SIZE / 2];
   int      rotation[ODO_PBOX_SUBROUNDS - 1][ODO_STATE_SIZE / 2];
} OdoPbox;

typedef struct
{
   uint8_t  Sbox1[ODO_SMALL_SBOX_COUNT][1 << ODO_SMALL_SBOX_WIDTH];   // [40][64]
   uint16_t Sbox2[ODO_LARGE_SBOX_COUNT][1 << ODO_LARGE_SBOX_WIDTH];   // [10][1024]
   OdoPbox  Permutation[2];
   int      Rotations[ODO_ROTATION_COUNT];
   uint16_t RoundKey[ODO_ROUNDS];
#if defined(__AVX512F__)
   // uint32 S-box copies for AVX512 i64gather (8-way path).
   uint32_t Sbox1_w[ODO_SMALL_SBOX_COUNT][1 << ODO_SMALL_SBOX_WIDTH];
   uint32_t Sbox2_w[ODO_LARGE_SBOX_COUNT][1 << ODO_LARGE_SBOX_WIDTH];
#endif
} OdoCrypt;

// Build the cipher tables for a given epoch key.
void odocrypt_init( OdoCrypt *c, uint32_t key );

// Encrypt one 80-byte block (in and out may alias).
void odocrypt_encrypt( const OdoCrypt *c, char out[ODO_DIGEST_SIZE],
                       const char in[ODO_DIGEST_SIZE] );

// Keccak-p[800] with 12 rounds, in place over a 100-byte (25 x uint32) state.
void odo_keccakp800_12( uint8_t state[100] );

#if defined(__AVX512F__)
#define ODO_8WAY 1
// Encrypt 8 independent 80-byte blocks at once (AVX512). out[l]/in[l] are the
// l-th lane's blocks; each lane's result is identical to odocrypt_encrypt.
void odocrypt_encrypt_8way( const OdoCrypt *c,
                            unsigned char out[8][ODO_DIGEST_SIZE],
                            const unsigned char in[8][ODO_DIGEST_SIZE] );
#endif

#endif /* ODOCRYPT_H__ */
