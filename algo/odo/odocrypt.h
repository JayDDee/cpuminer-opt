// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The DigiByte developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ODO_CRYPT
#define ODO_CRYPT

#include <stdint.h>

class OdoCrypt
{
public:
    // Block size, in bytes
    const static int DIGEST_SIZE = 80;

private:
    // Number of rounds.
    const static int ROUNDS = 84;
    // Odo utilizes two sbox sizes - 6-bit sboxes, which are ideally suited for
    // FPGA logic elements, and 10-bit sboxes, which are ideally suited for FPGA
    // RAM elements.
    const static int SMALL_SBOX_WIDTH = 6;
    const static int LARGE_SBOX_WIDTH = 10;
    // The pboxes are constructed using 3 primitives, applied multiple times.
    const static int PBOX_SUBROUNDS = 6;
    // This constant should be a generator for the multiplicative group of
    // integers modulo STATE_SIZE (3 or 7 for a STATE_SIZE of 10).  It controls
    // one part of the pbox step.
    const static int PBOX_M = 3;
    // The multiplicative inverse of PBOX_M modulo STATE_SIZE
    const static int INV_PBOX_M = 7;
    // This constant must be even.  It controls the number of rotations used in
    // the linear mixing step.
    const static int ROTATION_COUNT = 6;
    // Odo internally operates on 64-bit words.
    const static int WORD_BITS = 64;

    const static int DIGEST_BITS = 8*DIGEST_SIZE;
    const static int STATE_SIZE = DIGEST_BITS / WORD_BITS;
    const static int SMALL_SBOX_COUNT = DIGEST_BITS / (SMALL_SBOX_WIDTH + LARGE_SBOX_WIDTH);
    const static int LARGE_SBOX_COUNT = STATE_SIZE;

public:
    OdoCrypt(uint32_t key);

    void Encrypt(char cipher[DIGEST_SIZE], const char plain[DIGEST_SIZE]) const;

    // test-only, proves that this really is a permutation function
    void Decrypt(char plain[DIGEST_SIZE], const char cipher[DIGEST_SIZE]) const;

private:
    struct Pbox
    {
        uint64_t mask[PBOX_SUBROUNDS][STATE_SIZE/2];
        int rotation[PBOX_SUBROUNDS-1][STATE_SIZE/2];
    };

    uint8_t Sbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH];
    uint16_t Sbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH];
    Pbox Permutation[2];
    int Rotations[ROTATION_COUNT];
    uint16_t RoundKey[ROUNDS];

    // Pack/unpack bytes into internal state
    static void Unpack(uint64_t state[STATE_SIZE], const char bytes[DIGEST_SIZE]);
    static void Pack(const uint64_t state[STATE_SIZE], char bytes[DIGEST_SIZE]);

    // Pre-mix the bits.  Involution.  After this step, 95% of the bits depend
    // on a bit from the nonce.
    static void PreMix(uint64_t state[STATE_SIZE]);

    // Non-linear substitution.
    static void ApplySboxes(
        uint64_t state[STATE_SIZE],
        const uint8_t sbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH],
        const uint16_t sbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH]);

    // ApplyPbox helpers
    static void ApplyMaskedSwaps(uint64_t state[STATE_SIZE], const uint64_t mask[STATE_SIZE/2]);
    static void ApplyWordShuffle(uint64_t state[STATE_SIZE], int m);
    static void ApplyPboxRotations(uint64_t state[STATE_SIZE], const int rotation[STATE_SIZE/2]);

    // Permute the bits.
    static void ApplyPbox(uint64_t state[STATE_SIZE], const Pbox& perm);

    // Inverse transform of ApplyPbox.  Only used by Decrypt.
    static void ApplyInvPbox(uint64_t state[STATE_SIZE], const Pbox& perm);

    // Linear mix step.
    static void ApplyRotations(uint64_t state[STATE_SIZE], const int rotations[ROTATION_COUNT]);

    // Add round key. Involution.
    static void ApplyRoundKey(uint64_t state[STATE_SIZE], int roundKey);
};

#endif
