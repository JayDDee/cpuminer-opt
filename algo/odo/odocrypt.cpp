// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The DigiByte developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "odocrypt.h"

#include <algorithm>

struct OdoRandom
{
    // LCG parameters from Knuth
    const static uint64_t BASE_MULTIPLICAND = 6364136223846793005ull;
    const static uint64_t BASE_ADDEND = 1442695040888963407ull;

    OdoRandom(uint32_t seed):
        current(seed),
        multiplicand(1),
        addend(0)
    {}

    // For a standard LCG, every seed produces the same sequence, but from a different
    // starting point.  This generator gives the 1st, 3rd, 6th, 10th, etc output from
    // a standard LCG.  This ensures that every seed produces a unique sequence.
    inline uint32_t NextInt()
    {
        addend += multiplicand * BASE_ADDEND;
        multiplicand *= BASE_MULTIPLICAND;
        current = current * multiplicand + addend;
        return current >> 32;
    }

    inline uint64_t NextLong()
    {
        uint64_t hi = NextInt();
        return (hi << 32) | NextInt();
    }

    inline int Next(int N)
    {
        return ((uint64_t)NextInt() * N) >> 32;
    }

    template<class T, size_t sz>
    void Permutation(T (&arr)[sz])
    {
        for (size_t i = 0; i < sz; i++)
            arr[i] = i;
        for (size_t i = 1; i < sz; i++)
            std::swap(arr[i], arr[Next(i+1)]);
    }

    uint64_t current;
    uint64_t multiplicand;
    uint64_t addend;
};

OdoCrypt::OdoCrypt(uint32_t key)
{
    OdoRandom r(key);

    // Randomize each s-box
    for (int i = 0; i < SMALL_SBOX_COUNT; i++)
    {
        r.Permutation(Sbox1[i]);
    }
    for (int i = 0; i < LARGE_SBOX_COUNT; i++)
    {
        r.Permutation(Sbox2[i]);
    }

    // Randomize each p-box
    for (int i = 0; i < 2; i++)
    {
        Pbox& perm = Permutation[i];
        for (int j = 0; j < PBOX_SUBROUNDS; j++)
        for (int k = 0; k < STATE_SIZE/2; k++)
            perm.mask[j][k] = r.NextLong();
        for (int j = 0; j < PBOX_SUBROUNDS-1; j++)
        for (int k = 0; k < STATE_SIZE/2; k++)
            perm.rotation[j][k] = r.Next(63) + 1;
    }

    // Randomize rotations
    // Rotations must be distinct, non-zero, and have odd sum
    {
        int bits[WORD_BITS-1];
        r.Permutation(bits);
        int sum = 0;
        for (int j = 0; j < ROTATION_COUNT-1; j++)
        {
            Rotations[j] = bits[j] + 1;
            sum += Rotations[j];
        }
        for (int j = ROTATION_COUNT-1; ; j++)
        {
            if ((bits[j] + 1 + sum) % 2)
            {
                Rotations[ROTATION_COUNT-1] = bits[j] + 1;
                break;
            }
        }
    }

    // Randomize each round key
    for (int i = 0; i < ROUNDS; i++)
        RoundKey[i] = r.Next(1 << STATE_SIZE);
}

void OdoCrypt::Encrypt(char cipher[DIGEST_SIZE], const char plain[DIGEST_SIZE]) const
{
    uint64_t state[STATE_SIZE];
    Unpack(state, plain);
    PreMix(state);
    for (int round = 0; round < ROUNDS; round++)
    {
        ApplyPbox(state, Permutation[0]);
        ApplySboxes(state, Sbox1, Sbox2);
        ApplyPbox(state, Permutation[1]);
        ApplyRotations(state, Rotations);
        ApplyRoundKey(state, RoundKey[round]);
    }
    Pack(state, cipher);
}

template<class T, size_t sz1, size_t sz2>
void InvertMapping(T (&res)[sz1][sz2], const T (&mapping)[sz1][sz2])
{
    for (size_t i = 0; i < sz1; i++)
    for (size_t j = 0; j < sz2; j++)
        res[i][mapping[i][j]] = j;
}

void OdoCrypt::Decrypt(char plain[DIGEST_SIZE], const char cipher[DIGEST_SIZE]) const
{
    uint8_t invSbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH];
    uint16_t invSbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH];

    InvertMapping(invSbox1, Sbox1);
    InvertMapping(invSbox2, Sbox2);

    uint64_t state[STATE_SIZE];
    Unpack(state, cipher);
    for (int round = ROUNDS-1; round >= 0; round--)
    {
        ApplyRoundKey(state, RoundKey[round]);
        // LCM(STATE_SIZE, WORD_BITS)-1 is enough iterations, but this will do.
        for (int i = 0; i < STATE_SIZE*WORD_BITS-1; i++)
            ApplyRotations(state, Rotations);
        ApplyInvPbox(state, Permutation[1]);
        ApplySboxes(state, invSbox1, invSbox2);
        ApplyInvPbox(state, Permutation[0]);
    }
    PreMix(state);
    Pack(state, plain);
}

void OdoCrypt::Unpack(uint64_t state[STATE_SIZE], const char bytes[DIGEST_SIZE])
{
    std::fill(state, state+STATE_SIZE, 0);
    for (int i = 0; i < STATE_SIZE; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            state[i] |= (uint64_t)(uint8_t)bytes[8*i + j] << (8*j);
        }
    }
}

void OdoCrypt::Pack(const uint64_t state[STATE_SIZE], char bytes[DIGEST_SIZE])
{
    std::fill(bytes, bytes+DIGEST_SIZE, 0);
    for (int i = 0; i < STATE_SIZE; i++)
    {
        for (int j = 0; j < 8; j++)
        {
            bytes[8*i + j] = (state[i] >> (8*j)) & 0xff;
        }
    }
}

void OdoCrypt::PreMix(uint64_t state[STATE_SIZE])
{
    uint64_t total = 0;
    for (int i = 0; i < STATE_SIZE; i++)
        total ^= state[i];
    total ^= total >> 32;
    for (int i = 0; i < STATE_SIZE; i++)
        state[i] ^= total;
}

void OdoCrypt::ApplySboxes(
    uint64_t state[STATE_SIZE],
    const uint8_t sbox1[SMALL_SBOX_COUNT][1 << SMALL_SBOX_WIDTH],
    const uint16_t sbox2[LARGE_SBOX_COUNT][1 << LARGE_SBOX_WIDTH])
{
    const static uint64_t MASK1 = (1 << SMALL_SBOX_WIDTH) - 1;
    const static uint64_t MASK2 = (1 << LARGE_SBOX_WIDTH) - 1;

    int smallSboxIndex = 0;
    for (int i = 0; i < STATE_SIZE; i++)
    {
        uint64_t next = 0;
        int pos = 0;
        int largeSboxIndex = i;
        for (int j = 0; j < SMALL_SBOX_COUNT / STATE_SIZE; j++)
        {
            next |= (uint64_t)sbox1[smallSboxIndex][(state[i] >> pos) & MASK1] << pos;
            pos += SMALL_SBOX_WIDTH;
            next |= (uint64_t)sbox2[largeSboxIndex][(state[i] >> pos) & MASK2] << pos;
            pos += LARGE_SBOX_WIDTH;
            smallSboxIndex++;
        }
        state[i] = next;
    }
}

void OdoCrypt::ApplyMaskedSwaps(uint64_t state[STATE_SIZE], const uint64_t mask[STATE_SIZE/2])
{
    for (int i = 0; i < STATE_SIZE/2; i++)
    {
        uint64_t& a = state[2*i];
        uint64_t& b = state[2*i+1];
        // For each bit set in the mask, swap the corresponding bits in `a` and `b`
        uint64_t swp = mask[i] & (a ^ b);
        a ^= swp;
        b ^= swp;
    }
}

void OdoCrypt::ApplyWordShuffle(uint64_t state[STATE_SIZE], int m)
{
    uint64_t next[STATE_SIZE];
    for (int i = 0; i < STATE_SIZE; i++)
    {
        next[m*i % STATE_SIZE] = state[i];
    }
    std::copy(next, next+STATE_SIZE, state);
}

inline uint64_t Rot(uint64_t x, int r)
{
    return r == 0 ? x : (x << r) ^ (x >> (64-r));
}

void OdoCrypt::ApplyPboxRotations(uint64_t state[STATE_SIZE], const int rotation[STATE_SIZE/2])
{
    for (int i = 0; i < STATE_SIZE/2; i++)
    {
        // Only rotate the even words.  Rotating the odd words wouldn't actually
        // be useful - a transformation that rotates all the words can be
        // transformed into one that only rotates the even words, then rotates
        // the odd words once after the final iteration.
        state[2*i] = Rot(state[2*i], rotation[i]);
    }
}

void OdoCrypt::ApplyPbox(uint64_t state[STATE_SIZE], const Pbox& perm)
{
    for (int i = 0; i < PBOX_SUBROUNDS-1; i++)
    {
        // Conditionally move bits between adjacent pairs of words
        ApplyMaskedSwaps(state, perm.mask[i]);
        // Move the words around
        ApplyWordShuffle(state, PBOX_M);
        // Rotate the bits within words
        ApplyPboxRotations(state, perm.rotation[i]);
    }
    ApplyMaskedSwaps(state, perm.mask[PBOX_SUBROUNDS-1]);
}

void OdoCrypt::ApplyInvPbox(uint64_t state[STATE_SIZE], const Pbox& perm)
{
    ApplyMaskedSwaps(state, perm.mask[PBOX_SUBROUNDS-1]);
    for (int i = PBOX_SUBROUNDS-2; i >= 0; i--)
    {
        int invRotation[STATE_SIZE/2];
        for (int j = 0; j < STATE_SIZE/2; j++)
            invRotation[j] = WORD_BITS - perm.rotation[i][j];
        ApplyPboxRotations(state, invRotation);
        ApplyWordShuffle(state, INV_PBOX_M);
        ApplyMaskedSwaps(state, perm.mask[i]);
    }
}

void OdoCrypt::ApplyRotations(uint64_t state[STATE_SIZE], const int rotations[ROTATION_COUNT])
{
    uint64_t next[STATE_SIZE];
    std::rotate_copy(state, state+1, state+STATE_SIZE, next);
    for (int i = 0; i < STATE_SIZE; i++)
    for (int j = 0; j < ROTATION_COUNT; j++)
    {
            next[i] ^= Rot(state[i], rotations[j]);
    }
    std::copy(next, next+STATE_SIZE, state);
}

void OdoCrypt::ApplyRoundKey(uint64_t state[STATE_SIZE], int roundKey)
{
    for (int i = 0; i < STATE_SIZE; i++)
        state[i] ^= (roundKey >> i) & 1;
}
