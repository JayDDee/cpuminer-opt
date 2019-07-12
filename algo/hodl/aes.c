#include <stdint.h>
#include <x86intrin.h>
#include "wolf-aes.h"
#include "miner.h"

#if defined(__AES__)

static inline void ExpandAESKey256_sub1(__m128i *tmp1, __m128i *tmp2)
{
    __m128i tmp4;
    *tmp2 = _mm_shuffle_epi32(*tmp2, 0xFF);
    tmp4 = _mm_slli_si128(*tmp1, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp1 = _mm_xor_si128(*tmp1, tmp4);
    *tmp1 = _mm_xor_si128(*tmp1, *tmp2);
}

static inline void ExpandAESKey256_sub2(__m128i *tmp1, __m128i *tmp3)
{
    __m128i tmp2, tmp4;

    tmp4 = _mm_aeskeygenassist_si128(*tmp1, 0x00);
    tmp2 = _mm_shuffle_epi32(tmp4, 0xAA);
    tmp4 = _mm_slli_si128(*tmp3, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    tmp4 = _mm_slli_si128(tmp4, 0x04);
    *tmp3 = _mm_xor_si128(*tmp3, tmp4);
    *tmp3 = _mm_xor_si128(*tmp3, tmp2);
}

// Special thanks to Intel for helping me
// with ExpandAESKey256() and its subroutines
void ExpandAESKey256(__m128i *keys, const __m128i *KeyBuf)
{
    __m128i tmp1, tmp2, tmp3;

    tmp1 = keys[0] = KeyBuf[0];
    tmp3 = keys[1] = KeyBuf[1];

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x01);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[2] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[3] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x02);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[4] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[5] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x04);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[6] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[7] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x08);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[8] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[9] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x10);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[10] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[11] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x20);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[12] = tmp1;
    ExpandAESKey256_sub2(&tmp1, &tmp3);
    keys[13] = tmp3;

    tmp2 = _mm_aeskeygenassist_si128(tmp3, 0x40);
    ExpandAESKey256_sub1(&tmp1, &tmp2);
    keys[14] = tmp1;
}

#if defined(__SSE4_2__)
//#ifdef __AVX__

#define AESENC(i,j) \
    State[j] = _mm_aesenc_si128(State[j], ExpandedKey[j][i]);

#define AESENC_N(i) \
    AESENC(i,0) \
    AESENC(i,1) \
    AESENC(i,2) \
    AESENC(i,3) \
    AESENC(i,4) \
    AESENC(i,5) \
    AESENC(i,6) \
    AESENC(i,7) \


static inline void AES256Core(__m128i* State, __m128i ExpandedKey[][16])
{
    const uint32_t N = AES_PARALLEL_N;

    for(int j=0; j<N; ++j) {
        State[j] = _mm_xor_si128(State[j], ExpandedKey[j][0]);
    }

    AESENC_N(1)
    AESENC_N(2)
    AESENC_N(3)
    AESENC_N(4)
    AESENC_N(5)
    AESENC_N(6)
    AESENC_N(7)
    AESENC_N(8)
    AESENC_N(9)
    AESENC_N(10)
    AESENC_N(11)
    AESENC_N(12)
    AESENC_N(13)

    for(int j=0; j<N; ++j) {
        State[j] = _mm_aesenclast_si128(State[j], ExpandedKey[j][14]);
    }        
}

void AES256CBC(__m128i** data, const __m128i** next, __m128i ExpandedKey[][16], __m128i* IV)
{
    const uint32_t N = AES_PARALLEL_N;
    __m128i State[N];
    for(int j=0; j<N; ++j) {
        State[j] = _mm_xor_si128( _mm_xor_si128(data[j][0], next[j][0]), IV[j]);
    }

    AES256Core(State, ExpandedKey);
    for(int j=0; j<N; ++j) {
        data[j][0] = State[j];
    }

    for(int i = 1; i < BLOCK_COUNT; ++i) {
        for(int j=0; j<N; ++j) {
            State[j] = _mm_xor_si128( _mm_xor_si128(data[j][i], next[j][i]), data[j][i - 1]);
        }
        AES256Core(State, ExpandedKey);
        for(int j=0; j<N; ++j) {
            data[j][i] = State[j];
        }
    }
}

#else    // NO AVX

static inline __m128i AES256Core(__m128i State, const __m128i *ExpandedKey)
{
        State = _mm_xor_si128(State, ExpandedKey[0]);

        for(int i = 1; i < 14; ++i) State = _mm_aesenc_si128(State, ExpandedKey[i]);

        return(_mm_aesenclast_si128(State, ExpandedKey[14]));
}

void AES256CBC(__m128i *Ciphertext, const __m128i *Plaintext, const __m128i *ExpandedKey, __m128i IV, uint32_t BlockCount)
{
        __m128i State = _mm_xor_si128(Plaintext[0], IV);
        State = AES256Core(State, ExpandedKey);
        Ciphertext[0] = State;

        for(int i = 1; i < BlockCount; ++i)
        {
                State = _mm_xor_si128(Plaintext[i], Ciphertext[i - 1]);
                State = AES256Core(State, ExpandedKey);
                Ciphertext[i] = State;
        }
}

#endif

#endif

