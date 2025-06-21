#include "simd-utils.h"

#if defined(SIMD512)

const __m512i V512_BSWAP64 =     { 0x0001020304050607, 0x08090a0b0c0d0e0f,
                                   0x0001020304050607, 0x08090a0b0c0d0e0f,
                                   0x0001020304050607, 0x08090a0b0c0d0e0f,
                                   0x0001020304050607, 0x08090a0b0c0d0e0f };

const __m512i V512_BSWAP32 =     { 0x0405060700010203, 0x0c0d0e0f08090a0b,
                                   0x0405060700010203, 0x0c0d0e0f08090a0b,
                                   0x0405060700010203, 0x0c0d0e0f08090a0b,
                                   0x0405060700010203, 0x0c0d0e0f08090a0b };

#elif defined(__AVX2__)

const __m256i V256_BSWAP64     = { 0x0001020304050607, 0x08090a0b0c0d0e0f,
                                   0x0001020304050607, 0x08090a0b0c0d0e0f };

const __m256i V256_BSWAP32     = { 0x0405060700010203, 0x0c0d0e0f08090a0b,
                                   0x0405060700010203, 0x0c0d0e0f08090a0b };

const __m256i V256_SHUFLR64_8  = { 0x0007060504030201, 0x080f0e0d0c0b0a09,
                                   0x0007060504030201, 0x080f0e0d0c0b0a09 };

const __m256i V256_SHUFLR64_24 = { 0x0201000706050403, 0x0a09080f0e0d0c0b,
                                   0x0201000706050403, 0x0a09080f0e0d0c0b };

const __m256i V256_SHUFLL64_8  = { 0x0605040302010007, 0x0e0d0c0b0a09080f,
                                   0x0605040302010007, 0x0e0d0c0b0a09080f };

const __m256i V256_SHUFLL64_24 = { 0x0403020100070605, 0x0c0b0a09080f0e0d,
                                   0x0403020100070605, 0x0c0b0a09080f0e0d };

const __m256i V256_SHUFLR32_8  = { 0x0407060500030201, 0x0c0f0e0d080b0a09,
                                   0x0407060500030201, 0x0c0f0e0d080b0a09 };

const __m256i V256_SHUFLL32_8  = { 0x0605040702010003, 0x0e0d0c0f0a09080b,
                                   0x0605040702010003, 0x0e0d0c0f0a09080b };

#elif defined(__SSSE3__)

const v128_t V128_BSWAP64      = { 0x0001020304050607, 0x08090a0b0c0d0e0f };
const v128_t V128_BSWAP32      = { 0x0405060700010203, 0x0c0d0e0f08090a0b };

const v128_t V128_SHUFLR64_8   = { 0x0007060504030201, 0x080f0e0d0c0b0a09 };
const v128_t V128_SHUFLR64_24  = { 0x0201000706050403, 0x0a09080f0e0d0c0b };
const v128_t V128_SHUFLL64_8   = { 0x0605040302010007, 0x0e0d0c0b0a09080f };
const v128_t V128_SHUFLL64_24  = { 0x0403020100070605, 0x0c0b0a09080f0e0d };

const v128_t V128_SHUFLR32_8   = { 0x0407060500030201, 0x0c0f0e0d080b0a09 };
const v128_t V128_SHUFLL32_8   = { 0x0605040702010003, 0x0e0d0c0f0a09080b };

#endif

