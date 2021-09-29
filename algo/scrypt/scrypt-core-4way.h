#ifndef SCRYPT_CORE_4WAY_H__
#define SCRYPT_CORE_4WAY_H__

#include "simd-utils.h"
#include <stdlib.h>
#include <stdint.h>

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

void scrypt_core_16way( __m512i *X, __m512i *V, const uint32_t N );

// Serial SIMD over 4 way parallel
void scrypt_core_simd128_4way( __m128i *X, __m128i *V, const uint32_t N );

// 4 way parallel over serial SIMD
void scrypt_core_4way_simd128( __m512i *X, __m512i *V, const uint32_t N );

#endif

#if defined(__AVX2__)

void scrypt_core_8way( __m256i *X, __m256i *V, uint32_t N );

// 2 way parallel over SIMD128
void scrypt_core_2way_simd128( __m256i *X, __m256i *V, const uint32_t N );

// Double buffered 2 way parallel over SIMD128
void scrypt_core_2way_simd128_2buf( __m256i *X, __m256i *V, const uint32_t N );

// Triplee buffered 2 way parallel over SIMD128
void scrypt_core_2way_simd128_3buf( __m256i *X, __m256i *V, const uint32_t N );

// Serial SIMD128 over 2 way parallel
void scrypt_core_simd128_2way( uint64_t *X, uint64_t *V, const uint32_t N );

// Double buffered simd over parallel
void scrypt_core_simd128_2way_2buf( uint64_t *X, uint64_t *V, const uint32_t N );

// Triple buffered 2 way
void scrypt_core_simd128_2way_3buf( uint64_t *X, uint64_t *V, const uint32_t N );

// Quadruple buffered
void scrypt_core_simd128_2way_4buf( uint64_t *X, uint64_t *V, const uint32_t N );

#endif

#if defined(__SSE2__)

// Parallel 4 way, 4x memory
void scrypt_core_4way( __m128i *X, __m128i *V, const uint32_t N );

// Linear SIMD 1 way, 1x memory, lowest
void scrypt_core_simd128( uint32_t *X, uint32_t *V, const uint32_t N );

// Double buffered, 2x memory
void scrypt_core_simd128_2buf( uint32_t *X, uint32_t *V, const uint32_t N );

// Triple buffered
void scrypt_core_simd128_3buf( uint32_t *X, uint32_t *V, const uint32_t N );

// Quadruple buffered, 4x memory
void scrypt_core_simd128_4buf( uint32_t *X, uint32_t *V, const uint32_t N );

#endif

// For reference only
void scrypt_core_1way( uint32_t *X, uint32_t *V, const uint32_t N );

#endif   

