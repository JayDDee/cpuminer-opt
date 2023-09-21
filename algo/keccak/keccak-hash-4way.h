#ifndef KECCAK_HASH_4WAY_H__
#define KECCAK_HASH_4WAY_H__

#ifdef  __AVX2__

#include <stddef.h>
#include "simd-utils.h"

/**
 * This structure is a context for Keccak computations: it contains the
 * intermediate values and some data from the last entered block. Once a
 * Keccak computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running Keccak computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

typedef struct {
        __m512i buf[144*8];
        __m512i w[25];
        size_t ptr, lim;
} keccak64_ctx_m512i __attribute__((aligned(128)));

typedef keccak64_ctx_m512i keccak256_8way_context;
typedef keccak64_ctx_m512i keccak512_8way_context;

void keccak256_8way_init(void *cc);
void keccak256_8way_update(void *cc, const void *data, size_t len);
void keccak256_8way_close(void *cc, void *dst);

void keccak512_8way_init(void *cc);
void keccak512_8way_update(void *cc, const void *data, size_t len);
void keccak512_8way_close(void *cc, void *dst);
void keccak512_8way_addbits_and_close(
        void *cc, unsigned ub, unsigned n, void *dst);

#endif   

typedef struct {
        __m256i buf[144*8];  
        __m256i w[25];
        size_t ptr, lim;
} keccak64_ctx_m256i __attribute__((aligned(128)));

typedef keccak64_ctx_m256i keccak256_4way_context;
typedef keccak64_ctx_m256i keccak512_4way_context;

void keccak256_4way_init(void *cc);
void keccak256_4way_update(void *cc, const void *data, size_t len);
void keccak256_4way_close(void *cc, void *dst);

void keccak512_4way_init(void *cc);
void keccak512_4way_update(void *cc, const void *data, size_t len);
void keccak512_4way_close(void *cc, void *dst);
void keccak512_4way_addbits_and_close(
        void *cc, unsigned ub, unsigned n, void *dst);

#endif

#endif
