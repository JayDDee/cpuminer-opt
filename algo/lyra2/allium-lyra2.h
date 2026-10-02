#ifndef ALLIUM_LYRA2_OPT_H
#define ALLIUM_LYRA2_OPT_H

#include <stdint.h>
#include "lyra2.h"

#define ALLIUM_LYRA2_NROWS 8
#define ALLIUM_LYRA2_NCOLS 8
#define ALLIUM_LYRA2_MATRIX_WORDS \
    (BLOCK_LEN_INT64 * ALLIUM_LYRA2_NCOLS * ALLIUM_LYRA2_NROWS)
#define ALLIUM_LYRA2_2WAY_MATRIX_WORDS (2 * ALLIUM_LYRA2_MATRIX_WORDS)

int LYRA2RE_ALLIUM(void *K, uint64_t *wholeMatrix);
int LYRA2RE_ALLIUM_selftest(void);

#if defined(SIMD512)
/*
 * lyra2.h exposes this only when SIMD512 was already defined before that
 * header was parsed. SIMD512 can be provided later by the SIMD headers in
 * this translation unit, so keep the oracle prototype explicit.
 */
int LYRA2RE_2WAY(void *K, uint64_t kLen, const void *pwd, uint64_t pwdlen,
                 uint64_t timeCost, uint64_t nRows, uint64_t nCols);

int LYRA2RE_2WAY_ALLIUM(void *K, uint64_t *wholeMatrix);
int LYRA2RE_2WAY_ALLIUM_selftest(void);
#endif

#endif
