#ifndef __WOLF_AES_H
#define __WOLF_AES_H

#include <stdint.h>
#include "simd-utils.h"

void ExpandAESKey256(v128_t *keys, const v128_t *KeyBuf);

#if defined(__SSE4_2__)
//#ifdef __AVX__

#define AES_PARALLEL_N 8
#define BLOCK_COUNT 256

void AES256CBC( v128_t** data, const v128_t** next, v128_t ExpandedKey[][16],
                v128_t* IV );

#else

void AES256CBC( v128_t *Ciphertext, const v128_t *Plaintext,
               const v128_t *ExpandedKey, v128_t IV, uint32_t BlockCount );

#endif

#endif		// __WOLF_AES_H
