/*
 * file        : hash_api.h
 * version     : 1.0.208
 * date        : 14.12.2010
 * 
 * Fugue vperm implementation Hash API
 *
 * Cagdas Calik
 * ccalik@metu.edu.tr
 * Institute of Applied Mathematics, Middle East Technical University, Turkey.
 *
 */

#ifndef FUGUE_HASH_API_H
#define FUGUE_HASH_API_H

#if defined(__AES__) 

#if !defined(__SSE4_1__)
#error "Unsupported configuration, AES needs SSE4.1. Compile without AES."
#endif

#include "algo/sha/sha3_common.h"
#include "simd-utils.h"


typedef struct
{
	__m128i			state[12];
	unsigned int	base;

	unsigned int	uHashSize;
	unsigned int	uBlockLength;
	unsigned int	uBufferBytes;
	DataLength		processed_bits;
	BitSequence		buffer[4];

} hashState_fugue __attribute__ ((aligned (64)));

HashReturn fugue512_Init(hashState_fugue *state, int hashbitlen);

HashReturn fugue512_Update(hashState_fugue *state, const void *data, DataLength databitlen);

HashReturn fugue512_Final(hashState_fugue *state, void *hashval);

HashReturn fugue512_full(hashState_fugue *hs, void *hashval, const void *data, DataLength databitlen);

#endif // AES
#endif // HASH_API_H

