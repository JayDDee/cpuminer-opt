#ifndef __HODL_H
#define __HODL_H

#include <stdint.h>
#include <x86intrin.h>
#include "miner.h"

#define AES_ITERATIONS 		15

#define GARBAGE_SIZE		(1 << 30)
#define GARBAGE_CHUNK_SIZE	(1 << 6)
#define GARBAGE_SLICE_SIZE	(1 << 12)
#define TOTAL_CHUNKS		(1 << 24)   // GARBAGE_SIZE / GARBAGE_CHUNK_SIZE
#define COMPARE_SIZE		(1 << 18)   // GARBAGE_SIZE / GARBAGE_SLICE_SIZE

typedef union _CacheEntry
{
	uint32_t dwords[GARBAGE_SLICE_SIZE >> 2] __attribute__((aligned(16)));
	__m128i dqwords[GARBAGE_SLICE_SIZE >> 4] __attribute__((aligned(16)));
} CacheEntry;

int scanhash_hodl_wolf( struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr );

void GenRandomGarbage( CacheEntry *Garbage, uint32_t *pdata, int thr_id);

#endif		// __HODL_H
