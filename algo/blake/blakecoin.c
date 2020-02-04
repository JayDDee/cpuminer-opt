#include "blakecoin-gate.h"

#if !defined(BLAKECOIN_8WAY) && !defined(BLAKECOIN_4WAY)

#define BLAKE32_ROUNDS 8
#include "sph_blake.h"

void blakecoin_init(void *cc);
void blakecoin(void *cc, const void *data, size_t len);
void blakecoin_close(void *cc, void *dst);

#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <openssl/sha.h>

// context management is staged for efficiency.
// 1. global initial ctx cached on startup
// 2. per-thread midstate ctx cache refreshed every scan
// 3. local ctx for final hash calculation

static          sph_blake256_context blake_init_ctx;
static __thread sph_blake256_context blake_mid_ctx;

static void blake_midstate_init( const void* input )
{
    // copy cached initial state
    memcpy( &blake_mid_ctx, &blake_init_ctx, sizeof blake_mid_ctx );
    blakecoin( &blake_mid_ctx, input, 64 );
}

void blakecoinhash( void *state, const void *input )
{
	sph_blake256_context ctx;
	uint8_t hash[64] __attribute__ ((aligned (32)));
	uint8_t *ending = (uint8_t*) input + 64;

        // copy cached midstate
        memcpy( &ctx, &blake_mid_ctx, sizeof ctx );
	blakecoin( &ctx, ending, 16 );
	blakecoin_close( &ctx, hash );
	memcpy( state, hash, 32 );
}

int scanhash_blakecoin( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	const uint32_t first_nonce = pdata[19];
	uint32_t HTarget = ptarget[7];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	uint32_t _ALIGN(32) hash64[8];
	uint32_t _ALIGN(32) endiandata[20];

	uint32_t n = first_nonce;

	if (opt_benchmark)
		HTarget = 0x7f;

	// we need big endian data...
        for (int kk=0; kk < 19; kk++) 
                be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);

        blake_midstate_init( endiandata );

#ifdef DEBUG_ALGO
	applog(LOG_DEBUG,"[%d] Target=%08x %08x", thr_id, ptarget[6], ptarget[7]);
#endif

	do {
		be32enc(&endiandata[19], n);
		blakecoinhash(hash64, endiandata);
#ifndef DEBUG_ALGO
		if (hash64[7] <= HTarget && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			return true;
		}
#else
		if (!(n % 0x1000) && !thr_id) printf(".");
		if (hash64[7] == 0) {
			printf("[%d]",thr_id);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		}
#endif
		n++; pdata[19] = n;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

#endif
