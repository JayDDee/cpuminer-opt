#include "blake2s-gate.h"

#if  !defined(BLAKE2S_16WAY) && !defined(BLAKE2S_8WAY) && !defined(BLAKE2S)

#include <string.h>
#include <stdint.h>

#include "sph-blake2s.h"

static __thread blake2s_state blake2s_ctx;
//static __thread blake2s_state s_ctx;
#define MIDLEN 76

void blake2s_hash( void *output, const void *input )
{
   unsigned char _ALIGN(64) hash[BLAKE2S_OUTBYTES];
   blake2s_state ctx __attribute__ ((aligned (64)));
  
   memcpy( &ctx, &blake2s_ctx, sizeof ctx );
   blake2s_update( &ctx, input+64, 16 );
 
//	blake2s_init(&ctx, BLAKE2S_OUTBYTES);
//	blake2s_update(&ctx, input, 80);
	blake2s_final( &ctx, hash, BLAKE2S_OUTBYTES );

	memcpy(output, hash, 32);
}
/*
static void blake2s_hash_end(uint32_t *output, const uint32_t *input)
{
	s_ctx.buflen = MIDLEN;
	memcpy(&s_ctx, &s_midstate, 32 + 16 + MIDLEN);
	blake2s_update(&s_ctx, (uint8_t*) &input[MIDLEN/4], 80 - MIDLEN);
	blake2s_final(&s_ctx, (uint8_t*) output, BLAKE2S_OUTBYTES);
}
*/
int scanhash_blake2s( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

	uint32_t _ALIGN(64) hash64[8];
	uint32_t _ALIGN(64) endiandata[20];
   int thr_id = mythr->id;  // thr_id arg is deprecated

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[19];

	uint32_t n = first_nonce;

        swab32_array( endiandata, pdata, 20 );

	// midstate
	blake2s_init( &blake2s_ctx, BLAKE2S_OUTBYTES );
	blake2s_update( &blake2s_ctx, (uint8_t*) endiandata, 64 );

	do {
		be32enc(&endiandata[19], n);
		blake2s_hash( hash64, endiandata );
		if (hash64[7] <= Htarg && fulltest(hash64, ptarget)) {
			*hashes_done = n - first_nonce + 1;
			pdata[19] = n;
			return true;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);

	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;

	return 0;
}
#endif
