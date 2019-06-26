#include "miner.h"
#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>

#include "sph_shavite.h"

extern void inkhash(void *state, const void *input)
{
    sph_shavite512_context	 ctx_shavite;
    uint32_t hash[16];
	
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512 (&ctx_shavite, (const void*) input, 80);
    sph_shavite512_close(&ctx_shavite, (void*) hash);
    
    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, (const void*) hash, 64);
    sph_shavite512_close(&ctx_shavite, (void*) hash);

    memcpy(state, hash, 32);

/*	
	int ii;
	printf("result: ");
	for (ii=0; ii < 32; ii++)
	{
		printf ("%.2x",((uint8_t*)state)[ii]);
	};
	printf ("\n");	
*/	
}

int scanhash_ink( struct work *work,
	uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
   int thr_id = mythr->id;

	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];

	uint32_t _ALIGN(32) hash64[8];
	uint32_t endiandata[32];
	
	//char testdata[] = {"\x70\x00\x00\x00\x5d\x38\x5b\xa1\x14\xd0\x79\x97\x0b\x29\xa9\x41\x8f\xd0\x54\x9e\x7d\x68\xa9\x5c\x7f\x16\x86\x21\xa3\x14\x20\x10\x00\x00\x00\x00\x57\x85\x86\xd1\x49\xfd\x07\xb2\x2f\x3a\x8a\x34\x7c\x51\x6d\xe7\x05\x2f\x03\x4d\x2b\x76\xff\x68\xe0\xd6\xec\xff\x9b\x77\xa4\x54\x89\xe3\xfd\x51\x17\x32\x01\x1d\xf0\x73\x10\x00"};
	
	//we need bigendian data...
	//lessons learned: do NOT endianchange directly in pdata, this will all proof-of-works be considered as stale from minerd.... 
	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

//	if (opt_debug) 
//	{
//		applog(LOG_DEBUG, "Thr: %02d, firstN: %08x, maxN: %08x, ToDo: %d", thr_id, first_nonce, max_nonce, max_nonce-first_nonce);
//	}
	
	/* I'm to lazy to put the loop in an inline function... so dirty copy'n'paste.... */
	/* i know that i could set a variable, but i don't know how the compiler will optimize it, not that then the cpu needs to load the value *everytime* in a register */
	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (((hash64[7]&0xFFFFF000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else if (ptarget[7]<=0xFFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (((hash64[7]&0xFFFF0000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			inkhash(hash64, endiandata);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	}
	
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

bool register_shavite_algo( algo_gate_t* gate )
{
    algo_not_implemented();
    return false;

//    gate->scanhash = (void*)&scanhash_ink;
//    gate->hash     = (void*)&inkhash;
//    return true;
};

