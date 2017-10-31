/**
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2015 kernels10, tpruvot
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     drop.c
 * @author   kernels10 <kernels10@gmail.com.com>
 * @author   tpruvot <tpruvot@github>
 */

#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000
 
#include "algo-gate-api.h"

#include <string.h>

#include "algo/blake/sph_blake.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/echo/sph_echo.h"
#include "algo/fugue//sph_fugue.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/simd/sph_simd.h"
#include "algo/shavite/sph_shavite.h"

static void shiftr_lp(const uint32_t *input, uint32_t *output, unsigned int shift)
{
	if(!shift) {
		memcpy(output, input, 64);
		return;
	}

	memset(output, 0, 64);
	for(int i = 0; i < 15; ++i) {
		output[i + 1] |= (input[i] >> (32 - shift));
		output[i] |= (input[i] << shift);
	}

	output[15] |= (input[15] << shift);
	return;
}

static void switchHash(const void *input, void *output, int id)
{
/*
 	sph_keccak512_context ctx_keccak;
	sph_blake512_context ctx_blake;
	sph_groestl512_context ctx_groestl;
	sph_skein512_context ctx_skein;
	sph_luffa512_context ctx_luffa;
	sph_echo512_context ctx_echo;
	sph_simd512_context ctx_simd;
	sph_cubehash512_context ctx_cubehash;
	sph_fugue512_context ctx_fugue;
	sph_shavite512_context ctx_shavite;

	switch(id) {
	case 0:
		sph_keccak512_init(&ctx_keccak); sph_keccak512(&ctx_keccak, input, 64); sph_keccak512_close(&ctx_keccak, output);
		break;
	case 1:
		sph_blake512_init(&ctx_blake); sph_blake512(&ctx_blake, input, 64); sph_blake512_close(&ctx_blake, output);
		break;
	case 2:
		sph_groestl512_init(&ctx_groestl); sph_groestl512(&ctx_groestl, input, 64); sph_groestl512_close(&ctx_groestl, output);
		break;
	case 3:
		sph_skein512_init(&ctx_skein); sph_skein512(&ctx_skein, input, 64); sph_skein512_close(&ctx_skein, output);
		break;
	case 4:
		sph_luffa512_init(&ctx_luffa); sph_luffa512(&ctx_luffa, input, 64); sph_luffa512_close(&ctx_luffa, output);
		break;
	case 5:
		sph_echo512_init(&ctx_echo); sph_echo512(&ctx_echo, input, 64); sph_echo512_close(&ctx_echo, output);
		break;
	case 6:
		sph_shavite512_init(&ctx_shavite); sph_shavite512(&ctx_shavite, input, 64); sph_shavite512_close(&ctx_shavite, output);
		break;
	case 7:
		sph_fugue512_init(&ctx_fugue); sph_fugue512(&ctx_fugue, input, 64); sph_fugue512_close(&ctx_fugue, output);
		break;
	case 8:
		sph_simd512_init(&ctx_simd); sph_simd512(&ctx_simd, input, 64); sph_simd512_close(&ctx_simd, output);
		break;
	case 9:
		sph_cubehash512_init(&ctx_cubehash); sph_cubehash512(&ctx_cubehash, input, 64); sph_cubehash512_close(&ctx_cubehash, output);
		break;
	default:
		break;
	}
*/
}

void droplp_hash(void *state, const void *input)
{
	uint32_t _ALIGN(64) hash[2][16];
	sph_jh512_context ctx_jh;
	uint32_t *hashA = hash[0];
	uint32_t *hashB = hash[1];

	sph_jh512_init(&ctx_jh);
	sph_jh512(&ctx_jh, input, 80);
	sph_jh512_close(&ctx_jh, (void*)(hashA));

	unsigned int startPosition = hashA[0] % 31;
	unsigned int i = 0;
	int j = 0;
	int start = 0;

	for (i = startPosition; i < 31; i+=9) {
		start = i % 10;
		for (j = start; j < 10; j++) {
			shiftr_lp(hashA, hashB, (i & 3));
			switchHash((const void*)hashB, (void*)hashA, j);
		}
		for (j = 0; j < start; j++) {
			shiftr_lp(hashA, hashB, (i & 3));
			switchHash((const void*)hashB, (void*)hashA, j);
		}
	}
	for (i = 0; i < startPosition; i += 9) {
		start = i % 10;
		for (j = start; j < 10; j++) {
			shiftr_lp(hashA, hashB, (i & 3));
			switchHash((const void*)hashB, (void*)hashA, j);
		}
		for (j = 0; j < start; j++) {
			shiftr_lp(hashA, hashB, (i & 3));
			switchHash((const void*)hashB, (void*)hashA, j);
		}
	}

	memcpy(state, hashA, 32);
}

static void droplp_hash_pok(void *output, uint32_t *pdata, const uint32_t version)
{
	uint32_t _ALIGN(64) hash[8];
	uint32_t pok;

	pdata[0] = version;
	droplp_hash(hash, pdata);

	// fill PoK
	pok = version | (hash[0] & POK_DATA_MASK);
	if (pdata[0] != pok) {
		pdata[0] = pok;
		droplp_hash(hash, pdata);
	}
	memcpy(output, hash, 32);
}

int scanhash_drop(int thr_id, struct work *work, uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t _ALIGN(64) hash[16];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;
	const uint32_t version = pdata[0] & (~POK_DATA_MASK);
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;
	#define tmpdata pdata

	if (opt_benchmark)
		ptarget[7] = 0x07ff;

	const uint32_t htarg = ptarget[7];

	do {
		tmpdata[19] = nonce;
		droplp_hash_pok(hash, tmpdata, version);

		if (hash[7] <= htarg && fulltest(hash, ptarget)) {
			pdata[0] = tmpdata[0];
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce + 1;
			if (opt_debug)
				applog(LOG_INFO, "found nonce %x", nonce);
			return 1;
		}
		nonce++;

	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

void drop_get_new_work( struct work* work, struct work* g_work, int thr_id,
                        uint32_t* end_nonce_ptr, bool clean_job )
{
   // ignore POK in first word
// const int nonce_i = 19;
   const int wkcmp_sz = 72;  // (19-1) * sizeof(uint32_t)
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );
   if ( memcmp( &work->data[1], &g_work->data[1], wkcmp_sz )
       && ( clean_job || ( *nonceptr >= *end_nonce_ptr ) ) )
   {
      work_free( work );
      work_copy( work, g_work );
      *nonceptr = ( 0xffffffffU / opt_n_threads ) * thr_id;
      if ( opt_randomize )
         *nonceptr += ( (rand() *4 ) & UINT32_MAX ) / opt_n_threads;
      *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20;
   }
   else
       ++(*nonceptr);
}

void drop_display_pok( struct work* work ) 
{
      if ( work->data[0] & 0x00008000 ) 
        applog(LOG_BLUE, "POK received: %08xx", work->data[0] );
}

// Need to fix POK offset problems like zr5
bool register_drop_algo( algo_gate_t* gate )
{
    algo_not_tested();
    gate->scanhash              = (void*)&scanhash_drop;
    gate->hash                  = (void*)&droplp_hash_pok;
    gate->get_new_work          = (void*)&drop_get_new_work;
    gate->set_target            = (void*)&scrypt_set_target;
    gate->build_stratum_request = (void*)&std_be_build_stratum_request;
    gate->work_decode           = (void*)&std_be_work_decode;
    gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
    gate->set_work_data_endian  = (void*)&set_work_data_big_endian;
    gate->display_extra_data    = (void*)&drop_display_pok;
    gate->work_data_size        = 80;
    gate->work_cmp_size         = 72;
    return true;
};

