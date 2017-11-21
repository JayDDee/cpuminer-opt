/**
 * Blake2-B Implementation
 * tpruvot@github 2015-2016
 */

#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include "algo/blake/sph_blake2b.h"

//static __thread sph_blake2b_ctx s_midstate;
//static __thread sph_blake2b_ctx s_ctx;
#define MIDLEN 76
#define A 64

void blake2b_hash(void *output, const void *input)
{
	uint8_t _ALIGN(A) hash[32];
	sph_blake2b_ctx ctx __attribute__ ((aligned (64)));

	sph_blake2b_init(&ctx, 32, NULL, 0);
	sph_blake2b_update(&ctx, input, 80);
	sph_blake2b_final(&ctx, hash);

	memcpy(output, hash, 32);
}

/*
static void blake2b_hash_end(uint32_t *output, const uint32_t *input)
{
	s_ctx.outlen = MIDLEN;
	memcpy(&s_ctx, &s_midstate, 32 + 16 + MIDLEN);
	sph_blake2b_update(&s_ctx, (uint8_t*) &input[MIDLEN/4], 80 - MIDLEN);
	sph_blake2b_final(&s_ctx, (uint8_t*) output);
}
*/

int scanhash_blake2b( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done )
{
	uint32_t _ALIGN(A) vhashcpu[8];
	uint32_t _ALIGN(A) endiandata[20];
	uint32_t *pdata = work->data;
	uint32_t *ptarget = work->target;

	const uint32_t Htarg = ptarget[7];
	const uint32_t first_nonce = pdata[8];

	uint32_t n = first_nonce;

	for (int i=0; i < 19; i++) {
		be32enc(&endiandata[i], pdata[i]);
	}

	// midstate (untested yet)
	//blake2b_init(&s_midstate, 32, NULL, 0);
	//blake2b_update(&s_midstate, (uint8_t*) endiandata, MIDLEN);
	//memcpy(&s_ctx, &s_midstate, sizeof(blake2b_ctx));

	do {
		be32enc(&endiandata[8], n);
		//blake2b_hash_end(vhashcpu, endiandata);
		blake2b_hash(vhashcpu, endiandata);

		if (vhashcpu[7] < Htarg && fulltest(vhashcpu, ptarget)) {
			work_set_target_ratio(work, vhashcpu);
			*hashes_done = n - first_nonce + 1;
			pdata[8] = n;
			return 1;
		}
		n++;

	} while (n < max_nonce && !work_restart[thr_id].restart);
	*hashes_done = n - first_nonce + 1;
	pdata[8] = n;

	return 0;
}

static inline void swab256(void *dest_p, const void *src_p)
{
	uint32_t *dest = (uint32_t *)dest_p;
	const uint32_t *src = (uint32_t *)src_p;

	dest[0] = swab32(src[7]);
	dest[1] = swab32(src[6]);
	dest[2] = swab32(src[5]);
	dest[3] = swab32(src[4]);
	dest[4] = swab32(src[3]);
	dest[5] = swab32(src[2]);
	dest[6] = swab32(src[1]);
	dest[7] = swab32(src[0]);
}

/* compute nbits to get the network diff */
void blake2b_calc_network_diff(struct work *work)
{
        // sample for diff 43.281 : 1c05ea29
        uint32_t nbits = work->data[11]; // unsure if correct
        uint32_t bits = (nbits & 0xffffff);
        int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

        double d = (double)0x0000ffff / (double)bits;
        for (int m=shift; m < 29; m++) d *= 256.0;
        for (int m=29; m < shift; m++) d /= 256.0;
        if (opt_debug_diff)
                applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);
        net_diff = d;
}

void blake2b_be_build_stratum_request( char *req, struct work *work )
{
   unsigned char *xnonce2str;
   uint32_t ntime,       nonce;
   char     ntimestr[9], noncestr[9];
   be32enc( &ntime, work->data[ algo_gate.ntime_index ] );
   be32enc( &nonce, work->data[ algo_gate.nonce_index ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   uint16_t high_nonce = swab32(work->data[9]) >> 16;
   xnonce2str = abin2hex((unsigned char*)(&high_nonce), 2);
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
         rpc_user, work->job_id, xnonce2str, ntimestr, noncestr );
   free( xnonce2str );
}

#define min(a,b) (a>b ? (b) :(a))

// merkle root handled here, no need for gen_merkle_root gate target
void blake2b_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
    uchar merkle_root[64] = { 0 };
    uint32_t extraheader[32] = { 0 };
    int headersize = 0;
    size_t t;
    int i;

    // merkle root
    memcpy( merkle_root, sctx->job.coinbase, 32 );
    headersize = min( (int)sctx->job.coinbase_size - 32, sizeof(extraheader) );
    memcpy( extraheader, &sctx->job.coinbase[32], headersize );
    // Increment extranonce2 
    for ( t = 0; t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] ); t++ );
    // Assemble block header 
    memset( g_work->data, 0, sizeof(g_work->data) );
//    g_work->data[0] = le32dec( sctx->job.version );
//    for ( i = 0; i < 8; i++ )
//       g_work->data[1 + i] = le32dec( (uint32_t *) sctx->job.prevhash + i );
    for ( i = 0; i < 8; i++ )
       g_work->data[i] = ((uint32_t*)sctx->job.prevhash)[7-i];
//    for ( i = 0; i < 8; i++ )
//       g_work->data[9 + i] = be32dec( (uint32_t *) merkle_root + i );
    g_work->data[8]  = 0; // nonce
    g_work->data[9]  = swab32( extraheader[0] ) | ( rand() & 0xf0 );
    g_work->data[10] = be32dec( sctx->job.ntime );
    g_work->data[11] = be32dec( sctx->job.nbits );
    for ( i = 0; i < 8; i++ )
       g_work->data[12+i] = ( (uint32_t*)merkle_root )[i];
}

#undef min

void blake2b_get_new_work( struct work* work, struct work* g_work, int thr_id,
                           uint32_t* end_nonce_ptr, bool clean_job )
{
   const int wkcmp_sz = 32;  // bytes
   const int wkcmp_off = 32 + 16; 
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );

   if ( memcmp( &work->data[ wkcmp_off ], &g_work->data[ wkcmp_off ], wkcmp_sz )
      && ( clean_job || ( *nonceptr >= *end_nonce_ptr ) 
      || strcmp( work->job_id, g_work->job_id ) ) )
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

   // suprnova job_id check without data/target/height change...
   // we just may have copied new g_wwork to work so why this test here?
//   if (  have_stratum && strcmp( work->job_id, g_work->job_id ) )
      // exit thread loop
//      continue;
//   else
//   {
//      nonceptr[1] += 0x10;
//      nonceptr[1] |= thr_id;
//   }
}

bool blake2b_ready_to_mine( struct work* work, struct stratum_ctx* stratum,
                           int thr_id )
{
   if ( have_stratum && strcmp( stratum->job.job_id, work->job_id ) )
      // need to regen g_work..
      return false;
   // extradata: prevent duplicates
   work->data[ 8     ] += 0x10;
   work->data[ 8 + 1 ] |= thr_id;
   return true;
}

double blake2b_get_max64() { return 0x1fffffLL; }

bool register_blake2b_algo( algo_gate_t* gate )
{
  algo_not_tested();
  gate->ntime_index   = 10;
  gate->nbits_index   = 11;
  gate->nonce_index   =  8;
  gate->work_cmp_size = 32;
  gate->scanhash              = (void*)&scanhash_blake2b;
  gate->hash                  = (void*)&blake2b_hash;
  gate->calc_network_diff     = (void*)&blake2b_calc_network_diff;
  gate->build_stratum_request = (void*)&blake2b_be_build_stratum_request;
  gate->work_decode           = (void*)&std_be_work_decode;
  gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
  gate->build_extraheader     = (void*)&blake2b_build_extraheader;
  gate->get_new_work          = (void*)&blake2b_get_new_work;
  gate->get_max64             = (void*)&blake2b_get_max64;
  gate->ready_to_mine         = (void*)&blake2b_ready_to_mine;
  have_gbt = false;
  return true;
}
