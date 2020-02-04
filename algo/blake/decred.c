#include "decred-gate.h"

#if !defined(DECRED_8WAY) && !defined(DECRED_4WAY)

#include "sph_blake.h"

#include <string.h>
#include <stdint.h>
#include <memory.h>
#include <unistd.h>

/*
#ifndef min
#define min(a,b) (a>b ? b : a)
#endif
#ifndef max 
#define max(a,b) (a<b ? b : a)
#endif
*/
/*
#define DECRED_NBITS_INDEX 29
#define DECRED_NTIME_INDEX 34
#define DECRED_NONCE_INDEX 35
#define DECRED_XNONCE_INDEX 36
#define DECRED_DATA_SIZE 192
#define DECRED_WORK_COMPARE_SIZE 140
*/
static __thread sph_blake256_context blake_mid;
static __thread bool ctx_midstate_done = false;

void decred_hash(void *state, const void *input)
{
//        #define MIDSTATE_LEN 128
        sph_blake256_context ctx __attribute__ ((aligned (64)));

        uint8_t *ending = (uint8_t*) input;
        ending += DECRED_MIDSTATE_LEN;

        if (!ctx_midstate_done) {
                sph_blake256_init(&blake_mid);
                sph_blake256(&blake_mid, input, DECRED_MIDSTATE_LEN);
                ctx_midstate_done = true;
        }
        memcpy(&ctx, &blake_mid, sizeof(blake_mid));

        sph_blake256(&ctx, ending, (180 - DECRED_MIDSTATE_LEN));
        sph_blake256_close(&ctx, state);
}

void decred_hash_simple(void *state, const void *input)
{
        sph_blake256_context ctx;
        sph_blake256_init(&ctx);
        sph_blake256(&ctx, input, 180);
        sph_blake256_close(&ctx, state);
}

int scanhash_decred( struct work *work, uint32_t max_nonce,
               uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t _ALIGN(64) endiandata[48];
        uint32_t _ALIGN(64) hash32[8];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
   int thr_id = mythr->id;  // thr_id arg is deprecated

//        #define DCR_NONCE_OFT32 35

        const uint32_t first_nonce = pdata[DECRED_NONCE_INDEX];
        const uint32_t HTarget = opt_benchmark ? 0x7f : ptarget[7];

        uint32_t n = first_nonce;

        ctx_midstate_done = false;

#if 1
        memcpy(endiandata, pdata, 180);
#else
        for (int k=0; k < (180/4); k++)
                be32enc(&endiandata[k], pdata[k]);
#endif

        do {
                //be32enc(&endiandata[DCR_NONCE_OFT32], n);
                endiandata[DECRED_NONCE_INDEX] = n;
                decred_hash(hash32, endiandata);

                if (hash32[7] <= HTarget && fulltest(hash32, ptarget))
                {
                   pdata[DECRED_NONCE_INDEX] = n;
                   submit_solution( work, hash32, mythr );
                }

                n++;

        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[DECRED_NONCE_INDEX] = n;
        return 0;
}

/*
uint32_t *decred_get_nonceptr( uint32_t *work_data )
{
   return &work_data[ DECRED_NONCE_INDEX ];
}

double decred_calc_network_diff( struct work* work )
{
   // sample for diff 43.281 : 1c05ea29
   // todo: endian reversed on longpoll could be zr5 specific...
   uint32_t nbits = work->data[ DECRED_NBITS_INDEX ];
   uint32_t bits = ( nbits & 0xffffff );
   int16_t shift = ( swab32(nbits) & 0xff ); // 0x1c = 28
   int m;
   double d = (double)0x0000ffff / (double)bits;

   for ( m = shift; m < 29; m++ )
       d *= 256.0;
   for ( m = 29; m < shift; m++ )
       d /= 256.0;
   if ( shift == 28 )
       d *= 256.0; // testnet
   if ( opt_debug_diff )
       applog( LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d,
                           shift, bits );
   return net_diff;
}

void decred_decode_extradata( struct work* work, uint64_t* net_blocks )
{
   // some random extradata to make the work unique
   work->data[ DECRED_XNONCE_INDEX ] = (rand()*4);
   work->height = work->data[32];
   if (!have_longpoll && work->height > *net_blocks + 1)
   {
      char netinfo[64] = { 0 };
      if (net_diff > 0.)
      {
         if (net_diff != work->targetdiff)
	    sprintf(netinfo, ", diff %.3f, target %.1f", net_diff,
                   work->targetdiff);
	 else
	     sprintf(netinfo, ", diff %.3f", net_diff);
       }
       applog(LOG_BLUE, "%s block %d%s", algo_names[opt_algo], work->height,
                       netinfo);
       *net_blocks = work->height - 1;
   }
}

void decred_be_build_stratum_request( char *req, struct work *work,
                                      struct stratum_ctx *sctx )
{
   unsigned char *xnonce2str;
   uint32_t ntime, nonce;
   char ntimestr[9], noncestr[9];

   be32enc( &ntime, work->data[ DECRED_NTIME_INDEX ] );
   be32enc( &nonce, work->data[ DECRED_NONCE_INDEX ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex( (char*)( &work->data[ DECRED_XNONCE_INDEX ] ),
                                     sctx->xnonce1_size );
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
         rpc_user, work->job_id, xnonce2str, ntimestr, noncestr );
   free(xnonce2str);
}
*/
/*
// data shared between gen_merkle_root and build_extraheader.
__thread uint32_t decred_extraheader[32] = { 0 };
__thread int decred_headersize = 0;

void decred_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
   // getwork over stratum, getwork merkle + header passed in coinb1
   memcpy(merkle_root, sctx->job.coinbase, 32);
   decred_headersize = min((int)sctx->job.coinbase_size - 32, 
                  sizeof(decred_extraheader) );
   memcpy( decred_extraheader, &sctx->job.coinbase[32], decred_headersize);
}
*/

/*
#define min(a,b) (a>b ? (b) :(a))

void decred_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_root[64] = { 0 };
   uint32_t extraheader[32] = { 0 };
   int headersize = 0;
   uint32_t* extradata = (uint32_t*) sctx->xnonce1;
   size_t t;
   int i;

   // getwork over stratum, getwork merkle + header passed in coinb1
   memcpy(merkle_root, sctx->job.coinbase, 32);
   headersize = min((int)sctx->job.coinbase_size - 32,
                  sizeof(extraheader) );
   memcpy( extraheader, &sctx->job.coinbase[32], headersize );

   // Increment extranonce2 
   for ( t = 0; t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] ); t++ );

   // Assemble block header 
   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = le32dec( sctx->job.version );
   for ( i = 0; i < 8; i++ )
      g_work->data[1 + i] = swab32(
                              le32dec( (uint32_t *) sctx->job.prevhash + i ) );
   for ( i = 0; i < 8; i++ )
      g_work->data[9 + i] = swab32( be32dec( (uint32_t *) merkle_root + i ) );

//   for ( i = 0; i < 8; i++ ) // prevhash
//      g_work->data[1 + i] = swab32( g_work->data[1 + i] );
//   for ( i = 0; i < 8; i++ ) // merkle
//      g_work->data[9 + i] = swab32( g_work->data[9 + i] );

   for ( i = 0; i < headersize/4; i++ ) // header
      g_work->data[17 + i] = extraheader[i];
   // extradata

   for ( i = 0; i < sctx->xnonce1_size/4; i++ )
      g_work->data[ DECRED_XNONCE_INDEX + i ] = extradata[i];
   for ( i = DECRED_XNONCE_INDEX + sctx->xnonce1_size/4; i < 45; i++ )
      g_work->data[i] = 0;
   g_work->data[37] = (rand()*4) << 8;
   // block header suffix from coinb2 (stake version)
   memcpy( &g_work->data[44],
           &sctx->job.coinbase[ sctx->job.coinbase_size-4 ], 4 );
   sctx->bloc_height = g_work->data[32];
   //applog_hex(work->data, 180);
   //applog_hex(&work->data[36], 36);
}

#undef min

bool decred_ready_to_mine( struct work* work, struct stratum_ctx* stratum,
                           int thr_id )
{
   if ( have_stratum && strcmp(stratum->job.job_id, work->job_id)  )
      // need to regen g_work..
      return false;
   if ( have_stratum && !work->data[0] && !opt_benchmark )
   {
      sleep(1);
      return false;
   }      
   // extradata: prevent duplicates
   work->data[ DECRED_XNONCE_INDEX     ] += 1;
   work->data[ DECRED_XNONCE_INDEX + 1 ] |= thr_id;
   return true;
}


bool register_decred_algo( algo_gate_t* gate )
{
  gate->optimizations         = SSE2_OPT;
  gate->scanhash              = (void*)&scanhash_decred;
  gate->hash                  = (void*)&decred_hash;
  gate->get_nonceptr          = (void*)&decred_get_nonceptr;
  gate->decode_extra_data     = (void*)&decred_decode_extradata;
  gate->build_stratum_request = (void*)&decred_be_build_stratum_request;
  gate->work_decode           = (void*)&std_be_work_decode;
  gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
  gate->build_extraheader     = (void*)&decred_build_extraheader;
  gate->ready_to_mine         = (void*)&decred_ready_to_mine;
  gate->nbits_index           = DECRED_NBITS_INDEX;
  gate->ntime_index           = DECRED_NTIME_INDEX;
  gate->nonce_index           = DECRED_NONCE_INDEX;
  gate->work_data_size        = DECRED_DATA_SIZE;
  gate->work_cmp_size         = DECRED_WORK_COMPARE_SIZE; 
  allow_mininginfo            = false;
  have_gbt                    = false;
  return true;
}
*/

#endif
