#include "decred-gate.h"
#include <unistd.h>
#include <memory.h>
#include <string.h>

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
      if ( net_diff > 0. )
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
#define min(a,b) (a>b ? (b) :(a))

void decred_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_root[64] = { 0 };
   uint32_t extraheader[32] = { 0 };
   int headersize = 0;
   uint32_t* extradata = (uint32_t*) sctx->xnonce1;
   int i;

   // getwork over stratum, getwork merkle + header passed in coinb1
   memcpy(merkle_root, sctx->job.coinbase, 32);
   headersize = min((int)sctx->job.coinbase_size - 32,
                  sizeof(extraheader) );
   memcpy( extraheader, &sctx->job.coinbase[32], headersize );

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
   sctx->block_height = g_work->data[32];
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

int decred_get_work_data_size() { return DECRED_DATA_SIZE; }

bool register_decred_algo( algo_gate_t* gate )
{
#if defined(DECRED_4WAY)
  four_way_not_tested();
  gate->scanhash  = (void*)&scanhash_decred_4way;
  gate->hash      = (void*)&decred_hash_4way;
#else
  gate->scanhash  = (void*)&scanhash_decred;
  gate->hash      = (void*)&decred_hash;
#endif
  gate->optimizations = AVX2_OPT;
//  gate->get_nonceptr          = (void*)&decred_get_nonceptr;
  gate->decode_extra_data     = (void*)&decred_decode_extradata;
  gate->build_stratum_request = (void*)&decred_be_build_stratum_request;
  gate->work_decode           = (void*)&std_be_work_decode;
  gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
  gate->build_extraheader     = (void*)&decred_build_extraheader;
  gate->ready_to_mine         = (void*)&decred_ready_to_mine;
  gate->nbits_index           = DECRED_NBITS_INDEX;
  gate->ntime_index           = DECRED_NTIME_INDEX;
  gate->nonce_index           = DECRED_NONCE_INDEX;
  gate->get_work_data_size    = (void*)&decred_get_work_data_size;
  gate->work_cmp_size         = DECRED_WORK_COMPARE_SIZE;
  allow_mininginfo            = false;
  have_gbt                    = false;
  return true;
}

