#include "lbry-gate.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

// std_le should work but it doesn't
void lbry_le_build_stratum_request( char *req, struct work *work,
                                      struct stratum_ctx *sctx )
{
   unsigned char *xnonce2str;
   uint32_t ntime, nonce;
   char ntimestr[9], noncestr[9];

   le32enc( &ntime, work->data[ LBRY_NTIME_INDEX ] );
   le32enc( &nonce, work->data[ LBRY_NONCE_INDEX ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex( work->xnonce2, work->xnonce2_len);
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
         rpc_user, work->job_id, xnonce2str, ntimestr, noncestr );
   free(xnonce2str);
}

void lbry_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   unsigned char merkle_root[64] = { 0 };
   int i;

   algo_gate.gen_merkle_root( merkle_root, sctx );

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = le32dec( sctx->job.version );

   for ( i = 0; i < 8; i++ )
      g_work->data[1 + i] = le32dec( (uint32_t *) sctx->job.prevhash + i );

   for ( i = 0; i < 8; i++ )
      g_work->data[9 + i] = be32dec( (uint32_t *) merkle_root + i );

   for ( int i = 0; i < 8; i++ )
        g_work->data[17 + i] = ((uint32_t*)sctx->job.extra)[i];

   g_work->data[ LBRY_NTIME_INDEX ] = le32dec(sctx->job.ntime);
   g_work->data[ LBRY_NBITS_INDEX ] = le32dec(sctx->job.nbits);
   g_work->data[28] = 0x80000000;
}

int lbry_get_work_data_size() { return LBRY_WORK_DATA_SIZE; }

bool register_lbry_algo( algo_gate_t* gate )
{
//  gate->optimizations = AVX2_OPT | AVX512_OPT | SHA_OPT;
#if defined (LBRY_16WAY)
  gate->scanhash              = (void*)&scanhash_lbry_16way;
  gate->hash                  = (void*)&lbry_16way_hash;
  gate->optimizations = AVX2_OPT | AVX512_OPT;
#elif defined (LBRY_8WAY)
  gate->scanhash              = (void*)&scanhash_lbry_8way;
  gate->hash                  = (void*)&lbry_8way_hash;
  gate->optimizations = AVX2_OPT | AVX512_OPT;
#elif defined (LBRY_4WAY)
  gate->scanhash              = (void*)&scanhash_lbry_4way;
  gate->hash                  = (void*)&lbry_4way_hash;
  gate->optimizations = AVX2_OPT | AVX512_OPT;
#else 
  gate->scanhash              = (void*)&scanhash_lbry;
  gate->hash                  = (void*)&lbry_hash;
  gate->optimizations = AVX2_OPT | AVX512_OPT | SHA_OPT;
#endif
  gate->build_stratum_request = (void*)&lbry_le_build_stratum_request;
  gate->build_extraheader     = (void*)&lbry_build_extraheader;
  gate->ntime_index           = LBRY_NTIME_INDEX;
  gate->nbits_index           = LBRY_NBITS_INDEX;
  gate->nonce_index           = LBRY_NONCE_INDEX;
  gate->get_work_data_size    = (void*)&lbry_get_work_data_size;
  opt_target_factor = 256.0;
  return true;
}

