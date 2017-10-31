#include <memory.h>
#include <stdlib.h>

#include "hodl-gate.h"
#include "hodl-wolf.h"

#define HODL_NSTARTLOC_INDEX 20
#define HODL_NFINALCALC_INDEX 21

static struct work hodl_work;

pthread_barrier_t hodl_barrier;

// All references to this buffer are local to this file, so no args
// need to be passed.
unsigned char *hodl_scratchbuf = NULL;

void hodl_set_target( struct work* work, double diff )
{
     diff_to_target(work->target, diff / 8388608.0 );
}

void hodl_le_build_stratum_request( char* req, struct work* work,
                                    struct stratum_ctx *sctx ) 
{
   uint32_t ntime,       nonce,       nstartloc,       nfinalcalc;
   char     ntimestr[9], noncestr[9], nstartlocstr[9], nfinalcalcstr[9];
   unsigned char *xnonce2str;

   le32enc( &ntime, work->data[ algo_gate.ntime_index ] );
   le32enc( &nonce, work->data[ algo_gate.nonce_index ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex(work->xnonce2, work->xnonce2_len );
   le32enc( &nstartloc,  work->data[ HODL_NSTARTLOC_INDEX ] );
   le32enc( &nfinalcalc, work->data[ HODL_NFINALCALC_INDEX ] );
   bin2hex( nstartlocstr,  (char*)(&nstartloc),  sizeof(uint32_t) );
   bin2hex( nfinalcalcstr, (char*)(&nfinalcalc), sizeof(uint32_t) );
   sprintf( req, "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
           rpc_user, work->job_id, xnonce2str, ntimestr, noncestr,
           nstartlocstr, nfinalcalcstr );
   free( xnonce2str );
}

void hodl_build_extraheader( struct work* g_work, struct stratum_ctx *sctx )
{
   uchar merkle_root[64] = { 0 };
   size_t t;
   int i;

   algo_gate.gen_merkle_root( merkle_root, sctx );
   // Increment extranonce2
   for ( t = 0; t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] ); t++ );
   // Assemble block header
   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = le32dec( sctx->job.version );
   for ( i = 0; i < 8; i++ )
      g_work->data[1 + i] = le32dec( (uint32_t *) sctx->job.prevhash + i );
   for ( i = 0; i < 8; i++ )
      g_work->data[9 + i] = be32dec( (uint32_t *) merkle_root + i );

   g_work->data[ algo_gate.ntime_index ] = le32dec( sctx->job.ntime );
   g_work->data[ algo_gate.nbits_index ] = le32dec( sctx->job.nbits );
   g_work->data[22] = 0x80000000;
   g_work->data[31] = 0x00000280;
}

// called only by thread 0, saves a backup of g_work
void hodl_get_new_work( struct work* work, struct work* g_work)
{
     work_free( &hodl_work );
     work_copy( &hodl_work, g_work );
     hodl_work.data[ algo_gate.nonce_index ] = ( clock() + rand() ) % 9999;
}

// called by every thread, copies the backup to each thread's work.
void hodl_resync_threads( struct work* work )
{
   int nonce_index = algo_gate.nonce_index;
   pthread_barrier_wait( &hodl_barrier );
   if ( memcmp( work->data, hodl_work.data, algo_gate.work_cmp_size ) )
   {
      work_free( work );
      work_copy( work, &hodl_work );
   }
   work->data[ nonce_index ] = swab32( hodl_work.data[ nonce_index ] );
}

bool hodl_do_this_thread( int thr_id )
{
  return ( thr_id == 0 );
}

int hodl_scanhash( int thr_id, struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done )
{
#ifndef NO_AES_NI
  GenRandomGarbage( hodl_scratchbuf, work->data, thr_id );
  pthread_barrier_wait( &hodl_barrier );
  return scanhash_hodl_wolf( thr_id, work, max_nonce, hashes_done );
#endif
}

bool register_hodl_algo( algo_gate_t* gate )
{
#ifdef NO_AES_NI
  applog( LOG_ERR, "Only CPUs with AES are supported, use legacy version.");
  return false;
#endif
  pthread_barrier_init( &hodl_barrier, NULL, opt_n_threads );
  gate->optimizations         = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->scanhash              = (void*)&hodl_scanhash;
  gate->get_new_work          = (void*)&hodl_get_new_work;
  gate->set_target            = (void*)&hodl_set_target;
  gate->build_stratum_request = (void*)&hodl_le_build_stratum_request;
  gate->build_extraheader     = (void*)&hodl_build_extraheader;
  gate->resync_threads        = (void*)&hodl_resync_threads;
  gate->do_this_thread        = (void*)&hodl_do_this_thread;
  gate->work_cmp_size         = 76;
  hodl_scratchbuf = (unsigned char*)malloc( 1 << 30 );
  return ( hodl_scratchbuf != NULL );
}


