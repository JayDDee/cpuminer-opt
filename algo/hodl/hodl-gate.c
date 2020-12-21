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

char* hodl_malloc_txs_request( struct work *work )
{
  char* req;
  json_t *val;
  char data_str[2 * sizeof(work->data) + 1];
  int i;

  for ( i = 0; i < ARRAY_SIZE(work->data); i++ )
    be32enc( work->data + i, work->data[i] );

  bin2hex( data_str, (unsigned char *)work->data, 88 );
  if ( work->workid )
  {
    char *params;
    val = json_object();
    json_object_set_new( val, "workid", json_string( work->workid ) );
    params = json_dumps( val, 0 );
    json_decref( val );
    req = malloc( 128 + 2*88 + strlen( work->txs ) + strlen( params ) );
    sprintf( req,
     "{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":1}\r\n",
      data_str, work->txs, params);
    free( params );
  }
  else
  {
    req = malloc( 128 + 2*88 + strlen(work->txs));
    sprintf( req,
       "{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":1}\r\n",
        data_str, work->txs);
  }
  return req;
}

void hodl_build_block_header( struct work* g_work, uint32_t version,
                              uint32_t *prevhash, uint32_t *merkle_tree,
                              uint32_t ntime, uint32_t nbits )
{
   int i;

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = version;

   if ( have_stratum )
      for ( i = 0; i < 8; i++ )
         g_work->data[ 1+i ] = le32dec( prevhash + i );
   else
      for (i = 0; i < 8; i++)
         g_work->data[ 8-i ] = le32dec( prevhash + i );

   for ( i = 0; i < 8; i++ )
      g_work->data[ 9+i ] = be32dec( merkle_tree + i );

   g_work->data[ algo_gate.ntime_index ] = ntime;
   g_work->data[ algo_gate.nbits_index ] = nbits;
   g_work->data[22] = 0x80000000;
   g_work->data[31] = 0x00000280;
}

// called only by thread 0, saves a backup of g_work
void hodl_get_new_work( struct work* work, struct work* g_work)
{
//   pthread_rwlock_rdlock( &g_work_lock );

   work_free( &hodl_work );
   work_copy( &hodl_work, g_work );
   hodl_work.data[ algo_gate.nonce_index ] = ( clock() + rand() ) % 9999;

//   pthread_rwlock_unlock( &g_work_lock );
}

json_t *hodl_longpoll_rpc_call( CURL *curl, int *err, char* lp_url )
{
   json_t *val;
   char *req = NULL;

   if ( have_gbt )
   {
      req = malloc( strlen( gbt_lp_req ) + strlen( lp_id ) + 1 );
      sprintf( req, gbt_lp_req, lp_id );
   }
   val = json_rpc_call( curl, lp_url, rpc_userpass,
                        req ? req : getwork_req, err, JSON_RPC_LONGPOLL );
   free( req );
   return val;
}

// called by every thread, copies the backup to each thread's work.
void hodl_resync_threads( int thr_id, struct work* work )
{
   int nonce_index = algo_gate.nonce_index;
   pthread_barrier_wait( &hodl_barrier );
   if ( memcmp( work->data, hodl_work.data, algo_gate.work_cmp_size ) )
   {
      work_free( work );
      work_copy( work, &hodl_work );
   }
   work->data[ nonce_index ] = swab32( hodl_work.data[ nonce_index ] );
   work_restart[thr_id].restart = 0;
}

bool hodl_do_this_thread( int thr_id )
{
  return ( thr_id == 0 );
}

int hodl_scanhash( struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done, struct thr_info *mythr )
{
#if defined(__AES__)
  GenRandomGarbage( (CacheEntry*)hodl_scratchbuf, work->data, mythr->id );
  pthread_barrier_wait( &hodl_barrier );
  return scanhash_hodl_wolf( work, max_nonce, hashes_done, mythr );
#endif
  return false;
}

bool register_hodl_algo( algo_gate_t* gate )
{
#if !defined(__AES__)
  applog( LOG_ERR, "Only CPUs with AES are supported, use legacy version.");
  return false;
#endif

  if ( GARBAGE_SIZE % opt_n_threads )
     applog( LOG_WARNING,"WARNING: Thread count must be power of 2. Miner may crash or produce invalid hash!" );

  pthread_barrier_init( &hodl_barrier, NULL, opt_n_threads );
  gate->optimizations         = SSE42_OPT | AES_OPT | AVX2_OPT;
  gate->scanhash              = (void*)&hodl_scanhash;
  gate->get_new_work          = (void*)&hodl_get_new_work;
  gate->longpoll_rpc_call     = (void*)&hodl_longpoll_rpc_call;
  gate->build_stratum_request = (void*)&hodl_le_build_stratum_request;
  gate->malloc_txs_request    = (void*)&hodl_malloc_txs_request;
  gate->build_block_header    = (void*)&hodl_build_block_header;
  gate->resync_threads        = (void*)&hodl_resync_threads;
  gate->do_this_thread        = (void*)&hodl_do_this_thread;
  gate->work_cmp_size         = 76;
  hodl_scratchbuf = (unsigned char*)_mm_malloc( 1 << 30, 64 );
  allow_getwork = false;
  opt_target_factor = 8388608.0;
  return ( hodl_scratchbuf != NULL );
}


