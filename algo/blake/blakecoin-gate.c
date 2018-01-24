#include "blakecoin-gate.h"
#include <memory.h>

// changed to get_max64_0x3fffffLL in cpuminer-multi-decred
int64_t blakecoin_get_max64 ()
{
  return 0x7ffffLL;
//  return 0x3fffffLL;
}

// Blakecoin 4 way hashes so fast it runs out of nonces.
// This is an attempt to solve this but the result may be
// to rehash old nonces until new work is received.
void bc4w_get_new_work( struct work* work, struct work* g_work, int thr_id,
                     uint32_t *end_nonce_ptr, bool clean_job )
{
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );
 
//   if ( have_stratum && ( *nonceptr >= *end_nonce_ptr ) )
//      algo_gate.stratum_gen_work( &stratum, g_work );

   if ( memcmp( work->data, g_work->data, algo_gate.work_cmp_size ) 
   || ( *nonceptr >= *end_nonce_ptr )
   || ( (  work->job_id != g_work->job_id ) && clean_job ) )
/*
   if ( memcmp( work->data, g_work->data, algo_gate.work_cmp_size )
      && ( clean_job || ( *nonceptr >= *end_nonce_ptr )
         || ( work->job_id != g_work->job_id ) ) )
*/   
   {
     work_free( work );
     work_copy( work, g_work );
     *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
     if ( opt_randomize )
       *nonceptr += ( (rand() *4 ) & UINT32_MAX ) / opt_n_threads;
     *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20; 
// try incrementing the xnonce to chsnge the data
//     for ( int i = 0; i < work->xnonce2_size && !( ++work->xnonce2[i] ); i++ );
   }
   else
       ++(*nonceptr);
}


// vanilla uses default gen merkle root, otherwise identical to blakecoin
bool register_vanilla_algo( algo_gate_t* gate )
{
#if defined(BLAKECOIN_4WAY)
//  four_way_not_tested();
  gate->scanhash  = (void*)&scanhash_blakecoin_4way;
  gate->hash      = (void*)&blakecoin_4way_hash;
//  gate->get_new_work = (void*)&bc4w_get_new_work;
//  blakecoin_4way_init( &blake_4way_init_ctx );
#else
  gate->scanhash = (void*)&scanhash_blakecoin;
  gate->hash     = (void*)&blakecoinhash;
//  blakecoin_init( &blake_init_ctx );
#endif
  gate->optimizations = AVX2_OPT;
  gate->get_max64 = (void*)&blakecoin_get_max64;
  return true;
}

bool register_blakecoin_algo( algo_gate_t* gate )
{
  register_vanilla_algo( gate );
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  return true;
}

