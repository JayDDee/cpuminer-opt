#include "lyra2-gate.h"


__thread uint64_t* l2v3_wholeMatrix;

bool lyra2rev3_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   l2v3_wholeMatrix = _mm_malloc( size, 64 );
#if defined (LYRA2REV3_4WAY)
   init_lyra2rev3_4way_ctx();;
#else
   init_lyra2rev3_ctx();
#endif
   return l2v3_wholeMatrix;
}

bool register_lyra2rev3_algo( algo_gate_t* gate )
{
#if defined (LYRA2REV3_4WAY)
  gate->scanhash  = (void*)&scanhash_lyra2rev3_4way;
  gate->hash      = (void*)&lyra2rev3_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_lyra2rev3;
  gate->hash      = (void*)&lyra2rev3_hash;
#endif
  gate->optimizations = SSE2_OPT | SSE42_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&lyra2rev3_thread_init;
  gate->set_target        = (void*)&alt_set_target;
  return true;
};

//////////////////////////////////

__thread uint64_t* l2v2_wholeMatrix;

bool lyra2rev2_thread_init()
{
   const int64_t ROW_LEN_INT64 = BLOCK_LEN_INT64 * 4; // nCols
   const int64_t ROW_LEN_BYTES = ROW_LEN_INT64 * 8;

   int size = (int64_t)ROW_LEN_BYTES * 4; // nRows;
   l2v2_wholeMatrix = _mm_malloc( size, 64 );
#if defined (LYRA2REV2_4WAY)
   init_lyra2rev2_4way_ctx();;
#else
   init_lyra2rev2_ctx();
#endif
   return l2v2_wholeMatrix;
}

bool register_lyra2rev2_algo( algo_gate_t* gate )
{
#if defined (LYRA2REV2_4WAY)
  gate->scanhash  = (void*)&scanhash_lyra2rev2_4way;
  gate->hash      = (void*)&lyra2rev2_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_lyra2rev2;
  gate->hash      = (void*)&lyra2rev2_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->miner_thread_init = (void*)&lyra2rev2_thread_init;
  gate->set_target        = (void*)&alt_set_target;
  return true;
};

/////////////////////////////

bool register_lyra2z_algo( algo_gate_t* gate )
{
#if defined(LYRA2Z_8WAY)
  gate->miner_thread_init = (void*)&lyra2z_8way_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z_8way;
  gate->hash       = (void*)&lyra2z_8way_hash;
#elif defined(LYRA2Z_4WAY)
  gate->miner_thread_init = (void*)&lyra2z_4way_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z_4way;
  gate->hash       = (void*)&lyra2z_4way_hash;
#else
  gate->miner_thread_init = (void*)&lyra2z_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z;
  gate->hash       = (void*)&lyra2z_hash;
#endif
  gate->optimizations = SSE42_OPT | AVX2_OPT;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&alt_set_target;
  return true;
};


////////////////////////

bool register_lyra2h_algo( algo_gate_t* gate )
{
#ifdef LYRA2H_4WAY
  gate->miner_thread_init = (void*)&lyra2h_4way_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2h_4way;
  gate->hash       = (void*)&lyra2h_4way_hash;
#else
  gate->miner_thread_init = (void*)&lyra2h_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2h;
  gate->hash       = (void*)&lyra2h_hash;
#endif
  gate->optimizations = SSE42_OPT | AVX2_OPT;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&alt_set_target;
  return true;
};

/////////////////////////////////

int64_t allium_get_max64_0xFFFFLL() { return 0xFFFFLL; }

bool register_allium_algo( algo_gate_t* gate )
{
#if defined (ALLIUM_4WAY)
  gate->miner_thread_init = (void*)&init_allium_4way_ctx;
  gate->scanhash  = (void*)&scanhash_allium_4way;
  gate->hash      = (void*)&allium_4way_hash;
#else
  gate->miner_thread_init = (void*)&init_allium_ctx;
  gate->scanhash  = (void*)&scanhash_allium;
  gate->hash      = (void*)&allium_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
  gate->set_target        = (void*)&alt_set_target;
  gate->get_max64         = (void*)&allium_get_max64_0xFFFFLL;
  return true;
};

/////////////////////////////////////////

bool phi2_has_roots;
bool phi2_use_roots = false;

int phi2_get_work_data_size() { return phi2_use_roots ? 144 : 128; }

void phi2_decode_extra_data( struct work *work )
{
   if ( work->data[0] & ( 1<<30 ) ) phi2_use_roots = true;
   else for ( int i = 20; i < 36; i++ )
   {
      if (work->data[i]) { phi2_use_roots = true; break; }
   }
}

void phi2_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_tree[64] = { 0 };
   size_t t;

   algo_gate.gen_merkle_root( merkle_tree, sctx );
   // Increment extranonce2
   for ( t = 0; t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] ); t++ );
   // Assemble block header
   algo_gate.build_block_header( g_work, le32dec( sctx->job.version ),
                  (uint32_t*) sctx->job.prevhash, (uint32_t*) merkle_tree,
                  le32dec( sctx->job.ntime ), le32dec(sctx->job.nbits) );
   for ( t = 0; t < 16; t++ )
      g_work->data[ 20+t ] = ((uint32_t*)sctx->job.extra)[t];
}


bool register_phi2_algo( algo_gate_t* gate )
{
   init_phi2_ctx();
   gate->optimizations = SSE2_OPT | AES_OPT | SSE42_OPT | AVX2_OPT;
   gate->get_work_data_size = (void*)&phi2_get_work_data_size;
   gate->decode_extra_data  = (void*)&phi2_decode_extra_data;
   gate->build_extraheader  = (void*)&phi2_build_extraheader;
   gate->set_target         = (void*)&alt_set_target; 
   gate->get_max64          = (void*)&get_max64_0xffffLL;
   gate->scanhash           = (void*)&scanhash_phi2;
   return true;
}
