#include "tribus-gate.h"
/*
bool tribus_thread_init()
{
   sph_jh512_init( &tribus_ctx.jh );
   sph_keccak512_init( &tribus_ctx.keccak );
#ifdef NO_AES_NI
   sph_echo512_init( &tribus_ctx.echo );
#else
   init_echo( &tribus_ctx.echo, 512 );
#endif
  return true;
}
*/
bool register_tribus_algo( algo_gate_t* gate )
{
//  gate->miner_thread_init = (void*)&tribus_thread_init;
  gate->get_max64     = (void*)&get_max64_0x1ffff;
#if defined (TRIBUS_4WAY)
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->scanhash      = (void*)&scanhash_tribus_4way;
  gate->hash          = (void*)&tribus_hash_4way;
#else
  gate->miner_thread_init = (void*)&tribus_thread_init;
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash      = (void*)&scanhash_tribus;
  gate->hash          = (void*)&tribus_hash;
#endif
  return true;
};

