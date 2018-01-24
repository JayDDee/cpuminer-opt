#include "lyra2z-gate.h"
#include "lyra2.h"

void lyra2z_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_lyra2z_algo( algo_gate_t* gate )
{
#ifdef LYRA2Z_4WAY
  gate->miner_thread_init = (void*)&lyra2z_4way_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z_4way;
  gate->hash       = (void*)&lyra2z_4way_hash;
#else
  gate->miner_thread_init = (void*)&lyra2z_thread_init;
  gate->scanhash   = (void*)&scanhash_lyra2z;
  gate->hash       = (void*)&lyra2z_hash;
#endif
  gate->optimizations = AVX_OPT | AVX2_OPT;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  gate->set_target = (void*)&lyra2z_set_target;
  return true;
};

