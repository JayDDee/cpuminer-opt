#include "xevan-gate.h"

void xevan_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_xevan_algo( algo_gate_t* gate )
{
#if defined (XEVAN_4WAY)
  init_xevan_4way_ctx();
  gate->scanhash  = (void*)&scanhash_xevan_4way;
  gate->hash      = (void*)&xevan_4way_hash;
#else
  init_xevan_ctx();
  gate->scanhash  = (void*)&scanhash_xevan;
  gate->hash      = (void*)&xevan_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->set_target = (void*)&xevan_set_target;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  return true;
};

