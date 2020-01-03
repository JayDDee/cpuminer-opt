#include "groestl-gate.h"

bool register_dmd_gr_algo( algo_gate_t *gate )
{
#if defined (GROESTL_4WAY_VAES)
  gate->scanhash  = (void*)&scanhash_groestl_4way;
  gate->hash      = (void*)&groestl_4way_hash;
#else
  init_groestl_ctx();
  gate->scanhash  = (void*)&scanhash_groestl;
  gate->hash      = (void*)&groestlhash;
#endif
  gate->optimizations = AES_OPT | VAES_OPT;
  return true;
};

bool register_groestl_algo( algo_gate_t* gate )
{
    register_dmd_gr_algo( gate );
    gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
    return true;
};

