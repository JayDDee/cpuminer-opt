#include "keccak-gate.h"

void keccak_set_target( struct work* work, double job_diff )
{
  work_set_target( work, job_diff / (128.0 * opt_diff_factor) );
}

int64_t keccak_get_max64() { return 0x7ffffLL; }

bool register_keccak_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  gate->set_target      = (void*)&keccak_set_target;
  gate->get_max64       = (void*)&keccak_get_max64;
#if defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash        = (void*)&scanhash_keccak;
  gate->hash            = (void*)&keccakhash;
#endif
  return true;
};

void keccakc_set_target( struct work* work, double job_diff )
{
  work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_keccakc_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->gen_merkle_root = (void*)&sha256d_gen_merkle_root;
  gate->set_target      = (void*)&keccakc_set_target;
  gate->get_max64       = (void*)&keccak_get_max64;
#if defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash        = (void*)&scanhash_keccak;
  gate->hash            = (void*)&keccakhash;
#endif
  return true;
};

