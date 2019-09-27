#include "keccak-gate.h"

int64_t keccak_get_max64() { return 0x7ffffLL; }

bool register_keccak_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  gate->get_max64       = (void*)&keccak_get_max64;
  opt_target_factor = 128.0;
#if defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash        = (void*)&scanhash_keccak;
  gate->hash            = (void*)&keccakhash;
#endif
  return true;
};

bool register_keccakc_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT;
  gate->gen_merkle_root = (void*)&sha256d_gen_merkle_root;
  gate->get_max64       = (void*)&keccak_get_max64;
  opt_target_factor = 256.0;
#if defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash        = (void*)&scanhash_keccak;
  gate->hash            = (void*)&keccakhash;
#endif
  return true;
};

