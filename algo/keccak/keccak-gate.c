#include "keccak-gate.h"


bool register_keccak_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&SHA256_gen_merkle_root;
  opt_target_factor = 128.0;
#if defined (KECCAK_8WAY)
  gate->scanhash  = (void*)&scanhash_keccak_8way;
  gate->hash      = (void*)&keccakhash_8way;
#elif defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash  = (void*)&scanhash_keccak;
  gate->hash      = (void*)&keccakhash;
#endif
  return true;
};

bool register_keccakc_algo( algo_gate_t* gate )
{
  gate->optimizations = AVX2_OPT | AVX512_OPT;
  gate->gen_merkle_root = (void*)&sha256d_gen_merkle_root;
  opt_target_factor = 256.0;
#if defined (KECCAK_8WAY)
  gate->scanhash  = (void*)&scanhash_keccak_8way;
  gate->hash      = (void*)&keccakhash_8way;
#elif defined (KECCAK_4WAY)
  gate->scanhash  = (void*)&scanhash_keccak_4way;
  gate->hash      = (void*)&keccakhash_4way;
#else
  gate->scanhash  = (void*)&scanhash_keccak;
  gate->hash      = (void*)&keccakhash;
#endif
  return true;
};

