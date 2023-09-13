#include "blakecoin-gate.h"
#include <memory.h>

// vanilla uses default gen merkle root, otherwise identical to blakecoin
bool register_vanilla_algo( algo_gate_t* gate )
{
#if defined(BLAKECOIN_16WAY)
  gate->scanhash  = (void*)&scanhash_blakecoin_16way;
#elif defined(BLAKECOIN_8WAY)
  gate->scanhash  = (void*)&scanhash_blakecoin_8way;
#elif defined(BLAKECOIN_4WAY)
  gate->scanhash  = (void*)&scanhash_blakecoin_4way;
  gate->hash      = (void*)&blakecoin_4way_hash;
#else
  gate->scanhash = (void*)&scanhash_blakecoin;
  gate->hash     = (void*)&blakecoinhash;
#endif
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
  return true;
}

bool register_blakecoin_algo( algo_gate_t* gate )
{
  register_vanilla_algo( gate );
  gate->gen_merkle_root = (void*)&sha256_gen_merkle_root;
  return true;
}

