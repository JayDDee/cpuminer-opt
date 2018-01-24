#include "anime-gate.h"

bool register_anime_algo( algo_gate_t* gate )
{
#if defined (ANIME_4WAY)
  init_anime_4way_ctx();
  gate->scanhash  = (void*)&scanhash_anime_4way;
  gate->hash      = (void*)&anime_4way_hash;
#else
  init_anime_ctx();
  gate->scanhash  = (void*)&scanhash_anime;
  gate->hash      = (void*)&anime_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

