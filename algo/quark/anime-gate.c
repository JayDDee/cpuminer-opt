#include "anime-gate.h"

bool register_anime_algo( algo_gate_t* gate )
{
#if defined (ANIME_8WAY)
  gate->scanhash  = (void*)&scanhash_anime_8way;
  gate->hash      = (void*)&anime_8way_hash;
#elif defined (ANIME_4WAY)
  gate->scanhash  = (void*)&scanhash_anime_4way;
  gate->hash      = (void*)&anime_4way_hash;
#else
  init_anime_ctx();
  gate->scanhash  = (void*)&scanhash_anime;
  gate->hash      = (void*)&anime_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT;
  return true;
};

