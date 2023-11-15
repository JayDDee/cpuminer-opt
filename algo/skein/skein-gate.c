#include "skein-gate.h"
#include "skein-hash-4way.h"

bool register_skein_algo( algo_gate_t* gate )
{
#if defined(SKEIN_8WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
    gate->scanhash  = (void*)&scanhash_skein_8way;
    gate->hash      = (void*)&skeinhash_8way;
#elif defined(SKEIN_4WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | SHA_OPT | NEON_OPT;
    gate->scanhash  = (void*)&scanhash_skein_4way;
    gate->hash      = (void*)&skeinhash_4way;
#elif defined(SKEIN_2WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | SHA_OPT | NEON_OPT;
    gate->scanhash  = (void*)&scanhash_skein_2x64;
    gate->hash      = (void*)&skeinhash_2x64;
#else
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | SHA_OPT | NEON_OPT;
    gate->scanhash  = (void*)&scanhash_skein;
    gate->hash      = (void*)&skeinhash;
#endif
    return true;
};

bool register_skein2_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
#if defined(SKEIN_8WAY)
  gate->scanhash  = (void*)&scanhash_skein2_8way;
#elif defined(SKEIN_4WAY)
  gate->scanhash  = (void*)&scanhash_skein2_4way;
#elif defined(SKEIN_2WAY)
  gate->scanhash  = (void*)&scanhash_skein2_2x64;
#else
  gate->scanhash  = (void*)&scanhash_skein2;
#endif
  return true;
};


