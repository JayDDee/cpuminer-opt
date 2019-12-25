#include "x22i-gate.h"

bool register_x22i_algo( algo_gate_t* gate )
{
#if defined (X22I_8WAY)
  gate->scanhash  = (void*)&scanhash_x22i_8way;
  gate->hash      = (void*)&x22i_8way_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
#elif defined (X22I_4WAY)
  gate->scanhash  = (void*)&scanhash_x22i_4way;
  gate->hash      = (void*)&x22i_4way_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT | AVX512_OPT;
#else
  gate->scanhash  = (void*)&scanhash_x22i;
  gate->hash      = (void*)&x22i_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT | AVX512_OPT;
#endif
  return true;
};

bool register_x25x_algo( algo_gate_t* gate )
{
#if defined (X25X_8WAY)
  gate->scanhash  = (void*)&scanhash_x25x_8way;
  gate->hash      = (void*)&x25x_8way_hash;
//  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
#elif defined (X25X_4WAY)
  gate->scanhash  = (void*)&scanhash_x25x_4way;
  gate->hash      = (void*)&x25x_4way_hash;
//  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT | AVX512_OPT;
#else
  gate->scanhash  = (void*)&scanhash_x25x;
  gate->hash      = (void*)&x25x_hash;
//  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT | AVX512_OPT;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT;

  return true;
};

