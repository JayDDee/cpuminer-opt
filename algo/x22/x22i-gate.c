#include "x22i-gate.h"

// Ryzen has poor AVX2 performance so use SHA over AVX2.
// Intel has AVX512 so use AVX512 over SHA.
// When Ryzen AVX2 improves use AVX2 over SHA.

bool register_x22i_algo( algo_gate_t* gate )
{
#if defined (X22I_8WAY)

#if defined(X22I_8WAY_SHA)
  gate->scanhash  = (void*)&scanhash_x22i_8way_sha;
#else
  gate->scanhash  = (void*)&scanhash_x22i_8way;
#endif
  gate->hash      = (void*)&x22i_8way_hash;

#elif defined (X22I_4WAY)

#if defined(X22I_4WAY_SHA)
  gate->scanhash  = (void*)&scanhash_x22i_4way_sha;
#else
  gate->scanhash  = (void*)&scanhash_x22i_4way;
#endif
  gate->hash      = (void*)&x22i_4way_hash;

#else

  gate->scanhash  = (void*)&scanhash_x22i;
  gate->hash      = (void*)&x22i_hash;

#endif

  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT
                      | AVX512_OPT | VAES_OPT | VAES256_OPT;
  return true;
};

bool register_x25x_algo( algo_gate_t* gate )
{
#if defined (X25X_8WAY)
  gate->scanhash  = (void*)&scanhash_x25x_8way;
  gate->hash      = (void*)&x25x_8way_hash;
#elif defined (X25X_4WAY)
  gate->scanhash  = (void*)&scanhash_x25x_4way;
  gate->hash      = (void*)&x25x_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x25x;
  gate->hash      = (void*)&x25x_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | SHA_OPT |
                        AVX512_OPT | VAES_OPT | VAES256_OPT;
  return true;
};

