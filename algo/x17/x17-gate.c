#include "x17-gate.h"

bool register_x17_algo( algo_gate_t* gate )
{
#if defined (X17_16X32)
  gate->scanhash  = (void*)&scanhash_x17_16x32;
  gate->hash      = (void*)&x17_16way_hash;
#elif defined (X17_8WAY)
  gate->scanhash  = (void*)&scanhash_x17_8x64;
  gate->hash      = (void*)&x17_8x64_hash;
#elif defined (X17_4WAY)
  gate->scanhash  = (void*)&scanhash_x17_4x64;
  gate->hash      = (void*)&x17_4x64_hash;
#elif defined (X17_2X64)
  gate->scanhash  = (void*)&scanhash_x17_2x64;
  gate->hash      = (void*)&x17_2x64_hash;
#else
  gate->hash      = (void*)&x17_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | VAES_OPT
                      | NEON_OPT;
  return true;
};

