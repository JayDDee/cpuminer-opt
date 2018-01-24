#include "x16r-gate.h"

void x16r_getAlgoString( const uint8_t* prevblock, char *output )
{
   char *sptr = output;
   for ( int j = 0; j < X16R_HASH_FUNC_COUNT; j++ )
   {
      uint8_t b = (15 - j) >> 1; // 16 first ascii hex chars (lsb in uint256)
      uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
      if (algoDigit >= 10)
          sprintf(sptr, "%c", 'A' + (algoDigit - 10));
      else
          sprintf(sptr, "%u", (uint32_t) algoDigit);
      sptr++;
   }
   *sptr = '\0';
}


bool register_x16r_algo( algo_gate_t* gate )
{
#if defined (X16R_4WAY)
  init_x16r_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x16r_4way;
  gate->hash      = (void*)&x16r_4way_hash;
#else
  init_x16r_ctx();
  gate->scanhash  = (void*)&scanhash_x16r;
  gate->hash      = (void*)&x16r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->set_target = (void*)&alt_set_target;
  return true;
};

