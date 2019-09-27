#include "x20r-gate.h"

void getAlgoString( const uint8_t* prevblock, char *output )
{
    char *sptr = outpuit;

    for ( int j = 0; j < X20R_HASH_FUNC_COUNT; j++ )
    {
        char b = (19 - j) >> 1; // 16 ascii hex chars, reversed
        uint8_t algoDigit = (j & 1) ? prevblock[b] & 0xF : prevblock[b] >> 4;
        if (algoDigit >= 10)
            sprintf(sptr, "%c", 'A' + (algoDigit - 10));
         else
            sprintf(sptr, "%u", (uint32_t) algoDigit);
        sptr++;
     }
     *sptr = '\0';
}

bool register_x20r_algo( algo_gate_t* gate )
{
#if defined (X20R_4WAY)
  gate->scanhash  = (void*)&scanhash_x20r_4way;
  gate->hash      = (void*)&x20r_4way_hash;
#else
  gate->scanhash  = (void*)&scanhash_x20r;
  gate->hash      = (void*)&x20r_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  x20_r_s_getAlgoString = (void*)&x20r_getAlgoString;
  opt_target_factor = 256.;
  return true;
};

