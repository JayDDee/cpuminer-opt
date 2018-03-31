#include "x16r-gate.h"

void x16r_getAlgoString( const char* prevblock, char *output )
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

void x16s_getAlgoString( const char* prevblock, char *output )
{
   uint8_t* data = (uint8_t*)prevblock;
   strcpy( output, "0123456789ABCDEF" );
   for ( int i = 0; i < 16; i++ )
   {
      uint8_t b = (15 - i) >> 1; // 16 ascii hex chars, reversed
      uint8_t algoDigit = (i & 1) ? data[b] & 0xF : data[b] >> 4;
      int offset = algoDigit;
      // insert the nth character at the front
      char oldVal = output[offset];
      for( int j = offset; j-- > 0; )
         output[j+1] = output[j];
      output[0] = oldVal;
   }
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
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->set_target = (void*)&alt_set_target;
  x16_r_s_getAlgoString = (void*)&x16r_getAlgoString;
  return true;
};

bool register_x16s_algo( algo_gate_t* gate )
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
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  gate->set_target = (void*)&alt_set_target;
  x16_r_s_getAlgoString = (void*)&x16s_getAlgoString;
  return true;
};

