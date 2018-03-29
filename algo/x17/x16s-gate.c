#include "x16s-gate.h"

void x16s_getAlgoString( const uint8_t* prevblock, char *output )
{
   uint8_t* data = (uint8_t*)prevblock;

   strcpy(output, "0123456789ABCDEF");

   for ( int i = 0; i < X16S_HASH_FUNC_COUNT; i++ )
   {
      uint8_t b = (15 - i) >> 1; // 16 first ascii hex chars (lsb in uint256)
      uint8_t algoDigit = (i & 1) ? data[b] & 0xF : data[b] >> 4;
      int offset = algoDigit;
      // insert the nth character at the front
      char oldVal = output[offset];
      for(int j = offset; j-- > 0;){
         output[j + 1] = output[j];
      }
      output[0] = oldVal;
}


bool register_x16s_algo( algo_gate_t* gate )
{
#if defined (X16S_4WAY)
  init_x16s_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x16s_4way;
  gate->hash      = (void*)&x16s_4way_hash;
#else
  init_x16s_ctx();
  gate->scanhash  = (void*)&scanhash_x16s;
  gate->hash      = (void*)&x16s_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->set_target = (void*)&alt_set_target;
  return true;
};

