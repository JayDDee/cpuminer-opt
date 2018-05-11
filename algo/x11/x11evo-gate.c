#include "x11evo-gate.h"

int s_seq = -1;

static inline int getCurrentAlgoSeq( uint32_t current_time )
{
   // change once per day
   return (int) (current_time - X11EVO_INITIAL_DATE) / (60 * 60 * 24);
}

// swap_vars doesn't work here
void evo_swap( uint8_t *a, uint8_t *b )
{
   uint8_t __tmp = *a;
   *a = *b;
   *b = __tmp;
}

void initPerm( uint8_t n[], uint8_t count )
{
   int i;
   for ( i = 0; i<count; i++ )
       n[i] = i;
}

int nextPerm( uint8_t n[], uint32_t count )
{
   uint32_t tail = 0, i = 0, j = 0;

   if (unlikely( count <= 1 ))
      return 0;

   for ( i = count - 1; i>0 && n[i - 1] >= n[i]; i-- );
   tail = i;

   if ( tail > 0 )
   {
      for ( j = count - 1; j>tail && n[j] <= n[tail - 1]; j-- );
      evo_swap( &n[tail - 1], &n[j] );
   }

   for ( i = tail, j = count - 1; i<j; i++, j-- )
      evo_swap( &n[i], &n[j] );

   return ( tail != 0 );
}

void getAlgoString( char *str, uint32_t count )
{
   uint8_t algoList[X11EVO_FUNC_COUNT];
   char *sptr;
   int j;
   int k;
   initPerm( algoList, X11EVO_FUNC_COUNT );

   for ( k = 0; k < count; k++ )
      nextPerm( algoList, X11EVO_FUNC_COUNT );

   sptr = str;
   for ( j = 0; j < X11EVO_FUNC_COUNT; j++ )
   {
      if ( algoList[j] >= 10 )
          sprintf( sptr, "%c", 'A' + (algoList[j] - 10) );
      else
          sprintf( sptr, "%u", algoList[j] );
      sptr++;
   }
  *sptr = 0;

        //applog(LOG_DEBUG, "nextPerm %s", str);
}

void evo_twisted_code( uint32_t ntime, char *permstr )
{
   int seq = getCurrentAlgoSeq( ntime );
   if ( s_seq != seq )
   {
       getAlgoString( permstr, seq );
       s_seq = seq;
   }
}

bool register_x11evo_algo( algo_gate_t* gate )
{
#if defined (X11EVO_4WAY)
  init_x11evo_4way_ctx();
  gate->scanhash  = (void*)&scanhash_x11evo_4way;
  gate->hash      = (void*)&x11evo_4way_hash;
#else
  init_x11evo_ctx();
  gate->scanhash  = (void*)&scanhash_x11evo;
  gate->hash      = (void*)&x11evo_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  return true;
};

