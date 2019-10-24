#include "timetravel10-gate.h"

bool register_timetravel10_algo( algo_gate_t* gate )
{
#ifdef TIMETRAVEL10_4WAY
  init_tt10_4way_ctx();
  gate->scanhash   = (void*)&scanhash_timetravel10_4way;
  gate->hash       = (void*)&timetravel10_4way_hash;
#else
  init_tt10_ctx();
  gate->scanhash   = (void*)&scanhash_timetravel10;
  gate->hash       = (void*)&timetravel10_hash;
#endif
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
  opt_target_factor = 256.0;
  return true;
};

inline void tt10_swap( int *a, int *b )
{
        int c = *a;
        *a = *b;
        *b = c;
}

inline void reverse( int *pbegin, int *pend )
{
   while ( (pbegin != pend) && (pbegin != --pend) )
   {
      tt10_swap( pbegin, pend );
      pbegin++;
   }
}

void tt10_next_permutation( int *pbegin, int *pend )
{
   if ( pbegin == pend )
        return;

   int *i = pbegin;
   ++i;
   if ( i == pend )
        return;

   i = pend;
   --i;

   while (1)
   {
        int *j = i;
        --i;

        if ( *i < *j )
        {
           int *k = pend;

           while ( !(*i < *--k) ) /* do nothing */ ;

           tt10_swap( i, k );
           reverse(j, pend);
                return; // true
        }

        if ( i == pbegin )
        {
           reverse(pbegin, pend);
           return; // false
        }
        // else?
   }
}

