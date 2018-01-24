#include "timetravel10-gate.h"

void tt10_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

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
  gate->set_target = (void*)&tt10_set_target;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
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

