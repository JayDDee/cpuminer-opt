#include "timetravel-gate.h"

void tt8_set_target( struct work* work, double job_diff )
{
 work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

bool register_timetravel_algo( algo_gate_t* gate )
{
#ifdef TIMETRAVEL_4WAY
  init_tt8_4way_ctx();
  gate->scanhash   = (void*)&scanhash_timetravel_4way;
  gate->hash       = (void*)&timetravel_4way_hash;
#else
  init_tt8_ctx();
  gate->scanhash   = (void*)&scanhash_timetravel;
  gate->hash       = (void*)&timetravel_hash;
#endif
  gate->set_target = (void*)&tt8_set_target;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  gate->get_max64  = (void*)&get_max64_0xffffLL;
  return true;
};

inline void tt_swap( int *a, int *b )
{
        int c = *a;
        *a = *b;
        *b = c;
}

inline void reverse( int *pbegin, int *pend )
{
   while ( (pbegin != pend) && (pbegin != --pend) )
   {
      tt_swap( pbegin, pend );
      pbegin++;
   }
}

void tt8_next_permutation( int *pbegin, int *pend )
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

           tt_swap( i, k );
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

