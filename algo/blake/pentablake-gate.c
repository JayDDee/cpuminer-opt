#include "pentablake-gate.h"

bool register_pentablake_algo( algo_gate_t* gate )
{
#if defined (PENTABLAKE_4WAY)
    gate->scanhash  = (void*)&scanhash_pentablake_4way;
    gate->hash      = (void*)&pentablakehash_4way;
#else
    gate->scanhash  = (void*)&scanhash_pentablake;
    gate->hash      = (void*)&pentablakehash;
#endif
    gate->optimizations = AVX2_OPT;
    return true;
};

