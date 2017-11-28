#include "pentablake-gate.h"

bool register_pentablake_algo( algo_gate_t* gate )
{
#if defined (PENTABLAKE_4WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT;
    gate->scanhash  = (void*)&scanhash_pentablake_4way;
    gate->hash      = (void*)&pentablakehash_4way;
#else
    gate->scanhash  = (void*)&scanhash_pentablake;
    gate->hash      = (void*)&pentablakehash;
#endif
    gate->get_max64 = (void*)&get_max64_0x3ffff;
    return true;
};

