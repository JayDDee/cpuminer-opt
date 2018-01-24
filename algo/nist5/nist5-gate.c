#include "nist5-gate.h"

bool register_nist5_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT;
#if defined (NIST5_4WAY)
    gate->scanhash = (void*)&scanhash_nist5_4way;
    gate->hash     = (void*)&nist5hash_4way;
#else
    init_nist5_ctx();
    gate->scanhash = (void*)&scanhash_nist5;
    gate->hash     = (void*)&nist5hash;
#endif
    return true;
};

