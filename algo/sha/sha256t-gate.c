#include "sha256t-gate.h"

bool register_sha256t_algo( algo_gate_t* gate )
{
#if defined(SHA256T_8WAY)
    gate->scanhash   = (void*)&scanhash_sha256t_8way;
    gate->hash       = (void*)&sha256t_8way_hash;
#elif defined(SHA256T_4WAY)
    gate->scanhash   = (void*)&scanhash_sha256t_4way;
    gate->hash       = (void*)&sha256t_4way_hash;
#else
    gate->scanhash   = (void*)&scanhash_sha256t;
    gate->hash       = (void*)&sha256t_hash;
#endif
    gate->optimizations = SSE42_OPT | AVX2_OPT | SHA_OPT;
    gate->get_max64  = (void*)&get_max64_0x3ffff;
    return true;
}

