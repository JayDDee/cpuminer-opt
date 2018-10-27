#include "sha256q-gate.h"

bool register_sha256q_algo( algo_gate_t* gate )
{
#if defined(SHA256Q_8WAY)
    gate->scanhash   = (void*)&scanhash_sha256q_8way;
    gate->hash       = (void*)&sha256q_8way_hash;
#elif defined(SHA256Q_4WAY)
    gate->scanhash   = (void*)&scanhash_sha256q_4way;
    gate->hash       = (void*)&sha256q_4way_hash;
#else
    gate->scanhash   = (void*)&scanhash_sha256q;
    gate->hash       = (void*)&sha256q_hash;
#endif
    gate->optimizations = SSE42_OPT | AVX2_OPT | SHA_OPT;
    gate->get_max64  = (void*)&get_max64_0x3ffff;
    return true;
}

