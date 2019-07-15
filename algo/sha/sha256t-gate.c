#include "sha256t-gate.h"

bool register_sha256t_algo( algo_gate_t* gate )
{
#if defined(SHA256T_8WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256t_8way;
    gate->hash       = (void*)&sha256t_8way_hash;
#elif defined(SHA256T_4WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256t_4way;
    gate->hash       = (void*)&sha256t_4way_hash;
#else
    gate->optimizations = SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256t;
    gate->hash       = (void*)&sha256t_hash;
#endif
    gate->get_max64  = (void*)&get_max64_0x3ffff;
    return true;
}

bool register_sha256q_algo( algo_gate_t* gate )
{
#if defined(SHA256T_8WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256q_8way;
    gate->hash       = (void*)&sha256q_8way_hash;
#elif defined(SHA256T_4WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256q_4way;
    gate->hash       = (void*)&sha256q_4way_hash;
#else
    gate->optimizations = SHA_OPT;
    gate->scanhash   = (void*)&scanhash_sha256q;
    gate->hash       = (void*)&sha256q_hash;
#endif
    gate->get_max64  = (void*)&get_max64_0x3ffff;
    return true;

}

