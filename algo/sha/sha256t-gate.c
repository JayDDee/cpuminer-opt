#include "sha256t-gate.h"

bool register_sha256t_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
#if defined(SHA256T_16WAY)
    gate->scanhash   = (void*)&scanhash_sha256t_16way;
#elif defined(SHA256T_SHA)
    gate->optimizations = SSE2_OPT | SHA256_OPT;
    gate->scanhash   = (void*)&scanhash_sha256t_sha;
#elif defined(SHA256T_NEON_SHA2)
    gate->optimizations = NEON_OPT | SHA256_OPT;
    gate->scanhash   = (void*)&scanhash_sha256t_neon_sha2;
#elif defined(SHA256T_8WAY)
    gate->scanhash   = (void*)&scanhash_sha256t_8way;
#elif defined(SHA256T_4WAY)
    gate->scanhash   = (void*)&scanhash_sha256t_4way;
#else
    gate->scanhash   = (void*)&scanhash_sha256t;

#endif
    return true;
}

bool register_sha256q_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
#if defined(SHA256T_16WAY)
    gate->scanhash   = (void*)&scanhash_sha256q_16way;
    gate->hash       = (void*)&sha256q_16way_hash;
//#elif defined(SHA256T_SHA)
//    gate->optimizations = SHA256_OPT;
//    gate->scanhash   = (void*)&scanhash_sha256q;
//    gate->hash       = (void*)&sha256q_hash;
#elif defined(SHA256T_8WAY)
    gate->scanhash   = (void*)&scanhash_sha256q_8way;
    gate->hash       = (void*)&sha256q_8way_hash;
#elif defined(SHA256T_4WAY)
    gate->scanhash   = (void*)&scanhash_sha256q_4way;
    gate->hash       = (void*)&sha256q_4way_hash;
//#else
//    gate->scanhash   = (void*)&scanhash_sha256q;
//    gate->hash       = (void*)&sha256q_4way;
#endif
    return true;
}

