#include "skein-gate.h"
#include "sph_skein.h"
#include "skein-hash-4way.h"

int64_t skein_get_max64() { return 0x7ffffLL; }

bool register_skein_algo( algo_gate_t* gate )
{
#if defined (SKEIN_4WAY)
    gate->optimizations = SSE2_OPT | AVX2_OPT | SHA_OPT;
    gate->scanhash  = (void*)&scanhash_skein_4way;
    gate->hash      = (void*)&skeinhash_4way;
#else
    gate->optimizations = SSE2_OPT | SHA_OPT;
    gate->scanhash  = (void*)&scanhash_skein;
    gate->hash      = (void*)&skeinhash;
#endif
    gate->get_max64 = (void*)&skein_get_max64;
    return true;
};

