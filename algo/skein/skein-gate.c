#include "skein-gate.h"
#include "sph_skein.h"
#include "skein-hash-4way.h"

bool register_skein_algo( algo_gate_t* gate )
{
    gate->optimizations = AVX2_OPT | SHA_OPT;
#if defined (SKEIN_4WAY)
    gate->scanhash  = (void*)&scanhash_skein_4way;
    gate->hash      = (void*)&skeinhash_4way;
#else
    gate->scanhash  = (void*)&scanhash_skein;
    gate->hash      = (void*)&skeinhash;
#endif
    return true;
};

