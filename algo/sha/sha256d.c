#include "sha256-hash.h"
#include "sha256d.h"

void sha256d( void *hash, const void *data, int len )
{
   sha256_full( hash, data, len );
   sha256_full( hash, hash,  32 );
}
bool register_sha256d_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | AVX2_OPT | AVX512_OPT;
#if defined(SHA256D_16WAY)
   gate->scanhash = (void*)&scanhash_sha256d_16way;
#elif defined(SHA256D_SHA)
   gate->optimizations = SHA_OPT;
   gate->scanhash = (void*)&scanhash_sha256d_sha;
#elif defined(SHA256D_NEON_SHA2)
   gate->optimizations = SHA_OPT;
   gate->scanhash = (void*)&scanhash_sha256d_neon_sha2;
#elif defined(SHA256D_8WAY)
   gate->scanhash = (void*)&scanhash_sha256d_8way;
#elif defined(SHA256D_4WAY)
   gate->scanhash = (void*)&scanhash_sha256d_4x32;
#else
   gate->hash     = (void*)&sha256d;
#endif
   return true;
};

