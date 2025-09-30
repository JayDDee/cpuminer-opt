#include "cpunet-gate.h"
#include "../sha/sha256-hash.h"

#include <string.h>
#include <stdio.h>

int cpunet_hash( void *hash, const void *data, int thr_id)
{
   static const uint8_t cpunet_suffix[7] = {'c', 'p', 'u', 'n', 'e', 't', '\0'};
   uint8_t preimage[87];
   uint8_t hash1[32];

   memcpy(preimage, data, 80);
   memcpy(preimage+80, cpunet_suffix, sizeof(cpunet_suffix));
   sha256_full( hash1, preimage,  87 );
   sha256_full( hash, hash1,  32 );
   return 1;
}

bool register_cpunet_algo( algo_gate_t* gate )
{
   gate->optimizations = 0;
   gate->hash = (void*)&cpunet_hash;
   return true;
}
