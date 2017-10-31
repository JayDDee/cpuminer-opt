// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "cpuminer-config.h"
#include "algo-gate-api.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl256.h"
#endif

#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "cryptonight.h"

/*
#if defined __unix__ && (!defined __APPLE__)
#include <sys/mman.h>
#elif defined _WIN32
#include <windows.h>
#endif
*/

void do_blake_hash(const void* input, size_t len, char* output) {
    blake256_hash((uint8_t*)output, input, len);
}

void do_groestl_hash(const void* input, size_t len, char* output) {
#ifdef NO_AES_NI
    groestl(input, len * 8, (uint8_t*)output);
#else
    hashState_groestl256 ctx;
    init_groestl256( &ctx, 32 );
    update_and_final_groestl256( &ctx, output, input, len * 8 );
#endif
}

void do_jh_hash(const void* input, size_t len, char* output) {
    jh_hash(32 * 8, input, 8 * len, (uint8_t*)output);
}

void do_skein_hash(const void* input, size_t len, char* output) {
    skein_hash(8 * 32, input, 8 * len, (uint8_t*)output);
}

void (* const extra_hashes[4])( const void *, size_t, char *) =
    { do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash };

void cryptonight_hash( void *restrict output, const void *input, int len )
{

#ifdef NO_AES_NI
  cryptonight_hash_ctx ( output, input, len );
#else 
  cryptonight_hash_aes( output, input, len );
#endif
}

void cryptonight_hash_suw( void *restrict output, const void *input )
{
#ifdef NO_AES_NI
  cryptonight_hash_ctx ( output, input, 76 );
#else
  cryptonight_hash_aes( output, input, 76 );
#endif
}

int scanhash_cryptonight( int thr_id, struct work *work, uint32_t max_nonce,
                   uint64_t *hashes_done )
 {
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    uint32_t *nonceptr = (uint32_t*) (((char*)pdata) + 39);
    uint32_t n = *nonceptr - 1;
    const uint32_t first_nonce = n + 1;
    const uint32_t Htarg = ptarget[7];
    uint32_t hash[32 / 4] __attribute__((aligned(32)));
    do
    {
       *nonceptr = ++n;
       cryptonight_hash( hash, pdata, 76 );
       if (unlikely( hash[7] < Htarg ))
       {
           *hashes_done = n - first_nonce + 1;
	   return true;
       }
    } while (likely((n <= max_nonce && !work_restart[thr_id].restart)));
    
    *hashes_done = n - first_nonce + 1;
    return 0;
}

bool register_cryptonight_algo( algo_gate_t* gate )
{
  register_json_rpc2( gate );
  gate->optimizations = SSE2_OPT | AES_OPT;
  gate->scanhash         = (void*)&scanhash_cryptonight;
  gate->hash             = (void*)&cryptonight_hash;
  gate->hash_suw         = (void*)&cryptonight_hash_suw;  
  gate->get_max64        = (void*)&get_max64_0x40LL;
  return true;
};

