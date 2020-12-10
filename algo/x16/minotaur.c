// Minotaur hash

#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/echo/sph_echo.h"
  #include "algo/groestl/sph_groestl.h"
  #include "algo/fugue/sph_fugue.h"
#endif

// Config
#define MINOTAUR_ALGO_COUNT	16

typedef struct TortureNode TortureNode;
typedef struct TortureGarden TortureGarden;

// Graph of hash algos plus SPH contexts
struct TortureGarden
{
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
        hashState_fugue         fugue;
#else
        sph_echo512_context     echo;
        sph_groestl512_context  groestl;
        sph_fugue512_context    fugue;
#endif
        sph_blake512_context    blake;
        sph_bmw512_context      bmw;
        sph_skein512_context    skein;
        sph_jh512_context       jh;
        sph_keccak512_context   keccak;
        hashState_luffa         luffa;
        cubehashParam           cube;
        shavite512_context      shavite;
        hashState_sd            simd;
        sph_hamsi512_context    hamsi;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        sph_sha512_context      sha512;

    struct TortureNode {
        unsigned int algo;
        TortureNode *child[2];
    } nodes[22];
} __attribute__ ((aligned (64)));

// Get a 64-byte hash for given 64-byte input, using given TortureGarden contexts and given algo index
static void get_hash( void *output, const void *input, TortureGarden *garden,
	              unsigned int algo )
{    
	unsigned char hash[64] __attribute__ ((aligned (64)));

    switch (algo) {
        case 0:
            sph_blake512_init(&garden->blake);
            sph_blake512(&garden->blake, input, 64);
            sph_blake512_close(&garden->blake, hash);
            break;
        case 1:
            sph_bmw512_init(&garden->bmw);
            sph_bmw512(&garden->bmw, input, 64);
            sph_bmw512_close(&garden->bmw, hash);        
            break;
        case 2:
            cubehashInit( &garden->cube, 512, 16, 32 );
            cubehashUpdateDigest( &garden->cube, (byte*)hash,
			         (const byte*)input, 64 );
            break;
        case 3:
#if defined(__AES__)
            echo_full( &garden->echo, (BitSequence *)hash, 512,
                              (const BitSequence *)input, 64 );
#else
            sph_echo512_init(&garden->echo);
            sph_echo512(&garden->echo, input, 64);
            sph_echo512_close(&garden->echo, hash);          
#endif
	    break;
        case 4:
#if defined(__AES__)
            fugue512_full( &garden->fugue, hash, input, 64 );
#else
            sph_fugue512_full( &garden->fugue, hash, input, 64 );
#endif
	    break;
        case 5:
#if defined(__AES__)
            groestl512_full( &garden->groestl, (char*)hash, (char*)input, 512 );
#else
            sph_groestl512_init(&garden->groestl);
            sph_groestl512(&garden->groestl, input, 64);
            sph_groestl512_close(&garden->groestl, hash);          
#endif
	    break;
        case 6:
            sph_hamsi512_init(&garden->hamsi);
            sph_hamsi512(&garden->hamsi, input, 64);
            sph_hamsi512_close(&garden->hamsi, hash);          
            break;
        case 7:
            sph_sha512_init( &garden->sha512 );
            sph_sha512( &garden->sha512, input, 64 );
            sph_sha512_close( &garden->sha512, hash );
            break;
        case 8:
            sph_jh512_init(&garden->jh);
            sph_jh512(&garden->jh, input, 64);
            sph_jh512_close(&garden->jh, hash);          
            break;
        case 9:
            sph_keccak512_init(&garden->keccak);
            sph_keccak512(&garden->keccak, input, 64);
            sph_keccak512_close(&garden->keccak, hash);
            break;
        case 10:
            init_luffa( &garden->luffa, 512 );
            update_and_final_luffa( &garden->luffa, (BitSequence*)hash,
                                    (const BitSequence*)input, 64 );
            break;
        case 11:
            sph_shabal512_init(&garden->shabal);
            sph_shabal512(&garden->shabal, input, 64);
            sph_shabal512_close(&garden->shabal, hash);          
            break;
        case 12:
            sph_shavite512_init(&garden->shavite);
            sph_shavite512(&garden->shavite, input, 64);
            sph_shavite512_close(&garden->shavite, hash);          
            break;
        case 13:
            init_sd( &garden->simd, 512 );
            update_final_sd( &garden->simd, (BitSequence *)hash,
                              (const BitSequence*)input, 512 );
            break;
        case 14:
            sph_skein512_init(&garden->skein);
            sph_skein512(&garden->skein, input, 64);
            sph_skein512_close(&garden->skein, hash);          
            break;
        case 15:
            sph_whirlpool_init(&garden->whirlpool);
            sph_whirlpool(&garden->whirlpool, input, 64);
            sph_whirlpool_close(&garden->whirlpool, hash);          
            break;
    }

    memcpy(output, hash, 64);
}

static __thread TortureGarden garden;

bool initialize_torture_garden()
{
    // Create torture garden nodes. Note that both sides of 19 and 20 lead to 21, and 21 has no children (to make traversal complete).

   garden.nodes[ 0].child[0] = &garden.nodes[ 1];
   garden.nodes[ 0].child[1] = &garden.nodes[ 2];
   garden.nodes[ 1].child[0] = &garden.nodes[ 3];
   garden.nodes[ 1].child[1] = &garden.nodes[ 4];
   garden.nodes[ 2].child[0] = &garden.nodes[ 5];
   garden.nodes[ 2].child[1] = &garden.nodes[ 6];
   garden.nodes[ 3].child[0] = &garden.nodes[ 7];
   garden.nodes[ 3].child[1] = &garden.nodes[ 8];
   garden.nodes[ 4].child[0] = &garden.nodes[ 9];
   garden.nodes[ 4].child[1] = &garden.nodes[10];
   garden.nodes[ 5].child[0] = &garden.nodes[11];
   garden.nodes[ 5].child[1] = &garden.nodes[12];
   garden.nodes[ 6].child[0] = &garden.nodes[13];
   garden.nodes[ 6].child[1] = &garden.nodes[14];
   garden.nodes[ 7].child[0] = &garden.nodes[15];
   garden.nodes[ 7].child[1] = &garden.nodes[16];
   garden.nodes[ 8].child[0] = &garden.nodes[15];
   garden.nodes[ 8].child[1] = &garden.nodes[16];
   garden.nodes[ 9].child[0] = &garden.nodes[15];
   garden.nodes[ 9].child[1] = &garden.nodes[16];
   garden.nodes[10].child[0] = &garden.nodes[15];
   garden.nodes[10].child[1] = &garden.nodes[16];
   garden.nodes[11].child[0] = &garden.nodes[17];
   garden.nodes[11].child[1] = &garden.nodes[18];
   garden.nodes[12].child[0] = &garden.nodes[17];
   garden.nodes[12].child[1] = &garden.nodes[18];
   garden.nodes[13].child[0] = &garden.nodes[17];
   garden.nodes[13].child[1] = &garden.nodes[18];
   garden.nodes[14].child[0] = &garden.nodes[17];
   garden.nodes[14].child[1] = &garden.nodes[18];
   garden.nodes[15].child[0] = &garden.nodes[19];
   garden.nodes[15].child[1] = &garden.nodes[20];
   garden.nodes[16].child[0] = &garden.nodes[19];
   garden.nodes[16].child[1] = &garden.nodes[20];
   garden.nodes[17].child[0] = &garden.nodes[19];
   garden.nodes[17].child[1] = &garden.nodes[20];
   garden.nodes[18].child[0] = &garden.nodes[19];
   garden.nodes[18].child[1] = &garden.nodes[20];
   garden.nodes[19].child[0] = &garden.nodes[21];
   garden.nodes[19].child[1] = &garden.nodes[21];
   garden.nodes[20].child[0] = &garden.nodes[21];
   garden.nodes[20].child[1] = &garden.nodes[21];
   garden.nodes[21].child[0] = NULL;
   garden.nodes[21].child[1] = NULL;

   return true;
}

// Produce a 32-byte hash from 80-byte input data
int minotaur_hash( void *output, const void *input, int thr_id )
{    
    unsigned char hash[64] __attribute__ ((aligned (64)));

    // Find initial sha512 hash
    sph_sha512_init( &garden.sha512 );
    sph_sha512( &garden.sha512, input, 80 );
    sph_sha512_close( &garden.sha512, hash );

    // algo 6 (Hamsi) is very slow. It's faster to skip hashing this nonce
    // if Hamsi is needed but only the first and last functions are
    // currently known. Abort if either is Hamsi.
    if ( ( ( hash[ 0] % MINOTAUR_ALGO_COUNT ) == 6 )
      || ( ( hash[21] % MINOTAUR_ALGO_COUNT ) == 6 ) )
         return 0;

    // Assign algos to torture garden nodes based on initial hash
    for ( int i = 0; i < 22; i++ )
        garden.nodes[i].algo = hash[i] % MINOTAUR_ALGO_COUNT;

    // Send the initial hash through the torture garden
    TortureNode *node = &garden.nodes[0];

    while ( node )
    {
      get_hash( hash, hash, &garden, node->algo );
      node = node->child[ hash[63] & 1 ];
    }

    memcpy( output, hash, 32 );
    return 1;
}

int scanhash_minotaur( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   uint64_t skipped = 0;

   mm128_bswap32_80( edata, pdata );
   do
   {
      edata[19] = n;
      if ( likely( algo_gate.hash( hash, edata, thr_id ) ) )
      {
	 if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
         {
            pdata[19] = bswap_32( n );
            submit_solution( work, hash, mythr );
         }
      }
      else skipped++;
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce - skipped;
   pdata[19] = n;
   return 0;
}

bool register_minotaur_algo( algo_gate_t* gate )
{
  gate->scanhash = (void*)&scanhash_minotaur;
  gate->hash      = (void*)&minotaur_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
  gate->miner_thread_init = (void*)&initialize_torture_garden;
  return true;
};

