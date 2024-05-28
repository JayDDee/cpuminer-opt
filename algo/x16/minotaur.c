// Minotaur hash

#include "algo-gate-api.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include "algo/blake/blake512-hash.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "algo/simd/simd-hash-2way.h"
#include "algo/hamsi/sph_hamsi.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include "algo/sha/sph_sha2.h"
#include "algo/yespower/yespower.h"
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/echo/aes_ni/hash_api.h"
#else
  #include "algo/echo/sph_echo.h"
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
 #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
  #include "algo/fugue/fugue-aesni.h"
#else
  #include "algo/fugue/sph_fugue.h"
#endif

// Config
#define MINOTAUR_ALGO_COUNT	16

static const yespower_params_t minotaurx_yespower_params =
                         { YESPOWER_1_0, 2048, 8, "et in arcadia ego", 17 };

typedef struct TortureNode TortureNode;
typedef struct TortureGarden TortureGarden;

// Graph of hash algos plus SPH contexts
struct TortureGarden
{
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_groestl       groestl;
#else
   sph_groestl512_context  groestl;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_echo          echo;
#else
   sph_echo512_context     echo;
#endif
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
   hashState_fugue         fugue;
#else
   sph_fugue512_context    fugue;
#endif
   blake512_context        blake;
   sph_bmw512_context      bmw;
   sph_skein512_context    skein;
   sph_jh512_context       jh;
   sph_keccak512_context   keccak;
   cubehashParam           cube;
   shavite512_context      shavite;
   hashState_luffa         luffa;
   simd512_context         simd;
   sph_hamsi512_context    hamsi;
   sph_shabal512_context   shabal;
   sph_whirlpool_context   whirlpool;
   sph_sha512_context      sha512;
    struct TortureNode
    {
        unsigned int algo;
        TortureNode *child[2];
    } nodes[22];
} __attribute__ ((aligned (64)));

// Get a 64-byte hash for given 64-byte input, using given TortureGarden contexts and given algo index
static int get_hash( void *output, const void *input, TortureGarden *garden,
	                  unsigned int algo, int thr_id )
{    
	unsigned char hash[64] __attribute__ ((aligned (64)));
   int rc = 1;

    switch ( algo )
    {
        case 0:
            blake512_full( &garden->blake, hash, input, 64 );
            break;
        case 1:
            sph_bmw512_init( &garden->bmw );
            sph_bmw512( &garden->bmw, input, 64 );
            sph_bmw512_close( &garden->bmw, hash );        
            break;
        case 2:
            cubehashInit( &garden->cube, 512, 16, 32 );
            cubehashUpdateDigest( &garden->cube, hash, input, 64 );
            break;
        case 3:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            echo_full( &garden->echo, hash, 512, input, 64 );
#else
            sph_echo512_init( &garden->echo );
            sph_echo512( &garden->echo, input, 64 );
            sph_echo512_close( &garden->echo, hash );          
#endif
	         break;
        case 4:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            fugue512_full( &garden->fugue, hash, input, 64 );
#else
            sph_fugue512_full( &garden->fugue, hash, input, 64 );
#endif
	         break;
        case 5:
#if defined(__AES__) || defined(__ARM_FEATURE_AES)
            groestl512_full( &garden->groestl, hash, input, 512 );
#else
            sph_groestl512_init( &garden->groestl) ;
            sph_groestl512( &garden->groestl, input, 64 );
            sph_groestl512_close( &garden->groestl, hash );          
#endif
	         break;
        case 6:
            sph_hamsi512_init( &garden->hamsi );
            sph_hamsi512( &garden->hamsi, input, 64 );
            sph_hamsi512_close( &garden->hamsi, hash );          
            break;
        case 7:
            sph_sha512_init( &garden->sha512 );
            sph_sha512( &garden->sha512, input, 64 );
            sph_sha512_close( &garden->sha512, hash );
            break;
        case 8:
            sph_jh512_init( &garden->jh );
            sph_jh512( &garden->jh, input, 64 );
            sph_jh512_close( &garden->jh, hash );          
            break;
        case 9:
            sph_keccak512_init( &garden->keccak );
            sph_keccak512( &garden->keccak, input, 64 );
            sph_keccak512_close( &garden->keccak, hash );
            break;
        case 10:
            luffa_full( &garden->luffa, hash, 512, input, 64 );
            break;
        case 11:
            sph_shabal512_init( &garden->shabal );
            sph_shabal512( &garden->shabal, input, 64 );
            sph_shabal512_close( &garden->shabal, hash );          
            break;
        case 12:
            sph_shavite512_init( &garden->shavite );
            sph_shavite512( &garden->shavite, input, 64 );
            sph_shavite512_close( &garden->shavite, hash );          
            break;
        case 13:
            simd512_ctx( &garden->simd, hash, input, 64 );
            break;
        case 14:
            sph_skein512_init( &garden->skein );
            sph_skein512( &garden->skein, input, 64 );
            sph_skein512_close( &garden->skein, hash );          
            break;
        case 15:
            sph_whirlpool_init( &garden->whirlpool );
            sph_whirlpool( &garden->whirlpool, input, 64 );
            sph_whirlpool_close( &garden->whirlpool, hash );          
            break;
        case 16: // minotaurx only, yespower hardcoded for last node
            rc = yespower_tls( input, 64, &minotaurx_yespower_params,
                               (yespower_binary_t*)hash, thr_id );
    }

    memcpy(output, hash, 64);
    return rc;
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
    int rc = 1;

    // Find initial sha512 hash
    sph_sha512_init( &garden.sha512 );
    sph_sha512( &garden.sha512, input, 80 );
    sph_sha512_close( &garden.sha512, hash );
    
    if ( opt_algo != ALGO_MINOTAURX )
    {
       // algo 6 (Hamsi) is very slow. It's faster to skip hashing this nonce
       // if Hamsi is needed but only the first and last functions are
       // currently known. Abort if either is Hamsi.
       if ( ( ( hash[ 0] % MINOTAUR_ALGO_COUNT ) == 6 )
         || ( ( hash[21] % MINOTAUR_ALGO_COUNT ) == 6 ) )
           return 0;
    }

    // Assign algos to torture garden nodes based on initial hash
    for ( int i = 0; i < 22; i++ )
        garden.nodes[i].algo = hash[i] % MINOTAUR_ALGO_COUNT;

    // MinotaurX override algo for last node with yespower
    if ( opt_algo == ALGO_MINOTAURX )
        garden.nodes[21].algo = MINOTAUR_ALGO_COUNT;
    
    // Send the initial hash through the torture garden
    TortureNode *node = &garden.nodes[0];
    while ( rc && node )
    {
      rc = get_hash( hash, hash, &garden, node->algo, thr_id );
      node = node->child[ hash[63] & 1 ];
    }

    memcpy( output, hash, 32 );
    return rc;
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

   v128_bswap32_80( edata, pdata );
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

// hash function has hooks for minotaurx
bool register_minotaur_algo( algo_gate_t* gate )
{
  gate->scanhash          = (void*)&scanhash_minotaur;
  gate->hash              = (void*)&minotaur_hash;
  gate->miner_thread_init = (void*)&initialize_torture_garden;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT | NEON_OPT;
  if ( opt_algo == ALGO_MINOTAURX ) gate->optimizations |= SHA256_OPT;
  return true;
};

