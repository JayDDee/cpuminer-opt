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
#include "algo/fugue/sph_fugue.h"
#include "algo/shabal/sph_shabal.h"
#include "algo/whirlpool/sph_whirlpool.h"
#include <openssl/sha.h>
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/echo/sph_echo.h"
  #include "algo/groestl/sph_groestl.h"
#endif

// Config
#define MINOTAUR_ALGO_COUNT	16

typedef struct TortureNode TortureNode;
typedef struct TortureGarden TortureGarden;

// Graph of hash algos plus SPH contexts
struct TortureGarden {
#if defined(__AES__)
        hashState_echo          echo;
        hashState_groestl       groestl;
#else
        sph_echo512_context      echo;
        sph_groestl512_context   groestl;
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
        sph_fugue512_context    fugue;
        sph_shabal512_context   shabal;
        sph_whirlpool_context   whirlpool;
        SHA512_CTX              sha512;

    struct TortureNode {
        unsigned int algo;
        TortureNode *childLeft;
        TortureNode *childRight;
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
            sph_fugue512_init(&garden->fugue);
            sph_fugue512(&garden->fugue, input, 64);
            sph_fugue512_close(&garden->fugue, hash);          
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
            SHA512_Init( &garden->sha512 );
            SHA512_Update( &garden->sha512, input, 64 );
            SHA512_Final( (unsigned char*)hash, &garden->sha512 );
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

    // Output the hash
    memcpy(output, hash, 64);
}

// Recursively traverse a given torture garden starting with a given hash and given node within the garden. The hash is overwritten with the final hash.
static void traverse_garden( TortureGarden *garden, void *hash,
	                     TortureNode *node )
{
    unsigned char partialHash[64] __attribute__ ((aligned (64)));
    get_hash(partialHash, hash, garden, node->algo);

    if ( partialHash[63] % 2 == 0 )
    {   // Last byte of output hash is even
        if ( node->childLeft != NULL )
            traverse_garden( garden, partialHash, node->childLeft );
    }
    else
    {   // Last byte of output hash is odd
        if ( node->childRight != NULL )
            traverse_garden( garden, partialHash, node->childRight );
    }

    memcpy( hash, partialHash, 64 );
}

// Associate child nodes with a parent node
static inline void link_nodes( TortureNode *parent, TortureNode *childLeft,
	                       TortureNode *childRight ) 
{
    parent->childLeft = childLeft;
    parent->childRight = childRight;
}

static __thread TortureGarden garden;

bool initialize_torture_garden()
{
    // Create torture garden nodes. Note that both sides of 19 and 20 lead to 21, and 21 has no children (to make traversal complete).
    link_nodes(&garden.nodes[0], &garden.nodes[1], &garden.nodes[2]);
    link_nodes(&garden.nodes[1], &garden.nodes[3], &garden.nodes[4]);
    link_nodes(&garden.nodes[2], &garden.nodes[5], &garden.nodes[6]);
    link_nodes(&garden.nodes[3], &garden.nodes[7], &garden.nodes[8]);
    link_nodes(&garden.nodes[4], &garden.nodes[9], &garden.nodes[10]);
    link_nodes(&garden.nodes[5], &garden.nodes[11], &garden.nodes[12]);
    link_nodes(&garden.nodes[6], &garden.nodes[13], &garden.nodes[14]);
    link_nodes(&garden.nodes[7], &garden.nodes[15], &garden.nodes[16]);
    link_nodes(&garden.nodes[8], &garden.nodes[15], &garden.nodes[16]);
    link_nodes(&garden.nodes[9], &garden.nodes[15], &garden.nodes[16]);
    link_nodes(&garden.nodes[10], &garden.nodes[15], &garden.nodes[16]);
    link_nodes(&garden.nodes[11], &garden.nodes[17], &garden.nodes[18]);
    link_nodes(&garden.nodes[12], &garden.nodes[17], &garden.nodes[18]);
    link_nodes(&garden.nodes[13], &garden.nodes[17], &garden.nodes[18]);
    link_nodes(&garden.nodes[14], &garden.nodes[17], &garden.nodes[18]);
    link_nodes(&garden.nodes[15], &garden.nodes[19], &garden.nodes[20]);
    link_nodes(&garden.nodes[16], &garden.nodes[19], &garden.nodes[20]);
    link_nodes(&garden.nodes[17], &garden.nodes[19], &garden.nodes[20]);
    link_nodes(&garden.nodes[18], &garden.nodes[19], &garden.nodes[20]);
    link_nodes(&garden.nodes[19], &garden.nodes[21], &garden.nodes[21]);
    link_nodes(&garden.nodes[20], &garden.nodes[21], &garden.nodes[21]);
    garden.nodes[21].childLeft = NULL;
    garden.nodes[21].childRight = NULL;
    return true;
}

// Produce a 32-byte hash from 80-byte input data
int minotaur_hash( void *output, const void *input, int thr_id )
{    
    unsigned char hash[64] __attribute__ ((aligned (64)));

    // Find initial sha512 hash
    SHA512_Init( &garden.sha512 );
    SHA512_Update( &garden.sha512, input, 80 );
    SHA512_Final( (unsigned char*) hash, &garden.sha512 );

    // Assign algos to torture garden nodes based on initial hash
    for ( int i = 0; i < 22; i++ )
        garden.nodes[i].algo = hash[i] % MINOTAUR_ALGO_COUNT;

    // Send the initial hash through the torture garden
    traverse_garden( &garden, hash, &garden.nodes[0] );

    memcpy( output, hash, 32 );

    return 1;
}

bool register_minotaur_algo( algo_gate_t* gate )
{
  gate->hash      = (void*)&minotaur_hash;
  gate->optimizations = SSE2_OPT | AES_OPT | AVX2_OPT | AVX512_OPT;
  gate->miner_thread_init = (void*)&initialize_torture_garden;
  return true;
};

