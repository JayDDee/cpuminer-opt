#include "gr-gate.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "../blake/sph_blake.h"
#include "../bmw/sph_bmw.h"
#include "../jh/sph_jh.h"
#include "../keccak/sph_keccak.h"
#include "../skein/sph_skein.h"
#include "../luffa/sph_luffa.h"
#include "../cubehash/sph_cubehash.h"
#include "../shavite/sph_shavite.h"
#include "../simd/sph_simd.h"
#include "../hamsi/sph_hamsi.h"
#include "../fugue/sph_fugue.h"
#include "../shabal/sph_shabal.h"
#include "../whirlpool/sph_whirlpool.h"
#include "../sha/sph_sha2.h"
#if defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
  #include "algo/echo/sph_echo.h"
#endif 
#include "../tiger/sph_tiger.h"
#include "../lyra2/lyra2.h"
#include "../haval/sph-haval.h"
#include "../gost/sph_gost.h"
#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "cryptonote/cryptonight_dark.h"
#include "cryptonote/cryptonight_dark_lite.h"
#include "cryptonote/cryptonight_fast.h"
#include "cryptonote/cryptonight.h"
#include "cryptonote/cryptonight_lite.h"
#include "cryptonote/cryptonight_soft_shell.h"
#include "cryptonote/cryptonight_turtle.h"
#include "cryptonote/cryptonight_turtle_lite.h"

bool register_gr_algo( algo_gate_t* gate )
{
  gate->scanhash         = (void*)&scanhash_gr;
  gate->hash             = (void*)&gr_hash;
  gate->optimizations    = SSE2_OPT | AES_OPT | AVX2_OPT;
  opt_target_factor = 65536.0;
  return true;
};

enum Algo {
        BLAKE = 0,
        BMW,
        GROESTL,
        JH,
        KECCAK,
        SKEIN,
        LUFFA,
        CUBEHASH,
        SHAVITE,
        SIMD,
        ECHO,
        HAMSI,
        FUGUE,
        SHABAL,
        WHIRLPOOL,
        HASH_FUNC_COUNT
};

enum CNAlgo {
	CNDark = 0,
	CNDarklite,
	CNFast,
	CNLite,
	CNTurtle,
	CNTurtlelite,
	CN_HASH_FUNC_COUNT
};

static void selectAlgo(unsigned char nibble, bool* selectedAlgos, uint8_t* selectedIndex, int algoCount, int* currentCount) {
	uint8_t algoDigit = (nibble & 0x0F) % algoCount;
	if(!selectedAlgos[algoDigit]) {
		selectedAlgos[algoDigit] = true;
		selectedIndex[currentCount[0]] = algoDigit;
		currentCount[0] = currentCount[0] + 1;
	}
	algoDigit = (nibble >> 4) % algoCount;
	if(!selectedAlgos[algoDigit]) {
		selectedAlgos[algoDigit] = true;
		selectedIndex[currentCount[0]] = algoDigit;
		currentCount[0] = currentCount[0] + 1;
	}
}

static void getAlgoString(void *mem, unsigned int size, uint8_t* selectedAlgoOutput, int algoCount) {
  int i;
  unsigned char *p = (unsigned char *)mem;
  unsigned int len = size/2;
  unsigned char j = 0;
  bool selectedAlgo[algoCount];
  for(int z=0; z < algoCount; z++) {
	  selectedAlgo[z] = false;
  }
  int selectedCount = 0;
  for (i=0;i<len; i++) {
	  selectAlgo(p[i], selectedAlgo, selectedAlgoOutput, algoCount, &selectedCount);
	  if(selectedCount == algoCount) {
		  break;
	  }
  }
  if(selectedCount < algoCount) {
	for(uint8_t i = 0; i < algoCount; i++) {
		if(!selectedAlgo[i]) {
			selectedAlgoOutput[selectedCount] = i;
			selectedCount++;
		}
	}
  }
}

void gr_hash(void* output, const void* input) {

	uint32_t hash[64/4];
	sph_blake512_context ctx_blake;
	sph_bmw512_context ctx_bmw;
#if defined(__AES__)
   hashState_groestl       ctx_groestl;
#else
   sph_groestl512_context  ctx_groestl;
#endif
	sph_jh512_context ctx_jh;
	sph_keccak512_context ctx_keccak;
	sph_skein512_context ctx_skein;
	sph_luffa512_context ctx_luffa;
	sph_cubehash512_context ctx_cubehash;
	sph_shavite512_context ctx_shavite;
	sph_simd512_context ctx_simd;
#if  defined(__AES__)
     hashState_echo          ctx_echo;
#else
    sph_echo512_context ctx_echo;
#endif
	sph_hamsi512_context ctx_hamsi;
	sph_fugue512_context ctx_fugue;
	sph_shabal512_context ctx_shabal;
	sph_whirlpool_context ctx_whirlpool;
	sph_haval256_5_context ctx_haval;
	sph_tiger_context ctx_tiger;
	sph_gost512_context ctx_gost;
	sph_sha256_context ctx_sha;

	void *in = (void*) input;
	int size = 80;
	uint8_t selectedAlgoOutput[15] = {0};
	uint8_t selectedCNAlgoOutput[6] = {0};
	getAlgoString(&input[4], 64, selectedAlgoOutput, 15);
	getAlgoString(&input[4], 64, selectedCNAlgoOutput, 6);
	int i;
	for (i = 0; i < 18; i++)
	{
		uint8_t algo;
		uint8_t cnAlgo;
		int coreSelection;
		int cnSelection = -1;
		if(i < 5) {
			coreSelection = i;
		} else if(i < 11) {
			coreSelection = i-1;
		} else {
			coreSelection = i-2;
		}
		if(i==5) {
			coreSelection = -1;
			cnSelection = 0;
		}
		if(i==11) {
			coreSelection = -1;
			cnSelection = 1;
		}
		if(i==17) {
			coreSelection = -1;
			cnSelection = 2;
		}
		if(coreSelection >= 0) {
			algo = selectedAlgoOutput[(uint8_t)coreSelection];
		} else {
			algo = 16; // skip core hashing for this loop iteration
		}
		if(cnSelection >=0) {
			cnAlgo = selectedCNAlgoOutput[(uint8_t)cnSelection];
		} else {
			cnAlgo = 14; // skip cn hashing for this loop iteration
		}
		//selection cnAlgo. if a CN algo is selected then core algo will not be selected
		switch(cnAlgo)
		{
		 case CNDark:
			cryptonightdark_hash(in, hash, size, 1);
			break;
		 case CNDarklite:
			cryptonightdarklite_hash(in, hash, size, 1);
			break;
		 case CNFast:
			cryptonightfast_hash(in, hash, size, 1);
			break;
		 case CNLite:
			cryptonightlite_hash(in, hash, size, 1);
			break;
		 case CNTurtle:
			cryptonightturtle_hash(in, hash, size, 1);
			break;
		 case CNTurtlelite:
			cryptonightturtlelite_hash(in, hash, size, 1);
			break;
		}
		//selection core algo
		switch (algo) {
		case BLAKE:
				sph_blake512_init(&ctx_blake);
				sph_blake512(&ctx_blake, in, size);
				sph_blake512_close(&ctx_blake, hash);
				break;
		case BMW:
				sph_bmw512_init(&ctx_bmw);
				sph_bmw512(&ctx_bmw, in, size);
				sph_bmw512_close(&ctx_bmw, hash);
				break;
		case GROESTL:
				#if defined(__AES__)
					init_groestl( &ctx_groestl, 64 );
					update_and_final_groestl( &ctx_groestl, (char*)hash,
											 (const char*)in, size<<3 );
				#else
					sph_groestl512_init(&ctx_groestl);
					sph_groestl512(&ctx_groestl, in, size);
					sph_groestl512_close(&ctx_groestl, hash);
				#endif
                break;
		case SKEIN:
				sph_skein512_init(&ctx_skein);
				sph_skein512(&ctx_skein, in, size);
				sph_skein512_close(&ctx_skein, hash);
				break;
		case JH:
				sph_jh512_init(&ctx_jh);
				sph_jh512(&ctx_jh, in, size);
				sph_jh512_close(&ctx_jh, hash);
				break;
		case KECCAK:
				sph_keccak512_init(&ctx_keccak);
				sph_keccak512(&ctx_keccak, in, size);
				sph_keccak512_close(&ctx_keccak, hash);
				break;
	   case LUFFA:
                init_luffa( &ctx_luffa, 512 );
                update_and_final_luffa( &ctx_luffa, (BitSequence*)hash,
                                        (const BitSequence*)in, size );
		break;
           case CUBEHASH:
                cubehashInit( &ctx_cubehash, 512, 16, 32 );
                cubehashUpdateDigest( &ctx_cubehash, (byte*) hash,
                                      (const byte*)in, size );
		break;
		case SHAVITE:
				sph_shavite512_init(&ctx_shavite);
				sph_shavite512(&ctx_shavite, in, size);
				sph_shavite512_close(&ctx_shavite, hash);
				break;
		case SIMD:
				sph_simd512_init(&ctx_simd);
				sph_simd512(&ctx_simd, in, size);
				sph_simd512_close(&ctx_simd, hash);
				break;
        case ECHO:
				#if defined(__AES__)
						init_echo( &ctx_echo, 512 );
						update_final_echo ( &ctx_echo, (BitSequence *)hash,
											(const BitSequence *)in, size<<3 );
				#else
						sph_echo512_init(&ctx_echo);
						sph_echo512(&ctx_echo, in, size);
						sph_echo512_close(&ctx_echo, hash);
				#endif
				break;
		case HAMSI:
				sph_hamsi512_init(&ctx_hamsi);
				sph_hamsi512(&ctx_hamsi, in, size);
				sph_hamsi512_close(&ctx_hamsi, hash);
				break;
		case FUGUE:
				sph_fugue512_init(&ctx_fugue);
				sph_fugue512(&ctx_fugue, in, size);
				sph_fugue512_close(&ctx_fugue, hash);
				break;
		case SHABAL:
				sph_shabal512_init(&ctx_shabal);
				sph_shabal512(&ctx_shabal, in, size);
				sph_shabal512_close(&ctx_shabal, hash);
				break;
		case WHIRLPOOL:
				sph_whirlpool_init(&ctx_whirlpool);
				sph_whirlpool(&ctx_whirlpool, in, size);
				sph_whirlpool_close(&ctx_whirlpool, hash);
				break;
		}
		if(cnSelection >= 0) {
			memset(&hash[8], 0, 32);
		}
		in = (void*) hash;
		size = 64;
	}
	memcpy(output, hash, 32);
}

int scanhash_gr( struct work *work, uint32_t max_nonce, uint64_t *hashes_done, struct thr_info *mythr)
{
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        uint32_t _ALIGN(64) endiandata[20];
        const uint32_t first_nonce = pdata[19];
        uint32_t nonce = first_nonce;
        int thr_id = mythr->id;

        if (opt_benchmark)
                ((uint32_t*)ptarget)[7] = 0x0000ff;

        swab32_array( endiandata, pdata, 20 );

        do {
                const uint32_t Htarg = ptarget[7];
                uint32_t hash[8];
                be32enc(&endiandata[19], nonce);
                gr_hash(hash, endiandata);

                if (hash[7] <= Htarg) {
                        pdata[19] = nonce;
                        *hashes_done = pdata[19] - first_nonce;
                        return 1;
                }
                nonce++;

        } while (nonce < max_nonce && !work_restart[thr_id].restart);

        pdata[19] = nonce;
        *hashes_done = pdata[19] - first_nonce + 1;
        return 0;
}
