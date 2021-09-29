#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <x86intrin.h>
#include "sha512-avx.h"
#include "wolf-aes.h"
#include "hodl-gate.h"
#include "hodl-wolf.h"
#include "miner.h"
#include "algo/sha/sha256d.h"

#if defined(__AES__)               

void GenerateGarbageCore( CacheEntry *Garbage, int ThreadID, int ThreadCount,
     void *MidHash )
{
    const int Chunk = TOTAL_CHUNKS / ThreadCount;
    const uint32_t StartChunk = ThreadID * Chunk;
    const uint32_t EndChunk   = StartChunk + Chunk;

#if defined(__SSE4_2__)
//#ifdef __AVX__
    uint64_t* TempBufs[ SHA512_PARALLEL_N ] ;
    uint64_t* desination[ SHA512_PARALLEL_N ];

    for ( int i=0; i < SHA512_PARALLEL_N; ++i )
    {
        TempBufs[i] = (uint64_t*)malloc( 32 );
        memcpy( TempBufs[i], MidHash, 32 );
    }

    for ( uint32_t i = StartChunk; i < EndChunk; i += SHA512_PARALLEL_N )
    {
        for ( int j = 0; j < SHA512_PARALLEL_N; ++j )
        {
            ( (uint32_t*)TempBufs[j] )[0] = i + j;
            desination[j] = (uint64_t*)( (uint8_t *)Garbage + ( (i+j)
                            * GARBAGE_CHUNK_SIZE ) );
        }
        sha512Compute32b_parallel( TempBufs, desination );
    }

    for ( int i = 0; i < SHA512_PARALLEL_N; ++i )
        free( TempBufs[i] );
#else
    uint32_t TempBuf[8];
    memcpy( TempBuf, MidHash, 32 );

    for ( uint32_t i = StartChunk; i < EndChunk; ++i )
    {
        TempBuf[0] = i;
        SHA512( ( uint8_t *)TempBuf, 32,
                ( (uint8_t *)Garbage ) + ( i * GARBAGE_CHUNK_SIZE ) );
    }
#endif
}

/*
void Rev256(uint32_t *Dest, const uint32_t *Src)
{
	for(int i = 0; i < 8; ++i) Dest[i] = swab32(Src[i]);
}
*/

int scanhash_hodl_wolf( struct work* work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
#if defined(__SSE4_2__)
//#ifdef __AVX__
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    int threadNumber = mythr->id;
    CacheEntry *Garbage = (CacheEntry*)hodl_scratchbuf;
    CacheEntry Cache[AES_PARALLEL_N] __attribute__ ((aligned (64)));
    __m128i* data[AES_PARALLEL_N];
    const __m128i* next[AES_PARALLEL_N];
    uint32_t CollisionCount = 0;

    for ( int n=0; n<AES_PARALLEL_N; ++n )
    {
        data[n] = Cache[n].dqwords;
    }

    // Search for pattern in psuedorandom data	
    int searchNumber = COMPARE_SIZE / opt_n_threads;
    int startLoc = threadNumber * searchNumber;
	
    for ( int32_t k = startLoc; k < startLoc + searchNumber && !work_restart[threadNumber].restart; k += AES_PARALLEL_N )
    {
        // copy data to first l2 cache
        for ( int n=0; n<AES_PARALLEL_N; ++n )
        {
            memcpy(Cache[n].dwords, Garbage + k + n, GARBAGE_SLICE_SIZE);
        }

        for(int j = 0; j < AES_ITERATIONS; ++j)
        {
            __m128i ExpKey[AES_PARALLEL_N][16];
            __m128i ivs[AES_PARALLEL_N];

            // use last 4 bytes of first cache as next location
            for(int n=0; n<AES_PARALLEL_N; ++n) {
                uint32_t nextLocation = Cache[n].dwords[(GARBAGE_SLICE_SIZE >> 2) - 1] & (COMPARE_SIZE - 1); //% COMPARE_SIZE;
                next[n] = Garbage[nextLocation].dqwords;

                __m128i last[2];
                last[0] = _mm_xor_si128(Cache[n].dqwords[254], next[n][254]);
                last[1] = _mm_xor_si128(Cache[n].dqwords[255], next[n][255]);

                // Key is last 32b of Cache
                // IV is last 16b of Cache
                ExpandAESKey256(ExpKey[n], last);
                ivs[n] = last[1];
            }
            AES256CBC(data, next, ExpKey, ivs);
        }

        for(int n=0; n<AES_PARALLEL_N; ++n)
        if((Cache[n].dwords[(GARBAGE_SLICE_SIZE >> 2) - 1] & (COMPARE_SIZE - 1)) < 1000)
        {
            uint32_t BlockHdr[22], FinalPoW[8];

            swab32_array( BlockHdr, pdata, 20 );

            BlockHdr[20] = k + n;
            BlockHdr[21] = Cache[n].dwords[(GARBAGE_SLICE_SIZE >> 2) - 2];

	      sha256d( (uint8_t *)FinalPoW, (uint8_t *)BlockHdr, 88 );
	      CollisionCount++;
	      if( FinalPoW[7] <= ptarget[7] )
	      {
	          pdata[20] = swab32( BlockHdr[20] );
             pdata[21] = swab32( BlockHdr[21] );
		       *hashes_done = CollisionCount;
             submit_solution( work, FinalPoW, mythr );
             return(0);
	      }
	   }
	}
	
    *hashes_done = CollisionCount;
    return(0);


#else  // no AVX

    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;
    uint32_t BlockHdr[22], FinalPoW[8];
    CacheEntry *Garbage = (CacheEntry*)hodl_scratchbuf;
    CacheEntry Cache;
    uint32_t CollisionCount = 0;
    int threadNumber = mythr->id;

    swab32_array( BlockHdr, pdata, 20 );
        // Search for pattern in psuedorandom data      
        int searchNumber = COMPARE_SIZE / opt_n_threads;
        int startLoc = threadNumber * searchNumber;

        if ( opt_debug )
           applog( LOG_DEBUG,"Hash target= %08lx", ptarget[7] );

        for(int32_t k = startLoc; k < startLoc + searchNumber && !work_restart[threadNumber].restart; k++)
        {
           // copy data to first l2 cache
           memcpy(Cache.dwords, Garbage + k, GARBAGE_SLICE_SIZE);
           for(int j = 0; j < AES_ITERATIONS; j++)
           {
                CacheEntry TmpXOR;
                __m128i ExpKey[16];

                // use last 4 bytes of first cache as next location
                uint32_t nextLocation = Cache.dwords[(GARBAGE_SLICE_SIZE >> 2)
                                   - 1] & (COMPARE_SIZE - 1); //% COMPARE_SIZE;

                // Copy data from indicated location to second l2 cache -
                memcpy(&TmpXOR, Garbage + nextLocation, GARBAGE_SLICE_SIZE);
                //XOR location data into second cache
                for( int i = 0; i < (GARBAGE_SLICE_SIZE >> 4); ++i )
                   TmpXOR.dqwords[i] = _mm_xor_si128( Cache.dqwords[i],
                                                      TmpXOR.dqwords[i] );
                // Key is last 32b of TmpXOR
                // IV is last 16b of TmpXOR

                ExpandAESKey256( ExpKey, TmpXOR.dqwords +
                                 (GARBAGE_SLICE_SIZE / sizeof(__m128i)) - 2 );
                AES256CBC( Cache.dqwords, TmpXOR.dqwords, ExpKey,
                        TmpXOR.dqwords[ (GARBAGE_SLICE_SIZE / sizeof(__m128i))
                                                             - 1 ], 256 );                 }
           // use last X bits as solution
           if( ( Cache.dwords[ (GARBAGE_SLICE_SIZE >> 2) - 1 ]
                                         & (COMPARE_SIZE - 1) ) < 1000 )
           {
              BlockHdr[20] = k;
              BlockHdr[21] = Cache.dwords[ (GARBAGE_SLICE_SIZE >> 2) - 2 ];
              sha256d( (uint8_t *)FinalPoW, (uint8_t *)BlockHdr, 88 );
              CollisionCount++;
              if( FinalPoW[7] <= ptarget[7] )
              {
                  pdata[20] = swab32( BlockHdr[20] );
                  pdata[21] = swab32( BlockHdr[21] );
                  *hashes_done = CollisionCount;
                  submit_solution( work, FinalPoW, mythr );
                  return(0);
              }
           }
        }

    *hashes_done = CollisionCount;
    return(0);

#endif  // AVX else

}

void GenRandomGarbage(CacheEntry *Garbage, uint32_t *pdata, int thr_id)
{
	uint32_t BlockHdr[20], MidHash[8];
        swab32_array( BlockHdr, pdata, 20 );
	sha256d((uint8_t *)MidHash, (uint8_t *)BlockHdr, 80);
	GenerateGarbageCore(Garbage, thr_id, opt_n_threads, MidHash);
}

#endif // AES

