#include "miner.h"
#include "hodl-gate.h"
#include "hodl_uint256.h"
#include "hodl_arith_uint256.h"
#include "block.h"
#include <sstream>
#include "tinyformat.h"
#include <unordered_map>
#include "hash.h"
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))
#define PSUEDORANDOM_DATA_SIZE 30 //2^30 = 1GB
#define PSUEDORANDOM_DATA_CHUNK_SIZE 6 //2^6 = 64 bytes //must be same as SHA512_DIGEST_LENGTH 64
#define L2CACHE_TARGET 12 // 2^12 = 4096 bytes
#define AES_ITERATIONS 15

void SHA512Filler(char *mainMemoryPsuedoRandomData, int threadNumber, uint256 midHash){
	//Generate psuedo random data to store in main memory
	uint32_t chunks=(1<<(PSUEDORANDOM_DATA_SIZE-PSUEDORANDOM_DATA_CHUNK_SIZE)); //2^(30-6) = 16 mil
	uint32_t chunkSize=(1<<(PSUEDORANDOM_DATA_CHUNK_SIZE)); //2^6 = 64 bytes
        unsigned char hash_tmp[sizeof(midHash)];
        memcpy((char*)&hash_tmp[0], (char*)&midHash, sizeof(midHash) );
        uint32_t* index = (uint32_t*)hash_tmp;
//        uint32_t chunksToProcess=chunks/totalThreads;
        uint32_t chunksToProcess = chunks / opt_n_threads;
        uint32_t startChunk=threadNumber*chunksToProcess;
        for( uint32_t i = startChunk; i < startChunk+chunksToProcess;  i++){
        	//This changes the first character of hash_tmp
                *index = i;
                SHA512((unsigned char*)hash_tmp, sizeof(hash_tmp), (unsigned char*)&(mainMemoryPsuedoRandomData[i*chunkSize]));
        }
}

extern "C"
// max_nonce is not used by this function
int scanhash_hodl( int threadNumber, struct work* work, uint32_t max_nonce,
                   uint64_t *hashes_done )
{
    unsigned char *mainMemoryPsuedoRandomData = hodl_scratchbuf;
    uint32_t *pdata = work->data;
    uint32_t *ptarget = work->target;

    //retreive target
    std::stringstream s;
    for (int i = 7; i>=0; i--)
      s << strprintf("%08x", ptarget[i]);

    //retreive preveios hash
    std::stringstream p;
    for (int i = 0; i < 8; i++) 
      p << strprintf("%08x", swab32(pdata[8 - i]));

    //retreive merkleroot
    std::stringstream m;
    for (int i = 0; i < 8; i++) 
      m << strprintf("%08x", swab32(pdata[16 - i]));

    CBlock pblock;
    pblock.SetNull();

    pblock.nVersion=swab32(pdata[0]);
    pblock.nNonce=swab32(pdata[19]);
    pblock.nTime=swab32(pdata[17]);
    pblock.nBits=swab32(pdata[18]);
    pblock.hashPrevBlock=uint256S(p.str());
    pblock.hashMerkleRoot=uint256S(m.str());
    uint256 hashTarget=uint256S(s.str());
    int collisions=0;
    uint256 hash;

		//Begin AES Search
	        //Allocate temporary memory
		uint32_t cacheMemorySize = (1<<L2CACHE_TARGET); //2^12 = 4096 bytes
    		uint32_t comparisonSize=(1<<(PSUEDORANDOM_DATA_SIZE-L2CACHE_TARGET)); //2^(30-12) = 256K
                unsigned char *cacheMemoryOperatingData;
                unsigned char *cacheMemoryOperatingData2;
                cacheMemoryOperatingData=new unsigned char[cacheMemorySize+16];
                cacheMemoryOperatingData2=new unsigned char[cacheMemorySize];
                //Create references to data as 32 bit arrays
                uint32_t* cacheMemoryOperatingData32 = (uint32_t*)cacheMemoryOperatingData;
                uint32_t* cacheMemoryOperatingData322 = (uint32_t*)cacheMemoryOperatingData2;

                //Search for pattern in psuedorandom data
                unsigned char key[32] = {0};
                unsigned char iv[AES_BLOCK_SIZE];
                int outlen1, outlen2;

                //Iterate over the data
//                int searchNumber=comparisonSize/totalThreads;
                int searchNumber = comparisonSize / opt_n_threads;
                int startLoc=threadNumber*searchNumber;
		EVP_CIPHER_CTX ctx;
                  for(int32_t k = startLoc;k<startLoc+searchNumber && !work_restart[threadNumber].restart;k++){
                    //copy data to first l2 cache
                    memcpy((char*)&cacheMemoryOperatingData[0], (char*)&mainMemoryPsuedoRandomData[k*cacheMemorySize], cacheMemorySize);
                    for(int j=0;j<AES_ITERATIONS;j++){
                        //use last 4 bytes of first cache as next location
                        uint32_t nextLocation = cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
                        //Copy data from indicated location to second l2 cache -
                        memcpy((char*)&cacheMemoryOperatingData2[0], (char*)&mainMemoryPsuedoRandomData[nextLocation*cacheMemorySize], cacheMemorySize);
                        //XOR location data into second cache
                        for(uint32_t i = 0; i < cacheMemorySize/4; i++)
                            cacheMemoryOperatingData322[i] = cacheMemoryOperatingData32[i] ^ cacheMemoryOperatingData322[i];
                        memcpy(key,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-32],32);
                        memcpy(iv,(unsigned char*)&cacheMemoryOperatingData2[cacheMemorySize-AES_BLOCK_SIZE],AES_BLOCK_SIZE);
                        EVP_EncryptInit(&ctx, EVP_aes_256_cbc(), key, iv);
                        EVP_EncryptUpdate(&ctx, cacheMemoryOperatingData, &outlen1, cacheMemoryOperatingData2, cacheMemorySize);
                        EVP_EncryptFinal(&ctx, cacheMemoryOperatingData + outlen1, &outlen2);
                        EVP_CIPHER_CTX_cleanup(&ctx);
                    }
                    //use last X bits as solution
                    uint32_t solution=cacheMemoryOperatingData32[(cacheMemorySize/4)-1]%comparisonSize;
                    if(solution<1000){
                        uint32_t proofOfCalculation=cacheMemoryOperatingData32[(cacheMemorySize/4)-2];
			pblock.nStartLocation = k;
                        pblock.nFinalCalculation = proofOfCalculation;
                        hash = Hash(BEGIN(pblock.nVersion), END(pblock.nFinalCalculation));
			collisions++;
			if (UintToArith256(hash) <= UintToArith256(hashTarget) && !work_restart[threadNumber].restart){
        		  pdata[21] = swab32(pblock.nFinalCalculation);
        		  pdata[20] = swab32(pblock.nStartLocation);
        		  *hashes_done = collisions;
			  //free memory
			  delete [] cacheMemoryOperatingData;
                	  delete [] cacheMemoryOperatingData2;
        		  return 1;
    			}
                    }
                  }

    //free memory
    delete [] cacheMemoryOperatingData;
    delete [] cacheMemoryOperatingData2;
    *hashes_done = collisions;
    return 0;
}

extern "C"
void GetPsuedoRandomData( char* mainMemoryPsuedoRandomData, uint32_t *pdata,
                            int thr_id )
  {

    //retreive preveios hash
    std::stringstream p;
    for (int i = 0; i < 8; i++)
      p << strprintf("%08x", swab32(pdata[8 - i]));

    //retreive merkleroot
    std::stringstream m;
    for (int i = 0; i < 8; i++)
      m << strprintf("%08x", swab32(pdata[16 - i]));

    CBlock pblock;
    pblock.SetNull();

    pblock.nVersion=swab32(pdata[0]);
    pblock.nTime=swab32(pdata[17]);
    pblock.nBits=swab32(pdata[18]);
    pblock.hashPrevBlock= uint256S(p.str());
    pblock.hashMerkleRoot= uint256S(m.str());
    pblock.nNonce=swab32(pdata[19]);
    uint256 midHash = Hash(BEGIN(pblock.nVersion), END(pblock.nNonce));
    SHA512Filler( mainMemoryPsuedoRandomData, thr_id, midHash);
  }
