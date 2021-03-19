#include "algo-gate-api.h"
#include "algo/sha/sph_sha2.h"
#include "Verthash.h"

static verthash_info_t verthashInfo;

// Verthash data file hash in bytes for verification
// 0x48aa21d7afededb63976d48a8ff8ec29d5b02563af4a1110b056cd43e83155a5
static const uint8_t verthashDatFileHash_bytes[32] =
{ 0xa5, 0x55, 0x31, 0xe8, 0x43, 0xcd, 0x56, 0xb0,
  0x10, 0x11, 0x4a, 0xaf, 0x63, 0x25, 0xb0, 0xd5,
  0x29, 0xec, 0xf8, 0x8f, 0x8a, 0xd4, 0x76, 0x39,
  0xb6, 0xed, 0xed, 0xaf, 0xd7, 0x21, 0xaa, 0x48 };

static const char* verthash_data_file_name = "verthash.dat"; 

int scanhash_verthash( struct work *work, uint32_t max_nonce,
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

   mm128_bswap32_80( edata, pdata );
//   verthash_sha3_prehash_72( edata );
   do
   {
      edata[19] = n;
      verthash_hash( verthashInfo.data, verthashInfo.dataSize, 
                     (const unsigned char (*)[80]) edata,
                     (unsigned char (*)[32]) hash );
      if ( valid_hash( hash, ptarget ) && !bench )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}


bool register_verthash_algo( algo_gate_t* gate )
{

  opt_target_factor = 256.0;
  gate->scanhash  = (void*)&scanhash_verthash;
   
  // verthash data file
  int vhLoadResult = verthash_info_init(&verthashInfo, verthash_data_file_name );
  // Check Verthash initialization status
  if (vhLoadResult == 0) // No Error
  {
      applog(LOG_INFO, "Verthash data file has been loaded succesfully!");

      //  and verify data file(if it was enabled)
      if ( true )
//            if (!cmdr.disableVerthashDataFileVerification)
      {
         uint8_t vhDataFileHash[32] = { 0 };
         sph_sha256_full( vhDataFileHash, verthashInfo.data,
                          verthashInfo.dataSize );

         if ( memcmp( vhDataFileHash, verthashDatFileHash_bytes,
                      sizeof(verthashDatFileHash_bytes) ) == 0 )
            applog(LOG_INFO, "Verthash data file has been verified succesfully!");
         else
            applog(LOG_ERR, "Verthash data file verification has failed!");
      }
      else
         applog(LOG_WARNING, "Verthash data file verification stage is disabled!");
   }
   else
   {
       // Handle Verthash error codes
       if (vhLoadResult == 1)
          applog(LOG_ERR, "Verthash data file name is invalid");
       else if (vhLoadResult == 2)
          applog(LOG_ERR, "Failed to allocate memory for Verthash data");
       else // for debugging purposes
          applog(LOG_ERR, "Verthash data initialization unknown error code: %d",
                 vhLoadResult);
       return false;
   }

   return true;
}

