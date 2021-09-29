#include "myrgr-gate.h"

#if !defined(MYRGR_8WAY) && !defined(MYRGR_4WAY)

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#ifdef __AES__
  #include "aes_ni/hash-groestl.h"
#else
  #include "sph_groestl.h"
#endif
#include "algo/sha/sha256-hash.h"

typedef struct {
#ifdef __AES__
    hashState_groestl       groestl;
#else
    sph_groestl512_context  groestl;
#endif
} myrgr_ctx_holder;

myrgr_ctx_holder myrgr_ctx;

void init_myrgr_ctx()
{
#ifdef __AES__
     init_groestl ( &myrgr_ctx.groestl, 64 );
#else
     sph_groestl512_init( &myrgr_ctx.groestl );
#endif
}

void myriad_hash(void *output, const void *input)
{
   myrgr_ctx_holder ctx;
   memcpy( &ctx, &myrgr_ctx, sizeof(myrgr_ctx) );

   uint32_t _ALIGN(32) hash[16];

#ifdef __AES__
   update_groestl( &ctx.groestl, (char*)input, 640 );
   final_groestl( &ctx.groestl, (char*)hash);
#else
   sph_groestl512(&ctx.groestl, input, 80);
   sph_groestl512_close(&ctx.groestl, hash);
#endif

   sha256_full( hash, hash, 64 );

   memcpy(output, hash, 32);
}

int scanhash_myriad( struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
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
      myriad_hash(hash, endiandata);

      if (hash[7] <= Htarg && fulltest(hash, ptarget))
      {
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
#endif
