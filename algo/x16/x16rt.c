#include "x16r-gate.h"

#if !defined(X16R_8WAY) && !defined(X16R_4WAY)

int scanhash_x16rt( struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash32[8];
   uint32_t _ALIGN(128) edata[20];
   uint32_t _ALIGN(64) timeHash[8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const int thr_id = mythr->id; 
   uint32_t nonce = first_nonce;
   volatile uint8_t *restart = &(work_restart[thr_id].restart);
   const bool bench = opt_benchmark;
   if ( bench )  ptarget[7] = 0x0cff;

   mm128_bswap32_80( edata, pdata );

   static __thread uint32_t s_ntime = UINT32_MAX;
   uint32_t ntime = swab32( pdata[17] );
   if ( s_ntime != ntime )
   {
      x16rt_getTimeHash( ntime, &timeHash );
      x16rt_getAlgoString( &timeHash[0], x16r_hash_order );
      s_ntime = ntime;
      if ( opt_debug && !thr_id )
          applog( LOG_INFO, "hash order: %s time: (%08x) time hash: (%08x)",
                               x16r_hash_order, ntime, timeHash );
   }
   
   x16r_prehash( edata, pdata );
   
   do
   {
      edata[19] = nonce;
      if ( x16r_hash( hash32, edata, thr_id ) )
      if ( valid_hash( hash32, ptarget ) && !bench )
      {
         pdata[19] = bswap_32( nonce );
         submit_solution( work, hash32, mythr );
      }
      nonce++;
   } while ( nonce < max_nonce && !(*restart) );
   pdata[19] = nonce;
   *hashes_done = pdata[19] - first_nonce;
   return 0;
}

#endif  // !defined(X16R_8WAY) && !defined(X16R_4WAY)

