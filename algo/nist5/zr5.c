/*
 * Copyright 2014 mkimid
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include "cpuminer-config.h"
#include "algo-gate-api.h"
#include <string.h>
#include <stdint.h>
#include "algo/blake/sph_blake.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#if defined(__AES__)
  #include "algo/groestl/aes_ni/hash-groestl.h"
#else
  #include "algo/groestl/sph_groestl.h"
#endif

#define ZR_BLAKE 0
#define ZR_GROESTL 1
#define ZR_JH 2
#define ZR_SKEIN 3
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

static void zr5hash(void *state, const void *input)
{
   char hash[128] __attribute__((aligned(64)));
   sph_blake512_context    ctx_blake;
#if defined(__AES__)
   hashState_groestl       ctx_groestl;
#else
   sph_groestl512_context  ctx_groestl;
#endif
   sph_skein512_context    ctx_skein;
   sph_jh512_context       ctx_jh;
   sph_keccak512_context   ctx_keccak;
    
static const int arrOrder[][4] =
{
   { 0, 1, 2, 3 }, { 0, 1, 3, 2 }, { 0, 2, 1, 3 }, { 0, 2, 3, 1 },
   { 0, 3, 1, 2 }, { 0, 3, 2, 1 }, { 1, 0, 2, 3 }, { 1, 0, 3, 2 },
   { 1, 2, 0, 3 }, { 1, 2, 3, 0 }, { 1, 3, 0, 2 }, { 1, 3, 2, 0 },
   { 2, 0, 1, 3 }, { 2, 0, 3, 1 }, { 2, 1, 0, 3 }, { 2, 1, 3, 0 },
   { 2, 3, 0, 1 }, { 2, 3, 1, 0 }, { 3, 0, 1, 2 }, { 3, 0, 2, 1 },
   { 3, 1, 0, 2 }, { 3, 1, 2, 0 }, { 3, 2, 0, 1 }, { 3, 2, 1, 0 }
};

    sph_keccak512_init( &ctx_keccak );
    sph_keccak512( &ctx_keccak, input, 80 );
    sph_keccak512_close( &ctx_keccak, hash );
  
    unsigned int nOrder = *(unsigned int *)(&hash) % 24;
    unsigned int i = 0;

    for ( i = 0; i < 4; i++ )
    {
       switch ( arrOrder[nOrder][i] )
       {
         case 0:
            sph_blake512_init( &ctx_blake );
            sph_blake512( &ctx_blake, hash, 64 );
            sph_blake512_close( &ctx_blake, hash );
		      break;
         case 1:
#if defined(__AES__)
            init_groestl( &ctx_groestl, 64 );
            update_and_final_groestl( &ctx_groestl, (char*)hash,
                                               (const char*)hash, 512 );
#else
            sph_groestl512_init( &ctx_groestl );
            sph_groestl512( &ctx_groestl, hash, 64 );
            sph_groestl512_close( &ctx_groestl, hash );
#endif
	         break;
         case 2:
            sph_jh512_init( &ctx_jh );
            sph_jh512( &ctx_jh, hash, 64 );
            sph_jh512_close( &ctx_jh, hash );
	         break;
         case 3:
            sph_skein512_init( &ctx_skein );
            sph_skein512( &ctx_skein, hash, 64 );
            sph_skein512_close( &ctx_skein, hash );
            break;
         default:
           break;
       }
    }
	memcpy( state, hash, 32 );
}

int scanhash_zr5( struct work *work, uint32_t max_nonce,
                  unsigned long *hashes_done, struct thr_info *mythr )
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t hash[16] __attribute__((aligned(64)));
  uint32_t tmpdata[20] __attribute__((aligned(64)));
  const uint32_t version = pdata[0] & (~POK_DATA_MASK);
  const uint32_t first_nonce = pdata[19];
  uint32_t nonce = first_nonce;
  int thr_id = mythr->id;  // thr_id arg is deprecated

  memcpy(tmpdata, pdata, 80);

  do
  {
    #define Htarg ptarget[7]
    tmpdata[0] = version;
    tmpdata[19] = nonce;
    zr5hash(hash, tmpdata);
    tmpdata[0] = version | (hash[0] & POK_DATA_MASK);
    zr5hash(hash, tmpdata);
    if (hash[7] <= Htarg )
    {
       if( fulltest(hash, ptarget) )
       {
         pdata[0] = tmpdata[0];
         pdata[19] = nonce;
         submit_solution( work, hash, mythr );
       }
    }
    nonce++;
  } while (nonce < max_nonce && !work_restart[thr_id].restart);

  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce + 1;
  return 0;
}

void zr5_get_new_work( struct work* work, struct work* g_work, int thr_id,
                       uint32_t* end_nonce_ptr )
{
//   pthread_rwlock_rdlock( &g_work_lock );

   // ignore POK in first word
   const int wkcmp_sz = 72;  // (19-1) * sizeof(uint32_t)
   uint32_t *nonceptr = work->data + algo_gate.nonce_index;
   if ( memcmp( &work->data[1], &g_work->data[1], wkcmp_sz )
      || ( *nonceptr >= *end_nonce_ptr ) )
   {
      work_free( work );
      work_copy( work, g_work );
      *nonceptr = ( 0xffffffffU / opt_n_threads ) * thr_id;
      if ( opt_randomize )
         *nonceptr += ( (rand() *4 ) & UINT32_MAX ) / opt_n_threads;
      *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20;
   }
   else
       ++(*nonceptr);

//   pthread_rwlock_unlock( &g_work_lock );
}

void zr5_display_pok( struct work* work )
{
      if ( work->data[0] & 0x00008000 )
        applog(LOG_BLUE, "POK received: %08xx", work->data[0] );
}

int zr5_get_work_data_size() { return 80; }

bool register_zr5_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AES_OPT;
    gate->get_new_work          = (void*)&zr5_get_new_work;
    gate->scanhash              = (void*)&scanhash_zr5;
    gate->hash                  = (void*)&zr5hash;
    gate->decode_extra_data     = (void*)&zr5_display_pok;
    gate->build_stratum_request = (void*)&std_be_build_stratum_request;
    gate->work_decode           = (void*)&std_be_work_decode;
    gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
    gate->set_work_data_endian  = (void*)&set_work_data_big_endian;
    gate->get_work_data_size    = (void*)&zr5_get_work_data_size;
    gate->work_cmp_size         = 72;
    return true;
};

