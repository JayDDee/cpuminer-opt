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

#include "algo/groestl/sph_groestl.h"
#include "algo/keccak/sph_keccak.h"

#ifndef NO_AES_NI
  #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

#include "algo/jh/sse2/jh_sse2_opt64.h"
#include "algo/skein/sse2/skein.c"
#include "algo/blake/sse2/blake.c"

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
#endif

#define ZR_BLAKE 0
#define ZR_GROESTL 1
#define ZR_JH 2
#define ZR_SKEIN 3
#define POK_BOOL_MASK 0x00008000
#define POK_DATA_MASK 0xFFFF0000

typedef struct {
  #ifdef NO_AES_NI
    sph_groestl512_context  groestl;
  #else
    hashState_groestl       groestl;
  #endif
    sph_keccak512_context    keccak;
} zr5_ctx_holder;

zr5_ctx_holder zr5_ctx;

void init_zr5_ctx()
{
  #ifdef NO_AES_NI
     sph_groestl512_init( &zr5_ctx.groestl );
  #else
     init_groestl( &zr5_ctx.groestl, 64 );
  #endif
     sph_keccak512_init(&zr5_ctx.keccak);
}  

static void zr5hash(void *state, const void *input)
{
    
DATA_ALIGN16(unsigned char hashbuf[128]);
DATA_ALIGN16(unsigned char hash[128]);
DATA_ALIGN16(size_t hashptr);
DATA_ALIGN16(sph_u64 hashctA);
DATA_ALIGN16(sph_u64 hashctB);

//memset(hash, 0, 128);

static const int arrOrder[][4] =
{
   { 0, 1, 2, 3 }, { 0, 1, 3, 2 }, { 0, 2, 1, 3 }, { 0, 2, 3, 1 },
   { 0, 3, 1, 2 }, { 0, 3, 2, 1 }, { 1, 0, 2, 3 }, { 1, 0, 3, 2 },
   { 1, 2, 0, 3 }, { 1, 2, 3, 0 }, { 1, 3, 0, 2 }, { 1, 3, 2, 0 },
   { 2, 0, 1, 3 }, { 2, 0, 3, 1 }, { 2, 1, 0, 3 }, { 2, 1, 3, 0 },
   { 2, 3, 0, 1 }, { 2, 3, 1, 0 }, { 3, 0, 1, 2 }, { 3, 0, 2, 1 },
   { 3, 1, 0, 2 }, { 3, 1, 2, 0 }, { 3, 2, 0, 1 }, { 3, 2, 1, 0 }
};

    zr5_ctx_holder ctx;
    memcpy( &ctx, &zr5_ctx, sizeof(zr5_ctx) );

    sph_keccak512 (&ctx.keccak, input, 80);
    sph_keccak512_close(&ctx.keccak, hash);
  
    unsigned int nOrder = *(unsigned int *)(&hash) % 24;
    unsigned int i = 0;

    for (i = 0; i < 4; i++)
    {
       switch (arrOrder[nOrder][i])
       {
         case 0:
		{DECL_BLK;
		BLK_I;
		BLK_U;
		BLK_C;}
		break;
         case 1:
            #ifdef NO_AES_NI
                sph_groestl512 (&ctx.groestl, hash, 64);
                sph_groestl512_close(&ctx.groestl, hash);
            #else
                update_groestl( &ctx.groestl, (char*)hash,512);
                final_groestl( &ctx.groestl, (char*)hash);
            #endif
	    break;
         case 2:
		{DECL_JH;
		JH_H;} 
		break;
         case 3:
		{DECL_SKN;
                SKN_I;
                SKN_U;
                SKN_C; }
		break;
         default:
           break;
       }
    }
	asm volatile ("emms");
	memcpy(state, hash, 32);
}

int scanhash_zr5( int thr_id, struct work *work,
                   uint32_t max_nonce, unsigned long *hashes_done)
{
  uint32_t *pdata = work->data;
  uint32_t *ptarget = work->target;
  uint32_t hash[16] __attribute__((aligned(64)));
  uint32_t tmpdata[20] __attribute__((aligned(64)));
  const uint32_t version = pdata[0] & (~POK_DATA_MASK);
  const uint32_t first_nonce = pdata[19];
  uint32_t nonce = first_nonce;

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
         *hashes_done = pdata[19] - first_nonce + 1;
         work_set_target_ratio( work, hash );
         if (opt_debug)
           applog(LOG_INFO, "found nonce %x", nonce);
         return 1;
       }
    }
    nonce++;
  } while (nonce < max_nonce && !work_restart[thr_id].restart);

  pdata[19] = nonce;
  *hashes_done = pdata[19] - first_nonce + 1;
  return 0;
}

void zr5_get_new_work( struct work* work, struct work* g_work, int thr_id,
                       uint32_t* end_nonce_ptr, bool clean_job )
{
   // ignore POK in first word
// const int nonce_i = 19;
   const int wkcmp_sz = 72;  // (19-1) * sizeof(uint32_t)
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );
   if ( memcmp( &work->data[1], &g_work->data[1], wkcmp_sz )
      && ( clean_job || ( *nonceptr >= *end_nonce_ptr ) ) )
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
}

int64_t zr5_get_max64 ()
{
//  return 0x1ffffLL;
  return 0x1fffffLL;
}

void zr5_display_pok( struct work* work )
{
      if ( work->data[0] & 0x00008000 )
        applog(LOG_BLUE, "POK received: %08xx", work->data[0] );
}

bool register_zr5_algo( algo_gate_t* gate )
{
    gate->optimizations = SSE2_OPT | AES_OPT;
    init_zr5_ctx();
    gate->get_new_work          = (void*)&zr5_get_new_work;
    gate->scanhash              = (void*)&scanhash_zr5;
    gate->hash                  = (void*)&zr5hash;
    gate->get_max64             = (void*)&zr5_get_max64;
    gate->display_extra_data    = (void*)&zr5_display_pok;
    gate->build_stratum_request = (void*)&std_be_build_stratum_request;
    gate->work_decode           = (void*)&std_be_work_decode;
    gate->submit_getwork_result = (void*)&std_be_submit_getwork_result;
    gate->set_work_data_endian  = (void*)&set_work_data_big_endian;
    gate->work_data_size        = 80;
    gate->work_cmp_size         = 72;
    return true;
};

