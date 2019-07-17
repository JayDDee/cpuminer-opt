/*-
 * Copyright 2018 Cryply team
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
 * This file was originally written by Cryply team as part of the Cryply
 * coin.
 */
#include "yespower.h"

#include "algo-gate-api.h"

static yespower_params_t yespower_params;

void yespower_hash( const char *input, char *output, uint32_t len )
{
   yespower_tls( input, len, &yespower_params, (yespower_binary_t*)output ); 
}

int scanhash_yespower( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
        uint32_t _ALIGN(64) vhash[8];
        uint32_t _ALIGN(64) endiandata[20];
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;

        const uint32_t Htarg = ptarget[7];
        const uint32_t first_nonce = pdata[19];
        uint32_t n = first_nonce;
        int thr_id = mythr->id;  // thr_id arg is deprecated

        for (int k = 0; k < 19; k++)
                be32enc(&endiandata[k], pdata[k]);
        do {
           be32enc(&endiandata[19], n);
           yespower_hash((char*) endiandata, (char*) vhash, 80);
           if ( vhash[7] < Htarg && fulltest( vhash, ptarget )
              && !opt_benchmark )
           {
               pdata[19] = n;
               submit_solution( work, vhash, mythr );
            }
            n++;
        } while (n < max_nonce && !work_restart[thr_id].restart);

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;

        return 0;
}

int64_t yespower_get_max64()
{
  return 0xfffLL;
}

bool register_yespower_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 2048;
  yespower_params.r       = 32;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations = SSE2_OPT;
  gate->get_max64     = (void*)&yespower_get_max64;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  gate->set_target    = (void*)&scrypt_set_target;
  return true;
};

bool register_yespowerr16_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 4096;
  yespower_params.r       = 16;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations = SSE2_OPT;
  gate->get_max64     = (void*)&yespower_get_max64;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  gate->set_target    = (void*)&scrypt_set_target;
  return true;
 };


int64_t yescrypt_05_get_max64()
{
  return 0x1ffLL;
}

int64_t yescryptr16_05_get_max64()
{
  return 0xfffLL;
}

bool register_yescrypt_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->set_target = (void*)&scrypt_set_target;
   gate->get_max64  = (void*)&yescrypt_05_get_max64;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 2048;
   yespower_params.r       = 8;
   yespower_params.pers    = NULL;
   yespower_params.perslen = 0;
   return true;
}

bool register_yescryptr8_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->set_target = (void*)&scrypt_set_target;
   gate->get_max64  = (void*)&yescrypt_05_get_max64;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 2048;
   yespower_params.r       = 8;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   return true;
}

bool register_yescryptr16_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->set_target = (void*)&scrypt_set_target;
   gate->get_max64  = (void*)&yescryptr16_05_get_max64;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 16;
   yespower_params.pers    = NULL;
   yespower_params.perslen = 0;
   return true;
}

bool register_yescryptr32_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   gate->set_target = (void*)&scrypt_set_target;
   gate->get_max64  = (void*)&yescryptr16_05_get_max64;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 32;
   yespower_params.pers    = "WaviBanana";
   yespower_params.perslen = 10;
   return true;
}

