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

yespower_params_t yespower_params;

__thread sha256_context sha256_prehash_ctx;

// YESPOWER

int yespower_hash( const char *input, char *output, uint32_t len, int thrid )
{
   return yespower_tls( input, len, &yespower_params,
           (yespower_binary_t*)output, thrid ); 
}

int scanhash_yespower( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   // do sha256 prehash
   sha256_ctx_init( &sha256_prehash_ctx );
   sha256_update( &sha256_prehash_ctx, endiandata, 64 );

   do {
      if ( yespower_hash( (char*)endiandata, (char*)vhash, 80, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

// YESPOWER-B2B

int yespower_b2b_hash( const char *input, char *output, uint32_t len, int thrid )
{
  return yespower_b2b_tls( input, len, &yespower_params, (yespower_binary_t*)output, thrid );
}

int scanhash_yespower_b2b( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(64) vhash[8];
   uint32_t _ALIGN(64) endiandata[20];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   uint32_t n = first_nonce;
   const uint32_t last_nonce = max_nonce;
   const int thr_id = mythr->id;

   for ( int k = 0; k < 19; k++ )
      be32enc( &endiandata[k], pdata[k] );
   endiandata[19] = n;

   do {
      if (yespower_b2b_hash( (char*) endiandata, (char*) vhash, 80, thr_id ) )
      if unlikely( valid_hash( vhash, ptarget ) && !opt_benchmark )
      {
          be32enc( pdata+19, n );
          submit_solution( work, vhash, mythr );
      }
      endiandata[19] = ++n;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_yespower_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( opt_param_n )  yespower_params.N = opt_param_n;
  else                yespower_params.N = 2048;

  if ( opt_param_r )  yespower_params.r = opt_param_r;
  else                yespower_params.r = 32;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

  gate->optimizations = SSE2_OPT | SHA_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
};

bool register_yespowerr16_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;
  yespower_params.N       = 4096;
  yespower_params.r       = 16;
  yespower_params.pers    = NULL;
  yespower_params.perslen = 0;
  gate->optimizations = SSE2_OPT | SHA_OPT;
  gate->scanhash      = (void*)&scanhash_yespower;
  gate->hash          = (void*)&yespower_hash;
  opt_target_factor = 65536.0;
  return true;
 };

// Legacy Yescrypt (yespower v0.5)

bool register_yescrypt_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   yespower_params.version = YESPOWER_0_5;
   opt_target_factor = 65536.0;

   if ( opt_param_n )  yespower_params.N = opt_param_n;
   else                yespower_params.N = 2048;

   if ( opt_param_r )  yespower_params.r = opt_param_r;
   else                yespower_params.r = 8;

   if ( opt_param_key )
   {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
   }
   else
   {
     yespower_params.pers = NULL;
     yespower_params.perslen = 0;
   }

   applog( LOG_NOTICE,"Yescrypt parameters: N= %d, R= %d.",
                                      yespower_params.N, yespower_params.r );
   if ( yespower_params.pers )
     applog( LOG_NOTICE,"Key= \"%s\"\n", yespower_params.pers );

   return true;
}


bool register_yescryptr8_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 2048;
   yespower_params.r       = 8;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

bool register_yescryptr16_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 16;
   yespower_params.pers    = "Client Key";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

bool register_yescryptr32_05_algo( algo_gate_t* gate )
{
   gate->optimizations = SSE2_OPT | SHA_OPT;
   gate->scanhash   = (void*)&scanhash_yespower;
   yespower_params.version = YESPOWER_0_5;
   yespower_params.N       = 4096;
   yespower_params.r       = 32;
   yespower_params.pers    = "WaviBanana";
   yespower_params.perslen = 10;
   opt_target_factor = 65536.0;
   return true;
}

// POWER2B

bool register_power2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  yespower_params.N = 2048;
  yespower_params.r = 32;
  yespower_params.pers = "Now I am become Death, the destroyer of worlds";
  yespower_params.perslen = 46;

  applog( LOG_NOTICE,"yespower-b2b parameters: N= %d, R= %d", yespower_params.N,
                                                           yespower_params.r );
  applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
  applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );

  gate->optimizations = SSE2_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
  gate->hash          = (void*)&yespower_b2b_hash;
  opt_target_factor = 65536.0;
  return true;
};

// Generic yespower + blake2b
bool register_yespower_b2b_algo( algo_gate_t* gate )
{
  yespower_params.version = YESPOWER_1_0;

  if ( !( opt_param_n && opt_param_r ) )
  {
     applog(LOG_ERR,"Yespower-b2b N & R parameters are required");
     return false;
  }

  yespower_params.N = opt_param_n;
  yespower_params.r = opt_param_r;

  if ( opt_param_key )
  {
     yespower_params.pers = opt_param_key;
     yespower_params.perslen = strlen( opt_param_key );
  }
  else
  {
     yespower_params.pers    = NULL;
     yespower_params.perslen = 0;
  }

  applog( LOG_NOTICE,"Yespower-b2b parameters: N= %d, R= %d",
                       yespower_params.N, yespower_params.r );
  if ( yespower_params.pers )
  {
     applog( LOG_NOTICE,"Key= \"%s\"", yespower_params.pers );
     applog( LOG_NOTICE,"Key length= %d\n", yespower_params.perslen );
  }  

  gate->optimizations = SSE2_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_b2b;
  gate->hash          = (void*)&yespower_b2b_hash;
  opt_target_factor = 65536.0;
  return true;
};

