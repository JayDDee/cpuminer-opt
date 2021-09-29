/*-
 * Copyright 2013-2018 Alexander Peslyak
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
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
 */

#include "cpuminer-config.h"
#include "miner.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "yescrypt-r8g.h"

int scanhash_yespower_r8g( struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr )
{
    uint64_t hash[4] __attribute__((aligned(64)));
    uint32_t endiandata[32];
    uint32_t *pdata = work->data;
    const uint64_t *ptarget = (const uint64_t*)work->target;
    uint32_t n = pdata[19];
    const uint32_t first_nonce = pdata[19];
    const uint32_t last_nonce = max_nonce;
    const int thr_id = mythr->id;

    yespower_params_t params =
    {
		.version = YESPOWER_0_5,
		.N = 2048,
		.r = 8,
		.pers = (const uint8_t *)endiandata,
		.perslen = work->sapling ? 112 : 80,
    };

    //we need bigendian data...
    for ( int i = 0 ; i < 32; i++ )
       be32enc( &endiandata[ i], pdata[ i ]);
    endiandata[19] = n;

// do sha256 prehash
   sha256_ctx_init( &sha256_prehash_ctx );
   sha256_update( &sha256_prehash_ctx, endiandata, 64 );
    
    do {
       yespower_tls( (unsigned char *)endiandata, params.perslen,
                      &params, (yespower_binary_t*)hash, thr_id );
      
       if unlikely( valid_hash( hash, ptarget ) && !opt_benchmark )
       {
           be32enc( pdata+19, n );
           submit_solution( work, hash, mythr );
       }
       endiandata[19] = ++n;
    } while (n < last_nonce && !work_restart[thr_id].restart);

    *hashes_done = n - first_nonce + 1;
    pdata[19] = n;
    return 0;
}

bool register_yescryptr8g_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | SHA_OPT;
  gate->scanhash      = (void*)&scanhash_yespower_r8g;
  gate->hash          = (void*)&yespower_tls;
  pk_buffer_size      = 26;
  opt_sapling         = true;
  opt_target_factor   = 65536.0;
  return true;
 };


