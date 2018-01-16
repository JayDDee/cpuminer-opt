#include "cpuminer-config.h"
#include "quark-gate.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"

#include "algo/blake/sse2/blake.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/keccak/sse2/keccak.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"

#ifndef NO_AES_NI
 #include "algo/groestl/aes_ni/hash-groestl.h"
#endif

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
      #define DATA_ALIGN16(x) x __attribute__ ((aligned(16)))
      #define DATA_ALIGNXY(x,y) x __attribute__ ((aligned(y)))

#else
      #define DATA_ALIGN16(x) __declspec(align(16)) x
      #define DATA_ALIGNXY(x,y) __declspec(align(y)) x
#endif

#ifdef NO_AES_NI
    sph_groestl512_context quark_ctx;
#else
    hashState_groestl      quark_ctx;
#endif

void init_quark_ctx()
{
#ifdef NO_AES_NI
   sph_groestl512_init( &quark_ctx );
#else
   init_groestl( &quark_ctx, 64 );
#endif
}

void quark_hash(void *state, const void *input)
{
    unsigned char hashbuf[128];
    size_t hashptr;
    sph_u64 hashctA;
    sph_u64 hashctB;
    int i;
    unsigned char hash[128] __attribute__ ((aligned (32)));
#ifdef NO_AES_NI
    sph_groestl512_context ctx;
#else
    hashState_groestl ctx;
#endif

    memcpy( &ctx, &quark_ctx, sizeof(ctx) );

    // Blake
    DECL_BLK;
    BLK_I;
    BLK_W;
    for(i=0; i<9; i++)
    {
    /* blake is split between 64byte hashes and the 80byte initial block */
    //DECL_BLK;
      switch (i+(16*((hash[0] & (uint32_t)(8)) == (uint32_t)(0))))
      {
        // Blake
        case 5 :
            BLK_I;
            BLK_U;
        case 0:
        case 16: 
            BLK_C;
            break;
        case 1:
        case 17:
        case 21:

            // BMW
            do
            { 
              DECL_BMW;
              BMW_I;
              BMW_U;
              /* bmw compress uses some defines */
              /* i havent gotten around to rewriting these */
              #define M(x)    sph_dec64le_aligned(data + 8 * (x))
              #define H(x)    (h[x])
              #define dH(x)   (dh[x])
              BMW_C;
              #undef M
              #undef H
              #undef dH
            } while(0); continue;;

        case 2:
            // dos this entry point represent a second groestl round?

        case 3:
        case 19:
          // Groestl 
          do
          {

#ifdef NO_AES_NI
             sph_groestl512_init( &ctx );
             sph_groestl512 ( &ctx, hash, 64 );
             sph_groestl512_close( &ctx, hash );
#else
             reinit_groestl( &ctx );
             update_and_final_groestl( &ctx, (char*)hash, (char*)hash, 512 );
//             update_groestl( &ctx, (char*)hash, 512 );
//             final_groestl( &ctx, (char*)hash );
#endif

          } while(0); continue;

        case 4:
        case 20:
        case 24:
            // JH
            do
            {
              DECL_JH;
              JH_H;
            } while(0); continue;

        case 6:
        case 22:
        case 8:
            // Keccak
            do
            {
              DECL_KEC;
              KEC_I;
              KEC_U;
              KEC_C;
            } while(0); continue;

        case 18:
        case 7:
        case 23:
            // Skein
            do
            {
              DECL_SKN;
              SKN_I;
              SKN_U;
              SKN_C; /* is a magintue faster than others, done */
            } while(0); continue;
 
       default:
            /* bad things happend, i counted to potato */
            abort();
    }
    /* only blake shouuld get here without continue */
    /* blake finishs from top split */
    //BLK_C;
 }
 

//    asm volatile ("emms");
  memcpy(state, hash, 32);
}

int scanhash_quark( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done)
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(32)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];

        swab32_array( endiandata, pdata, 20 );

	do {
		pdata[19] = ++n;
		be32enc(&endiandata[19], n); 
		quark_hash(hash64, &endiandata);
                if ((hash64[7]&0xFFFFFF00)==0)
                {
                  if (fulltest(hash64, ptarget)) 
                  {
                    work_set_target_ratio( work, hash64 );
                    *hashes_done = n - first_nonce + 1;
		    return true;
                  }
               }
	} while (n < max_nonce && !work_restart[thr_id].restart);
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}

