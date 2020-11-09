#include "lyra2-gate.h"
#include "algo/skein/skein-hash-4way.h"
#include "algo/jh/jh-hash-4way.h"
#include "algo/gost/sph_gost.h"
#include "algo/cubehash/cubehash_sse2.h"
#include "lyra2.h"
#if defined(__VAES__) && defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
  #include "algo/echo/echo-hash-4way.h"
#elif defined(__AES__)
  #include "algo/echo/aes_ni/hash_api.h"
#endif

#if defined(PHI2_8WAY)

typedef struct {
     cubehashParam           cube;
     jh512_8way_context      jh;
#if  defined(__VAES__)
     echo_4way_context       echo;
#else
     hashState_echo          echo;
#endif
     sph_gost512_context     gost;
     skein512_8way_context   skein;
} phi2_8way_ctx_holder;

void phi2_8way_hash( void *state, const void *input )
{
   unsigned char _ALIGN(128) hash[64*8];
   unsigned char _ALIGN(128) hashA[64*2];
   unsigned char _ALIGN(64) hash0[64];
   unsigned char _ALIGN(64) hash1[64];
   unsigned char _ALIGN(64) hash2[64];
   unsigned char _ALIGN(64) hash3[64];
   unsigned char _ALIGN(64) hash4[64];
   unsigned char _ALIGN(64) hash5[64];
   unsigned char _ALIGN(64) hash6[64];
   unsigned char _ALIGN(64) hash7[64];
   const int size = phi2_has_roots ? 144 : 80 ;
   phi2_8way_ctx_holder ctx __attribute__ ((aligned (64)));

   cubehash_full( &ctx.cube, (byte*)hash0, 512,
                       (const byte*)input,         size );
   cubehash_full( &ctx.cube, (byte*)hash1, 512,
                       (const byte*)input +   144, size );
   cubehash_full( &ctx.cube, (byte*)hash2, 512,
                       (const byte*)input + 2*144, size );
   cubehash_full( &ctx.cube, (byte*)hash3, 512,
                       (const byte*)input + 3*144, size );
   cubehash_full( &ctx.cube, (byte*)hash4, 512,
                       (const byte*)input + 4*144, size );
   cubehash_full( &ctx.cube, (byte*)hash5, 512,
                       (const byte*)input + 5*144, size );
   cubehash_full( &ctx.cube, (byte*)hash6, 512,
                       (const byte*)input + 6*144, size );
   cubehash_full( &ctx.cube, (byte*)hash7, 512,
                       (const byte*)input + 7*144, size );

   intrlv_2x256( hashA, hash0, hash1, 512 );
   LYRA2RE_2WAY( hash,        32, hashA,        32, 1, 8, 8 );
   LYRA2RE_2WAY( hash + 2*32, 32, hashA + 2*32, 32, 1, 8, 8 );
   dintrlv_2x256( hash0, hash1, hash, 512 );
   intrlv_2x256( hashA, hash2, hash3, 512 );
   LYRA2RE_2WAY( hash,        32, hashA,        32, 1, 8, 8 );
   LYRA2RE_2WAY( hash + 2*32, 32, hashA + 2*32, 32, 1, 8, 8 );
   dintrlv_2x256( hash2, hash3, hash, 512 );
   intrlv_2x256( hashA, hash4, hash5, 512 );
   LYRA2RE_2WAY( hash,        32, hashA,        32, 1, 8, 8 );
   LYRA2RE_2WAY( hash + 2*32, 32, hashA + 2*32, 32, 1, 8, 8 );
   dintrlv_2x256( hash4, hash5, hash, 512 );
   intrlv_2x256( hashA, hash6, hash7, 512 );
   LYRA2RE_2WAY( hash,        32, hashA,        32, 1, 8, 8 );
   LYRA2RE_2WAY( hash + 2*32, 32, hashA + 2*32, 32, 1, 8, 8 );
   dintrlv_2x256( hash6, hash7, hash, 512 );
   
   intrlv_8x64_512( hash, hash0, hash1, hash2, hash3,
                          hash4, hash5, hash6, hash7 );

   jh512_8way_init( &ctx.jh );
   jh512_8way_update( &ctx.jh, (const void*)hash, 64 );
   jh512_8way_close( &ctx.jh, (void*)hash );

   dintrlv_8x64_512( hash0, hash1, hash2, hash3,
                     hash4, hash5, hash6, hash7, hash );

#if defined (__VAES__)

   unsigned char _ALIGN(64) hashA0[64];
   unsigned char _ALIGN(64) hashA1[64];
   unsigned char _ALIGN(64) hashA2[64];
   unsigned char _ALIGN(64) hashA3[64];
   unsigned char _ALIGN(64) hashA4[64];
   unsigned char _ALIGN(64) hashA5[64];
   unsigned char _ALIGN(64) hashA6[64];
   unsigned char _ALIGN(64) hashA7[64];

   intrlv_4x128_512( hash, hash0, hash1, hash2, hash3 );
   echo_4way_full( &ctx.echo, hash, 512, hash, 64 ); 
   echo_4way_full( &ctx.echo, hash, 512, hash, 64 );
   dintrlv_4x128_512( hashA0, hashA1, hashA2, hashA3, hash );

   intrlv_4x128_512( hash, hash4, hash5, hash6, hash7 );
   echo_4way_full( &ctx.echo, hash, 512, hash, 64 );
   echo_4way_full( &ctx.echo, hash, 512, hash, 64 );    
   dintrlv_4x128_512( hashA4, hashA5, hashA6, hashA7, hash );

#endif    

   if ( hash0[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash0, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash0 );
   }
   else
#if defined (__VAES__)
      memcpy( hash0, hashA0, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                      (const BitSequence *)hash0, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                      (const BitSequence *)hash0, 64 );
   }
#endif
   if ( hash1[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash1, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash1 );
   }
   else
#if defined (__VAES__)
      memcpy( hash1, hashA1, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                      (const BitSequence *)hash1, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                      (const BitSequence *)hash1, 64 );
   }
#endif
   if ( hash2[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash2, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash2 );
   }
   else
#if defined (__VAES__)
      memcpy( hash2, hashA2, 64 );
#else 
   {
      echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                      (const BitSequence *)hash2, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                      (const BitSequence *)hash2, 64 );
   }
#endif
   if ( hash3[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash3, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash3 );
   }
   else
#if defined (__VAES__)
      memcpy( hash3, hashA3, 64 );
#else  
   {
      echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                      (const BitSequence *)hash3, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                      (const BitSequence *)hash3, 64 );
   }
#endif
   if ( hash4[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash4, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash4 );
   }
   else
#if defined (__VAES__)
      memcpy( hash4, hashA4, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                      (const BitSequence *)hash4, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash4, 512,
                      (const BitSequence *)hash4, 64 );
   }
#endif   
   if ( hash5[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash5, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash5 );
   }
   else
#if defined (__VAES__)
      memcpy( hash5, hashA5, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                      (const BitSequence *)hash5, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash5, 512,
                      (const BitSequence *)hash5, 64 );
   }
#endif   
   if ( hash6[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash6, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash6 );
   }
   else
#if defined (__VAES__)
      memcpy( hash6, hashA6, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                      (const BitSequence *)hash6, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash6, 512,
                      (const BitSequence *)hash6, 64 );
   }
#endif   
   if ( hash7[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash7, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash7 );
   }
   else
#if defined (__VAES__)
      memcpy( hash7, hashA7, 64 );
#else
   {
      echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                      (const BitSequence *)hash7, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash7, 512,
                      (const BitSequence *)hash7, 64 );
   }
#endif

   intrlv_8x64_512( hash, hash0, hash1, hash2, hash3,
                          hash4, hash5, hash6, hash7 );

   skein512_8way_init( &ctx.skein );
   skein512_8way_update( &ctx.skein, (const void*)hash, 64 );
   skein512_8way_close( &ctx.skein, (void*)hash );

   for ( int i = 0; i < 4; i++ )
      casti_m512i( state, i ) = _mm512_xor_si512( casti_m512i( hash, i ),
                                                  casti_m512i( hash, i+4 ) );
}

int scanhash_phi2_8way( struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash[16*8];
   uint32_t _ALIGN(128) edata[36*8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t *hash7 = &(hash[49]);  
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   if ( bench )      ptarget[7] = 0x00ff;

   phi2_has_roots = false;

   for ( int i = 0; i < 36; i++ )
   {
      be32enc( &edata[i], pdata[i] );
      edata[ i +   36 ] = edata[ i + 2*36 ] = edata[ i + 3*36 ] =
      edata[ i + 4*36 ] = edata[ i + 5*36 ] = edata[ i + 6*36 ] =
      edata[ i + 7*36 ] = edata[ i ];
      if ( i >= 20 && pdata[i] ) phi2_has_roots = true;
   }

   edata[        19 ] = n;
   edata[   36 + 19 ] = n+1;
   edata[ 2*36 + 19 ] = n+2;
   edata[ 3*36 + 19 ] = n+3;
   edata[ 4*36 + 19 ] = n+4;
   edata[ 5*36 + 19 ] = n+5;
   edata[ 6*36 + 19 ] = n+6;
   edata[ 7*36 + 19 ] = n+7;
   
   do {
      phi2_8way_hash( hash, edata );

      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( hash7[ lane<<1 ] <= Htarg && !bench ) )
      {
         uint64_t _ALIGN(64) lane_hash[8];
         extr_lane_8x64( lane_hash, hash, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) )
         {
            be32enc( pdata + 19, n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      n += 8;
      edata[        19 ] += 8;
      edata[   36 + 19 ] += 8;
      edata[ 2*36 + 19 ] += 8;
      edata[ 3*36 + 19 ] += 8;
      edata[ 4*36 + 19 ] += 8;
      edata[ 5*36 + 19 ] += 8;
      edata[ 6*36 + 19 ] += 8;
      edata[ 7*36 + 19 ] += 8;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;

}

#elif defined(PHI2_4WAY)

typedef struct {
     cubehashParam           cube;
     jh512_4way_context      jh;
#if  defined(__AES__)
     hashState_echo          echo;
#else
     sph_echo512_context     echo;
#endif
     sph_gost512_context     gost;
     skein512_4way_context   skein;
} phi2_4way_ctx_holder;

phi2_4way_ctx_holder phi2_4way_ctx;

void phi2_4way_hash(void *state, const void *input)
{
	unsigned char _ALIGN(128) hash[64*4];
   unsigned char _ALIGN(64) hash0[64];
   unsigned char _ALIGN(64) hash1[64];
   unsigned char _ALIGN(64) hash2[64];
   unsigned char _ALIGN(64) hash3[64];
   unsigned char _ALIGN(64) hash0A[64];
   unsigned char _ALIGN(64) hash1A[64];
   unsigned char _ALIGN(64) hash2A[64];
   unsigned char _ALIGN(64) hash3A[64];
   const int size = phi2_has_roots ? 144 : 80 ;
   phi2_4way_ctx_holder ctx __attribute__ ((aligned (64)));

   cubehash_full( &ctx.cube, (byte*)hash0A, 512,
                       (const byte*)input,          size );
   cubehash_full( &ctx.cube, (byte*)hash1A, 512,
                       (const byte*)input +   144, size );
   cubehash_full( &ctx.cube, (byte*)hash2A, 512,
                       (const byte*)input + 2*144, size );
   cubehash_full( &ctx.cube, (byte*)hash3A, 512,
                       (const byte*)input + 3*144, size );
  
	LYRA2RE( &hash0[ 0], 32, hash0A,    32, hash0A,    32, 1, 8, 8 );
	LYRA2RE( &hash0[32], 32, hash0A+32, 32, hash0A+32, 32, 1, 8, 8 );
   LYRA2RE( &hash1[ 0], 32, hash1A,    32, hash1A,    32, 1, 8, 8 );
   LYRA2RE( &hash1[32], 32, hash1A+32, 32, hash1A+32, 32, 1, 8, 8 );
   LYRA2RE( &hash2[ 0], 32, hash2A,    32, hash2A,    32, 1, 8, 8 );
   LYRA2RE( &hash2[32], 32, hash2A+32, 32, hash2A+32, 32, 1, 8, 8 );
   LYRA2RE( &hash3[ 0], 32, hash3A,    32, hash3A,    32, 1, 8, 8 );
   LYRA2RE( &hash3[32], 32, hash3A+32, 32, hash3A+32, 32, 1, 8, 8 );

   intrlv_4x64_512( hash, hash0, hash1, hash2, hash3 );

   jh512_4way_init( &ctx.jh );
   jh512_4way_update( &ctx.jh, (const void*)hash, 64 );
	jh512_4way_close( &ctx.jh, (void*)hash );

   dintrlv_4x64_512( hash0, hash1, hash2, hash3, hash );

   if ( hash0[0] & 1 )
  	{
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash0, 64 );
	   sph_gost512_close( &ctx.gost, (void*)hash0 );
	}
  	else
  	{
      echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                      (const BitSequence *)hash0, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash0, 512,
                      (const BitSequence *)hash0, 64 );
	}
   if ( hash1[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash1, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash1 );
   }
   else
   {
      echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                      (const BitSequence *)hash1, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash1, 512,
                      (const BitSequence *)hash1, 64 );
   }
   if ( hash2[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash2, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash2 );
   }
   else
   {
      echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                      (const BitSequence *)hash2, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash2, 512,
                      (const BitSequence *)hash2, 64 );
   }
   if ( hash3[0] & 1 )
   {
      sph_gost512_init( &ctx.gost );
      sph_gost512( &ctx.gost, (const void*)hash3, 64 );
      sph_gost512_close( &ctx.gost, (void*)hash3 );
   }
   else
   {
      echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                      (const BitSequence *)hash3, 64 );
      echo_full( &ctx.echo, (BitSequence *)hash3, 512,
                      (const BitSequence *)hash3, 64 );
   }

   intrlv_4x64_512( hash, hash0, hash1, hash2, hash3 );

   skein512_4way_init( &ctx.skein );
	skein512_4way_update( &ctx.skein, (const void*)hash, 64 );
	skein512_4way_close( &ctx.skein, (void*)hash );


   for ( int i = 0; i < 4; i++ )
      casti_m256i( state, i ) = _mm256_xor_si256( casti_m256i( hash, i   ),
                                                  casti_m256i( hash, i+4 ) );
}

int scanhash_phi2_4way( struct work *work, uint32_t max_nonce,
	                     uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t _ALIGN(128) hash[16*4];
   uint32_t _ALIGN(128) edata[36*4];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   uint32_t *hash7 = &(hash[25]);   // 3*8+1
   const uint32_t Htarg = ptarget[7];
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   if ( bench )   	ptarget[7] = 0x00ff;
   
   phi2_has_roots = false;

   for ( int i = 0; i < 36; i++ )
   {
	   be32enc( &edata[i], pdata[i] );
      edata[ i+36 ] = edata[ i+72 ] = edata[ i+108 ] = edata[i];
      if ( i >= 20 && pdata[i] ) phi2_has_roots = true;
   }

   edata[        19 ] = n;
   edata[   36 + 19 ] = n+1;
   edata[ 2*36 + 19 ] = n+2;
   edata[ 3*36 + 19 ] = n+3;
   
   do {
	   phi2_4way_hash( hash, edata );

      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hash7[ lane<<1 ] <= Htarg && !bench ) )
      {
         uint64_t _ALIGN(64) lane_hash[8]; 
         extr_lane_4x64( lane_hash, hash, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) )
         {
            be32enc( pdata + 19, n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      edata[        19 ] += 4;
      edata[   36 + 19 ] += 4;
      edata[ 2*36 + 19 ] += 4;
      edata[ 3*36 + 19 ] += 4;
      n +=4;
   } while ( (n < last_nonce) && !work_restart[thr_id].restart);
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

#endif

