#include "bc3hash-gate.h"
#include "bc3hash-kat.h"
#include "bc3hash-ec.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>

/* The C++ core: derived from the coin's src/crypto/bc3, with the standard
 * hash primitives replaced by this tree's, see VENDOR.md. */
extern int bc3_hash_init_cxx( void );
extern int bc3_hash_cxx( const void *input, uint32_t len, unsigned char *output );
/* bc3_hash_lanes() inputs back to back, hashed in lockstep; same digests. */
extern unsigned bc3_hash_lanes( void );
extern int bc3_hash_lanes_cxx( const void *input, uint32_t len, unsigned char *output );
#define BC3HASH_MAX_LANES 16

/* Runtime curve-table window, provided by bc3hash-core.cpp. */
extern int bc3_hash_set_window( unsigned window );
extern unsigned bc3_hash_get_window( void );
extern uint64_t bc3_hash_table_bytes( unsigned window );
extern const char *bc3_hash_exp_path( void );

/* Keccak-vs-SHA3 selector for the whole tree, defined in algo/keccak/keccak-gate.c
 * and reset per registration by algo-gate-api.c. BC3 needs FIPS 202 SHA3; a
 * Keccak pad gives well-formed wrong digests, which only the self-test catches. */
extern int hard_coded_eb;

/* Registration runs more than once per process -- the algo is switchable at
 * runtime and util.c's print_hash_tests() re-registers through exec_hash_function().
 * The tables are build-once inside the core, but the self-test is not, and it
 * costs a few full hashes. */
static bool bc3hash_tables_built = false;

bool bc3hash_hash( void *output, const void *input )
{
   return bc3_hash_cxx( input, 80, (unsigned char*)output ) == 0;
}

const char *bc3hash_self_test( void )
{
   unsigned char out[32], hdr[80];

   for ( size_t i = 0; i < BC3HASH_NUM_KATS; i++ )
   {
      if ( !bc3hash_hash( out, bc3hash_kats[i].header ) )
         return bc3hash_kats[i].name;
      if ( memcmp( out, bc3hash_kats[i].digest, 32 ) )
         return bc3hash_kats[i].name;
   }

   /* Non-vacuity: a hasher that ignored its input would pass the vectors above. */
   memcpy( hdr, bc3hash_kats[0].header, 80 );
   hdr[76] ^= 0x01;
   if ( !bc3hash_hash( out, hdr ) )
      return "non-vacuity (unexpected internal failure)";
   if ( !memcmp( out, bc3hash_kats[0].digest, 32 ) )
      return "non-vacuity (nonce flip gave the same digest)";

   /* The lockstep path scanhash mines with, a different header per lane (so a
    * lane-indexing bug cannot hide): each digest must equal the single path's. */
   const unsigned lanes = bc3_hash_lanes();
   if ( lanes < 1 || lanes > BC3HASH_MAX_LANES )
      return "lane count out of range";
   unsigned char lhdr[BC3HASH_MAX_LANES][80], lout[BC3HASH_MAX_LANES][32];
   for ( unsigned l = 0; l < lanes; l++ )
   {
      memcpy( lhdr[l], bc3hash_kats[ ( lanes - 1 - l ) % BC3HASH_NUM_KATS ].header, 80 );
      if ( l >= BC3HASH_NUM_KATS )
         lhdr[l][76] ^= (unsigned char)l;
   }
   if ( bc3_hash_lanes_cxx( lhdr, 80, (unsigned char*)lout ) != 0 )
      return "lanes (unexpected internal failure)";
   for ( unsigned l = 0; l < lanes; l++ )
   {
      if ( !bc3hash_hash( out, lhdr[l] ) || memcmp( out, lout[l], 32 ) )
         return "lanes (lockstep digest differs from single)";
   }

   return NULL;
}

int scanhash_bc3hash( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   static __thread bool failure_logged = false;
   uint32_t _ALIGN(64) edata[BC3HASH_MAX_LANES][20];
   uint32_t _ALIGN(64) hash[BC3HASH_MAX_LANES][8];
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const unsigned lanes = bc3_hash_lanes();   /* <= MAX, checked by the self-test */
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - lanes;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;
   volatile uint8_t *restart = &( work_restart[thr_id].restart );

   /* LE wire header, same convention as curvehash's gate. */
   v128_bswap32_80( edata[0], pdata );
   for ( unsigned l = 1; l < lanes; l++ )
      memcpy( edata[l], edata[0], 80 );

   do
   {
      /* Lane l hashes nonce n + l, and must be submitted as such. */
      for ( unsigned l = 0; l < lanes; l++ )
         be32enc( &edata[l][19], n + l );

      if ( unlikely( bc3_hash_lanes_cxx( edata, 80, (unsigned char*)hash ) != 0 ) )
      {
         /* Logged once per thread: a persistent failure would otherwise
          * print one line per batch. */
         if ( !failure_logged )
         {
            applog( LOG_ERR, "bc3hash: internal failure at nonces %08x..%08x, "
                             "skipping failed batches", n, n + lanes - 1 );
            failure_logged = true;
         }
      }
      else
         for ( unsigned l = 0; l < lanes; l++ )
            if ( unlikely( valid_hash( hash[l], ptarget ) && !bench ) )
            {
               pdata[19] = n + l;
               submit_solution( work, hash[l], mythr );
            }
      n += lanes;
   } while ( likely( n < last_nonce && !( *restart ) ) );

   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

bool register_bc3hash_algo( algo_gate_t *gate )
{
   hard_coded_eb = 6;

   gate->scanhash = (void*)&scanhash_bc3hash;
   gate->hash     = (void*)&bc3hash_hash;
   gate->optimizations = SSE2_OPT | NEON_OPT;
   opt_target_factor = 1.0;

   /* -a bc3hash:W, like -a scrypt:N. 10 is the coin's compact window, 20 a
    * practical build-time limit; digests are identical at every W. */
   if ( opt_param_n && ( opt_param_n < 10 || opt_param_n > 20 ) )
   {
      applog( LOG_ERR, "bc3hash: curve window %d out of range (10..20)", opt_param_n );
      return false;
   }

   if ( bc3hash_tables_built )
   {
      /* Same digests at any window, so mining continues on the old tables. */
      if ( opt_param_n && (unsigned)opt_param_n != bc3_hash_get_window() )
         applog( LOG_WARNING, "bc3hash: window %d ignored, tables were built "
                 "at window %u; restart to change it",
                 opt_param_n, bc3_hash_get_window() );
      return true;
   }

   /* Always set, so a refused window does not stick to the next attempt. */
   bc3_hash_set_window( (unsigned)opt_param_n );

   /* One shared read-only copy, so the per-thread workspace cap does not
    * apply. Checked here because registration is also the runtime switch
    * path: failing it makes the API refuse the switch instead of building
    * tables that do not fit. */
   const unsigned w = bc3_hash_get_window();
   const uint64_t bytes = bc3_hash_table_bytes( w );
   uint64_t avail = 0;
   if ( workspace_thread_fit( (size_t)bytes, 1, &avail ) < 1 )
   {
      snprintf( algo_register_error, sizeof algo_register_error,
                "bc3hash window %u needs %.1f GB of tables but only %.1f GB "
                "is free; use a smaller window, e.g. bc3hash:10", w,
                bytes / (1024.0*1024.0*1024.0), avail / (1024.0*1024.0*1024.0) );
      applog( LOG_ERR, "%s", algo_register_error );
      return false;
   }

   applog( LOG_INFO, "bc3hash: building curve tables, window %u, %.0f MB",
           w, bytes / (1024.0*1024.0) );
   struct timeval t0, t1;
   gettimeofday( &t0, NULL );

   int rc = bc3_hash_init_cxx();
   if ( rc != 0 )
   {
      applog( LOG_ERR, "bc3hash: table build failed, rc=%d (-1 alloc, "
                       "-2 bad curve constant / point op, -3 other, "
                       "-4 EC kernel differs from libsecp256k1)", rc );
      return false;
   }

   gettimeofday( &t1, NULL );
   applog( LOG_INFO, "bc3hash: curve tables built in %.1f s; %u lanes, exp256 %s",
           ( t1.tv_sec - t0.tv_sec ) + ( t1.tv_usec - t0.tv_usec ) / 1e6,
           bc3_hash_lanes(), bc3_hash_exp_path() );
   applog( LOG_INFO, "bc3hash: EC %s", bc3ec_config() );

   const char *failed = bc3hash_self_test();
   if ( failed )
   {
      applog( LOG_ERR, "bc3hash self-test failed: %s", failed );
      return false;
   }

   bc3hash_tables_built = true;
   return true;
}
