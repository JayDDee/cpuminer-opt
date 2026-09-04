/* The Monero/CryptoNote stratum dialect, for RandomX.
 *
 * This is a different protocol from the bitcoin stratum the rest of the tree
 * speaks -- not a variant of it. There is no subscribe, no authorize, no
 * extranonce, no coinbase and no merkle branch. Instead:
 *
 *   -> {"id":1,"jsonrpc":"2.0","method":"login",
 *       "params":{"login":USER,"pass":PASS,"agent":...,"algo":["rx/0"]}}
 *   <- {"id":1,"error":null,"result":{"id":SESSION,"job":{...},"status":"OK"}}
 *   <- {"method":"job","params":{...}}                        (pushed)
 *   -> {"id":N,"jsonrpc":"2.0","method":"submit",
 *       "params":{"id":SESSION,"job_id":...,"nonce":HEX8,"result":HEX64}}
 *   <- {"id":N,"error":null,"result":{"status":"OK"}}
 *
 * A job object is:
 *   algo            "rx/0"
 *   blob            76-byte hashing blob, hex; nonce is 4 LE bytes at offset 39
 *   job_id          opaque string, echoed back on submit
 *   target          4-byte (or 8-byte) LE hex, compact
 *   height          block height
 *   seed_hash       32-byte hex: THE RANDOMX DATASET KEY
 *   next_seed_hash  the next epoch's key, or "" when not near a boundary
 *
 * The shapes above were taken from a live rx/0 pool rather than a spec.
 *
 * Note some pools also answer mining.subscribe with a bitcoin-stratum-looking
 * reply while still pushing Monero "job" payloads, so a subscribe response is
 * not evidence that the bitcoin dialect is the right one.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "randomx-gate.h"

/* ------------------------------------------------------------------ target */

/* Monero's compact target. A 4-byte target is the top 32 bits of a 256-bit
 * target; the miner compares the last 8 bytes of the hash, little endian,
 * against the 64-bit value produced here. */
static uint64_t rx_target_from_hex( const char *hex )
{
   unsigned char b[8];
   size_t len = hex ? strlen( hex ) : 0;

   if ( len == 8 )
   {
      uint64_t t32;
      if ( !hex2bin( b, hex, 4 ) ) return 0;
      t32 =  (uint64_t)b[0]        | ( (uint64_t)b[1] <<  8 )
          | ( (uint64_t)b[2] << 16 ) | ( (uint64_t)b[3] << 24 );
      if ( !t32 ) return 0;
      return 0xFFFFFFFFFFFFFFFFULL / ( 0xFFFFFFFFULL / t32 );
   }
   if ( len == 16 )
   {
      int i;
      uint64_t t64 = 0;
      if ( !hex2bin( b, hex, 8 ) ) return 0;
      for ( i = 7; i >= 0; i-- ) t64 = ( t64 << 8 ) | b[i];
      return t64;
   }
   return 0;
}

/* Stratum difficulty implied by a 64-bit target. */
static double rx_diff_from_target( uint64_t target )
{
   return target ? (double)( 0xFFFFFFFFFFFFFFFFULL / target ) : 0.;
}

/* -------------------------------------------------------------- job parse */

/* Fills sctx->job from a job object. Caller holds sctx->work_lock. */
static bool rx_parse_job( struct stratum_ctx *sctx, json_t *job )
{
   const char *blob, *job_id, *target, *seed, *next_seed, *algo;
   size_t blob_len;

   if ( !json_is_object( job ) )
      return false;

   blob   = json_string_value( json_object_get( job, "blob"      ) );
   job_id = json_string_value( json_object_get( job, "job_id"    ) );
   target = json_string_value( json_object_get( job, "target"    ) );
   seed   = json_string_value( json_object_get( job, "seed_hash" ) );
   algo   = json_string_value( json_object_get( job, "algo"      ) );

   /* seed_hash is required only by the algos that key a dataset on it; see
    * rx_algo_needs_seed(). k12 shares this dialect and its pool omits it. */
   if ( !blob || !job_id || !target
        || ( !seed && rx_algo_needs_seed( opt_algo ) ) )
   {
      applog( LOG_ERR, "%s job missing a required field (blob/job_id/target%s)",
              rx_variant_pool_algo(),
              rx_algo_needs_seed( opt_algo ) ? "/seed_hash" : "" );
      return false;
   }

   /* Refuse a variant we are not selected for rather than mining it wrong.
    * Variants differ in the argon salt or in VM/JIT constants, so a mismatch
    * yields 100% rejects, never a silent near-miss.
    *
    * A job with no "algo" field is accepted as the selected variant, which is
    * what rx/0 pools that predate the field expect, and pools are seen in the
    * wild sending it as null. Making the field mandatory, or deriving the
    * variant from the height, is owed at the Monero v2 fork: until then a v2
    * job without the field would be hashed as v1 and rejected wholesale. */
   if ( algo && strcmp( algo, rx_variant_pool_algo() ) )
   {
      applog( LOG_ERR, "RandomX: pool wants algo '%s', this run mines '%s'",
              algo, rx_variant_pool_algo() );
      return false;
   }

   blob_len = strlen( blob ) / 2;
   if ( strlen( blob ) & 1 || blob_len < RX_NONCE_OFFSET + 4
        || blob_len > RX_BLOB_MAX )
   {
      applog( LOG_ERR, "RandomX job blob is %zu bytes, expected %d..%d",
              blob_len, RX_NONCE_OFFSET + 4, RX_BLOB_MAX );
      return false;
   }

   if ( !hex2bin( sctx->job.rx_blob, blob, blob_len ) )
   {
      applog( LOG_ERR, "RandomX job blob is not valid hex" );
      return false;
   }
   sctx->job.rx_blob_len = blob_len;

   if ( !rx_algo_needs_seed( opt_algo ) )
      memset( sctx->job.rx_seed_hash, 0, 32 );
   else if ( strlen( seed ) != 64
             || !hex2bin( sctx->job.rx_seed_hash, seed, 32 ) )
   {
      applog( LOG_ERR, "RandomX job seed_hash is not 32 bytes of hex" );
      return false;
   }

   sctx->job.rx_target = rx_target_from_hex( target );
   if ( !sctx->job.rx_target )
   {
      applog( LOG_ERR, "RandomX job target '%s' is not a 4- or 8-byte hex "
                       "value", target );
      return false;
   }

   next_seed = json_string_value( json_object_get( job, "next_seed_hash" ) );
   sctx->job.rx_has_next_seed = false;
   if ( next_seed && strlen( next_seed ) == 64
        && hex2bin( sctx->job.rx_next_seed_hash, next_seed, 32 ) )
      sctx->job.rx_has_next_seed = true;

   free( sctx->job.job_id );
   sctx->job.job_id = strdup( job_id );
   sctx->job.diff   = rx_diff_from_target( sctx->job.rx_target );
   sctx->job.rx_job = true;
   sctx->job.clean  = true;

   sctx->block_height =
      (int) json_integer_value( json_object_get( job, "height" ) );

   return true;
}

/* --------------------------------------------------------------- login */

bool rx_stratum_login( struct stratum_ctx *sctx, const char *user,
                       const char *pass )
{
   char *req = NULL, *sret = NULL;
   json_t *val = NULL, *res, *err, *job;
   json_error_t jerr;
   const char *sid;
   bool ret = false;
   size_t len;

   len = ( user ? strlen( user ) : 0 ) + ( pass ? strlen( pass ) : 0 ) + 256;
   req = (char*) malloc( len );
   if ( !req )
      return false;

   /* "algo" is an array so a miner can advertise a capability set and let the
    * pool choose. Advertise only the one variant this run can actually hash --
    * offering more would invite a job we would then have to refuse. */
   snprintf( req, len,
      "{\"id\":1,\"jsonrpc\":\"2.0\",\"method\":\"login\",\"params\":{"
      "\"login\":\"%s\",\"pass\":\"%s\",\"agent\":\"" USER_AGENT "\","
      "\"algo\":[\"%s\"]}}",
      user ? user : "", pass ? pass : "", rx_variant_pool_algo() );

   if ( !stratum_send_line( sctx, req ) )
   {
      applog( LOG_ERR, "RandomX stratum login send failed" );
      goto out;
   }

   /* The login reply carries the first job, so there is nothing else to wait
    * for; but the pool may interleave a pushed job, so loop until we see a
    * reply with a result object. */
   for ( int tries = 0; tries < 4; tries++ )
   {
      if ( !stratum_socket_full( sctx, 30 ) )
      {
         applog( LOG_ERR, "RandomX stratum login timed out" );
         goto out;
      }
      sret = stratum_recv_line( sctx );
      if ( !sret )
         goto out;

      val = JSON_LOADS( sret, &jerr );
      free( sret ); sret = NULL;
      if ( !val )
      {
         applog( LOG_ERR, "RandomX login: JSON decode failed: %s", jerr.text );
         goto out;
      }

      res = json_object_get( val, "result" );
      if ( json_is_object( res ) )
         break;

      /* Not the login reply -- let the normal handler have it and try again. */
      json_decref( val ); val = NULL;
   }

   if ( !val )
      goto out;

   err = json_object_get( val, "error" );
   if ( err && !json_is_null( err ) )
   {
      const char *msg = json_string_value( json_object_get( err, "message" ) );
      applog( LOG_ERR, "RandomX stratum login rejected: %s",
              msg ? msg : "(no message)" );
      goto out;
   }

   res = json_object_get( val, "result" );
   sid = json_string_value( json_object_get( res, "id" ) );
   if ( !sid )
   {
      applog( LOG_ERR, "RandomX stratum login gave no session id" );
      goto out;
   }

   pthread_mutex_lock( &sctx->work_lock );
   free( sctx->rx_rpc_id );
   sctx->rx_rpc_id = strdup( sid );
   job = json_object_get( res, "job" );
   ret = rx_parse_job( sctx, job );
   pthread_mutex_unlock( &sctx->work_lock );

   if ( ret )
   {
      sctx->new_job = true;
      applog( LOG_BLUE, "RandomX stratum logged in, height %d, diff %.0f",
              sctx->block_height, sctx->job.diff );
   }

out:
   free( req );
   free( sret );
   if ( val ) json_decref( val );
   return ret;
}

/* ------------------------------------------------------- pushed job */

bool rx_stratum_job( struct stratum_ctx *sctx, json_t *params )
{
   bool ok;

   pthread_mutex_lock( &sctx->work_lock );
   ok = rx_parse_job( sctx, params );
   pthread_mutex_unlock( &sctx->work_lock );

   if ( ok )
      sctx->new_job = true;

   return ok;
}

/* ----------------------------------------------------------- seed change */

/* Called from stratum_thread with no locks held and after restart_threads().
 * See the lock-order note in randomx-vm.c: doing this inside stratum_gen_work,
 * which holds g_work_lock, would deadlock against a miner holding the dataset
 * read lock and waiting for g_work_lock. */
bool rx_stratum_available( void ) { return true; }

bool rx_stratum_prepare_seed( struct stratum_ctx *sctx )
{
   unsigned char seed[32];

   /* Nothing to key: no dataset, so no rebuild and no blocking. */
   if ( !rx_algo_needs_seed( opt_algo ) )
      return true;

   /* Test hook, off unless the environment asks for it. */
   {
      static time_t t0 = 0;
      static bool fired = false;
      const char *ev = getenv( "CPUMINER_RX_TEST_RESEED" );
      if ( ev && !fired )
      {
         long after = atol( ev );
         time_t now = time( NULL );
         if ( !t0 ) t0 = now;
         if ( after > 0 && now - t0 >= after )
         {
            fired = true;
            rx_force_reseed_for_test();
         }
      }
   }

   pthread_mutex_lock( &sctx->work_lock );
   if ( !sctx->job.rx_job )
   {
      pthread_mutex_unlock( &sctx->work_lock );
      return false;
   }
   memcpy( seed, sctx->job.rx_seed_hash, 32 );
   pthread_mutex_unlock( &sctx->work_lock );

   return rx_seed_update( seed );
}

/* -------------------------------------------------------------- gen work */

void rx_stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   /* Caller holds sctx->work_lock and g_work_lock (see stratum_gen_work). */
   g_work->rx_work     = true;
   g_work->rx_blob_len = sctx->job.rx_blob_len;
   g_work->rx_target   = sctx->job.rx_target;
   memcpy( g_work->rx_seed_hash, sctx->job.rx_seed_hash, 32 );

   memset( g_work->data, 0, sizeof g_work->data );
   memcpy( g_work->data, sctx->job.rx_blob, sctx->job.rx_blob_len );

   g_work->xnonce2_len = 0;

   /* The pool's 64-bit target is exact, so unlike the bitcoin path there is no
    * diff -> 256-bit-target round trip to lose precision in. target[] is filled
    * only for the shared reporting code; scanhash compares rx_target. */
   memset( g_work->target, 0xff, sizeof g_work->target );
   g_work->target[7] = (uint32_t)( sctx->job.rx_target >> 32 );
   g_work->target[6] = (uint32_t)( sctx->job.rx_target       );

   /* Internal scale, as the shared reporting code expects: pool difficulty over
    * opt_target_factor (see register_randomx_algo). work->sharediff stays in
    * pool scale, which is what scanhash_randomx computes. */
   g_work->targetdiff = opt_target_factor > 0.
                      ? sctx->job.diff / opt_target_factor : sctx->job.diff;
   /* There is no nbits in a Monero job, so net_diff cannot be derived. Left at
    * 0 rather than printing a meaningless number. */
   net_diff = 0.;
}

/* ---------------------------------------------------------------- submit */

void rx_build_stratum_request( char *req, struct work *work,
                               struct stratum_ctx *sctx )
{
   static int seq = 4;   /* the shared handler ignores ids below 4 */
   /* 8 bytes = 16 hex chars + NUL. Sized for the widest nonce field, not the
    * common one -- a 16-byte buffer here would overflow by one on k12. */
   char noncestr[17], hashstr[65];
   const unsigned char *blob = (const unsigned char*) work->data;

   /* The nonce is submitted as the raw bytes at offset 39, in memory order
    * (xmrig hexes &nonce directly, so it is little endian on the wire). The
    * field is 4 bytes for RandomX and 8 for k12 -- see
    * rx_algo_nonce_bytes(); the pool validates the length. */
   bin2hex( noncestr, blob + RX_NONCE_OFFSET,
            rx_algo_nonce_bytes( opt_algo ) );
   bin2hex( hashstr,  work->rx_result, 32 );

   snprintf( req, JSON_BUF_LEN,
      "{\"id\":%d,\"jsonrpc\":\"2.0\",\"method\":\"submit\",\"params\":{"
      "\"id\":\"%s\",\"job_id\":\"%s\",\"nonce\":\"%s\",\"result\":\"%s\"}}",
      seq++, sctx->rx_rpc_id ? sctx->rx_rpc_id : "", work->job_id,
      noncestr, hashstr );
}

/* -------------------------------------------------------------- response */

/* Parses a submit reply; false if this message was not one, leaving the outputs
 * untouched. Pure parser because share_result() is static in cpu-miner.c. The
 * reason string points into `val`, so the caller owns and decrefs it. */
bool rx_stratum_parse_response( json_t *val, bool *accepted,
                                const char **reason )
{
   json_t *res, *err, *id;
   const char *status, *msg;

   id = json_object_get( val, "id" );
   if ( !id || json_is_null( id ) )
      return false;

   /* The id is not always the integer we sent: some pools echo their own
    * session id as a string, and json_integer_value() answers 0 for a string,
    * so a bare "< 4" test classifies every submit reply as not ours and the
    * reject reason never reaches the log. Integer ids keep the numeric gate
    * (below 4 is login/keepalive); a string id is identified by shape, the
    * login reply being the only one carrying result.job. */
   if ( json_is_integer( id ) )
   {
      if ( json_integer_value( id ) < 4 )
         return false;
   }
   else if ( json_is_string( id ) )
   {
      json_t *r = json_object_get( val, "result" );
      if ( r && json_is_object( r ) && json_object_get( r, "job" ) )
         return false;
   }
   else
      return false;

   res = json_object_get( val, "result" );
   err = json_object_get( val, "error" );

   /* Monero says result:{"status":"OK"} rather than result:true, and
    * error:{"code":..,"message":..} rather than error:[code,message], so
    * neither half of the shared handler can read it. */
   status = json_is_object( res )
      ? json_string_value( json_object_get( res, "status" ) ) : NULL;
   msg = ( err && json_is_object( err ) )
      ? json_string_value( json_object_get( err, "message" ) ) : NULL;

   *accepted = ( status && !strcasecmp( status, "OK" ) && !msg );
   *reason   = msg;
   return true;
}
