/*
 * Collect-then-format for the miner API. See api_model.h.
 *
 * The format_*_binary() bodies are the legacy sprintf statements moved verbatim
 * out of api.c. Do not "clean them up": the field order, the widths and the
 * trailing '|' are a compatibility surface that api/tests/golden.py gates.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <time.h>

#include "miner.h"
#include "api_model.h"
#include "api_control.h"
#include "sysinfos.c"

#ifndef APIVERSION
#define APIVERSION "1.0"
#endif

/* Only what miner.h does NOT declare belongs here: redeclaring the rest is how
 * a type mismatch gets in (thr_hashrates is a double *, not a double []). */
extern uint32_t submitted_share_count;
extern uint32_t stale_share_count;
extern struct stratum_ctx stratum;      /* the single pool's live state */
extern char *rpc_url;
/* highest_share is file-local in cpu-miner.c; an accessor rather than a global
 * with a name that generic. */
extern double api_get_best_share( void );
extern bool   api_get_thread_shares( int thr_id, uint32_t *accepted,
                                     uint32_t *rejected );
extern uint32_t api_get_pool_disconnects( void );
extern bool     api_get_pool_session_s( uint32_t *out );

static time_t api_start_time = 0;

/* Process-lifetime share totals, carried across the counter reset a control
 * algo switch performs. accepted_per_min and the Prometheus miner_shares_total
 * are contract-bound to process lifetime, and a counter that decreases corrupts
 * rate(). API thread only, so no lock; idempotent. */
static uint64_t mono_accepted, mono_rejected, mono_stale, mono_solved,
                mono_submitted;

static void mono_carry( uint64_t *base, uint32_t *last, uint32_t now )
{
   if ( now < *last )      /* counter went backwards: it was reset */
      *base += *last;
   *last = now;
}

static void api_mono_update( void )
{
   static uint32_t l_acc, l_rej, l_stale, l_solved, l_sub;
   static uint64_t b_acc, b_rej, b_stale, b_solved, b_sub;

   mono_carry( &b_acc,    &l_acc,    accepted_share_count  );
   mono_carry( &b_rej,    &l_rej,    rejected_share_count  );
   mono_carry( &b_stale,  &l_stale,  stale_share_count     );
   mono_carry( &b_solved, &l_solved, solved_block_count    );
   mono_carry( &b_sub,    &l_sub,    submitted_share_count );

   mono_accepted  = b_acc    + accepted_share_count;
   mono_rejected  = b_rej    + rejected_share_count;
   mono_stale     = b_stale  + stale_share_count;
   mono_solved    = b_solved + solved_block_count;
   mono_submitted = b_sub    + submitted_share_count;
}

void api_model_set_start_time( time_t t )
{
   api_start_time = t;
}

void api_collect_summary( struct api_summary_snapshot *s )
{
   time_t ts = time( NULL );
   double uptime = difftime( ts, api_start_time );
   double diff;

   memset( s, 0, sizeof(*s) );

   s->name = PACKAGE_NAME;
   s->ver  = PACKAGE_VERSION;
   s->api  = APIVERSION;

   get_currentalgo( s->algo, sizeof(s->algo) );
   s->cpus = opt_n_threads;

   /* Copied, not aliased: a pool reset can free short_url while a renderer is
    * still walking it. */
   if ( short_url )
      snprintf( s->url, sizeof(s->url), "%s", short_url );

   /* Parked reports 0, not the last value (docs/api-rest.md section 6.1):
    * global_hashrate is only recomputed when a thread finishes a scan, so it
    * freezes while parked. Gated in the collector so /summary and the
    * Prometheus gauges inherit it. */
   s->hashrate  = api_ctl_mining_parked() ? 0. : (double)global_hashrate;
   s->accepted  = accepted_share_count;
   s->rejected  = rejected_share_count;
   s->solved    = solved_block_count;
   s->submitted = submitted_share_count;
   s->stale     = stale_share_count;

   /* Process-lifetime per the contract, so it uses the carried total rather
    * than the live counter, which a control algo switch resets. */
   api_mono_update();
   s->acc_per_min = ( 60.0 * (double)mono_accepted )
                  / ( uptime ? uptime : 1.0 );

   diff = net_diff > 0. ? net_diff : stratum_diff;
   s->diff      = diff;
   s->diff_pool = stratum_diff;
   s->diff_net  = net_diff;
   /* Legacy rounding: no decimals when the difficulty is integral. Bounded
    * write, so no diff value can turn a status read into a crash. */
   if ( diff == trunc( diff ) )
      snprintf( s->diff_str, sizeof(s->diff_str), "%.0f", diff );
   else
      snprintf( s->diff_str, sizeof(s->diff_str), "%.6f", diff );

   /* Unguarded, like the other collectors here: sysinfos.c is #included above
    * and already returns 0 where a platform has no sensor. Do not reinstate a
    * #ifdef -- the previous one was defined in another TU, so this block was
    * dead and every reader reported TEMP=0. */
   s->has_monitoring = true;
   s->cpu_temp  = cpu_temp( 0 );
   s->cpu_fan   = cpu_fanpercent();
   s->cpu_clock = cpu_clock( 0 );

   s->uptime = uptime;
   s->ts     = (uint32_t)ts;

   /* JSON-only, no binary equivalent. */
   s->net_hashrate = net_hashrate;
   s->best_share   = api_get_best_share();
}

int api_format_summary_binary( char *out, size_t len,
                               const struct api_summary_snapshot *s )
{
   return snprintf( out, len,
          "NAME=%s;VER=%s;API=%s;"
          "ALGO=%s;CPUS=%d;URL=%s;"
          "HS=%.2f;KHS=%.2f;ACC=%d;REJ=%d;SOL=%d;"
          "ACCMN=%.3f;DIFF=%s;TEMP=%.1f;FAN=%d;FREQ=%d;"
          "UPTIME=%.0f;TS=%u|",
           s->name, s->ver, s->api,
           s->algo, s->cpus, s->url,
           s->hashrate, s->hashrate / 1000.0,
           s->accepted, s->rejected, s->solved,
           s->acc_per_min, s->diff_str,
           s->cpu_temp, s->cpu_fan, s->cpu_clock,
           s->uptime, s->ts );
}

bool api_collect_thread( int thr_id, struct api_thread_snapshot *t )
{
   if ( thr_id < 0 || thr_id >= opt_n_threads )
      return false;
   memset( t, 0, sizeof(*t) );
   t->id          = thr_id;
   /* cpu-miner.c already zeroes thr_hashrates[] as each thread parks; gated
    * anyway to cover the window before a thread reaches its park point. */
   t->hashrate    = api_ctl_mining_parked() ? 0. : thr_hashrates[ thr_id ];
   t->have_shares = api_get_thread_shares( thr_id, &t->accepted, &t->rejected );
   return true;
}

int api_format_thread_binary( char *out, size_t len,
                              const struct api_thread_snapshot *t )
{
   /* The unit prefix is part of the KEY here (H/s, kH/s, MH/s ...), not just
    * the value: scale_hash_for_display() rewrites both. Anything comparing
    * this output must normalise the prefix first. */
   char units[4] = { 0 };
   double hashrate = t->hashrate;

   scale_hash_for_display( &hashrate, units );
   return snprintf( out, len, "CPU=%d;%sH/s=%.2f|", t->id, units, hashrate );
}

/* ------------------------------------------------------------ pool / system */

void api_collect_pool( struct api_pool_snapshot *p )
{
   memset( p, 0, sizeof(*p) );

   /* There are no named pools here, so the short URL is the name. */
   if ( short_url ) snprintf( p->name, sizeof(p->name), "%s", short_url );
   if ( rpc_url )   snprintf( p->url,  sizeof(p->url),  "%s", rpc_url );
   if ( rpc_user )  snprintf( p->user, sizeof(p->user), "%s", rpc_user );
   /* rpc_pass is never read: no endpoint may return it, and a field that is
    * not collected cannot leak. */
   get_currentalgo( p->algo, sizeof(p->algo) );

   p->stratum      = have_stratum;
   p->have_session = api_get_pool_session_s( &p->session_s );

   /* Not stratum.curl: it stays non-NULL across a drop, because the disconnect
    * paths defer stratum_disconnect() to the reset handler. The session flag is
    * cleared where the disconnect is counted. getwork/GBT is always up. */
   p->connected = have_stratum ? p->have_session : true;

   /* Global counters, not per-pool: with one pool they are the same numbers.
    * Do not add a per-pool accumulator, it would diverge the moment failover
    * exists and this miner is single-pool by design. */
   p->accepted = accepted_share_count;
   p->rejected = rejected_share_count;
   p->stale    = stale_share_count;
   p->solved   = solved_block_count;

   p->diff        = stratum_diff;
   p->best_share  = api_get_best_share();
   p->disconnects = api_get_pool_disconnects();

   if ( have_stratum )
   {
      pthread_mutex_lock( &stratum.work_lock );
      if ( stratum.job.job_id )
         snprintf( p->job_id, sizeof(p->job_id), "%s", stratum.job.job_id );
      p->height       = stratum.block_height;
      p->xnonce2_size = (int)stratum.xnonce2_size;
      pthread_mutex_unlock( &stratum.work_lock );
   }
}

void api_collect_system( struct api_system_snapshot *s )
{
   memset( s, 0, sizeof(*s) );
#if defined(WIN32)
   snprintf( s->os, sizeof(s->os), "windows" );
#elif defined(__APPLE__)
   snprintf( s->os, sizeof(s->os), "darwin" );
#elif defined(__FreeBSD__)
   snprintf( s->os, sizeof(s->os), "freebsd" );
#else
   snprintf( s->os, sizeof(s->os), "linux" );
#endif
   s->cpus          = num_cpus;
   s->cpu_temp      = cpu_temp( 0 );
   s->cpu_clock_khz = cpu_clock( 0 );
   /* cpu_fanpercent() is a stub returning 0 on every platform in this tree, and
    * 0 would mean a measured zero. Report "no sensor" instead. */
   s->cpu_fan_pct   = -1;
}

/* Instruction sets this build can use, collected space-separated and split
 * into docs/openapi.yaml's Device.cpu.features array at JSON build time. */
static void collect_features( char *out, size_t len )
{
   const struct { bool have; const char *name; } f[] = {
      { has_sse2(),      "SSE2"      }, { has_ssse3(),     "SSSE3"     },
      { has_sse42(),     "SSE4.2"    }, { has_avx(),       "AVX"       },
      { has_avx2(),      "AVX2"      }, { has_avx512(),    "AVX512"    },
      { has_vaes(),      "VAES"      }, { has_aes(),       "AES"       },
      { has_sha256(),    "SHA256"    }, { has_sha512(),    "SHA512"    },
      { has_neon(),      "NEON"      }, { has_sve(),       "SVE"       },
   };
   size_t used = 0;
   *out = '\0';
   for ( size_t i = 0; i < sizeof(f)/sizeof(f[0]); i++ )
   {
      if ( !f[i].have ) continue;
      int w = snprintf( out + used, len - used, used ? " %s" : "%s", f[i].name );
      if ( w < 0 || (size_t)w >= len - used ) break;
      used += (size_t)w;
   }
}

void api_collect_device( struct api_device_snapshot *d )
{
   memset( d, 0, sizeof(*d) );
   cpu_brand_string( d->name );
   d->threads       = num_cpus;
   d->cpu_temp      = cpu_temp( 0 );
   d->cpu_clock_khz = cpu_clock( 0 );
   d->cpu_fan_pct   = -1;
   /* Same rule as the summary collector: parked reports 0. */
   d->hashrate      = api_ctl_mining_parked() ? 0. : (double)global_hashrate;
   collect_features( d->features, sizeof(d->features) );
}

/* ----------------------------------------------------------------- history
 *
 * A per-thread ring of the last API_HISTORY_PER_THREAD scans. Written from the
 * mining loop once per scanhash return (order 1/s per thread), read by the API
 * thread, so it takes its own lock rather than borrowing stats_lock from the
 * share path. */

static pthread_mutex_t hist_lock = PTHREAD_MUTEX_INITIALIZER;
static struct api_history_record *hist_ring = NULL;  /* [threads][PER_THREAD] */
static int      *hist_count = NULL;                  /* records ever written  */
static int       hist_threads = 0;
static uint32_t  hist_next_id = 1;

/* Caller holds hist_lock. */
static bool history_alloc( void )
{
   if ( hist_ring ) return true;
   if ( opt_n_threads <= 0 ) return false;

   hist_ring = (struct api_history_record *)
      calloc( (size_t)opt_n_threads * API_HISTORY_PER_THREAD,
              sizeof(*hist_ring) );
   hist_count = (int *) calloc( (size_t)opt_n_threads, sizeof(*hist_count) );
   if ( !hist_ring || !hist_count )
   {
      /* History is a reporting nicety; mining must not care that it failed. */
      free( hist_ring );  hist_ring = NULL;
      free( hist_count ); hist_count = NULL;
      return false;
   }
   hist_threads = opt_n_threads;
   return true;
}

/* Samples either side of an algo switch are not comparable, so /history starts
 * empty rather than serving a series with a discontinuity in it. The ring is
 * kept: opt_n_threads has not changed. */
void api_history_reset( void )
{
   pthread_mutex_lock( &hist_lock );
   if ( hist_count )
      for ( int i = 0; i < hist_threads; i++ )
         hist_count[i] = 0;
   hist_next_id = 1;
   pthread_mutex_unlock( &hist_lock );
}

void api_history_add( int thr_id, uint32_t height, double hashrate,
                      double difficulty, uint64_t hashcount, bool found )
{
   struct api_history_record *r;

   pthread_mutex_lock( &hist_lock );
   if ( !history_alloc() || thr_id < 0 || thr_id >= hist_threads )
   {
      pthread_mutex_unlock( &hist_lock );
      return;
   }
   r = &hist_ring[ (size_t)thr_id * API_HISTORY_PER_THREAD
                   + ( hist_count[thr_id] % API_HISTORY_PER_THREAD ) ];
   r->id         = hist_next_id++;
   r->thread_id  = thr_id;
   r->height     = height;
   r->hashrate   = hashrate;
   r->difficulty = difficulty;
   r->hashcount  = hashcount;
   r->found      = found;
   r->ts         = (uint32_t) time( NULL );
   hist_count[thr_id]++;
   pthread_mutex_unlock( &hist_lock );
}

/* Newest first, so a client asking for 10 gets the 10 most recent.
 *
 * Across threads that means a k-way merge on the record id, not thread 0's
 * history followed by thread 1's: each thread's ring is independently
 * newest-first, and concatenating them is not sorted. */
int api_history_get( int thr_id, struct api_history_record *out, int max )
{
   int cursor[ 64 ];             /* how many records already taken per thread */
   int n = 0;

   if ( max <= 0 ) return 0;
   pthread_mutex_lock( &hist_lock );
   if ( !hist_ring || hist_threads > (int)( sizeof(cursor)/sizeof(cursor[0]) ) )
   {
      pthread_mutex_unlock( &hist_lock );
      return 0;
   }

   for ( int t = 0; t < hist_threads; t++ ) cursor[t] = 0;

   while ( n < max )
   {
      int best = -1;
      uint32_t best_id = 0;
      const struct api_history_record *best_rec = NULL;

      for ( int t = 0; t < hist_threads; t++ )
      {
         if ( thr_id >= 0 && t != thr_id ) continue;
         int have = hist_count[t] < API_HISTORY_PER_THREAD
                  ? hist_count[t] : API_HISTORY_PER_THREAD;
         if ( cursor[t] >= have ) continue;
         int slot = ( hist_count[t] - cursor[t] - 1 ) % API_HISTORY_PER_THREAD;
         const struct api_history_record *r =
            &hist_ring[ (size_t)t * API_HISTORY_PER_THREAD + slot ];
         if ( !best_rec || r->id > best_id )
         {
            best = t;
            best_id = r->id;
            best_rec = r;
         }
      }
      if ( !best_rec ) break;
      out[ n++ ] = *best_rec;
      cursor[ best ]++;
   }
   pthread_mutex_unlock( &hist_lock );
   return n;
}

/* ------------------------------------------------------------ JSON renderers
 *
 * Nothing below reads a global: every value comes from a snapshot, so the two
 * renderers cannot disagree. */

static json_t *jnum_or_null( double v, bool available )
{
   return available ? json_real( v ) : json_null();
}

static json_t *jint_or_null( json_int_t v, bool available )
{
   return available ? json_integer( v ) : json_null();
}

static json_t *jstr_or_null( const char *s )
{
   return ( s && *s ) ? json_string( s ) : json_null();
}

/* Space-separated feature list -> JSON array of strings. The contract types
 * Device.cpu.features as an array so a client never has to guess a separator;
 * null, not [], when nothing was detected. */
static json_t *jfeatures_or_null( const char *s )
{
   if ( !s || !*s ) return json_null();

   json_t *arr = json_array();
   if ( !arr ) return json_null();

   /* json_stringn is jansson 2.7+; compat/jansson is 2.6, so the fallback
    * build needs a bounded copy rather than a counted constructor. */
   for ( const char *p = s; *p; )
   {
      const char *end = strchr( p, ' ' );
      size_t n = end ? (size_t)( end - p ) : strlen( p );
      char name[ 32 ];
      if ( n && n < sizeof(name) )
      {
         memcpy( name, p, n );
         name[n] = 0;
         json_array_append_new( arr, json_string( name ) );
      }
      p = end ? end + 1 : p + n;
   }
   return arr;
}

json_t *api_build_miner_json( void )
{
   json_t *m = json_object();
   if ( !m ) return NULL;
   json_object_set_new( m, "name",        json_string( PACKAGE_NAME ) );
   json_object_set_new( m, "version",     json_string( PACKAGE_VERSION ) );
   /* The CONTRACT revision, not the miner version and not APIVERSION (which is
    * the binary protocol's). */
   json_object_set_new( m, "api_version", json_string( "1.0" ) );
   json_object_set_new( m, "kind",        json_string( "cpu" ) );
   return m;
}

json_t *api_build_summary_json( const struct api_summary_snapshot *s )
{
   json_t *o = json_object(), *shares = json_object();
   json_t *diff = json_object(), *net = json_object(), *pools = json_object();

   if ( !o || !shares || !diff || !net || !pools )
   {
      if ( o )      json_decref( o );
      if ( shares ) json_decref( shares );
      if ( diff )   json_decref( diff );
      if ( net )    json_decref( net );
      if ( pools )  json_decref( pools );
      return NULL;
   }

   json_object_set_new( o, "algo",        json_string( s->algo ) );
   json_object_set_new( o, "uptime_s",    json_integer( (json_int_t)s->uptime ) );
   json_object_set_new( o, "timestamp",   json_integer( s->ts ) );
   json_object_set_new( o, "hashrate_hs", json_real( s->hashrate ) );
   /* No rolling average is tracked; null, not the instantaneous rate. */
   json_object_set_new( o, "hashrate_avg_hs", json_null() );
   /* One CPU device, matching the length of the /devices array; threads is
    * the mining thread count, as CPUS= carries in the binary API. */
   json_object_set_new( o, "devices",     json_integer( 1 ) );
   json_object_set_new( o, "threads",     json_integer( s->cpus ) );

   json_object_set_new( shares, "accepted", json_integer( s->accepted ) );
   json_object_set_new( shares, "rejected", json_integer( s->rejected ) );
   /* Populated, not null: docs/api-rest.md section 10 says a cpu miner does
    * not track stale shares, which is wrong about this one
    * (stale_share_count, cpu-miner.c). */
   json_object_set_new( shares, "stale",    json_integer( s->stale ) );
   json_object_set_new( shares, "solved",   json_integer( s->solved ) );
   json_object_set_new( shares, "accepted_per_min", json_real( s->acc_per_min ) );
   json_object_set_new( o, "shares", shares );

   json_object_set_new( diff, "pool",
                        jnum_or_null( s->diff_pool, s->diff_pool > 0. ) );
   json_object_set_new( diff, "network",
                        jnum_or_null( s->diff_net, s->diff_net > 0. ) );
   json_object_set_new( diff, "best_share", jnum_or_null( s->best_share,
                                                          s->best_share > 0. ) );
   json_object_set_new( o, "difficulty", diff );

   json_object_set_new( net, "hashrate_hs", jnum_or_null( s->net_hashrate,
                                                          s->net_hashrate > 0. ) );
   json_object_set_new( o, "network", net );

   json_object_set_new( pools, "count",  json_integer( 1 ) );
   json_object_set_new( pools, "active", json_integer( 0 ) );
   /* Time spent waiting for work is not tracked here. */
   json_object_set_new( pools, "wait_time_s", json_null() );
   json_object_set_new( o, "pools", pools );

   return o;
}

json_t *api_build_thread_json( const struct api_thread_snapshot *t )
{
   json_t *o = json_object();
   if ( !o ) return NULL;
   json_object_set_new( o, "id",          json_integer( t->id ) );
   /* Every thread runs on the one CPU device. */
   json_object_set_new( o, "device_id",   json_integer( 0 ) );
   json_object_set_new( o, "hashrate_hs", json_real( t->hashrate ) );
   /* Attributed via the share_stats ring, so these are real numbers, not the
    * null docs/api-rest.md section 10 still predicts for a cpu miner. A stale
    * share counts as neither, as in the global counters. */
   json_object_set_new( o, "accepted", jint_or_null( t->accepted,
                                                     t->have_shares ) );
   json_object_set_new( o, "rejected", jint_or_null( t->rejected,
                                                     t->have_shares ) );
   /* A CPU thread has no hardware-error counter to report. */
   json_object_set_new( o, "hw_errors",  json_null() );
   json_object_set_new( o, "intensity",  json_null() );
   json_object_set_new( o, "throughput", json_null() );
   return o;
}

json_t *api_build_pool_json( int index, bool active,
                             const struct api_pool_snapshot *p )
{
   json_t *o = json_object(), *shares = json_object(), *job = json_object();

   if ( !o || !shares || !job )
   {
      if ( o )      json_decref( o );
      if ( shares ) json_decref( shares );
      if ( job )    json_decref( job );
      return NULL;
   }

   json_object_set_new( o, "index",  json_integer( index ) );
   json_object_set_new( o, "active", json_boolean( active ) );
   json_object_set_new( o, "name",   jstr_or_null( p->name ) );
   json_object_set_new( o, "url",    jstr_or_null( p->url ) );
   json_object_set_new( o, "user",   jstr_or_null( p->user ) );
   json_object_set_new( o, "algo",   jstr_or_null( p->algo ) );

   json_object_set_new( shares, "accepted", json_integer( p->accepted ) );
   json_object_set_new( shares, "rejected", json_integer( p->rejected ) );
   json_object_set_new( shares, "stale",    json_integer( p->stale ) );
   json_object_set_new( shares, "solved",   json_integer( p->solved ) );
   /* Per-minute rate is a summary-scope figure. */
   json_object_set_new( shares, "accepted_per_min", json_null() );
   json_object_set_new( o, "shares", shares );

   json_object_set_new( o, "type",   json_string( p->stratum ? "stratum" : "getwork" ) );
   json_object_set_new( o, "status", json_string( p->connected ? "connected"
                                                               : "disconnected" ) );
   json_object_set_new( o, "stale",  json_integer( p->stale ) );
   json_object_set_new( o, "difficulty", jnum_or_null( p->diff, p->diff > 0. ) );
   json_object_set_new( o, "best_share", jnum_or_null( p->best_share,
                                                       p->best_share > 0. ) );

   json_object_set_new( job, "id",     jstr_or_null( p->job_id ) );
   json_object_set_new( job, "height", jint_or_null( p->height, p->height > 0 ) );
   json_object_set_new( job, "extranonce2_size", json_integer( p->xnonce2_size ) );
   /* The extranonce2 in flight is per work item, not retained in printable
    * form; the binary API does not expose it here either. */
   json_object_set_new( job, "extranonce2", json_null() );
   json_object_set_new( o, "job", job );

   /* Counted only where the connection actually failed, so a seturl or a REST
    * pool change does not read as a pool fault. */
   json_object_set_new( o, "disconnects", json_integer( p->disconnects ) );
   /* Not tracked here, so null rather than 0: 0 would be a measurement. */
   json_object_set_new( o, "ping_ms",          json_null() );
   json_object_set_new( o, "wait_time_s",      json_null() );
   json_object_set_new( o, "last_share_age_s", json_null() );
   /* Pool session length, not the process uptime: separate fields so both can
    * be queried. null while disconnected; 0 would claim "connected just now". */
   json_object_set_new( o, "session_s", p->have_session
                        ? json_integer( (json_int_t)p->session_s ) : json_null() );
   return o;
}

json_t *api_build_system_json( const struct api_system_snapshot *s )
{
   json_t *o = json_object();
   if ( !o ) return NULL;
   json_object_set_new( o, "os",     json_string( s->os ) );
   /* No GPU, so no GPU driver. */
   json_object_set_new( o, "driver", json_null() );
   json_object_set_new( o, "cpus",   jint_or_null( s->cpus, s->cpus > 0 ) );
   json_object_set_new( o, "cpu_temp_c",
                        jnum_or_null( s->cpu_temp, s->cpu_temp > 0.f ) );
   json_object_set_new( o, "cpu_clock_mhz",
                        jint_or_null( s->cpu_clock_khz / 1000, s->cpu_clock_khz > 0 ) );
   json_object_set_new( o, "cpu_fan_pct",
                        jint_or_null( s->cpu_fan_pct, s->cpu_fan_pct >= 0 ) );
   return o;
}

/* -------------------------------------------------------------- metrics */

void api_collect_metrics( api_metrics_input *in )
{
   static char algo_buf[64];
   struct api_summary_snapshot s;
   struct api_pool_snapshot    p;

   memset( in, 0, sizeof(*in) );
   api_collect_summary( &s );
   api_collect_pool( &p );
   snprintf( algo_buf, sizeof(algo_buf), "%s", s.algo );

   in->name    = s.name;
   in->version = s.ver;
   in->kind    = "cpu";
   in->algo    = algo_buf;
   /* Reported for real, so a deliberately stopped miner does not look like a
    * fault: that distinction is the whole point of the series (section 11). */
   switch ( api_ctl_get_state() )
   {
      case CTL_PAUSED:    in->control_state = "paused";    break;
      case CTL_STOPPED:   in->control_state = "stopped";   break;
      case CTL_SWITCHING: in->control_state = "switching"; break;
      case CTL_RUNNING:
      default:            in->control_state = "running";   break;
   }

   /* Parked by the operator is not mining, however healthy the process is. */
   in->mining_active = opt_n_threads > 0
                     && api_ctl_get_state() == CTL_RUNNING;
   in->uptime_s        = s.uptime;
   in->hashrate_hs     = s.hashrate;
   in->net_difficulty  = s.diff_net;
   in->pool_difficulty = s.diff_pool;

   /* Carried totals, not s.* : these are Prometheus counters, and a control
    * algo switch resets the live counters underneath them. api_collect_summary
    * above has already refreshed them. */
   in->shares_accepted = mono_accepted;
   in->shares_rejected = mono_rejected;
   in->shares_stale    = mono_stale;
   in->blocks_solved   = mono_solved;

   /* One CPU device, matching /devices. Temperature only where there is a
    * sensor: an omitted series beats a fabricated zero. Power, fan and
    * hardware errors are not readable for a CPU here, so they stay absent. */
   in->devices[0].valid       = true;
   in->devices[0].device      = 0;
   snprintf( in->devices[0].type, sizeof(in->devices[0].type), "cpu" );
   snprintf( in->devices[0].algo, sizeof(in->devices[0].algo), "%s", s.algo );
   in->devices[0].hashrate_hs = s.hashrate;
   float t = cpu_temp( 0 );
   if ( t > 0.f )
   {
      in->devices[0].has_temp = true;
      in->devices[0].temp_c   = t;
   }
   in->ndevices = 1;

   in->pools[0].index       = 0;
   in->pools[0].active      = true;
   snprintf( in->pools[0].url, sizeof(in->pools[0].url), "%s", p.url );
   in->pools[0].stratum     = p.stratum;
   in->pools[0].connected   = p.connected;
   in->pools[0].disconnects = p.disconnects;
   /* last_share_age is not tracked, so that series is omitted rather than
    * reported as 0, which would read as "a share just arrived". */
   in->npools = 1;
}

json_t *api_build_history_json( const struct api_history_record *r )
{
   json_t *o = json_object();
   if ( !o ) return NULL;
   json_object_set_new( o, "thread_id",   json_integer( r->thread_id ) );
   /* One CPU device, so every thread reports device 0. */
   json_object_set_new( o, "device_id",   json_integer( 0 ) );
   json_object_set_new( o, "height",      json_integer( r->height ) );
   json_object_set_new( o, "hashrate_hs", json_real( r->hashrate ) );
   json_object_set_new( o, "difficulty",  json_real( r->difficulty ) );
   json_object_set_new( o, "hashcount",   json_integer( (json_int_t)r->hashcount ) );
   json_object_set_new( o, "found",       json_boolean( r->found ) );
   json_object_set_new( o, "id",          json_integer( r->id ) );
   json_object_set_new( o, "timestamp",   json_integer( r->ts ) );
   return o;
}

json_t *api_build_device_json( int id, const struct api_device_snapshot *d )
{
   json_t *o = json_object(), *c = json_object();

   if ( !o || !c )
   {
      if ( o ) json_decref( o );
      if ( c ) json_decref( c );
      return NULL;
   }

   json_object_set_new( o, "id",     json_integer( id ) );
   json_object_set_new( o, "type",   json_string( "cpu" ) );
   json_object_set_new( o, "name",   json_string( d->name ) );
   json_object_set_new( o, "temp_c", jnum_or_null( d->cpu_temp, d->cpu_temp > 0.f ) );
   json_object_set_new( o, "fan_pct", jint_or_null( d->cpu_fan_pct,
                                                    d->cpu_fan_pct >= 0 ) );
   json_object_set_new( o, "fan_rpm", json_null() );
   json_object_set_new( o, "clock_mhz",
                        jint_or_null( d->cpu_clock_khz / 1000, d->cpu_clock_khz > 0 ) );
   /* Memory clock, power draw and a power cap are not readable for a CPU here. */
   json_object_set_new( o, "mem_clock_mhz",  json_null() );
   json_object_set_new( o, "power_mw",       json_null() );
   json_object_set_new( o, "power_limit_mw", json_null() );
   json_object_set_new( o, "hashrate_hs",    json_real( d->hashrate ) );
   json_object_set_new( o, "hashrate_per_watt_khs", json_null() );

   /* Exactly one typed sub-object, never `gpu` here. Physical core count is
    * not detected: num_cpus is logical CPUs, and cores = threads/2 would be
    * wrong on every machine without SMT. */
   json_object_set_new( c, "cores",    json_null() );
   json_object_set_new( c, "threads",  jint_or_null( d->threads, d->threads > 0 ) );
   json_object_set_new( c, "features", jfeatures_or_null( d->features ) );
   json_object_set_new( o, "cpu", c );
   return o;
}
