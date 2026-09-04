/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Runtime control state machine - see api_control.h and docs/api-rest.md
 * section 7.
 *
 * Not shared with the sibling miner: the parking protocol below is built on
 * this miner's work_restart[] and gate, which have no GPU equivalent.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(__GLIBC__)
#include <malloc.h>
#endif

#include "miner.h"
#include "algo-gate-api.h"
#include "api_control.h"
#include "api_model.h"      /* api_reset_session_stats() */

extern char *rpc_url;
extern char *rpc_user;
extern char *rpc_pass;
extern bool  stratum_need_reset;
extern bool  stratum_down;
extern struct stratum_ctx stratum;

/* CLI, api_control.c owns the defaults so an unset option cannot mean 0. */
int  opt_api_control              = 0;
int  opt_api_control_min_interval = 15;
int  opt_api_control_park_timeout = 10000;

static pthread_mutex_t ctl_lock = PTHREAD_MUTEX_INITIALIZER;

static ctl_state_t ctl_state       = CTL_RUNNING;
static ctl_state_t ctl_state_saved = CTL_RUNNING;   /* for rollback */
static uint64_t    ctl_epoch       = 0;
static uint64_t    ctl_switches    = 0;
static time_t      ctl_since       = 0;
static time_t      ctl_last_switch = 0;
static char        ctl_last_error[256] = { 0 };

/* Parking. The mutation thread sets ctl_park_requested; each mining thread
 * clears its own bit as it stops hashing. Plain volatile ints rather than a
 * condvar: the mining loop must not take a lock per scan, and the only writer
 * of each element is its own thread. */
static volatile int  ctl_park_requested = 0;
static volatile int *ctl_thread_parked  = NULL;

/* Two-phase buffer handover, both phases run BY the mining thread on its own
 * __thread state. The control thread only bumps a generation and waits for the
 * acknowledgements; it must never call miner_thread_free/init itself. */
static volatile uint64_t  ctl_free_gen = 0, ctl_init_gen = 0;
static volatile uint64_t *ctl_thread_free_gen = NULL;
static volatile uint64_t *ctl_thread_init_gen = NULL;

void api_ctl_init( void )
{
   ctl_since = time( NULL );
   const size_t n = opt_n_threads > 0 ? (size_t)opt_n_threads : 1;
   ctl_thread_parked   = (volatile int*) calloc( n, sizeof(int) );
   ctl_thread_free_gen = (volatile uint64_t*) calloc( n, sizeof(uint64_t) );
   ctl_thread_init_gen = (volatile uint64_t*) calloc( n, sizeof(uint64_t) );
}

void api_ctl_thread_service( int thr_id )
{
   if ( thr_id < 0 || !ctl_thread_free_gen || !ctl_thread_init_gen ) return;

   if ( ctl_thread_free_gen[ thr_id ] != ctl_free_gen )
   {
      algo_gate.miner_thread_free( thr_id );
      ctl_thread_free_gen[ thr_id ] = ctl_free_gen;
   }
   if ( ctl_thread_init_gen[ thr_id ] != ctl_init_gen )
   {
      /* Take the generation FIRST: a failed init must not spin here forever,
       * and the thread stays parked anyway because the state says so. */
      ctl_thread_init_gen[ thr_id ] = ctl_init_gen;
      if ( !algo_gate.miner_thread_init( thr_id ) )
         applog( LOG_ERR, "control: thread %d failed to initialise for %s",
                 thr_id, algo_names[ opt_algo ] );
   }
}

/* Wait for every thread to have acknowledged the current generation. */
static bool wait_gen( volatile uint64_t *acks, uint64_t want, int wait_ms )
{
   const int step_ms = 10;
   int waited = 0;
   for ( ;; )
   {
      int done = 0;
      for ( int i = 0; i < opt_n_threads; i++ )
         if ( acks[i] == want ) done++;
      if ( done >= opt_n_threads ) return true;
      if ( waited >= wait_ms ) return false;
      usleep( step_ms * 1000 );
      waited += step_ms;
   }
}

bool api_ctl_enabled( void ) { return opt_api_control != 0; }

ctl_state_t api_ctl_get_state( void ) { return ctl_state; }

/* Called from the mining loop. Also the acknowledgement: a thread that reports
 * "do not run" has, by returning from here, stopped hashing. */
bool api_ctl_thread_should_run( int thr_id )
{
   if ( !opt_api_control ) return true;
   if ( thr_id < 0 || !ctl_thread_parked ) return true;

   const bool park = ctl_park_requested
                  || ctl_state == CTL_PAUSED
                  || ctl_state == CTL_STOPPED;

   ctl_thread_parked[ thr_id ] = park ? 1 : 0;
   return !park;
}

static int parked_count( void )
{
   int n = 0;
   if ( !ctl_thread_parked ) return 0;
   for ( int i = 0; i < opt_n_threads; i++ )
      if ( ctl_thread_parked[i] ) n++;
   return n;
}

/* Ask every thread to park and wait for them. restart_threads() is what makes
 * this quick: without it a thread inside a long scan would only notice at the
 * end of its nonce range, which for equihash is ~100 ms and for a big yespower
 * variant considerably more. */
static bool park_all( int wait_ms )
{
   ctl_park_requested = 1;
   restart_threads();

   const int step_ms = 10;
   int waited = 0;
   while ( waited < wait_ms )
   {
      if ( parked_count() >= opt_n_threads ) return true;
      usleep( step_ms * 1000 );
      waited += step_ms;
   }
   return parked_count() >= opt_n_threads;
}

static void unpark_all( void )
{
   ctl_park_requested = 0;
   restart_threads();
}

static void ctl_set_error( const char *fmt, ... )
{
   va_list ap;
   va_start( ap, fmt );
   vsnprintf( ctl_last_error, sizeof(ctl_last_error), fmt, ap );
   va_end( ap );
}

void api_ctl_get_status( struct ctl_status *out )
{
   time_t now = time( NULL );

   memset( out, 0, sizeof(*out) );
   pthread_mutex_lock( &ctl_lock );

   out->state          = ctl_state;
   out->epoch          = ctl_epoch;
   out->since_s        = difftime( now, ctl_since );
   out->threads_total  = opt_n_threads;
   out->threads_parked = parked_count();
   out->switch_count   = ctl_switches;
   out->min_interval_s = opt_api_control_min_interval;
   out->last_switch_age_s = ctl_last_switch
                          ? difftime( now, ctl_last_switch ) : -1.;
   out->ready_for_switch  = !ctl_last_switch
      || difftime( now, ctl_last_switch ) >= opt_api_control_min_interval;
   snprintf( out->last_error, sizeof(out->last_error), "%s", ctl_last_error );
   get_currentalgo( out->algo, sizeof(out->algo) );

   pthread_mutex_unlock( &ctl_lock );
}

/* ------------------------------------------------------------ transitions */

static void enter_state( ctl_state_t s )
{
   if ( ctl_state == s ) return;
   ctl_state = s;
   ctl_since = time( NULL );
}

ctl_result_t api_ctl_set_state( ctl_state_t target, int wait_ms )
{
   if ( !opt_api_control ) return CTL_DISABLED;
   if ( target == CTL_SWITCHING ) return CTL_BAD_REQUEST;

   pthread_mutex_lock( &ctl_lock );

   if ( ctl_state == CTL_SWITCHING )
   {
      pthread_mutex_unlock( &ctl_lock );
      return CTL_BUSY;
   }
   /* A no-op returns 200 and does NOT advance epoch, so a manager can be
    * crash-safe by re-asserting the state it wants (section 7.1). */
   if ( ctl_state == target )
   {
      pthread_mutex_unlock( &ctl_lock );
      return CTL_OK;
   }

   ctl_state_saved = ctl_state;
   enter_state( CTL_SWITCHING );
   pthread_mutex_unlock( &ctl_lock );

   bool ok = true;
   if ( target == CTL_PAUSED || target == CTL_STOPPED )
   {
      ok = park_all( wait_ms > 0 ? wait_ms : opt_api_control_park_timeout );
      if ( !ok )
         ctl_set_error( "only %d of %d threads parked within %d ms",
                        parked_count(), opt_n_threads,
                        wait_ms > 0 ? wait_ms : opt_api_control_park_timeout );
      /* stop also drops the pool connection; pause keeps it (section 7.1). */
      if ( ok && target == CTL_STOPPED && have_stratum )
         stratum_need_reset = true;
   }

   pthread_mutex_lock( &ctl_lock );
   if ( ok )
   {
      enter_state( target );
      ctl_epoch++;
      ctl_last_error[0] = '\0';
      /* The threads stay parked by state, not by the request flag. */
      ctl_park_requested = 0;
      if ( target == CTL_RUNNING ) unpark_all();
   }
   else
   {
      enter_state( ctl_state_saved );
      unpark_all();
   }
   pthread_mutex_unlock( &ctl_lock );

   return ok ? CTL_OK : CTL_FAILED;
}

/* ------------------------------------------------- algorithm parameters
 *
 * Derived from what register_*_algo() reads, not from the option list: a
 * parameter the registration ignores would be accepted and silently do
 * nothing. */

static const ctl_param_def_t ctl_params[] = {
   { "n",         CTLP_INT,    false },
   { "r",         CTLP_INT,    false },
   { "key",       CTLP_STRING, false },
   /* Loads a multi-gigabyte file, so the client must expect a long call
    * (section 9's slow tier). */
   { "data_file", CTLP_STRING, true  },
};

static const char *params_nrk[]  = { "n", "r", "key" };
static const char *params_n[]    = { "n" };
static const char *params_file[] = { "data_file" };

const char **api_ctl_algo_params( int algo, size_t *count )
{
   switch ( algo )
   {
      case ALGO_SCRYPT:
         *count = 1; return params_n;
      case ALGO_YESPOWER:
      case ALGO_YESCRYPT:
      case ALGO_YESPOWER_B2B:
         *count = 3; return params_nrk;
      case ALGO_VERTHASH:
         *count = 1; return params_file;
      default:
         *count = 0; return NULL;
   }
}

const ctl_param_def_t *api_ctl_param_find( const char *name )
{
   for ( size_t i = 0; i < sizeof(ctl_params)/sizeof(ctl_params[0]); i++ )
      if ( !strcasecmp( ctl_params[i].name, name ) ) return &ctl_params[i];
   return NULL;
}

static bool algo_takes_param( int algo, const char *name )
{
   size_t n = 0;
   const char **names = api_ctl_algo_params( algo, &n );
   for ( size_t i = 0; i < n; i++ )
      if ( !strcasecmp( names[i], name ) ) return true;
   return false;
}

/* Sticky per algorithm (section 9): switching away and back restores what was
 * last set, so a manager does not have to re-send a profile it already sent. */
struct ctl_algo_params
{
   bool has_n, has_r, has_key, has_file;
   int  n, r;
   char key[128];
   char file[512];
};
static struct ctl_algo_params ctl_stored[ ALGO_COUNT ];

/* Push the stored set for `algo` into the globals the registration reads.
 * Anything unset becomes 0/NULL, which is how each register_*_algo() is told
 * to use its own default. */
static void params_load_into_globals( int algo )
{
   const struct ctl_algo_params *p = &ctl_stored[ algo ];

   opt_param_n = p->has_n ? p->n : 0;
   opt_param_r = p->has_r ? p->r : 0;

   free( opt_param_key );
   opt_param_key = p->has_key ? strdup( p->key ) : NULL;

   if ( p->has_file )
   {
      free( opt_data_file );
      opt_data_file = strdup( p->file );
   }
}

/* Validate first, store second: section 9 requires that an unknown name, a
 * wrong type or a value the algo does not accept applies NOTHING. */
static bool params_validate( int algo, const ctl_param_set_t *ps, size_t n,
                             char *err, size_t errlen )
{
   for ( size_t i = 0; i < n; i++ )
   {
      const ctl_param_def_t *d = api_ctl_param_find( ps[i].name );
      if ( !d )
      {
         snprintf( err, errlen, "unknown parameter '%s'", ps[i].name );
         return false;
      }
      if ( !algo_takes_param( algo, ps[i].name ) )
      {
         snprintf( err, errlen, "%s does not accept '%s'",
                   algo_names[algo], ps[i].name );
         return false;
      }
      if ( ps[i].reset ) continue;
      if ( d->type == CTLP_INT )
      {
         if ( ps[i].ival <= 0 )
         {
            snprintf( err, errlen, "'%s' must be a positive integer",
                      ps[i].name );
            return false;
         }
         /* scrypt sizes a per-thread buffer as N*128 bytes and its own
          * registration warns above 0x4000; refuse rather than let a request
          * allocate gigabytes per thread. */
         if ( !strcasecmp( ps[i].name, "n" ) && ps[i].ival > 0x400000 )
         {
            snprintf( err, errlen, "'n' is unreasonably large" );
            return false;
         }
      }
      else if ( !ps[i].sval )
      {
         snprintf( err, errlen, "'%s' must be a string", ps[i].name );
         return false;
      }
   }
   return true;
}

static void params_store( int algo, const ctl_param_set_t *ps, size_t n )
{
   struct ctl_algo_params *st = &ctl_stored[ algo ];

   for ( size_t i = 0; i < n; i++ )
   {
      const bool reset = ps[i].reset;
      if ( !strcasecmp( ps[i].name, "n" ) )
      {
         st->has_n = !reset;
         if ( !reset ) st->n = (int) ps[i].ival;
      }
      else if ( !strcasecmp( ps[i].name, "r" ) )
      {
         st->has_r = !reset;
         if ( !reset ) st->r = (int) ps[i].ival;
      }
      else if ( !strcasecmp( ps[i].name, "key" ) )
      {
         st->has_key = !reset;
         if ( !reset ) snprintf( st->key, sizeof(st->key), "%s", ps[i].sval );
      }
      else if ( !strcasecmp( ps[i].name, "data_file" ) )
      {
         st->has_file = !reset;
         if ( !reset ) snprintf( st->file, sizeof(st->file), "%s", ps[i].sval );
      }
   }
}

bool api_ctl_param_get_int( const char *name, long *out )
{
   const struct ctl_algo_params *p = &ctl_stored[ opt_algo ];
   if ( !algo_takes_param( opt_algo, name ) ) return false;
   if ( !strcasecmp( name, "n" ) && p->has_n ) { *out = p->n; return true; }
   if ( !strcasecmp( name, "r" ) && p->has_r ) { *out = p->r; return true; }
   /* Not stored by us, but the miner may have been started with it. */
   if ( !strcasecmp( name, "n" ) && opt_param_n ) { *out = opt_param_n; return true; }
   if ( !strcasecmp( name, "r" ) && opt_param_r ) { *out = opt_param_r; return true; }
   return false;
}

bool api_ctl_param_get_str( const char *name, const char **out )
{
   const struct ctl_algo_params *p = &ctl_stored[ opt_algo ];
   if ( !algo_takes_param( opt_algo, name ) ) return false;
   if ( !strcasecmp( name, "key" ) )
   {
      if ( p->has_key ) { *out = p->key; return true; }
      if ( opt_param_key ) { *out = opt_param_key; return true; }
   }
   if ( !strcasecmp( name, "data_file" ) )
   {
      if ( p->has_file ) { *out = p->file; return true; }
      if ( opt_data_file ) { *out = opt_data_file; return true; }
   }
   return false;
}

/* ---------------------------------------------------------------- profile */

/* Free every thread's algo buffers, then re-register the gate. Returns false
 * with last_error set; the caller rolls back.
 *
 * `memcheck` refuses the switch when the new algo's per-thread workspace does
 * not fit in RAM. Pass false on a rollback: the algo being restored was already
 * running with these threads, so its workspace demonstrably fit, and a
 * transient dip in free memory must not strand the miner with no gate. */
static bool switch_algo( int new_algo, bool memcheck )
{
   /* Step 1: every thread frees its own buffers, under the algo that
    * allocated them. They are already parked, so this is a generation bump
    * and a wait. */
   ctl_free_gen++;
   if ( !wait_gen( ctl_thread_free_gen, ctl_free_gen,
                   opt_api_control_park_timeout ) )
   {
      ctl_set_error( "threads did not release their buffers within %d ms",
                     opt_api_control_park_timeout );
      return false;
   }
#if defined(__GLIBC__)
   /* Large freed blocks otherwise sit in the arena rather than going back to
    * the OS, which on a 3.6 GB equihash workspace is not academic. */
   malloc_trim( 0 );
#endif

   const enum algos prev = opt_algo;
   opt_algo = (enum algos) new_algo;

   if ( !register_algo_gate( new_algo, &algo_gate ) )
   {
      ctl_set_error( "algo %s failed to register", algo_names[ new_algo ] );
      opt_algo = prev;
      /* Put the old gate back; its registration already succeeded once, so
       * this is the one call in the rollback path that must not fail. */
      if ( !register_algo_gate( prev, &algo_gate ) )
         applog( LOG_ERR, "control: could not restore algo %s after a failed "
                          "switch -- mining is stopped", algo_names[ prev ] );
      return false;
   }

   /* Between registration and step 2 is the only window where refusing is
    * free: the gate now reports the new algo's workspace (equihash sizes it
    * from the params read at registration, so it cannot be known earlier), and
    * no thread has allocated yet. Past this point the threads take the memory
    * and touch it, so overcommit does not save us and the kernel kills the
    * process - losing the session, the share stats and any queued shares.
    * The startup cap in main() cannot cover this: it ran once, under whatever
    * algo was selected then, which for a 0-byte-workspace algo is no cap. */
   if ( memcheck )
   {
      const size_t ws = algo_gate.get_workspace_size();
      uint64_t     avail = 0;
      const int    fit = workspace_thread_fit( ws, opt_n_threads, &avail );
      if ( fit < opt_n_threads )
      {
         /* fit == 0 is a real answer, not a rounding artefact: equihash 125/4
          * wants 5.8 GB for one thread. Saying "restart with -t 0" would be
          * nonsense, so that case gets its own wording. */
         if ( fit < 1 )
            ctl_set_error( "%s needs %.1f GB per thread but only %.1f GB is "
                           "free -- this machine cannot mine it at any thread "
                           "count.",
                           algo_names[ new_algo ], ws / (1024.0*1024.0*1024.0),
                           avail / (1024.0*1024.0*1024.0) );
         else
            ctl_set_error( "%s needs %.1f GB for %d threads (%.0f MB each) but "
                           "only %.1f GB is free -- %d thread(s) would fit. "
                           "Restart with -t %d to mine it here.",
                           algo_names[ new_algo ],
                           (double)ws * opt_n_threads / (1024.0*1024.0*1024.0),
                           opt_n_threads, ws / (1024.0*1024.0),
                           avail / (1024.0*1024.0*1024.0), fit, fit );
         applog( LOG_WARNING, "control: refused switch to %s -- %s",
                 algo_names[ new_algo ], ctl_last_error );
         opt_algo = prev;
         if ( !register_algo_gate( prev, &algo_gate ) )
            applog( LOG_ERR, "control: could not restore algo %s after "
                             "refusing %s -- mining is stopped",
                    algo_names[ prev ], algo_names[ new_algo ] );
         return false;
      }
   }

   /* Step 2: the gate is the new algo's now, so the threads allocate against
    * it themselves, still parked, before hashing. Not optional and not lazy:
    * scrypt sizes its scratch buffer from N at registration, so without a
    * re-init the threads hash through a freed pointer. */
   ctl_init_gen++;
   if ( !wait_gen( ctl_thread_init_gen, ctl_init_gen,
                   opt_api_control_park_timeout ) )
   {
      ctl_set_error( "threads did not initialise %s within %d ms",
                     algo_names[ new_algo ], opt_api_control_park_timeout );
      return false;
   }


   /* Unconditional: a switch is rare, and registration mutates globals as
    * well as the gate (opt_target_factor), where a leak looks identical in the
    * share log to a header-format bug. */
   if ( opt_debug )
      applog( LOG_INFO, "control: %s active -- target_factor %.0f, "
                        "nonce_index %d, ntime_index %d, nbits_index %d, "
                        "work_data %d B",
              algo_names[ new_algo ], opt_target_factor,
              algo_gate.nonce_index, algo_gate.ntime_index,
              algo_gate.nbits_index, algo_gate.get_work_data_size() );

   /* Only now, and only on the success path: a rolled-back switch never ran the
    * new algorithm, so its stats still describe what is still running. Threads
    * are parked here, which is what makes an unlocked reset safe. */
   api_reset_session_stats();
   return true;
}

static int algo_by_name( const char *name )
{
   for ( int i = 1; i < ALGO_COUNT; i++ )
      if ( algo_names[i] && !strcasecmp( algo_names[i], name ) ) return i;
   return -1;
}

ctl_result_t api_ctl_profile( const char *algo, const char *pool_url,
                              const char *pool_user, const char *pool_pass,
                              const ctl_param_set_t *params, size_t nparams,
                              const bool *run, int wait_ms )
{
   if ( !opt_api_control ) return CTL_DISABLED;

   int new_algo = -1;
   if ( algo && *algo )
   {
      new_algo = algo_by_name( algo );
      if ( new_algo < 0 ) return CTL_BAD_REQUEST;
   }

   /* Parameters apply to the algo being switched TO, or to the current one
    * when only params were sent. Validated before anything is parked: an
    * invalid set must not stop mining even briefly (section 9). */
   const int param_algo = new_algo >= 0 ? new_algo : (int) opt_algo;
   bool slow_param = false;
   if ( nparams )
   {
      char err[sizeof(ctl_last_error)];
      if ( !params_validate( param_algo, params, nparams, err, sizeof(err) ) )
      {
         ctl_set_error( "%s", err );
         return CTL_BAD_REQUEST;
      }
      for ( size_t i = 0; i < nparams; i++ )
      {
         const ctl_param_def_t *d = api_ctl_param_find( params[i].name );
         if ( d && d->slow ) slow_param = true;
      }
   }

   pthread_mutex_lock( &ctl_lock );

   if ( ctl_state == CTL_SWITCHING )
   {
      pthread_mutex_unlock( &ctl_lock );
      return CTL_BUSY;
   }
   /* Anti-flap. start/pause/stop are deliberately not throttled, only
    * re-targeting (section 7.1). */
   if ( ctl_last_switch
        && difftime( time(NULL), ctl_last_switch ) < opt_api_control_min_interval )
   {
      pthread_mutex_unlock( &ctl_lock );
      return CTL_THROTTLED;
   }

   ctl_state_saved = ctl_state;
   enter_state( CTL_SWITCHING );
   pthread_mutex_unlock( &ctl_lock );

   const int timeout = wait_ms > 0 ? wait_ms : opt_api_control_park_timeout;
   bool ok = park_all( timeout );
   if ( !ok )
      ctl_set_error( "only %d of %d threads parked within %d ms",
                     parked_count(), opt_n_threads, timeout );

   /* Remember enough to undo a partial change. */
   const enum algos prev_algo = opt_algo;
   char *prev_url = rpc_url ? strdup( rpc_url ) : NULL;

   const struct ctl_algo_params prev_params = ctl_stored[ param_algo ];
   struct timeval t0, t1;
   gettimeofday( &t0, NULL );

   if ( ok && nparams )
      params_store( param_algo, params, nparams );

   if ( ok && new_algo >= 0 )
   {
      /* Sticky: load whatever was last set for the algo we are moving to,
       * including anything this call just stored. */
      params_load_into_globals( new_algo );
      ok = switch_algo( new_algo, true );
   }
   else if ( ok && nparams )
   {
      /* Parameters only: the registration is what reads them, so re-run it
       * for the algo already in use. */
      params_load_into_globals( param_algo );
      /* Params only, but equihash's workspace is sized from them, so a
       * 144/5 -> 192/7 change can be the thing that no longer fits. */
      ok = switch_algo( param_algo, true );
   }

   if ( ok && pool_url && *pool_url )
   {
      /* parse_arg('o') rewrites its argument and exits the process on a bad
       * scheme; the route layer validates before we get here. */
      char packed[1280];
      if ( pool_user && *pool_user )
      {
         const char *sep = strstr( pool_url, "://" );
         size_t schemelen = sep ? (size_t)( sep - pool_url ) + 3 : 0;
         snprintf( packed, sizeof(packed), "%.*s%s:%s@%s", (int)schemelen,
                   pool_url, pool_user,
                   ( pool_pass && *pool_pass ) ? pool_pass : "x",
                   pool_url + schemelen );
      }
      else
         snprintf( packed, sizeof(packed), "%s", pool_url );

      parse_arg( 'o', packed );
      /* Mark the pool down here, not from the stratum thread: unpark_all()
       * below releases the miners at once, and until the reset is processed a
       * resumed thread would hash the PREVIOUS pool's job with the NEW algo and
       * submit shares the pool rejects. Threads idle on stratum_down. The wake
       * is what makes the reset prompt rather than up to opt_timeout away. */
      stratum_down = true;
      stratum_need_reset = true;
      stratum_wake( &stratum );
   }

   pthread_mutex_lock( &ctl_lock );
   if ( ok )
   {
      ctl_epoch++;
      ctl_switches++;
      ctl_last_switch = time( NULL );
      ctl_last_error[0] = '\0';

      /* run absent means "keep the state we were in", which for a stopped or
       * paused miner is what the contract asks for (section 7.1). */
      ctl_state_t target = ctl_state_saved;
      if ( run ) target = *run ? CTL_RUNNING : CTL_PAUSED;
      enter_state( target );
      ctl_park_requested = 0;
      if ( target == CTL_RUNNING ) unpark_all();
   }
   else
   {
      ctl_stored[ param_algo ] = prev_params;
      if ( ( new_algo >= 0 && opt_algo != prev_algo ) || nparams )
      {
         params_load_into_globals( prev_algo );
         switch_algo( prev_algo, false );   /* see switch_algo's memcheck note */
      }
      if ( prev_url && ( !rpc_url || strcmp( prev_url, rpc_url ) ) )
      {
         char restore[1280];
         snprintf( restore, sizeof(restore), "%s", prev_url );
         parse_arg( 'o', restore );
         stratum_need_reset = true;
      }
      enter_state( ctl_state_saved );
      unpark_all();
   }
   pthread_mutex_unlock( &ctl_lock );

   free( prev_url );
   if ( !ok ) return CTL_FAILED;

   /* Section 9: a slow parameter cannot be promised inside a request. This
    * applies it synchronously and reports 202 when it overran the caller's
    * budget -- the state is already correct, so the client's poll succeeds
    * immediately rather than waiting on a background worker this miner does
    * not have. */
   gettimeofday( &t1, NULL );
   const double took_ms = ( t1.tv_sec - t0.tv_sec ) * 1e3
                        + ( t1.tv_usec - t0.tv_usec ) / 1e3;
   if ( slow_param && wait_ms > 0 && took_ms > wait_ms ) return CTL_ACCEPTED;
   if ( slow_param && wait_ms == 0 ) return CTL_ACCEPTED;
   return CTL_OK;
}
