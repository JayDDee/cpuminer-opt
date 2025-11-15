/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014-2016 Tanguy Pruvot
 * Copyright 2016-2023 Jay D Dee
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

/*
 *   Change log
 *
 *   2016-01-14: v 1.9-RC inititial limited release combining
 *                cpuminer-multi 1.2-prev, darkcoin-cpu-miner 1.3,
 *                and cp3u 2.3.2 plus some performance optimizations.
 *
 *   2016-02-04: v3.1 algo_gate implemntation
 */

#include <cpuminer-config.h>
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <memory.h>
#include <curl/curl.h>
#include <jansson.h>
//#include <openssl/sha.h>
//#include <mm_malloc.h>
#include "sysinfos.c"
#include "algo/sha/sha256d.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

#ifdef _MSC_VER
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

// GCC 9 warning sysctl.h is deprecated
#if ( __GNUC__ < 9 )
#include <sys/sysctl.h>
#endif

#endif  // HAVE_SYS_SYSCTL_H
#endif  // _MSC_VER ELSE

#ifndef WIN32
#include <sys/resource.h>
#endif

#include "miner.h"
#include "algo-gate-api.h"
#include "algo/sha/sha256-hash.h"

#ifdef WIN32
#include "compat/winansi.h"
//BOOL WINAPI ConsoleHandler(DWORD);
#endif
#ifdef _MSC_VER
#include <Mmsystem.h>
#pragma comment(lib, "winmm.lib")
#endif

#define LP_SCANTIME		60

algo_gate_t algo_gate;

bool opt_debug = false;
bool opt_debug_diff = false;
bool opt_protocol = false;
bool opt_benchmark = false;
bool opt_redirect = true;
bool opt_extranonce = true;
bool want_longpoll = false;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true;    // pretty useless
bool have_stratum = false;
bool stratum_down = true;
bool allow_mininginfo = true;
bool use_syslog = false;
bool use_colors = true;
static bool opt_background = false;
bool opt_quiet = false;
bool opt_randomize = false;
static int opt_retries = -1;
static int opt_fail_pause = 10;
static int opt_time_limit = 0;
static unsigned int time_limit_stop = 0;
int opt_timeout = 300;
static int opt_scantime = 0;
const int min_scantime = 1;
//static const bool opt_time = true;
enum algos opt_algo = ALGO_NULL;
char* opt_param_key = NULL;
int opt_param_n = 0;
int opt_param_r = 0;
int opt_n_threads = 0;
bool opt_sapling = false;
static uint64_t opt_affinity = 0xFFFFFFFFFFFFFFFFULL;  // default, use all cores
int opt_priority = 0;  // deprecated
int num_cpus = 1;
int num_cpugroups = 1;  // For Windows
char *rpc_url = NULL;
char *rpc_userpass = NULL;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
char *coinbase_address;
char *opt_data_file = NULL;
bool opt_verify = false;
static bool opt_stratum_keepalive = false;
static struct timeval stratum_keepalive_timer;
// Stratum typically times out in 5 minutes or 300 seconds
#define stratum_keepalive_timeout 150  // 2.5 minutes
static struct timeval stratum_reset_time;

// pk_buffer_size is used as a version selector by b58 code, therefore
// it must be set correctly to work.
const int pk_buffer_size_max = 26;
int pk_buffer_size = 25;
static unsigned char pk_script[ 26 ] = { 0 };
static size_t pk_script_size = 0;
static char coinbase_sig[101] = { 0 };
char *opt_cert;
char *opt_proxy;
long opt_proxy_type;
struct thr_info *thr_info;
int work_thr_id;
int longpoll_thr_id = -1;
int stratum_thr_id = -1;
int api_thr_id = -1;
bool stratum_need_reset = false;
struct work_restart *work_restart = NULL;
struct stratum_ctx stratum = {0};
double opt_diff_factor = 1.0;
double opt_target_factor = 1.0;
uint32_t zr5_pok = 0;
bool opt_stratum_stats = false;
bool opt_hash_meter = false;
uint32_t submitted_share_count= 0;
uint32_t accepted_share_count = 0;
uint32_t rejected_share_count = 0;
uint32_t stale_share_count = 0;
uint32_t solved_block_count = 0;
uint32_t stratum_errors = 0;
double *thr_hashrates;
double global_hashrate = 0.;
double total_hashes = 0.;
struct timeval total_hashes_time = {0,0};
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
uint32_t opt_work_size = 0;
bool     opt_bell = false;

// conditional mining
bool *conditional_state = NULL;
//bool conditional_state[MAX_CPUS] = { 0 };
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;

// API
static bool opt_api_enabled = false;
char *opt_api_allow = NULL;
int opt_api_listen = 0;
int opt_api_remote = 0;
const char *default_api_allow = "127.0.0.1";
int default_api_listen = 4048; 

  pthread_mutex_t applog_lock;
  pthread_mutex_t stats_lock;

static struct   timeval session_start;
static struct   timeval five_min_start;
static uint64_t session_first_block = 0;
static uint64_t submit_sum  = 0;
static uint64_t accept_sum  = 0;
static uint64_t stale_sum  = 0;
static uint64_t reject_sum  = 0;
static uint64_t solved_sum  = 0;
static double   norm_diff_sum = 0.;
static uint32_t last_block_height = 0;
static double   highest_share = 0;   // highest accepted share diff
static double   lowest_share = 9e99; // lowest accepted share diff
static double   last_targetdiff = 0.;
#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32) || defined(__APPLE__))
static uint32_t hi_temp = 0;
static uint32_t prev_temp = 0;
#endif

  
static char const short_options[] =
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"a:b:Bc:CDf:hK:m:n:N:p:Px:qr:R:s:t:T:o:u:O:V";

static struct work g_work __attribute__ ((aligned (64))) = {{ 0 }};
time_t g_work_time = 0;
pthread_rwlock_t g_work_lock;
static bool   submit_old = false;
char*  lp_id;

static void   workio_cmd_free(struct workio_cmd *wc);

static int *thread_affinity_map;

// display affinity mask graphically
static void format_affinity_mask( char *mask_str, uint64_t mask )
{
#if defined(WINDOWS_CPU_GROUPS_ENABLED)
   int n = num_cpus / num_cpugroups;
#else
   int n = num_cpus < 64 ? num_cpus : 64;
#endif
   int i;
   for ( i = 0; i < n; i++ )
   {
      if ( mask & 1 )  mask_str[i] = '!';
      else             mask_str[i] = '.';
      mask >>= 1;
   }
   memset( &mask_str[i], 0, 64 - i );
}

#ifdef __linux /* Linux specific policy and affinity management */
#include <sched.h>

static inline void drop_policy(void)
{
	struct sched_param param;
	param.sched_priority = 0;
#ifdef SCHED_IDLE
	if (unlikely(sched_setscheduler(0, SCHED_IDLE, &param) == -1))
#endif
#ifdef SCHED_BATCH
		sched_setscheduler(0, SCHED_BATCH, &param);
#endif
}

#ifdef __BIONIC__
#define pthread_setaffinity_np(tid,sz,s) {} /* only do process affinity */
#endif

static void affine_to_cpu( struct thr_info *thr )
{
   int thread = thr->id;
   cpu_set_t set;
   CPU_ZERO( &set );
   CPU_SET( thread_affinity_map[ thread ], &set );
   if ( opt_debug )
      applog( LOG_INFO, "Binding thread %d to cpu %d",
                        thread, thread_affinity_map[ thread ] );
   pthread_setaffinity_np( thr->pth, sizeof(set), &set );
}

#elif defined(WIN32) /* Windows */

static inline void drop_policy(void) { }

// Windows CPU groups to manage more than 64 CPUs.
// mask arg is ignored
static void affine_to_cpu( struct thr_info *thr )
{
   int thread = thr->id;
   unsigned long last_error = 0;    
   bool ok = true;

#if defined(WINDOWS_CPU_GROUPS_ENABLED)
   unsigned long group_size = GetActiveProcessorCount( 0 );
   unsigned long group      = thread / group_size;
   unsigned long cpu        = thread_affinity_map[ thread % group_size ];

   GROUP_AFFINITY affinity = {0};
   affinity.Group = group;
   affinity.Mask = 1ULL << cpu;

   if ( opt_debug )
      applog( LOG_INFO, "Binding thread %d to cpu %d in cpu group %d",
                        thread, cpu, group );

   ok = SetThreadGroupAffinity( GetCurrentThread(), &affinity, NULL );

#else

   unsigned long cpu = thread_affinity_map[ thread ];
   uint64_t mask = 1ULL << cpu;

   if ( opt_debug )
      applog( LOG_INFO, "Binding thread %d to cpu %d", thread, cpu );

   ok = SetThreadAffinityMask( GetCurrentThread(), mask );

#endif

   if ( !ok )
   {
      last_error = GetLastError();
      if ( !thread )
         applog( LOG_WARNING, "Set affinity returned error 0x%x", last_error );
   }
}   

#else

static inline void drop_policy(void) { }
static void affine_to_cpu( struct thr_info *thr ) { }

#endif

// not very useful, just index the arrray directly.
// but declaring this function in miner.h eliminates
// an annoying compiler warning for not using a static.
const char* algo_name( enum algos a ) {return algo_names[a];}

void get_currentalgo(char* buf, int sz)
{
	snprintf(buf, sz, "%s", algo_names[opt_algo]);
}

void proper_exit(int reason)
{
   if (opt_debug) applog(LOG_INFO,"Program exit");
#ifdef WIN32
	if (opt_background) {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// unhide parent command line windows
			ShowWindow(hcon, SW_SHOWMINNOACTIVE);
		}
	}
#endif
	exit(reason);
}

uint32_t* get_stratum_job_ntime()
{
   return (uint32_t*)stratum.job.ntime;
}

void work_free(struct work *w)
{
	if (w->txs) free(w->txs);
	if (w->workid) free(w->workid);
	if (w->job_id) free(w->job_id);
	if (w->xnonce2) free(w->xnonce2);
}

void work_copy(struct work *dest, const struct work *src)
{
	memcpy(dest, src, sizeof(struct work));
	if (src->txs)
		dest->txs = strdup(src->txs);
	if (src->workid)
		dest->workid = strdup(src->workid);
	if (src->job_id)
		dest->job_id = strdup(src->job_id);
	if (src->xnonce2) {
		dest->xnonce2 = (uchar*) malloc(src->xnonce2_len);
		memcpy(dest->xnonce2, src->xnonce2, src->xnonce2_len);
	}
}

int std_get_work_data_size() { return STD_WORK_DATA_SIZE; }

// Default
bool std_le_work_decode( struct work *work )
{
    int i;
    const int adata_sz    = algo_gate.get_work_data_size() / 4;
//    const int atarget_sz  = ARRAY_SIZE(work->target);

    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = le32dec( work->data + i );
    for ( i = 0; i < 8; i++ )
          work->target[i] = le32dec( work->target + i );
    return true;
}

bool std_be_work_decode( struct work *work )
{
    int i;
    const int adata_sz    = algo_gate.get_work_data_size() / 4;
//    const int atarget_sz  = ARRAY_SIZE(work->target);

    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = be32dec( work->data + i );
    for ( i = 0; i < 8; i++ )
          work->target[i] = le32dec( work->target + i );
    return true;
}

static bool work_decode( const json_t *val, struct work *work )
{
    const int data_size   = algo_gate.get_work_data_size();
    const int target_size = sizeof(work->target);

    if (unlikely( !jobj_binary(val, "data", work->data, data_size) ))
    {
       applog(LOG_ERR, "JSON invalid data");
       return false;
    }
    if (unlikely( !jobj_binary(val, "target", work->target, target_size) ))
    {
       applog(LOG_ERR, "JSON invalid target");
       return false;
    }

    if ( unlikely( !algo_gate.work_decode( work ) ) )
        return false;

    // many of these aren't used solo.
    net_diff =
    work->targetdiff = 
    stratum_diff =
    last_targetdiff = hash_to_diff( work->target );
    work->sharediff = 0;
    algo_gate.decode_extra_data( work, &net_blocks );

    return true;
}

// Only used for net_hashrate with GBT/getwork, data is from previous block.
static const char *info_req =
"{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo( CURL *curl, struct work *work )
{
	if ( have_stratum || !allow_mininginfo )
		return false;

	int curl_err = 0;
	json_t *val = json_rpc_call( curl, rpc_url, rpc_userpass, info_req,
                                &curl_err, 0 );

	if ( !val && curl_err == -1 )
   {
		allow_mininginfo = false;
      applog( LOG_NOTICE, "\"getmininginfo\" not supported, some stats not available" );
		return false;
	}

   json_t *res = json_object_get( val, "result" );
   // "blocks": 491493 (= current work height - 1)
   // "difficulty": 0.99607860999999998
   // "networkhashps": 56475980
   if ( res )
   {
      double difficulty = 0.;
  		json_t *key = json_object_get( res, "difficulty" );
   	if ( key )
      {
	   	if ( json_is_object( key ) )
		   	key = json_object_get( key, "proof-of-work" );
		   if ( json_is_real( key ) )
			   difficulty = json_real_value( key );
	   }

      key = json_object_get( res, "networkhashps" );
      if ( key )
      {
         if ( json_is_integer( key ) )
            net_hashrate = (double) json_integer_value( key );
         else if ( json_is_real( key ) )
            net_hashrate = (double) json_real_value( key );
      }

      key = json_object_get( res, "blocks" );
	   if ( key && json_is_integer( key ) )
		  	net_blocks = json_integer_value( key );

      if ( opt_debug )
         applog( LOG_INFO,"getmininginfo: difficulty %.5g, networkhashps %.5g, blocks %d", difficulty, net_hashrate, net_blocks );

      if ( !work->height )
      {
	      // complete missing data from getwork
         if ( opt_debug )
            applog( LOG_DEBUG, "work height set by getmininginfo" );
	      work->height = (uint32_t) net_blocks + 1;
	      if ( work->height > g_work.height )
            restart_threads();
	   }  // res
	}
	json_decref( val );
	return true;
}

// hodl needs 4 but leave it at 3 until gbt better understood
//#define BLOCK_VERSION_CURRENT 3
#define BLOCK_VERSION_CURRENT 4

static bool gbt_work_decode( const json_t *val, struct work *work )
{
   uint32_t prevhash[8] __attribute__ ((aligned (32)));
   uint32_t target[8] __attribute__ ((aligned (32)));
   unsigned char final_sapling_hash[32] __attribute__ ((aligned (32)));
   uint32_t version, curtime, bits;
   int cbtx_size;
   uchar *cbtx = NULL;
   int tx_count, tx_size;
   uchar txc_vi[9];
   uchar(*merkle_tree)[32] = NULL;
   bool coinbase_append = false;
   bool submit_coinbase = false;
   bool version_force = false;
   bool version_reduce = false;
   json_t *tmp, *txa;
   bool rc = false;
   int i, n;
   bool segwit = false;

   tmp = json_object_get( val, "rules" );
   if ( tmp && json_is_array( tmp ) )
   {
      n = json_array_size( tmp );
      for ( i = 0; i < n; i++ )
      {
         const char *s = json_string_value( json_array_get( tmp, i ) );
         if ( !s )
            continue;
         if ( !strcmp( s, "segwit" ) || !strcmp( s, "!segwit" ) )
         {
            segwit = true;
            if ( opt_debug )
               applog( LOG_INFO, "GBT: SegWit is enabled" );
         }
      }
   }

   tmp = json_object_get( val, "mutable" );
   if ( tmp && json_is_array( tmp ) )
   {
      n = (int) json_array_size( tmp );
      for ( i = 0; i < n; i++ )
      {
         const char *s = json_string_value( json_array_get( tmp, i ) );
         if ( !s )
            continue;
         if      ( !strcmp( s, "coinbase/append" ) ) coinbase_append = true;
         else if ( !strcmp( s, "submit/coinbase" ) ) submit_coinbase = true;
         else if ( !strcmp( s, "version/force"   ) ) version_force   = true;
         else if ( !strcmp( s, "version/reduce"  ) ) version_reduce  = true;
      }
   }

   tmp = json_object_get( val, "height" );
   if ( !tmp || !json_is_integer( tmp ) )
   {
      applog( LOG_ERR, "JSON invalid height" );
      goto out;
   }
   work->height = (int) json_integer_value( tmp );

   tmp = json_object_get(val, "version");
   if ( !tmp || !json_is_integer( tmp ) )
   {
      applog( LOG_ERR, "JSON invalid version" );
      goto out;
   }
   version = (uint32_t) json_integer_value( tmp );
   // yescryptr8g uses block version 5 and sapling.
   if ( opt_sapling )
      work->sapling = true;
   if ( (version & 0xffU) > BLOCK_VERSION_CURRENT )
   {
      if ( version_reduce )
         version = ( version & ~0xffU ) | BLOCK_VERSION_CURRENT;
      else if ( have_gbt && allow_getwork && !version_force )
      {
         applog( LOG_DEBUG, "Switching to getwork, gbt version %d", version );
         have_gbt = false;
         goto out;
      }
      else if ( !version_force )
      {
         applog(LOG_ERR, "Unrecognized block version: %u", version);
         goto out;
      }
   }

   if ( unlikely( !jobj_binary(val, "previousblockhash", prevhash,
        sizeof(prevhash)) ) )
   {
      applog( LOG_ERR, "JSON invalid previousblockhash" );
      goto out;
   }

   tmp = json_object_get( val, "curtime" );
   if ( !tmp || !json_is_integer( tmp ) )
   {
      applog( LOG_ERR, "JSON invalid curtime" );
      goto out;
   }
   curtime = (uint32_t) json_integer_value(tmp);

   if ( unlikely( !jobj_binary( val, "bits", &bits, sizeof(bits) ) ) )
   {
      applog(LOG_ERR, "JSON invalid bits");
      goto out;
   }

   if ( work->sapling )
   {
      if ( unlikely( !jobj_binary( val, "finalsaplingroothash",
                  final_sapling_hash, sizeof(final_sapling_hash) ) ) )
      {
         applog( LOG_ERR, "JSON invalid finalsaplingroothash" );
         goto out;
      }
   }

   /* find count and size of transactions */
   txa = json_object_get(val, "transactions" );
   if ( !txa || !json_is_array( txa ) )
   {
      applog( LOG_ERR, "JSON invalid transactions" );
      goto out;
   }
   tx_count = (int) json_array_size( txa );
   tx_size = 0;
   for ( i = 0; i < tx_count; i++ )
   {
      const json_t *tx = json_array_get( txa, i );
      const char *tx_hex = json_string_value( json_object_get( tx, "data" ) );
      if ( !tx_hex )
      {
         applog( LOG_ERR, "JSON invalid transactions" );
         goto out;
      }
      tx_size += (int) ( strlen( tx_hex ) / 2 );
   }

   /* build coinbase transaction */
   tmp = json_object_get( val, "coinbasetxn" );
   if ( tmp )
   {
      const char *cbtx_hex = json_string_value( json_object_get( tmp, "data" ));
      cbtx_size = cbtx_hex ? (int) strlen( cbtx_hex ) / 2 : 0;
      cbtx = (uchar*) malloc( cbtx_size + 100 );
      if ( cbtx_size < 60 || !hex2bin( cbtx, cbtx_hex, cbtx_size ) )
      {
         applog( LOG_ERR, "JSON invalid coinbasetxn" );
         goto out;
      }
   }
   else
   {
      int64_t cbvalue;
      if ( !pk_script_size )
      {
         if ( allow_getwork )
         {
            applog( LOG_INFO, "No payout address provided, switching to getwork");
            have_gbt = false;
         }
         else
            applog( LOG_ERR, "No payout address provided" );
         goto out;
      }
      tmp = json_object_get( val, "coinbasevalue" );
      if ( !tmp || !json_is_number( tmp ) )
      {
         applog( LOG_ERR, "JSON invalid coinbasevalue" );
         goto out;
      }
      cbvalue = (int64_t) ( json_is_integer( tmp ) ? json_integer_value( tmp )
                                                   : json_number_value( tmp ) );
      cbtx = (uchar*) malloc(256);
      le32enc( (uint32_t *)cbtx, 1 ); /* version */
      cbtx[4] = 1; /* in-counter */
      memset( cbtx+5, 0x00, 32 ); /* prev txout hash */
      le32enc( (uint32_t *)(cbtx+37), 0xffffffff ); /* prev txout index */
      cbtx_size = 43;
      /* BIP 34: height in coinbase */
      for ( n = work->height; n; n >>= 8 )
         cbtx[cbtx_size++] = n & 0xff;
      /* If the last byte pushed is >= 0x80, then we need to add
         another zero byte to signal that the block height is a
         positive number.  */
      if (cbtx[cbtx_size - 1] & 0x80)
         cbtx[cbtx_size++] = 0;
      cbtx[42] = cbtx_size - 43;
      cbtx[41] = cbtx_size - 42; /* scriptsig length */
      le32enc( (uint32_t *)( cbtx+cbtx_size ), 0xffffffff ); /* sequence */
      cbtx_size += 4;
      cbtx[cbtx_size++] = segwit ? 2 : 1; /* out-counter */
      le32enc( (uint32_t *)( cbtx+cbtx_size) , (uint32_t)cbvalue ); /* value */
      le32enc( (uint32_t *)( cbtx+cbtx_size+4 ), cbvalue >> 32 );
      cbtx_size += 8;
      cbtx[ cbtx_size++ ] = (uint8_t) pk_script_size; /* txout-script length */
      memcpy( cbtx+cbtx_size, pk_script, pk_script_size );
      cbtx_size += (int) pk_script_size;

       if ( segwit )
       {
          unsigned char (*wtree)[32] = calloc(tx_count + 2, 32);
         memset(cbtx+cbtx_size, 0, 8); /* value */
         cbtx_size += 8;
         cbtx[cbtx_size++] = 38; /* txout-script length */
         cbtx[cbtx_size++] = 0x6a; /* txout-script */
         cbtx[cbtx_size++] = 0x24;
         cbtx[cbtx_size++] = 0xaa;
         cbtx[cbtx_size++] = 0x21;
         cbtx[cbtx_size++] = 0xa9;
         cbtx[cbtx_size++] = 0xed;
         for ( i = 0; i < tx_count; i++ )
         {
            const json_t *tx = json_array_get( txa, i );
            const json_t *hash = json_object_get(tx, "hash" );
            if ( !hash || !hex2bin( wtree[1+i],
                                    json_string_value( hash ), 32 ) )
            {
               applog(LOG_ERR, "JSON invalid transaction hash");
               free(wtree);
               goto out;
            }
            memrev( wtree[1+i], 32 );
         }
         n = tx_count + 1;
         while ( n > 1 )
         {
            if ( n % 2 )
               memcpy( wtree[n], wtree[n-1], 32 );
            n = ( n + 1 ) / 2;
            for ( i = 0; i < n; i++ )
               sha256d( wtree[i], wtree[2*i], 64 );
         }
         memset( wtree[1], 0, 32 );  // witness reserved value = 0
         sha256d( cbtx+cbtx_size, wtree[0], 64 );
         cbtx_size += 32;
         free( wtree );
      }

      le32enc( (uint32_t *)( cbtx+cbtx_size ), 0 ); /* lock time */
      cbtx_size += 4;
      coinbase_append = true;
   }
   if ( coinbase_append )
   {
      unsigned char xsig[100];
      int xsig_len = 0;
      if ( *coinbase_sig )
      {
         n = (int) strlen( coinbase_sig );
         if ( cbtx[41] + xsig_len + n <= 100 )
         {
            memcpy( xsig+xsig_len, coinbase_sig, n );
            xsig_len += n;
         }
         else
            applog( LOG_WARNING,
                        "Signature does not fit in coinbase, skipping" );
      }
      tmp = json_object_get( val, "coinbaseaux" );
      if ( tmp && json_is_object( tmp ) )
      {
         void *iter = json_object_iter( tmp );
         while ( iter )
         {
            unsigned char buf[100];
            const char *s = json_string_value( json_object_iter_value( iter ) );
            n = s ? (int) ( strlen(s) / 2 ) : 0;
            if ( !s || n > 100 || !hex2bin( buf, s, n ) )
            {
               applog(LOG_ERR, "JSON invalid coinbaseaux");
               break;
            }
            if ( cbtx[41] + xsig_len + n <= 100 )
            {
               memcpy( xsig+xsig_len, buf, n );
               xsig_len += n;
            }
            iter = json_object_iter_next( tmp, iter );
         }
      }
      if ( xsig_len )
      {
         unsigned char *ssig_end = cbtx + 42 + cbtx[41];
         int push_len = cbtx[41] + xsig_len < 76
                        ? 1 : cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
         n = xsig_len + push_len;
         memmove( ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41] );
         cbtx[41] += n;
         if ( push_len == 2 )
            *(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
         if ( push_len )
            *(ssig_end++) = xsig_len;
         memcpy( ssig_end, xsig, xsig_len );
         cbtx_size += n;
      }
   }

   n = varint_encode( txc_vi, 1 + tx_count );
   work->txs = (char*) malloc( 2 * ( n + cbtx_size + tx_size ) + 1 );
   bin2hex( work->txs, txc_vi, n );
   bin2hex( work->txs + 2*n, cbtx, cbtx_size );

   /* generate merkle root */
   merkle_tree = (uchar(*)[32]) calloc( ( (1 + tx_count + 1) & ~1 ), 32 );
   sha256d( merkle_tree[0], cbtx, cbtx_size );
   for ( i = 0; i < tx_count; i++ )
   {
      tmp = json_array_get( txa, i );
      const char *tx_hex = json_string_value( json_object_get( tmp, "data" ) );
      const int tx_size = tx_hex ? (int) ( strlen( tx_hex ) / 2 ) : 0;

      if ( segwit )
      {
         const char *txid = json_string_value( json_object_get( tmp, "txid" ) );
         if ( !txid || !hex2bin( merkle_tree[1 + i], txid, 32 ) )
         {
            applog(LOG_ERR, "JSON invalid transaction txid");
            goto out;
         }
         memrev( merkle_tree[1 + i], 32 );
      }
      else
      {
         unsigned char *tx = (uchar*) malloc( tx_size );
         if ( !tx_hex || !hex2bin( tx, tx_hex, tx_size ) )
         {
            applog( LOG_ERR, "JSON invalid transactions" );
            free( tx );
            goto out;
         }
         sha256d( merkle_tree[1 + i], tx, tx_size );
         free( tx );
      }

      if ( !submit_coinbase )
         strcat( work->txs, tx_hex );
   }
   n = 1 + tx_count;
   while ( n > 1 )
   {
      if ( n % 2 )
      {
         memcpy( merkle_tree[n], merkle_tree[n-1], 32 );
         ++n;
      }
      n /= 2;
      for ( i = 0; i < n; i++ )
         sha256d( merkle_tree[i], merkle_tree[2*i], 64 );
   }

   work->tx_count = tx_count;

   /* assemble block header */
   algo_gate.build_block_header( work, bswap_32( version ),
                                 (uint32_t*) prevhash, (uint32_t*) merkle_tree,
                                 bswap_32( curtime ), le32dec( &bits ),
                                 final_sapling_hash );

   if ( unlikely( !jobj_binary( val, "target", target, sizeof(target) ) ) )
   {
      applog( LOG_ERR, "JSON invalid target" );
      goto out;
   }

   // reverse the bytes in target
   casti_v128( work->target, 0 ) = v128_bswap128( casti_v128( target, 1 ) );
   casti_v128( work->target, 1 ) = v128_bswap128( casti_v128( target, 0 ) );
   net_diff = work->targetdiff = hash_to_diff( work->target );

   tmp = json_object_get( val, "workid" );
   if ( tmp )
   {
      if ( !json_is_string( tmp ) )
      {
         applog( LOG_ERR, "JSON invalid workid" );
         goto out;
      }
      work->workid = strdup( json_string_value( tmp ) );
   }

   rc = true;
out:
   /* Long polling */
   tmp = json_object_get( val, "longpollid" );
   if ( want_longpoll && json_is_string( tmp ) )
   {
      free( lp_id );
      lp_id = strdup( json_string_value( tmp ) );
      if ( !have_longpoll )
      {
         char *lp_uri;
         tmp = json_object_get( val, "longpolluri" );
         lp_uri = json_is_string( tmp ) ? strdup( json_string_value( tmp ) )
                                        : rpc_url;
         have_longpoll = true;
         tq_push(thr_info[longpoll_thr_id].q, lp_uri);
      }
   }

   free( merkle_tree );
   free( cbtx );
   return rc;
}

// Does not account for leap years.
static inline void sprintf_et( char *str, long unsigned int seconds )
{
   long unsigned int minutes = seconds / 60;
   if ( minutes )
   {
      long unsigned int hours = minutes / 60;
      if ( hours )
      {
         long unsigned int days = hours / 24;
         if ( days )
         {
            long unsigned int years = days / 365;
            if ( years )   
               sprintf( str, "%luy%03lud", years, days % 365 ); // 0y000d
            else
               sprintf( str, "%lud%02luh", days, hours % 24 );  // 0d00h
         }
         else
            sprintf( str, "%luh%02lum", hours, minutes % 60 );  // 0h00m
      }
      else
         sprintf( str, "%lum%02lus", minutes, seconds % 60 );   // 0m00s
   }
   else
      sprintf( str, "%lus", seconds );   // 0s
}      

const long double exp32  = EXP32;                                 // 2**32
const long double exp48  = EXP32 * EXP16;                         // 2**48
const long double exp64  = EXP32 * EXP32;                         // 2**64
const long double exp96  = EXP32 * EXP32 * EXP32;                 // 2**96
const long double exp128 = EXP32 * EXP32 * EXP32 * EXP32;         // 2**128
const long double exp160 = EXP32 * EXP32 * EXP32 * EXP32 * EXP16; // 2**160

struct share_stats_t
{
   int share_count;
   struct timeval submit_time;
   double net_diff;
   double share_diff;
   double stratum_diff;
   double target_diff;
   uint32_t height;
   char   job_id[32];
};

#define s_stats_size 8
static struct share_stats_t share_stats[ s_stats_size ] = {{0}};
static int s_get_ptr = 0, s_put_ptr = 0;
static struct timeval last_submit_time = {0};

static inline int stats_ptr_incr( int p )
{
   return ++p % s_stats_size;
}

void report_summary_log( bool force )
{
   struct timeval now, et, uptime, start_time;

  if ( rejected_share_count > 10 )
  {
     if ( rejected_share_count > ( submitted_share_count / 2 ) )
     {
        applog(LOG_ERR,"Excessive rejected share rate, exiting...");
        exit(1);
     } 
     else if ( rejected_share_count > ( submitted_share_count / 10 ) )
       applog(LOG_WARNING,"High rejected share rate, check settings.");
   }

   gettimeofday( &now, NULL );
   timeval_subtract( &et, &now, &five_min_start );

#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32) || defined(__APPLE__))

   // Display CPU temperature and clock rate.
   int curr_temp = cpu_temp(0); 
   static struct timeval cpu_temp_time = {0};
   struct timeval diff;

   if ( !opt_quiet || ( curr_temp >= 80 ) )
   {
      int wait_time = curr_temp >= 90 ? 5
                    : curr_temp >= 80 ? 30
                    : curr_temp >= 70 ? 60 : 120;
      timeval_subtract( &diff, &now, &cpu_temp_time );
      if ( ( diff.tv_sec > wait_time )
        || ( ( curr_temp > prev_temp ) && ( curr_temp >= 75 ) ) )
      {
         char tempstr[32];
         float lo_freq = 0., hi_freq = 0.;

         memcpy( &cpu_temp_time, &now, sizeof(cpu_temp_time) );
         linux_cpu_hilo_freq( &lo_freq, &hi_freq );
         if ( use_colors && ( curr_temp >= 70 ) )
         {
            if ( curr_temp >= 80 )
               sprintf( tempstr, "%s%d C%s", CL_RED, curr_temp, CL_WHT );
            else
               sprintf( tempstr, "%s%d C%s", CL_YLW, curr_temp, CL_WHT );
         }
         else
            sprintf( tempstr, "%d C", curr_temp );

         applog( LOG_NOTICE,"CPU temp: curr %s max %d, Freq: %.3f/%.3f GHz",
                 tempstr, hi_temp, lo_freq / 1e6, hi_freq / 1e6 );
         if ( curr_temp > hi_temp ) hi_temp = curr_temp;
         if ( ( opt_max_temp > 0.0 ) && ( curr_temp > opt_max_temp ) )
            restart_threads();
         prev_temp = curr_temp;
      }
   }

#endif

   if ( !( force && ( submit_sum || ( et.tv_sec > 5 ) ) ) )
   {
      if ( et.tv_sec < 300 )
         return;
      if ( ( s_get_ptr != s_put_ptr ) && ( et.tv_sec < 360 ) )
         return;
   }
   
//   if ( !( force && ( submit_sum || ( et.tv_sec > 5 ) ) )
//     && ( et.tv_sec < 300 ) )
//      return;
   
   // collect and reset periodic counters
   pthread_mutex_lock( &stats_lock );

   uint64_t submits = submit_sum;  submit_sum = 0;
   uint64_t accepts = accept_sum;  accept_sum = 0;
   uint64_t rejects = reject_sum;  reject_sum = 0;
   uint64_t stales  = stale_sum;   stale_sum  = 0;
   uint64_t solved  = solved_sum;  solved_sum = 0;
   memcpy( &start_time, &five_min_start, sizeof start_time );
   memcpy( &five_min_start, &now, sizeof now );

   pthread_mutex_unlock( &stats_lock );

   timeval_subtract( &et, &now, &start_time );
   timeval_subtract( &uptime, &total_hashes_time, &session_start );
   
   double share_time = (double)et.tv_sec + (double)et.tv_usec * 1e-6;
   double ghrate = safe_div( total_hashes, (double)uptime.tv_sec, 0. );
   double target_diff = exp32 * last_targetdiff;
   double shrate = safe_div( target_diff * (double)(accepts),
                             share_time, 0. );
   double sess_hrate = safe_div( exp32 * norm_diff_sum,
                                 (double)uptime.tv_sec, 0. );
   double submit_rate = safe_div( (double)submits * 60., share_time, 0. );
   char shr_units[4] = {0};
   char ghr_units[4] = {0};
   char sess_hr_units[4] = {0};
   char et_str[24];
   char upt_str[24];

   scale_hash_for_display( &shrate, shr_units );
   scale_hash_for_display( &ghrate, ghr_units );
   scale_hash_for_display( &sess_hrate, sess_hr_units );

   sprintf_et( et_str, et.tv_sec );
   sprintf_et( upt_str, uptime.tv_sec );

   applog( LOG_BLUE, "%s: %s", algo_names[ opt_algo ], rpc_url );
   applog2( LOG_NOTICE, "Periodic Report     %s        %s", et_str, upt_str );
   applog2( LOG_INFO, "Share rate        %.2f/min     %.2f/min",
            submit_rate, safe_div( (double)submitted_share_count*60.,
              ( (double)uptime.tv_sec + (double)uptime.tv_usec * 1e-6 ), 0. ) );
   applog2( LOG_INFO, "Hash rate       %7.2f%sh/s   %7.2f%sh/s   (%.2f%sh/s)",
            shrate, shr_units, sess_hrate, sess_hr_units, ghrate, ghr_units );

   if ( accepted_share_count < submitted_share_count )
   {
      double lost_ghrate = safe_div( target_diff
                    * (double)(submitted_share_count - accepted_share_count ),
                    (double)uptime.tv_sec, 0. );
      double lost_shrate = safe_div( target_diff * (double)(submits - accepts ),                                     share_time, 0. );
      char lshr_units[4] = {0};
      char lghr_units[4] = {0};
      scale_hash_for_display( &lost_shrate, lshr_units );
      scale_hash_for_display( &lost_ghrate, lghr_units );
      applog2( LOG_INFO, "Lost hash rate  %7.2f%sh/s    %7.2f%sh/s",
               lost_shrate, lshr_units, lost_ghrate, lghr_units );
   }

   applog2( LOG_INFO,"Submitted       %7d      %7d",
               submits, submitted_share_count );
   applog2( LOG_INFO, "Accepted        %7d      %7d      %5.1f%%",
                      accepts, accepted_share_count,
                      100. * safe_div( (double)accepted_share_count, 
                                       (double)submitted_share_count, 0. ) ); 
   if ( stale_share_count )
   {
      int prio = stales ? LOG_MINR : LOG_INFO;
      applog2( prio, "Stale           %7d      %7d      %5.1f%%",
                      stales, stale_share_count,
                      100. * safe_div( (double)stale_share_count,
                                       (double)submitted_share_count, 0. ) );
   }
   if ( rejected_share_count )
   {
      int prio = rejects ? LOG_ERR : LOG_INFO;
      applog2( prio, "Rejected        %7d      %7d      %5.1f%%",
                      rejects, rejected_share_count,
                      100. * safe_div( (double)rejected_share_count,
                                       (double)submitted_share_count, 0. ) );
   }
   if ( solved_block_count )
   {      
      int prio = solved ? LOG_PINK : LOG_INFO;
      applog2( prio, "Blocks Solved   %7d      %7d",
               solved, solved_block_count );
   }
   if ( stratum_errors )
      applog2( LOG_INFO, "Stratum resets               %7d", stratum_errors );

   applog2( LOG_INFO, "Hi/Lo Share Diff  %.5g /  %.5g",
            highest_share, lowest_share );

   int mismatch = submitted_share_count
         - ( accepted_share_count + stale_share_count + rejected_share_count );

   if ( mismatch )
   {
      if ( stratum_errors )
         applog2( LOG_MINR, "Count mismatch: %d, stats may be inaccurate",
                            mismatch );
      else if ( !opt_quiet )
         applog2( LOG_INFO, CL_LBL
                  "Count mismatch, submitted share may still be pending" CL_N );
   }
}

static int share_result( int result, struct work *work,
                         const char *reason )
{
   double share_time = 0.; 
   double hashrate = 0.;
   int latency = 0;
   struct share_stats_t my_stats = {0};
   struct timeval ack_time, latency_tv, et;
   char ares[48];
   char sres[48];
   char rres[48];
   char bres[48];
   bool solved = false; 
   bool stale = false;
   char *acol, *bcol, *scol, *rcol;
   acol = bcol = scol = rcol = "\0";

   pthread_mutex_lock( &stats_lock );

   if ( likely( share_stats[ s_get_ptr ].submit_time.tv_sec ) )
   {
      memcpy( &my_stats, &share_stats[ s_get_ptr], sizeof my_stats );
      memset( &share_stats[ s_get_ptr ], 0, sizeof my_stats );
      s_get_ptr = stats_ptr_incr( s_get_ptr );
      pthread_mutex_unlock( &stats_lock );
   }
   else
   {
      // empty queue, it must have overflowed and stats were lost for a share.
      pthread_mutex_unlock( &stats_lock );
      applog(LOG_WARNING,"Share stats not available.");
   }

   // calculate latency and share time.
   if likely( my_stats.submit_time.tv_sec )
   {
      gettimeofday( &ack_time, NULL );
      timeval_subtract( &latency_tv, &ack_time, &my_stats.submit_time );
      latency = ( latency_tv.tv_sec * 1e3  + latency_tv.tv_usec / 1e3 );
      timeval_subtract( &et, &my_stats.submit_time, &last_submit_time );
      share_time = (double)et.tv_sec + ( (double)et.tv_usec / 1e6 );
      memcpy( &last_submit_time, &my_stats.submit_time,
              sizeof last_submit_time );
   }

   // check result
   if ( likely( result ) )
   {
      accepted_share_count++;
      if ( ( my_stats.share_diff > 0. ) 
        && ( my_stats.share_diff < lowest_share ) )
         lowest_share = my_stats.share_diff;
      if ( my_stats.share_diff > highest_share )
         highest_share = my_stats.share_diff;
      sprintf( sres, "S%d", stale_share_count );
      sprintf( rres, "R%d", rejected_share_count );
      if unlikely( ( my_stats.net_diff > 0. )
                && ( my_stats.share_diff >= my_stats.net_diff ) )
      {
         solved = true;
         solved_block_count++;
         sprintf( bres, "BLOCK SOLVED %d", solved_block_count );
         sprintf( ares, "A%d", accepted_share_count );
      }
      else
      {
         sprintf( bres, "B%d", solved_block_count );
         sprintf( ares, "Accepted %d", accepted_share_count );
      }
   }
   else
   {
     sprintf( ares, "A%d", accepted_share_count );
     sprintf( bres, "B%d", solved_block_count );
     if ( reason )
        stale = strstr( reason, "job" );
     else if ( work )
        stale =  work->data[ algo_gate.ntime_index ]
             != g_work.data[ algo_gate.ntime_index ];
     if ( stale )
     {
        stale_share_count++;
        sprintf( sres, "Stale %d", stale_share_count );
        sprintf( rres, "R%d", rejected_share_count );
     }
     else
     {
        rejected_share_count++;
        sprintf( sres, "S%d", stale_share_count );
        sprintf( rres, "Rejected %d" , rejected_share_count );
     }
   }

   // update global counters for summary report
   pthread_mutex_lock( &stats_lock );

   for ( int i = 0; i < opt_n_threads; i++ )
       hashrate += thr_hashrates[i];
   global_hashrate = hashrate;
   
   if ( likely( result ) )
   {
      accept_sum++;
      norm_diff_sum += my_stats.target_diff;
      if ( solved ) solved_sum++;
   }
   else
   {
      if ( stale )  stale_sum++;
      else          reject_sum++;
   }
   submit_sum++;

   pthread_mutex_unlock( &stats_lock );

   if ( use_colors )
   {
     bcol = acol = scol = rcol = CL_N;
     if ( likely( result ) )
     {
       acol = CL_LGR;       
       if ( unlikely( solved ) ) bcol = CL_LMA;
     }        
     else if ( stale ) scol = CL_YL2;
     else              rcol = CL_LRD;
   }

   const char *bell = !result && opt_bell ? &ASCII_BELL : "";
   applog( LOG_INFO, "%s%d %s%s %s%s %s%s %s%s%s, %.3f sec (%dms)",
           bell, my_stats.share_count, acol, ares, scol, sres, rcol, rres,
           bcol, bres, use_colors ? CL_N : "", share_time, latency );
   if ( unlikely( !( opt_quiet || result || stale ) ) )
   {
      applog2( LOG_INFO, "%sReject reason: %s", bell, reason ? reason : "" );
      applog2( LOG_INFO, "Share diff: %.5g, Target: %.5g",
                        my_stats.share_diff, my_stats.target_diff );
   }
   return 1;
}

static const char *json_submit_req =
   "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}";

void std_le_build_stratum_request( char *req, struct work *work )
{
   unsigned char *xnonce2str;
   uint32_t ntime,       nonce;
   char     ntimestr[9], noncestr[9];
   le32enc( &ntime, work->data[ algo_gate.ntime_index ] );
   le32enc( &nonce, work->data[ algo_gate.nonce_index ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex( work->xnonce2, work->xnonce2_len );
   snprintf( req, JSON_BUF_LEN, json_submit_req, rpc_user, work->job_id,
             xnonce2str, ntimestr, noncestr );
   free( xnonce2str );
}

// le is default
void std_be_build_stratum_request( char *req, struct work *work )
{
   unsigned char *xnonce2str;
   uint32_t ntime,       nonce;
   char     ntimestr[9], noncestr[9];
   be32enc( &ntime, work->data[ algo_gate.ntime_index ] );
   be32enc( &nonce, work->data[ algo_gate.nonce_index ] );
   bin2hex( ntimestr, (char*)(&ntime), sizeof(uint32_t) );
   bin2hex( noncestr, (char*)(&nonce), sizeof(uint32_t) );
   xnonce2str = abin2hex( work->xnonce2, work->xnonce2_len );
   snprintf( req, JSON_BUF_LEN, json_submit_req, rpc_user, work->job_id,
             xnonce2str, ntimestr, noncestr );
   free( xnonce2str );
}

static const char *json_getwork_req = 
  "{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n";

bool std_le_submit_getwork_result( CURL *curl, struct work *work )
{
   char req[JSON_BUF_LEN];
   json_t *val, *res, *reason;
   char* gw_str;
   int data_size = algo_gate.get_work_data_size();

   for ( int i = 0; i < data_size / sizeof(uint32_t); i++ )
     le32enc( &work->data[i], work->data[i] );
   gw_str = abin2hex( (uchar*)work->data, data_size );
   if ( unlikely( !gw_str ) )
   {
      applog(LOG_ERR, "submit_upstream_work OOM");
      return false;
   }
   // build JSON-RPC request 
   snprintf( req, JSON_BUF_LEN, json_getwork_req, gw_str );
   free( gw_str );
   // issue JSON-RPC request 
   val = json_rpc_call( curl, rpc_url, rpc_userpass, req, NULL, 0 );
   if ( unlikely(!val) )
   {
       applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
       return false;
   }
   res = json_object_get( val, "result" );
   reason = json_object_get( val, "reject-reason" );
   share_result( json_is_true( res ), work,
                 reason ? json_string_value( reason ) : NULL );
   json_decref( val );
   return true;
}

bool std_be_submit_getwork_result( CURL *curl, struct work *work )
{
   char req[JSON_BUF_LEN];
   json_t *val, *res, *reason;
   char* gw_str;
   int data_size = algo_gate.get_work_data_size();

   for ( int i = 0; i < data_size / sizeof(uint32_t); i++ )
     be32enc( &work->data[i], work->data[i] );
   gw_str = abin2hex( (uchar*)work->data, data_size );
   if ( unlikely( !gw_str ) )
   {
      applog(LOG_ERR, "submit_upstream_work OOM");
      return false;
   }
   // build JSON-RPC request 
   snprintf( req, JSON_BUF_LEN, json_getwork_req, gw_str );
   free( gw_str );
   // issue JSON-RPC request 
   val = json_rpc_call( curl, rpc_url, rpc_userpass, req, NULL, 0 );
   if ( unlikely(!val) )
   {
       applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
       return false;
   }
   res = json_object_get( val, "result" );
   reason = json_object_get( val, "reject-reason" );
   share_result( json_is_true( res ), work,
                 reason ? json_string_value( reason ) : NULL );
   json_decref( val );
   return true;
}

char* std_malloc_txs_request( struct work *work )
{
  char *req;
  json_t *val;
  char data_str[2 * sizeof(work->data) + 1];
  int i;
  // datasize is an ugly hack, it should go through the gate
  int datasize = work->sapling ? 112 : 80;

  for ( i = 0; i < ARRAY_SIZE(work->data); i++ )
     be32enc( work->data + i, work->data[i] );
  bin2hex( data_str, (unsigned char *)work->data, datasize );
  if ( work->workid )
  {
    char *params;
    val = json_object();
    json_object_set_new( val, "workid", json_string( work->workid ) );
    params = json_dumps( val, 0 );
    json_decref( val );
    req = (char*) malloc( 128 + 2 * datasize + strlen( work->txs )
                            + strlen( params ) );
    sprintf( req,
     "{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":4}\r\n",
      data_str, work->txs, params );
    free( params );
  }
  else
  {
    req = (char*) malloc( 128 + 2 * datasize + strlen( work->txs ) );
    sprintf( req,
         "{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
         data_str, work->txs);
  }
  return req;
} 

static bool submit_upstream_work( CURL *curl, struct work *work )
{
   if ( have_stratum )
   {
       char req[JSON_BUF_LEN];
       stratum.sharediff = work->sharediff;
       algo_gate.build_stratum_request( req, work, &stratum );
       if ( unlikely( !stratum_send_line( &stratum, req ) ) )
       {
          applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
          return false;
       }
       return true;
   }
   else if ( work->txs )
   {
      char *req = NULL;
      json_t *val, *res;

      req = algo_gate.malloc_txs_request( work );
      val = json_rpc_call( curl, rpc_url, rpc_userpass, req, NULL, 0 );
      free( req );

      if ( unlikely( !val ) )
      {
         applog( LOG_ERR, "submit_upstream_work json_rpc_call failed" );
         return false;
      }
      res = json_object_get( val, "result" );
      if ( json_is_object( res ) )
      {
         char *res_str;
         bool sumres = false;
         void *iter = json_object_iter( res );
         while ( iter )
         {
            if ( json_is_null( json_object_iter_value( iter ) ) )
            {
               sumres = true;
               break;
            }
            iter = json_object_iter_next( res, iter );
         }
         res_str = json_dumps( res, 0 );
         share_result( sumres, work, res_str );
         free( res_str );
      }
      else
         share_result( json_is_null( res ), work, json_string_value( res ) );
      json_decref( val );
      return true;     
   }
   else
       return algo_gate.submit_getwork_result( curl, work );
}

const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

#define GBT_RULES "[\"segwit\"]"

static const char *gbt_req =
   "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
   GBT_CAPABILITIES ", \"rules\": " GBT_RULES "}], \"id\":0}\r\n";
const char *gbt_lp_req =
   "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
   GBT_CAPABILITIES ", \"rules\": " GBT_RULES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

static bool get_upstream_work( CURL *curl, struct work *work )
{
   json_t *val;
   int err;
   bool rc;
   struct timeval tv_start, tv_end, diff;

start:
   gettimeofday( &tv_start, NULL );

   val = json_rpc_call( curl, rpc_url, rpc_userpass,
		           have_gbt ? gbt_req : getwork_req, &err,
                           have_gbt ? JSON_RPC_QUIET_404 : 0);
 
   gettimeofday( &tv_end, NULL );

   if ( have_stratum )
   {
      if ( val )
         json_decref(val);

      return true;
   }

   if ( !have_gbt && !allow_getwork )
   {
      applog( LOG_ERR, "No usable protocol" );
      if ( val )
         json_decref( val );
      return false;
   }

   if ( have_gbt && allow_getwork && !val && err == CURLE_OK )
   {
      applog( LOG_NOTICE, "getblocktemplate failed, falling back to getwork" );
      have_gbt = false;
      goto start;
   }

   if ( !val )
      return false;

   if ( have_gbt )
   {
      rc = gbt_work_decode( json_object_get( val, "result" ), work );
      if ( !have_gbt )
      {
         json_decref( val );
         goto start;
      }
      allow_getwork = false;  // GBT is working, disable fallback
   } 
   else
      rc = work_decode( json_object_get( val, "result" ), work );

   if ( rc ) 
   {
      bool new_work = true;

      json_decref( val );

      get_mininginfo( curl, work );
      report_summary_log( false );
      
      if ( opt_protocol || opt_debug )
      {
         timeval_subtract( &diff, &tv_end, &tv_start );
         applog( LOG_INFO, "%s new work received in %.2f ms",
              ( have_gbt ? "GBT" : "GetWork" ),
              ( 1000.0 * diff.tv_sec ) + ( 0.001 * diff.tv_usec ) );
      }

      if ( work->height > last_block_height )
      {
         last_block_height = work->height;
         last_targetdiff = net_diff;

         applog( LOG_BLUE, "New Block %d, Tx %d, Net Diff %.5g, Ntime %08x",
                             work->height, work->tx_count, net_diff,
                             bswap_32( work->data[ algo_gate.ntime_index ] ) );
      }
      else if ( memcmp( work->data, g_work.data, algo_gate.work_cmp_size ) )
         applog( LOG_BLUE, "New Work: Block %d, Tx %d, Net Diff %.5g, Ntime %08x",
                             work->height, work->tx_count, net_diff,
                             bswap_32( work->data[ algo_gate.ntime_index ] ) );
      else
        new_work = false;

      if ( new_work )
      {
         if ( !opt_quiet )
         {
            double miner_hr = 0.;
            double net_hr = net_hashrate;
            double nd = net_diff * exp32;
            char net_hr_units[4] = {0};
            char miner_hr_units[4] = {0};
            char net_ttf[32];
            char miner_ttf[32];

            pthread_mutex_lock( &stats_lock );

            for ( int i = 0; i < opt_n_threads; i++ )
               miner_hr += thr_hashrates[i];
            global_hashrate = miner_hr;

            pthread_mutex_unlock( &stats_lock );

            if ( net_hr > 0. )
               sprintf_et( net_ttf, nd / net_hr );
            else
               sprintf( net_ttf, "NA" );
            if ( miner_hr > 0. )
               sprintf_et( miner_ttf, nd / miner_hr );
            else
               sprintf( miner_ttf, "NA" );

            scale_hash_for_display ( &miner_hr, miner_hr_units );
            scale_hash_for_display ( &net_hr, net_hr_units );
            applog2( LOG_INFO,
                  "Miner TTF @ %.2f %sh/s %s, Net TTF @ %.2f %sh/s %s",
                  miner_hr, miner_hr_units, miner_ttf, net_hr,
                  net_hr_units, net_ttf );
         }
         restart_threads();
      }
   }  // rc

   return rc;
}

static void workio_cmd_free(struct workio_cmd *wc)
{
	if (!wc)
		return;

	switch (wc->cmd) {
	case WC_SUBMIT_WORK:
		work_free(wc->u.work);
		free(wc->u.work);
		break;
	default: /* do nothing */
		break;
	}

	memset(wc, 0, sizeof(*wc)); /* poison */
	free(wc);
}

static bool workio_get_work( struct workio_cmd *wc, CURL *curl )
{
   struct work *work_heap;
   int failures = 0;

   work_heap = calloc( 1, sizeof(struct work) );
   if ( !work_heap )  return false;

   /* obtain new work from bitcoin via JSON-RPC */
   while ( !get_upstream_work( curl, work_heap ) )
   {
      if ( unlikely( ( opt_retries >= 0 ) && ( ++failures > opt_retries ) ) )
      {
         applog( LOG_ERR, "json_rpc_call failed, terminating workio thread" );
         free( work_heap );
         return false;
      }

      /* pause, then restart work-request loop */
      applog( LOG_ERR, "json_rpc_call failed, retry after %d seconds",
              opt_fail_pause );
      sleep( opt_fail_pause );
   }

   /* send work to requesting thread */
   if ( !tq_push(wc->thr->q, work_heap ) )
      free( work_heap );

   return true;
}


static bool workio_submit_work(struct workio_cmd *wc, CURL *curl)
{
   int failures = 0;

   /* submit solution to bitcoin via JSON-RPC */
   while (!submit_upstream_work(curl, wc->u.work))
   {
	if (unlikely((opt_retries >= 0) && (++failures > opt_retries)))
        {
	   applog(LOG_ERR, "...terminating workio thread");
	   return false;
	}
        /* pause, then restart work-request loop */
        if (!opt_benchmark)
	    applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
        sleep(opt_fail_pause);
   }
   return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely( !curl ) )
   {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}

   while ( likely(ok) )
   {
		struct workio_cmd *wc;

		/* wait for workio_cmd sent to us, on our queue */
		wc = (struct workio_cmd *) tq_pop(mythr->q, NULL);
		if (!wc)
      {
			ok = false;
			break;
		}

		/* process workio_cmd */
		switch (wc->cmd)
      {
		   case WC_GET_WORK:
			   ok = workio_get_work(wc, curl);
			   break;
		   case WC_SUBMIT_WORK:
			   ok = workio_submit_work(wc, curl);
			   break;

		   default:		/* should never happen */
			   ok = false;
			   break;
		}
		workio_cmd_free(wc);
	}

   tq_freeze(mythr->q);
	curl_easy_cleanup(curl);
	return NULL;
}

static bool get_work(struct thr_info *thr, struct work *work)
{
	struct workio_cmd *wc;
   struct work *work_heap;

	if unlikely( opt_benchmark )
   {
		uint32_t ts = (uint32_t) time(NULL);

      // why 74? std cmp_size is 76, std data is 128
		for ( int n = 0; n < 74; n++ ) ( (char*)work->data )[n] = n;

      work->data[algo_gate.ntime_index] = bswap_32(ts);  // ntime
  
      // this overwrites much of the for loop init
      memset( work->data + algo_gate.nonce_index, 0x00, 52);  // nonce..nonce+52
		work->data[20] = 0x80000000; 
		work->data[31] = 0x00000280;
		return true;
	}
	/* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;
	wc->cmd = WC_GET_WORK;
	wc->thr = thr;
	/* send work request to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
   {
		workio_cmd_free(wc);
		return false;
	}
	/* wait for response, a unit of work */
	work_heap = (struct work*) tq_pop(thr->q, NULL);
	if ( !work_heap ) return false;
   /* copy returned work into storage provided by caller */
	memcpy( work, work_heap, sizeof(*work) );
	free( work_heap );
	return true;
}

static bool submit_work( struct thr_info *thr, const struct work *work_in )
{
	struct workio_cmd *wc;

   /* fill out work request message */
	wc = (struct workio_cmd *) calloc(1, sizeof(*wc));
	if (!wc)
		return false;
	wc->u.work = (struct work*) malloc(sizeof(*work_in));
	if (!wc->u.work)
		goto err_out;
	wc->cmd = WC_SUBMIT_WORK;
	wc->thr = thr;
	work_copy(wc->u.work, work_in);

	/* send solution to workio thread */
	if (!tq_push(thr_info[work_thr_id].q, wc))
		goto err_out;
	return true;
err_out:
	workio_cmd_free(wc);
	return false;
}

static void update_submit_stats( struct work *work, const void *hash )
{
   pthread_mutex_lock( &stats_lock );

   submitted_share_count++;
   share_stats[ s_put_ptr ].share_count = submitted_share_count;
   gettimeofday( &share_stats[ s_put_ptr ].submit_time, NULL );
   share_stats[ s_put_ptr ].share_diff = work->sharediff;
   share_stats[ s_put_ptr ].net_diff = net_diff;
   share_stats[ s_put_ptr ].stratum_diff = stratum_diff;
   share_stats[ s_put_ptr ].target_diff = work->targetdiff;
   share_stats[ s_put_ptr ].height = work->height; 
   if ( have_stratum )
      strncpy( share_stats[ s_put_ptr ].job_id, work->job_id, 30 );
   s_put_ptr = stats_ptr_incr( s_put_ptr );

   pthread_mutex_unlock( &stats_lock );
}

bool submit_solution( struct work *work, const void *hash,
                      struct thr_info *thr )
{
// Job went stale during hashing of a valid share.
//   if ( !opt_quiet && work_restart[ thr->id ].restart )
//      applog( LOG_INFO, CL_LBL "Share may be stale, submitting anyway..." CL_N );
   
   work->sharediff = hash_to_diff( hash );
   if ( likely( submit_work( thr, work ) ) )
   {
     update_submit_stats( work, hash );

     if unlikely( !have_stratum && !have_longpoll )
     {   // solo, block solved, force getwork
         pthread_rwlock_wrlock( &g_work_lock );
         g_work_time = 0;
         pthread_rwlock_unlock( &g_work_lock );
         restart_threads();
     }

     if ( !opt_quiet )
     {
        if ( have_stratum )
        {
           applog( LOG_INFO, "%d Submitted Diff %.5g, Block %d, Job %s",
                   submitted_share_count, work->sharediff, work->height,
                   work->job_id );
           if ( opt_debug && opt_extranonce )
           {
              unsigned char *xnonce2str = abin2hex( work->xnonce2,
                                                    work->xnonce2_len );
              applog( LOG_INFO, "Xnonce2 %s", xnonce2str );
              free( xnonce2str );
           }
        }
        else
           applog( LOG_INFO, "%d Submitted Diff %.5g, Block %d, Ntime %08x",
                   submitted_share_count, work->sharediff, work->height,
                   work->data[ algo_gate.ntime_index ] );

        if ( opt_debug )
        {
           uint32_t* h = (uint32_t*)hash;
           uint32_t* t = (uint32_t*)work->target;
           uint32_t* d = (uint32_t*)work->data;

           applog( LOG_INFO, "Data[ 0: 9]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                                                 d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9] );
           applog( LOG_INFO, "Data[10:19]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x",
                                        d[10],d[11],d[12],d[13],d[14],d[15],d[16],d[17],d[18],d[19] );
           applog( LOG_INFO, "Hash[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                                            h[7],h[6],h[5],h[4],h[3],h[2],h[1],h[0] );
           applog( LOG_INFO, "Targ[ 7: 0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                                            t[7],t[6],t[5],t[4],t[3],t[2],t[1],t[0] );
        }
     }
     return true;
   }
   else
     applog( LOG_WARNING, "%d failed to submit share", submitted_share_count );
   return false;
}

static bool wanna_mine(int thr_id)
{
	bool state = true;

#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32) || defined(__APPLE__))
  
	if (opt_max_temp > 0.0)
   {
		float temp = cpu_temp(0);
		if (temp > opt_max_temp)
      {
         if ( !thr_id && !conditional_state[thr_id] && !opt_quiet )
           applog(LOG_NOTICE, "CPU temp too high: %.0fC max %.0f, waiting...", temp, opt_max_temp );
         state = false;
		}
      if ( temp > hi_temp ) hi_temp = temp;
	}

#endif

   if (opt_max_diff > 0.0 && net_diff > opt_max_diff)
   {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
			applog(LOG_NOTICE, "network diff too high, waiting...");
		state = false;
	}
	if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate)
   {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
      {
			char rate[32];
			format_hashrate(opt_max_rate, rate);
			applog(LOG_NOTICE, "network hashrate too high (%s), waiting...", rate);
		}
		state = false;
	}
  
   if ( conditional_state[thr_id] && state && !thr_id && !opt_quiet )
      applog(LOG_NOTICE, "...resuming" );
	conditional_state[thr_id] = (uint8_t) !state;
	return state;
}

// Common target functions, default usually listed first.

// default, double sha256 for root hash
void sha256d_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha256d( merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size );
  for ( int i = 0; i < sctx->job.merkle_count; i++ )
  {
     memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
     sha256d( merkle_root, merkle_root, 64 );
  }
}
// single sha256 root hash
void sha256_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha256_full( merkle_root, sctx->job.coinbase, (int)sctx->job.coinbase_size );
  for ( int i = 0; i < sctx->job.merkle_count; i++ )
  {
     memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
     sha256d( merkle_root, merkle_root, 64 );
  }
}

// Default is do_nothing (assumed LE)
void set_work_data_big_endian( struct work *work )
{
   int nonce_index = algo_gate.nonce_index;
   for ( int i = 0; i < nonce_index; i++ )
        be32enc( work->data + i, work->data[i] );
}

void std_get_new_work( struct work* work, struct work* g_work, int thr_id,
                     uint32_t *end_nonce_ptr )
{
   uint32_t *nonceptr = work->data + algo_gate.nonce_index;
   bool force_new_work = false; 

   if ( have_stratum ) 
      force_new_work = work->job_id ?    strtoul(   work->job_id, NULL, 16 )
                                      != strtoul( g_work->job_id, NULL, 16 )
                                     : false;

   if ( force_new_work || ( *nonceptr >= *end_nonce_ptr )
     || memcmp( work->data, g_work->data, algo_gate.work_cmp_size ) )
   {
     work_free( work );
     work_copy( work, g_work );
     *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
     *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20;
   }
   else
       ++(*nonceptr);
}

static void stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   bool new_job;

   pthread_mutex_lock( &sctx->work_lock );

   new_job =  sctx->new_job;  // otherwise just increment extranonce2
   sctx->new_job = false;

   pthread_rwlock_wrlock( &g_work_lock );
   
   free( g_work->job_id );
   g_work->job_id = strdup( sctx->job.job_id );
   g_work->xnonce2_len = sctx->xnonce2_size;
   g_work->xnonce2 = (uchar*) realloc( g_work->xnonce2, sctx->xnonce2_size );
   g_work->height = sctx->block_height;
   g_work->targetdiff = sctx->job.diff
                           / ( opt_target_factor * opt_diff_factor );
   memcpy( g_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size );
   algo_gate.build_extraheader( g_work, sctx );
   net_diff = nbits_to_diff( g_work->data[ algo_gate.nbits_index ] );
   algo_gate.set_work_data_endian( g_work );
   diff_to_hash( g_work->target, g_work->targetdiff );

   g_work_time = time(NULL);
   restart_threads();
   pthread_rwlock_unlock( &g_work_lock );

   // Pre increment extranonce2 in case of being called again before receiving
   // a new job
   for ( int t = 0;
         t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] );
         t++ );

   pthread_mutex_unlock( &sctx->work_lock );

   pthread_mutex_lock( &stats_lock );

   double hr = 0.;
   for ( int i = 0; i < opt_n_threads; i++ )
      hr += thr_hashrates[i];
   global_hashrate = hr;

   pthread_mutex_unlock( &stats_lock );

   if ( stratum_diff != sctx->job.diff )
      applog( LOG_BLUE, "New Stratum Diff %g, Block %d, Tx %d, Job %s",
                        sctx->job.diff, sctx->block_height,
                        sctx->job.merkle_count, g_work->job_id );
   else if ( last_block_height != sctx->block_height )
      applog( LOG_BLUE, "New Block %d, Tx %d, Netdiff %.5g, Job %s",
                        sctx->block_height, sctx->job.merkle_count,
                        net_diff, g_work->job_id );
   else if ( g_work->job_id && new_job )
      applog( LOG_BLUE, "New Work: Block %d, Tx %d, Netdiff %.5g, Job %s",
                         sctx->block_height, sctx->job.merkle_count,
                         net_diff, g_work->job_id );
   else if ( opt_debug )
   {
      unsigned char *xnonce2str = bebin2hex( g_work->xnonce2,
                                             g_work->xnonce2_len );
      applog( LOG_INFO, "Extranonce2 0x%s, Block %d, Job %s",
                        xnonce2str, sctx->block_height, g_work->job_id );
      free( xnonce2str );
   }

   // Update data and calculate new estimates.
   if ( ( stratum_diff != sctx->job.diff )
     || ( last_block_height != sctx->block_height ) )
   {
      if ( unlikely( !session_first_block ) )
         session_first_block = stratum.block_height;
      last_block_height = stratum.block_height;
      stratum_diff      = sctx->job.diff;
      last_targetdiff   = g_work->targetdiff;
      if ( lowest_share < last_targetdiff )
         lowest_share = 9e99;
    }

    if ( new_job && !opt_quiet )
    {
       applog2( LOG_INFO, "Diff: Net %.5g, Stratum %.5g, Target %.5g",
                          net_diff, stratum_diff, g_work->targetdiff );

       if ( likely( hr > 0. ) )
       {
          double nd = net_diff * exp32;
          char hr_units[4] = {0};
          char block_ttf[32];
          char share_ttf[32];
          static bool multipool = false;
      
          if ( stratum.block_height < last_block_height ) multipool = true;
            
          sprintf_et( block_ttf, nd / hr );
          sprintf_et( share_ttf, ( g_work->targetdiff * exp32 ) / hr );
          scale_hash_for_display ( &hr, hr_units );
          applog2( LOG_INFO, "TTF @ %.2f %sh/s: Block %s, Share %s",
                             hr, hr_units, block_ttf, share_ttf );

          if ( !multipool && last_block_height > session_first_block )
          {
             struct timeval now, et;
             gettimeofday( &now, NULL );
             timeval_subtract( &et, &now, &session_start );
             uint64_t net_ttf = safe_div( et.tv_sec,
                                 last_block_height - session_first_block, 0 );
             if ( net_diff > 0. && net_ttf )
             {
                double net_hr = safe_div( nd, net_ttf, 0. );
                char net_hr_units[4] = {0};
                scale_hash_for_display ( &net_hr, net_hr_units );
                applog2( LOG_INFO, "Net hash rate (est) %.2f %sh/s",
                                   net_hr, net_hr_units );
             }
          }
       }  // hr > 0
    } // !quiet
}

static void *miner_thread( void *userdata )
{
   struct   work work __attribute__ ((aligned (64))) ;
   struct   thr_info *mythr = (struct thr_info *) userdata;
   int      thr_id = mythr->id;
   uint32_t max_nonce;
   uint32_t *nonceptr = work.data + algo_gate.nonce_index;

   // end_nonce gets read before being set so it needs to be initialized
   // what is an appropriate value that is completely neutral?
   // zero seems to work. No, it breaks benchmark.
//   uint32_t end_nonce = 0;
//   uint32_t end_nonce = opt_benchmark
//                      ? ( 0xffffffffU / opt_n_threads ) * (thr_id + 1) - 0x20
//                      : 0;
   uint32_t end_nonce = 0xffffffffU / opt_n_threads  * (thr_id + 1) - opt_n_threads;

   memset( &work, 0, sizeof(work) );
 
   /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
    * and if that fails, then SCHED_BATCH. No need for this to be an
    * error if it fails */
   if ( !opt_priority )
   {
      setpriority(PRIO_PROCESS, 0, 19);
      if ( !thr_id && opt_debug )
         applog(LOG_INFO, "Default miner thread priority %d (nice 19)", opt_priority );
      drop_policy();
   }
   else
   {
      int prio = 0;
#ifndef WIN32
      prio = 18;
      // note: different behavior on linux (-19 to 19)
	   switch ( opt_priority )
      {
	      case 1:   prio =   5;   break;
	      case 2:   prio =   0;   break;
	      case 3:   prio =  -5;   break;
	      case 4:   prio = -10;   break;
	      case 5:   prio = -15;
      }
	   if ( !thr_id )
      {
         applog( LOG_INFO, "User set miner thread priority %d (nice %d)",
                          opt_priority, prio );
         applog( LOG_WARNING, "High priority mining threads may cause system instability");
      }
#endif
      setpriority(PRIO_PROCESS, 0, prio);
	   if ( opt_priority == 0 )
	      drop_policy();
   }

   // CPU thread affinity
   if ( opt_affinity && num_cpus > 1 )   affine_to_cpu( mythr );

   if ( !algo_gate.miner_thread_init( thr_id ) )
   {
      applog( LOG_ERR, "FAIL: thread %d failed to initialize", thr_id );
      exit (1);
   }

   // wait for stratum to send first job
   if ( have_stratum ) while ( unlikely( !stratum.job.job_id ) )
   {
     if ( opt_debug )
        applog( LOG_INFO, "Thread %d waiting for first job", thr_id );
     sleep(1);
   }

   // nominal startng values
   int64_t max64 = 20;
   thr_hashrates[thr_id] = 20;
   while (1)
   {
       uint64_t hashes_done;
       struct timeval tv_start, tv_end, diff;
       int nonce_found = 0;

       if ( have_stratum ) 
       {
          while ( unlikely( stratum_down ) )
             sleep( 1 );
          if ( unlikely( ( *nonceptr >= end_nonce )
                        && !work_restart[thr_id].restart ) )
          {
             if ( opt_extranonce )
                stratum_gen_work( &stratum, &g_work );
             else
             {
                if ( !thr_id )
                {
                   applog( LOG_WARNING, "Nonce range exhausted, extranonce not subscribed." );
                   applog( LOG_WARNING, "Waiting for new work...");
                }
                while ( !work_restart[thr_id].restart )
                   sleep ( 1 );
             }
          }
       }
       else if ( !opt_benchmark ) // GBT or getwork
       {
          pthread_rwlock_wrlock( &g_work_lock );
          const time_t now = time(NULL);
          if ( ( ( now - g_work_time ) >= opt_scantime )
             || ( *nonceptr >= end_nonce ) )
          {
             if ( unlikely( !get_work( mythr, &g_work ) ) )
             {
                pthread_rwlock_unlock( &g_work_lock );
                applog( LOG_ERR, "work retrieval failed, exiting miner thread %d", thr_id );
		          goto out;
	          }
             g_work_time = now;
          }
          pthread_rwlock_unlock( &g_work_lock );
       }

       pthread_rwlock_rdlock( &g_work_lock );

       algo_gate.get_new_work( &work, &g_work, thr_id, &end_nonce );
       work_restart[thr_id].restart = 0;

       pthread_rwlock_unlock( &g_work_lock );

       // conditional mining
       if ( unlikely( !wanna_mine( thr_id ) ) )
       {
          restart_threads();
          sleep(5);
          continue;
       }
       
       // opt_scantime expressed in hashes
       max64 = opt_scantime * thr_hashrates[thr_id];

       // time limit
       if ( unlikely( opt_time_limit ) )
       {
          unsigned int now = (unsigned int)time(NULL);
          if ( now >= time_limit_stop )
          {
             if ( thr_id != 0 )
             {
                sleep(1);
                continue;
             }
             if (opt_benchmark)
             {
                char rate[32];
                format_hashrate( global_hashrate, rate );
                applog( LOG_NOTICE, "Benchmark: %s", rate );
             }
             else
                applog( LOG_NOTICE, "Mining timeout of %ds reached, exiting...",
                        opt_time_limit);

             proper_exit(0);
          }
          // else
          if ( time_limit_stop - now < opt_scantime )
              max64 = ( time_limit_stop - now ) * thr_hashrates[thr_id] ;
       }

       // Select nonce range based on max64, the estimated number of hashes
       // to meet the desired scan time.
       // Initial value arbitrarilly set to 1000 just to get
       // a sample hashrate for the next time.
       uint32_t work_nonce = *nonceptr;
       if ( max64 <= 0)
          max64 = 1000;
       if ( work_nonce + max64 > end_nonce )
          max_nonce = end_nonce;
       else
          max_nonce = work_nonce + (uint32_t)max64;

       // init time
       hashes_done = 0;
       gettimeofday( (struct timeval *) &tv_start, NULL );

       // Scan for nonce
       nonce_found = algo_gate.scanhash( &work, max_nonce, &hashes_done,
                                         mythr );

       // record scanhash elapsed time
       gettimeofday( &tv_end, NULL );
       timeval_subtract( &diff, &tv_end, &tv_start );
       if ( diff.tv_usec || diff.tv_sec )
       {
          pthread_mutex_lock( &stats_lock );
          total_hashes += hashes_done;
          total_hashes_time = tv_end;
          thr_hashrates[thr_id] =
          hashes_done / ( diff.tv_sec + diff.tv_usec * 1e-6 );
          pthread_mutex_unlock( &stats_lock );
       }

       // This code is deprecated, scanhash should never return true.
       // This remains as a backup in case some old implementations still exist.
       // If unsubmiited nonce(s) found, submit now. 
       if ( unlikely( nonce_found && !opt_benchmark ) )
       {  
          applog( LOG_WARNING, "BUG: See RELEASE_NOTES for reporting bugs. Algo = %s.",
                               algo_names[ opt_algo ] );
          if ( !submit_work( mythr, &work ) )
          {
             applog( LOG_WARNING, "Failed to submit share." );
             break;
          }
          if ( !opt_quiet )
              applog( LOG_NOTICE, "%d: submitted by thread %d.",
                      accepted_share_count + rejected_share_count + 1,
                      mythr->id );

          // prevent stale work in solo
          // we can't submit twice a block!
          if unlikely( !have_stratum && !have_longpoll )
          {
             pthread_rwlock_wrlock( &g_work_lock );
             // will force getwork
             g_work_time = 0;
             pthread_rwlock_unlock( &g_work_lock );
          }
       }

       // display hashrate
       if ( unlikely( opt_hash_meter ) )
       {
          char hr[16];
          char hr_units[2] = {0,0};
          double hashrate;

          hashrate  = thr_hashrates[thr_id];
          if ( hashrate != 0. )
          {
             scale_hash_for_display( &hashrate,  hr_units );
             sprintf( hr, "%.2f", hashrate );
             applog( LOG_INFO, "Thread %d, CPU %d: %s %sh/s",
                        thr_id, thread_affinity_map[ thr_id ], hr, hr_units );
          }
       }

       // Display benchmark total
       // Update hashrate for API if no shares accepted yet.
       if ( unlikely( ( opt_benchmark || !accepted_share_count ) 
            && thr_id == opt_n_threads - 1 ) )
       {
          double hashrate  = 0.;
          pthread_mutex_lock( &stats_lock );
          for ( int i = 0; i < opt_n_threads; i++ )
              hashrate  += thr_hashrates[i];
          global_hashrate  = hashrate;
          pthread_mutex_unlock( &stats_lock );

          if ( opt_benchmark )
          {
             struct timeval uptime;
             char hr[16];
             char hr_units[2] = {0,0};
             timeval_subtract( &uptime, &total_hashes_time, &session_start ); 
             double hashrate = safe_div( total_hashes, uptime.tv_sec, 0. );

             if ( hashrate > 0. )
             {
                scale_hash_for_display( &hashrate,  hr_units );
                sprintf( hr, "%.2f", hashrate );
#if (defined(_WIN64) || defined(__WINDOWS__) || defined(_WIN32) || defined(__APPLE__))
                applog( LOG_NOTICE, "Total: %s %sH/s", hr, hr_units );
#else
                float lo_freq = 0., hi_freq = 0.;
                linux_cpu_hilo_freq( &lo_freq, &hi_freq );
                applog( LOG_NOTICE,
                     "Total: %s %sH/s, Temp: %dC, Freq: %.3f/%.3f GHz",
                     hr, hr_units, (uint32_t)cpu_temp(0), lo_freq / 1e6,
                     hi_freq / 1e6 );
#endif
             }
          }
       }  // benchmark
   }  // miner_thread loop

out:
	tq_freeze(mythr->q);
	return NULL;
}

void restart_threads(void)
{
	for ( int i = 0; i < opt_n_threads; i++)
		work_restart[i].restart = 1;
   if ( opt_debug )
      applog( LOG_INFO, "Threads restarted for new work."); 
}

json_t *std_longpoll_rpc_call( CURL *curl, int *err, char* lp_url )
{
   json_t *val;
   char *req = NULL;
   if (have_gbt)
   {
       req = (char*) malloc( strlen(gbt_lp_req) + strlen(lp_id) + 1 );
       sprintf( req, gbt_lp_req, lp_id );
   }
   val = json_rpc_call( curl, rpc_url, rpc_userpass, getwork_req, err,
                        JSON_RPC_LONGPOLL );
   val = json_rpc_call( curl, lp_url, rpc_userpass, req ? req : getwork_req,
                        err, JSON_RPC_LONGPOLL);
   free(req);
   return val;
}

static void *longpoll_thread(void *userdata)
{
   struct thr_info *mythr = (struct thr_info*) userdata;
   CURL *curl = NULL;
   char *copy_start, *hdr_path = NULL, *lp_url = NULL;
   bool need_slash = false;

   curl = curl_easy_init();
   if (unlikely(!curl))
   {
	applog(LOG_ERR, "CURL init failed");
	goto out;
   }

start:
   hdr_path = (char*) tq_pop(mythr->q, NULL);
   if (!hdr_path)
 	goto out;

   /* full URL */
   if (strstr(hdr_path, "://"))
   {
	lp_url = hdr_path;
	hdr_path = NULL;
   }
   else
   /* absolute path, on current server */
   {
	copy_start = (*hdr_path == '/') ? (hdr_path + 1) : hdr_path;
	if (rpc_url[strlen(rpc_url) - 1] != '/')
		need_slash = true;

	lp_url = (char*) malloc(strlen(rpc_url) + strlen(copy_start) + 2);
	if (!lp_url)
		goto out;

	sprintf(lp_url, "%s%s%s", rpc_url, need_slash ? "/" : "", copy_start);
   }

   if (!opt_quiet)
	applog(LOG_BLUE, "Long-polling on %s", lp_url);

   while (1)
   {
      int err;
      json_t *val;
      val = (json_t*)algo_gate.longpoll_rpc_call( curl, &err, lp_url );

      if (have_stratum)
      {
         if (val)
             json_decref(val);
	      goto out;
      }
      if (likely( val ))
      {
      bool rc;
      char *start_job_id;
      double start_diff = 0.0;
      json_t *res, *soval;
	   res = json_object_get(val, "result");
      soval = json_object_get(res, "submitold");
      submit_old = soval ? json_is_true(soval) : false;

      pthread_rwlock_wrlock( &g_work_lock );

// This code has been here for a long time even though job_id isn't used.
// This needs to be changed eventually to test the block height properly
// using g_work.block_height .     
      start_job_id = g_work.job_id ? strdup(g_work.job_id) : NULL;
	   if (have_gbt)
	      rc = gbt_work_decode(res, &g_work);
	   else
	      rc = work_decode(res, &g_work);
	   if (rc)
      {
// purge job id from solo mining
        bool newblock = g_work.job_id && strcmp(start_job_id, g_work.job_id);
	     newblock |= (start_diff != net_diff); // the best is the height but... longpoll...
        if (newblock)
        {
          start_diff = net_diff;
	       if (!opt_quiet)
          {
	         char netinfo[64] = { 0 };
	         if ( net_diff > 0. )
            {
	 	         sprintf(netinfo, ", diff %.3f", net_diff);
	         }
	         sprintf( &netinfo[strlen(netinfo)], ", target %.3f",
                     g_work.targetdiff );
            applog(LOG_BLUE, "%s detected new block%s", short_url, netinfo);
	       }
	       time(&g_work_time);
	       restart_threads();
	     }
      }
      free(start_job_id);

      pthread_rwlock_unlock( &g_work_lock );

      json_decref(val);
    }
    else   // !val
    {
       pthread_rwlock_wrlock( &g_work_lock );
       g_work_time -= LP_SCANTIME;
       pthread_rwlock_unlock( &g_work_lock );
	    if (err == CURLE_OPERATION_TIMEDOUT)
       {
	       restart_threads();
	    }
       else
       {
          have_longpoll = false;
   	    restart_threads();
	       free(hdr_path);
	       free(lp_url);
	       lp_url = NULL;
	       sleep(opt_fail_pause);
	       goto start;
	    }
    }
  }

out:
	free(hdr_path);
	free(lp_url);
	tq_freeze(mythr->q);
	if (curl)
		curl_easy_cleanup(curl);

	return NULL;
}

static bool stratum_handle_response( char *buf )
{
	json_t *val, *id_val, *res_val, *err_val;
	json_error_t err;
	bool ret = false;
   bool share_accepted = false;

	val = JSON_LOADS( buf, &err );
	if (!val)
   {
      applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
	   goto out;
	}
   res_val = json_object_get( val, "result" );
   if ( !res_val ) { /* now what? */ }

   id_val = json_object_get( val, "id" );
	if ( !id_val || json_is_null(id_val) )
		goto out;

   err_val = json_object_get( val, "error" );

   if ( !res_val || json_integer_value( id_val ) < 4 )
      goto out;
   share_accepted = json_is_true( res_val );
   share_result( share_accepted, NULL, err_val ?
                 json_string_value( json_array_get(err_val, 1) ) : NULL );

	ret = true;
out:
	if (val)
		json_decref(val);
	return ret;
}

// used by stratum and gbt
void std_build_block_header( struct work* g_work, uint32_t version,
       uint32_t *prevhash, uint32_t *merkle_tree, uint32_t ntime,
       uint32_t nbits, unsigned char *final_sapling_hash )
{
   int i;

   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = version;
   g_work->sapling = opt_sapling;

   if ( have_stratum ) for ( i = 0; i < 8; i++ )
         g_work->data[ 1+i ] = le32dec( prevhash + i );
   else for (i = 0; i < 8; i++)
         g_work->data[ 8-i ] = le32dec( prevhash + i );
   for ( i = 0; i < 8; i++ )
      g_work->data[ 9+i ] = be32dec( merkle_tree + i );
   g_work->data[ algo_gate.ntime_index ] = ntime;
   g_work->data[ algo_gate.nbits_index ] = nbits;

   if ( g_work->sapling )
   {
      if ( have_stratum )
         for ( i = 0; i < 8; i++ )
            g_work->data[20 + i] = le32dec( (uint32_t*)final_sapling_hash + i );
      else
      {
         for ( i = 0; i < 8; i++ )
            g_work->data[27 - i] = le32dec( (uint32_t*)final_sapling_hash + i );
         g_work->data[19] = 0;
      }      
      g_work->data[28] = 0x80000000;
      g_work->data[29] = 0x00000000;
      g_work->data[30] = 0x00000000;
      g_work->data[31] = 0x00000380;
   }
   else
   {
      g_work->data[20] = 0x80000000;
      g_work->data[31] = 0x00000280;
   }
}

void std_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_tree[64] = { 0 };

   algo_gate.gen_merkle_root( merkle_tree, sctx );
   algo_gate.build_block_header( g_work, le32dec( sctx->job.version ),
          (uint32_t*) sctx->job.prevhash, (uint32_t*) merkle_tree,
          le32dec( sctx->job.ntime ), le32dec(sctx->job.nbits),
          sctx->job.final_sapling_hash );
}

// Loop is out of order:
//
//   connect/reconnect
//   handle message
//   get new message
//
// change to
//   connect/reconnect
//   get new message
//   handle message


static void *stratum_thread(void *userdata )
{
   struct thr_info *mythr = (struct thr_info *) userdata;
   char *s = NULL;

   stratum.url = (char*) tq_pop(mythr->q, NULL);
   if (!stratum.url)
      goto out;
   applog( LOG_BLUE, "Stratum connect %s", stratum.url );

   while (1)
   {
      int failures = 0;

      if ( unlikely( stratum_need_reset ) )
      {
          stratum_need_reset = false;
          gettimeofday( &stratum_reset_time, NULL );
          stratum_down = true;
          stratum_errors++;
          stratum_disconnect( &stratum );
          if ( strcmp( stratum.url, rpc_url ) )
          {
	          free( stratum.url );
	          stratum.url = strdup( rpc_url );
	          applog(LOG_BLUE, "Connection changed to %s", short_url);
          }
          else 
	          applog(LOG_BLUE, "Stratum connection reset");
          // reset stats queue as well
          restart_threads();
          if ( s_get_ptr != s_put_ptr ) s_get_ptr = s_put_ptr = 0;
      }

      while ( !stratum.curl )
      {
         stratum_down = true;
         restart_threads();
         pthread_rwlock_wrlock( &g_work_lock );
         g_work_time = 0;
         pthread_rwlock_unlock( &g_work_lock );
         if ( !stratum_connect( &stratum, stratum.url )
              || !stratum_subscribe( &stratum )
              || !stratum_authorize( &stratum, rpc_user, rpc_pass ) )
         {
            stratum_disconnect( &stratum );
            if (opt_retries >= 0 && ++failures > opt_retries)
            {
               applog(LOG_ERR, "...terminating workio thread");
               tq_push(thr_info[work_thr_id].q, NULL);
               goto out;
            }
            if (!opt_benchmark)
                applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
            sleep(opt_fail_pause);
         }
         else
         {
// sometimes stratum connects but doesn't immediately send a job, wait for one.
//            stratum_down = false;
            applog(LOG_BLUE,"Stratum connection established" );
            if ( stratum.new_job )   // prime first job
            {
               stratum_down = false;
               stratum_gen_work( &stratum, &g_work );
            }
         }
      }

      // Wait for new message from server
      if ( likely( stratum_socket_full( &stratum, opt_timeout ) ) )
      {
         if ( likely( s = stratum_recv_line( &stratum ) ) )
         {
            stratum_down = false;
            if ( likely( !stratum_handle_method( &stratum, s ) ) )
               stratum_handle_response( s );
            free( s );
         }
         else
         {
//            applog(LOG_WARNING, "Stratum connection interrupted");
//            stratum_disconnect( &stratum );
            stratum_need_reset = true;
         }
      }
      else
      {
         applog(LOG_ERR, "Stratum connection timeout");
         stratum_need_reset = true;
//         stratum_disconnect( &stratum );
      }

      report_summary_log( ( stratum_diff != stratum.job.diff )
                       && ( stratum_diff != 0. ) );

      if ( !stratum_need_reset )
      {
         // Is keepalive needed? Mutex would normally be required but that
         // would block any attempt to submit a share. A share is more
         // important even if it messes up the keepalive.

         if ( opt_stratum_keepalive )
         {
            struct timeval now, et;
            gettimeofday( &now, NULL );
            // any shares submitted since last keepalive?
            if ( last_submit_time.tv_sec > stratum_keepalive_timer.tv_sec )
               memcpy( &stratum_keepalive_timer, &last_submit_time,
                       sizeof (struct timeval) );

            timeval_subtract( &et, &now, &stratum_keepalive_timer );

            if ( et.tv_sec > stratum_keepalive_timeout )
            {
                double diff = stratum.job.diff * 0.5;
                stratum_keepalive_timer = now;
                if ( !opt_quiet )
                   applog( LOG_BLUE,
                           "Stratum keepalive requesting lower difficulty" );
                stratum_suggest_difficulty( &stratum, diff );
            }

            if ( last_submit_time.tv_sec > stratum_reset_time.tv_sec )
              timeval_subtract( &et, &now, &last_submit_time );
            else
              timeval_subtract( &et, &now, &stratum_reset_time );

            if ( et.tv_sec > stratum_keepalive_timeout + 90 )
            {
               applog( LOG_NOTICE, "No shares submitted, resetting stratum connection" );
               stratum_need_reset = true;
               stratum_keepalive_timer = now;
            }
         } // stratum_keepalive

         if ( stratum.new_job && !stratum_need_reset )
            stratum_gen_work( &stratum, &g_work );

      } // stratum_need_reset
   }  // loop
out:
  return NULL;
}

static void show_credits()
{
   printf("\n         **********  "PACKAGE_NAME" "PACKAGE_VERSION"  ********** \n");
   printf("     A CPU miner with multi algo support and optimized for CPUs\n");
   printf("     with AVX512, SHA, AES and NEON extensions by JayDDee.\n");
   printf("     BTC donation address: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT\n\n");
}

#define check_cpu_capability() cpu_capability( false )
#define display_cpu_capability() cpu_capability( true )

static bool cpu_capability( bool display_only )
{
     char cpu_brand[0x40];
     bool sw_has_x86_64    = false;
     bool sw_has_aarch64   = false;
     int  sw_arm_arch      = 0;            // AArch64 version
     bool sw_has_neon      = false;        // AArch64
     bool sw_has_sve       = false;
     bool sw_has_sve2      = false;
     bool sw_has_sme       = false;  
     bool sw_has_sme2      = false; 
     bool sw_has_sse2      = false;        // x86_64
     bool sw_has_ssse3     = false;
     bool sw_has_sse41     = false;
     bool sw_has_sse42     = false;
     bool sw_has_avx       = false;
     bool sw_has_avx2      = false;
     bool sw_has_avx512    = false;
     bool sw_has_avx10     = false;
     bool sw_has_amx       = false;
     bool sw_has_apx       = false;
     bool sw_has_aes       = false;        // x86_64 or AArch64
     bool sw_has_vaes      = false;        // x86_64
     bool sw_has_sha256    = false;        // x86_64 or AArch64
     bool sw_has_sha512    = false;

     #if defined(__x86_64__)
         sw_has_x86_64 = true;
     #elif defined(__aarch64__)
         sw_has_aarch64 = true;
         #ifdef __ARM_NEON
           sw_has_neon = true;
         #endif
         #ifdef __ARM_ARCH
           sw_arm_arch = __ARM_ARCH;
         #endif
     #endif

     // x86_64 only
     #if defined(__SSE2__)
         sw_has_sse2 = true;
     #endif
     #if defined(__SSSE3__)
         sw_has_ssse3 = true;
     #endif
     #if defined(__SSE41__)
         sw_has_sse41 = true;
     #endif
     #ifdef __SSE4_2__
         sw_has_sse42 = true;
     #endif
     #ifdef __AVX__
         sw_has_avx = true;
     #endif
     #ifdef __AVX2__
         sw_has_avx2 = true;
     #endif
     #if (defined(__AVX512F__) && defined(__AVX512DQ__) && defined(__AVX512BW__) && defined(__AVX512VL__))
         sw_has_avx512 = true;
     #endif
     #if defined(__AVX10_1__)    // version is not significant
         sw_has_avx10 = true;
     #endif
     #ifdef __AMX_TILE__
         sw_has_amx = true;
     #endif
     #ifdef __APX_F__
         sw_has_apx = true;
     #endif

     // x86_64 or AArch64 
     #if defined(__AES__) || defined(__ARM_FEATURE_AES)
         sw_has_aes = true;
     #endif
     #ifdef __VAES__
         sw_has_vaes = true;
     #endif
     #if defined(__SHA__) || defined(__ARM_FEATURE_SHA2)
         sw_has_sha256 = true;
     #endif
     #if defined(__SHA512__) || defined(__ARM_FEATURE_SHA512)
         sw_has_sha512 = true;
     #endif

     // AArch64 only
     #if defined(__ARM_NEON)
         sw_has_neon = true;
     #endif
     // FYI, SVE & SME not used by cpuminer
     #if defined(__ARM_FEATURE_SVE)
         sw_has_sve = true;
     #endif
     #if defined(__ARM_FEATURE_SVE2)
         sw_has_sve2 = true;
     #endif
     #if defined(__ARM_FEATURE_SME)
         sw_has_sme = true;
     #endif
     #if defined(__ARM_FEATURE_SME2)
         sw_has_sme2 = true;
     #endif

     // CPU
     cpu_brand_string( cpu_brand );
     printf( "CPU: %s\n", cpu_brand );

     // Build
     printf( "SW built on " __DATE__
     #if defined(__clang__)
        " with CLANG-%d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__ );
     #elif defined(__GNUC__)
        " with GCC-%d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__ );
     #endif

     // OS
     #if defined(__linux)
        printf(" Linux\n");
     #elif defined(WIN32)
        printf(" Windows");
        #if defined(__MINGW64__)
          printf(" MinGW-w64\n");
        #else
          printf("\n");
        #endif
     #elif defined(__APPLE__)
        printf(" MacOS\n");
     #elif defined(__bsd__) || defined(__unix__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
        printf(" BSD/Unix\n");
     #else
        printf("\n");
     #endif

     printf("CPU features: ");
     if ( cpu_arch_x86_64()  )
     {
       if      ( has_avx10()  )    printf( " AVX10.%d", avx10_version() );
       else if ( has_avx512() )    printf( " AVX512" );
       else if ( has_avx2()   )    printf( " AVX2  " );
       else if ( has_avx()    )    printf( " AVX   " );
       else if ( has_sse42()  )    printf( " SSE4.2" );
       else if ( has_sse41()  )    printf( " SSE4.1" );
       else if ( has_ssse3()  )    printf( " SSSE3 " );
       else if ( has_sse2()   )    printf( " SSE2  " );
       if      ( has_amx()    )    printf( " AMX"    );
       if      ( has_apx_f()  )    printf( " APX"    );

     }
     else if   ( cpu_arch_aarch64() )
     {
       if      ( has_neon()   )    printf( "       NEON" );
       if      ( has_sve2()   )    printf( " SVE2-%d", sve_vector_length() );
       else if ( has_sve()    )    printf( " SVE"    );
       if      ( has_sme2()   )    printf( " SME2"   );
       else if ( has_sme()    )    printf( " SME"    );
     }     
     if        ( has_vaes()   )    printf( " VAES"   );
     else if   ( has_aes()    )    printf( "  AES"   );
     if        ( has_sha512() )    printf( " SHA512" );
     else if   ( has_sha256() )    printf( " SHA256" );

     printf("\nSW features:  ");
     if ( sw_has_x86_64 )
     {                     
        if      ( sw_has_avx10     ) printf( " AVX10 " );
        else if ( sw_has_avx512    ) printf( " AVX512" );
        else if ( sw_has_avx2      ) printf( " AVX2  " );
        else if ( sw_has_avx       ) printf( " AVX   " );
        else if ( sw_has_sse42     ) printf( " SSE4.2" );
        else if ( sw_has_sse41     ) printf( " SSE4.1" );
        else if ( sw_has_ssse3     ) printf( " SSSE3 " );
        else if ( sw_has_sse2      ) printf( " SSE2  " );
        if      ( sw_has_amx       ) printf( " AMX"    );
        if      ( sw_has_apx       ) printf( " APX"    );
     }
     else if    ( sw_has_aarch64 ) 
     {
        if      ( sw_arm_arch    )   printf( " armv%d", sw_arm_arch );
        if      ( sw_has_neon    )   printf( " NEON"   );
        if      ( sw_has_sve2    )   printf( " SVE2"   );
        else if ( sw_has_sve     )   printf( " SVE"    );
        if      ( sw_has_sme2    )   printf( " SME2"   );
        else if ( sw_has_sme     )   printf( " SME"    );
     }
     if         ( sw_has_vaes    )   printf( " VAES"   );
     else if    ( sw_has_aes     )   printf( "  AES"   );
     if         ( sw_has_sha512  )   printf( " SHA512" );
     else if    ( sw_has_sha256  )   printf( " SHA256" );

     printf("\n");
     
     return true;
}

void show_usage_and_exit(int status)
{
	if (status)
                fprintf(stderr, "Try `--help' for more information.\n");
	else
		printf(usage);
	exit(status);
}

void strhide(char *s)
{
	if (*s) *s++ = 'x';
	while (*s) *s++ = '\0';
}

void parse_arg(int key, char *arg )
{
	char *p;
	int v, i;
	double d;

	switch( key )
   {
	   case 'a':  // algo
         get_algo_alias( &arg );
         for (i = 1; i < ALGO_COUNT; i++)
         {
	          v = (int) strlen( algo_names[i] );
             if ( v && !strncasecmp( arg, algo_names[i], v ) )
             {
	             if ( arg[v] == '\0' )
                {
		             opt_algo = (enum algos) i;
			          break;
		          }
			       if ( arg[v] == ':' )
                {
		             char *ep;
				       v = strtol( arg+v+1, &ep, 10 );
                   if ( *ep || v < 2 )
					       continue;
				       opt_algo = (enum algos) i;
				       opt_param_n = v;
				       break;
			       }
		      }
	      }
         if ( i == ALGO_COUNT )
         {
            applog( LOG_ERR,"Unknown algo: %s",arg );
            show_usage_and_exit( 1 );
         }
      break;

	case 'b':  // api-bind
      opt_api_enabled = true;
      p = strstr(arg, ":");
		if ( p )
      {
			/* ip:port */
			if ( p - arg > 0 )
         {
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if ( arg && strstr( arg, "." ) )
      {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
         opt_api_listen = default_api_listen;
      }
		else if ( arg )
      {
			/* port or 0 to disable */
         opt_api_allow = (char*)default_api_allow;      
         opt_api_listen = atoi(arg);
		}
      break;
	case 1030: // api-remote
		opt_api_remote = 1;
		break;
	case 'B':  // background
		opt_background = true;
		use_colors = false;
		break;
	case 'c': {  // config
		json_error_t err;
		json_t *config;
                
		if (arg && strstr(arg, "://"))
			config = json_load_url(arg, &err);
      else
			config = JSON_LOADF(arg, &err);
		if (!json_is_object(config))
      {
			if (err.line < 0)
				fprintf(stderr, "%s\n", err.text);
			else
				fprintf(stderr, "%s:%d: %s\n", arg, err.line, err.text);
		}
      else
      {
			parse_config(config, arg);
			json_decref(config);
		}
		break;
	}

   // debug overrides quiet          
	case 'q':  // quiet
      opt_quiet = !( opt_debug || opt_protocol );
		break;
	case 'D':  // debug
		opt_debug = true;
      opt_quiet =	false;
      break;
	case 'p':  // pass
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':  // protocol
		opt_protocol = true;
      opt_quiet = false;
		break;
	case 'r':  // retries
		v = atoi(arg);
		if (v < -1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
   case 1025:  // retry-pause
      v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
	case 's':  // scantime
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'T':  // timeout
		v = atoi(arg);
		if (v < 1 || v > 99999) /* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':  // threads
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':  // user
		free(rpc_user);
		rpc_user = strdup(arg);
		break;

   case 'o':  // url
   {
		char *ap, *hp;
		ap = strstr( arg, "://" );
		ap = ap ? ap + 3 : arg;
		hp = strrchr( arg, '@' );
		if ( hp )
      {
			*hp = '\0';
			p = strchr( ap, ':' );
			if ( p )
         {
				free( rpc_userpass );
				rpc_userpass = strdup( ap );
				free( rpc_user );
				rpc_user = (char*)calloc( p - ap + 1, 1 );
				strncpy( rpc_user, ap, p - ap );
				free( rpc_pass );
				rpc_pass = strdup( ++p );
				if ( *p ) *p++ = 'x';
				v = (int)strlen( hp + 1 ) + 1;
				memmove( p + 1, hp + 1, v );
				memset( p + v, 0, hp - p );
				hp = p;
			}
         else
         {
				free( rpc_user );
				rpc_user = strdup( ap );
			}
			*hp++ = '@';
		}
      else
			hp = ap;
		if ( ap != arg )
      {
			if ( strncasecmp( arg, "http://", 7 )
           && strncasecmp( arg, "https://", 8 )
           && strncasecmp( arg, "stratum+tcp://", 14 )
           && strncasecmp( arg, "stratum+ssl://", 14 )
           && strncasecmp( arg, "stratum+tcps://", 15 ) )
         {
            fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
			short_url = &rpc_url[ap - arg];
		}
      else
      {
			if ( *hp == '\0' || *hp == '/' )
         {
				fprintf( stderr, "invalid URL -- '%s'\n",	arg );
				show_usage_and_exit( 1 );
			}
			free( rpc_url );
			rpc_url = (char*) malloc( strlen(hp) + 15 );
			sprintf( rpc_url, "stratum+tcp://%s", hp );
			short_url = &rpc_url[ sizeof("stratum+tcp://") - 1 ];
		}
		have_stratum = !opt_benchmark && !strncasecmp( rpc_url, "stratum", 7 );
		break;
	}

   case 'O':  // userpass
		p = strchr(arg, ':');
		if (!p)
      {
			fprintf(stderr, "invalid username:password pair -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		free(rpc_userpass);
		rpc_userpass = strdup(arg);
		free(rpc_user);
		rpc_user = (char*) calloc(p - arg + 1, 1);
		strncpy(rpc_user, arg, p - arg);
		free(rpc_pass);
		rpc_pass = strdup(++p);
		strhide(p);
		break;
	case 'x':  // proxy
		if ( !strncasecmp( arg, "socks4://", 9 ) )
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if ( !strncasecmp( arg, "socks5://", 9 ) )
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if ( !strncasecmp( arg, "socks4a://", 10 ) )
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if ( !strncasecmp( arg, "socks5h://", 10 ) )
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 1001:  // cert
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:  // no-color
		use_colors = false;
		break;
	case 1003:  // no-longpoll
		want_longpoll = false;
		break;
	case 1005:  // benchmark
		opt_benchmark = true;
		want_longpoll = false;
		want_stratum = false;
		have_stratum = false;
		break;
	case 1006:  // cputest
//		print_hash_tests();
		exit(0);
	case 1007:  // no-stratum
		want_stratum = false;
		opt_extranonce = false;
		break;
	case 1008:  // time-limit
		opt_time_limit = atoi(arg);
		break;
	case 1009:  // no-redirect
		opt_redirect = false;
		break;
	case 1010:  // no-getwork
		allow_getwork = false;
		break;
	case 1011:  // no-gbt
		have_gbt = false;
		break;
	case 1012:  // no-extranonce
		opt_extranonce = false;
		break;
   case 1014:   // hash-meter
      opt_hash_meter = true;
      break;
   case 1031:   // bell
      opt_bell = true;
      break;
   case 1016:			/* --coinbase-addr */
      if ( arg ) coinbase_address = strdup( arg );
		break;
	case 1015:			/* --coinbase-sig */
		if ( strlen( arg ) + 1 > sizeof(coinbase_sig) )
      {
			fprintf( stderr, "coinbase signature too long\n" );
			show_usage_and_exit( 1 );
		}
		strcpy( coinbase_sig, arg );
		break;
	case 'f':
		d = atof(arg);
		if (d == 0.)	/* --diff-factor */
			show_usage_and_exit(1);
		opt_diff_factor = d;
		break;
	case 'm':
		d = atof(arg);
		if (d == 0.)	/* --diff-multiplier */
			show_usage_and_exit(1);
		opt_diff_factor = 1.0/d;
		break;
#ifdef HAVE_SYSLOG_H
	case 'S':  // syslog
		use_syslog = true;
		use_colors = false;
		break;
#endif
	case 1020:  // cpu-affinity
      p = strstr( arg, "0x" );
      opt_affinity = p ? strtoull( p, NULL, 16 )
                       : atoll( arg );
      break;
	case 1021:  // cpu-priority
		v = atoi(arg);
      applog(LOG_NOTICE,"--cpu-priority is deprecated and will be removed from a future release");
      if (v < 0 || v > 5)	/* sanity check */
			show_usage_and_exit(1);
		opt_priority = v;
		break;
   case 'N':    // N parameter for various scrypt algos
      d = atoi( arg );
      opt_param_n = d;
      break;    
   case 'R':   // R parameter for various scrypt algos
      d = atoi( arg );
      opt_param_r = d;
      break;
   case 'K':    // Client key for various algos
      free( opt_param_key );
      opt_param_key = strdup( arg );
      break;
   case 1060: // max-temp
		d = atof(arg);
		opt_max_temp = d;
		break;
	case 1061: // max-diff
		d = atof(arg);
		opt_max_diff = d;
		break;
	case 1062: // max-rate
		d = atof(arg);
		p = strstr(arg, "K");
		if (p) d *= 1e3;
		p = strstr(arg, "M");
		if (p) d *= 1e6;
		p = strstr(arg, "G");
		if (p) d *= 1e9;
		opt_max_rate = d;
		break;
	case 1024:
		opt_randomize = true;
      applog(LOG_NOTICE,"--randomize is deprecated and will be removed from a future release");
      break;
   case 1027:  // data-file
      opt_data_file = strdup( arg );
      break;
   case 1028:  // verify
      opt_verify = true;
      break;
   case 1029:  // stratum-keepalive
      opt_stratum_keepalive = true;
      break;
   case 'V':   // version
      display_cpu_capability();
      exit(0);
	case 'h':   // help
		show_usage_and_exit(0);

   default:
		show_usage_and_exit(1);
	}
}

void parse_config(json_t *config, char *ref)
{
	int i;
	json_t *val;

	for (i = 0; i < ARRAY_SIZE(options); i++) {
		if (!options[i].name)
			break;

		val = json_object_get(config, options[i].name);
		if (!val)
			continue;
		if (options[i].has_arg && json_is_string(val)) {
			char *s = strdup(json_string_value(val));
			if (!s)
				break;
			parse_arg(options[i].val, s);
			free(s);
		}
		else if (options[i].has_arg && json_is_integer(val)) {
			char buf[16];
			sprintf(buf, "%d", (int)json_integer_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (options[i].has_arg && json_is_real(val)) {
			char buf[16];
			sprintf(buf, "%f", json_real_value(val));
			parse_arg(options[i].val, buf);
		}
		else if (!options[i].has_arg) {
			if (json_is_true(val))
				parse_arg(options[i].val, "");
		}
		else
			applog(LOG_ERR, "JSON option %s invalid",
			options[i].name);
	}
}

static void parse_cmdline(int argc, char *argv[])
{
   int key;

   while (1)
   {
#if HAVE_GETOPT_LONG
      key = getopt_long(argc, argv, short_options, options, NULL);
#else
      key = getopt(argc, argv, short_options);
#endif
      if ( key < 0 )   break;
      parse_arg( key, optarg );
   }
   if ( optind < argc )
   {
      fprintf( stderr, "%s: unsupported non-option argument -- '%s'\n",
		                 argv[0], argv[optind]);
      show_usage_and_exit(1);
   }
}

#ifndef WIN32
static void signal_handler(int sig)
{
	switch (sig) {
	case SIGHUP:
		applog(LOG_INFO, "SIGHUP received");
		break;
	case SIGINT:
		applog(LOG_INFO, "SIGINT received, exiting");
		proper_exit(0);
		break;
	case SIGTERM:
		applog(LOG_INFO, "SIGTERM received, exiting");
		proper_exit(0);
		break;
	}
}
#else
BOOL WINAPI ConsoleHandler(DWORD dwType)
{
	switch (dwType) {
	case CTRL_C_EVENT:
		applog(LOG_INFO, "CTRL_C_EVENT received, exiting");
		proper_exit(0);
		break;
	case CTRL_BREAK_EVENT:
		applog(LOG_INFO, "CTRL_BREAK_EVENT received, exiting");
		proper_exit(0);
		break;
	default:
		return false;
	}
	return true;
}
#endif

static int thread_create(struct thr_info *thr, void* func)
{
	int err = 0;
	pthread_attr_init(&thr->attr);
	err = pthread_create(&thr->pth, &thr->attr, func, thr);
	pthread_attr_destroy(&thr->attr);
	return err;
}

void get_defconfig_path(char *out, size_t bufsize, char *argv0);

int main(int argc, char *argv[])
{
	struct thr_info *thr;
	long flags;
	int i, err;

	pthread_mutex_init(&applog_lock, NULL);

	show_credits();

	rpc_user = strdup("");
	rpc_pass = strdup("");

#if defined(WIN32)

// Get the number of cpus, display after parsing command line
#if defined(WINDOWS_CPU_GROUPS_ENABLED)
 	num_cpus = 0;
	num_cpugroups = GetActiveProcessorGroupCount();
	for( i = 0; i < num_cpugroups; i++ )
	{
 	   int cpus = GetActiveProcessorCount( i );
	   num_cpus += cpus;
	}

#else
   SYSTEM_INFO sysinfo;
   GetSystemInfo(&sysinfo);
   num_cpus = sysinfo.dwNumberOfProcessors;
#endif

#elif defined(_SC_NPROCESSORS_CONF)
	num_cpus = sysconf(_SC_NPROCESSORS_CONF);
#elif defined(CTL_HW) && defined(HW_NCPU)
	int req[] = { CTL_HW, HW_NCPU };
	size_t len = sizeof(num_cpus);
	sysctl(req, 2, &num_cpus, &len, NULL, 0);
#else
	num_cpus = 1;
#endif 

   if ( num_cpus < 1 )
      num_cpus = 1;
   opt_n_threads = num_cpus;

   parse_cmdline( argc, argv );

   if ( opt_algo == ALGO_NULL )
   {
      fprintf( stderr, "%s: No algo parameter specified\n", argv[0] );
      show_usage_and_exit(1);
   }

   if ( !opt_scantime )
   {
      if      ( have_stratum )  opt_scantime = 30;
      else if ( have_longpoll ) opt_scantime = LP_SCANTIME;
      else                      opt_scantime = 5;
   }

   if ( opt_time_limit )
      time_limit_stop = (unsigned int)time(NULL) + opt_time_limit;

   // need to register to get algo optimizations for cpu capabilities
   // but that causes registration logs before cpu capabilities is output.
   // Would need to split register function into 2 parts. First part sets algo
   // optimizations but no logging, second part does any logging.   
   if ( !register_algo_gate( opt_algo, &algo_gate ) )  exit(1);

   if ( !check_cpu_capability() ) exit(1);
   
	if ( !opt_benchmark )
   {
      if ( !short_url )
      {
         fprintf(stderr, "%s: no URL supplied\n", argv[0]);
         show_usage_and_exit(1);
      }
/*
            if ( !rpc_url )
            {
		// try default config file in binary folder
		char defconfig[MAX_PATH] = { 0 };
		get_defconfig_path(defconfig, MAX_PATH, argv[0]);
		if (strlen(defconfig))
                {
			if (opt_debug)
				applog(LOG_DEBUG, "Using config %s", defconfig);
			parse_arg('c', defconfig);
			parse_cmdline(argc, argv);
		}
            }
            if ( !rpc_url )
            {
		fprintf(stderr, "%s: no URL supplied\n", argv[0]);
		show_usage_and_exit(1);
            }
*/
	}

	if (!rpc_userpass)
   {
		rpc_userpass = (char*) malloc(strlen(rpc_user) + strlen(rpc_pass) + 2);
      if (rpc_userpass)
          sprintf(rpc_userpass, "%s:%s", rpc_user, rpc_pass);
       else
         return 1;
	}

   if ( coinbase_address )
   {
      pk_script_size = address_to_script( pk_script, pk_buffer_size,
                                          coinbase_address );
      if ( !pk_script_size )
      {
         applog(LOG_ERR,"Invalid coinbase address: '%s'", coinbase_address );
         exit(0);
      }
   }

	pthread_mutex_init( &stats_lock, NULL );
   pthread_rwlock_init( &g_work_lock, NULL );
	pthread_mutex_init( &stratum.sock_lock, NULL );
	pthread_mutex_init( &stratum.work_lock, NULL );

   flags = CURL_GLOBAL_ALL;
   if ( !opt_benchmark )
     if ( strncasecmp( rpc_url, "https:", 6 )
       && strncasecmp( rpc_url, "stratum+ssl://", 14 )
       && strncasecmp( rpc_url, "stratum+tcps://", 15 ) )
         flags &= ~CURL_GLOBAL_SSL;

   if ( curl_global_init( flags ) )
   {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

   if ( is_root() )
      applog( LOG_NOTICE, "Running cpuminer as Superuser is discouraged.");
   
#ifndef WIN32
	if (opt_background)
   {
		i = fork();
		if (i < 0) exit(1);
		if (i > 0) exit(0);
		i = setsid();
		if (i < 0)
			applog(LOG_ERR, "setsid() failed (errno = %d)", errno);
		i = chdir("/");
		if (i < 0)
			applog(LOG_ERR, "chdir() failed (errno = %d)", errno);
		signal(SIGHUP, signal_handler);
		signal(SIGTERM, signal_handler);
	}
	/* Always catch Ctrl+C */
	signal(SIGINT, signal_handler);
#else
	SetConsoleCtrlHandler((PHANDLER_ROUTINE)ConsoleHandler, TRUE);
	if (opt_background)
   {
		HWND hcon = GetConsoleWindow();
		if (hcon) {
			// this method also hide parent command line window
			ShowWindow(hcon, SW_HIDE);
		} else {
			HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
			CloseHandle(h);
			FreeConsole();
		}
	}
	if (opt_priority > 0)
   {
		DWORD prio = NORMAL_PRIORITY_CLASS;
		switch (opt_priority)
      {
	      case 1:
			   prio = BELOW_NORMAL_PRIORITY_CLASS;
			break;
	      case 3:
			   prio = ABOVE_NORMAL_PRIORITY_CLASS;
			break;
		   case 4:
			   prio = HIGH_PRIORITY_CLASS;
			break;
		   case 5:
			   prio = REALTIME_PRIORITY_CLASS;
		}
		SetPriorityClass(GetCurrentProcess(), prio);
	}
#endif

#if defined(WIN32)

#if defined(_WIN32_WINNT)
   if (opt_debug)
      applog( LOG_INFO, "_WIN32_WINNT = 0x%04x", _WIN32_WINNT ); 
#else
   if (opt_debug)
      applog( LOG_INFO, "_WIN32_WINNT undefined." );
#endif
#if defined(WINDOWS_CPU_GROUPS_ENABLED)
   if ( opt_debug || ( !opt_quiet && num_cpugroups > 1 ) )
      applog( LOG_INFO, "Found %d CPUs in %d groups",
                              num_cpus, num_cpugroups );
#endif

#endif

   conditional_state = malloc( opt_n_threads * ((sizeof(bool)) ) );
   memset( conditional_state, 0, opt_n_threads * ((sizeof(bool)) ) );
   
   const int map_size = opt_n_threads < num_cpus ? num_cpus : opt_n_threads;   
   thread_affinity_map = malloc( map_size * (sizeof (int)) );
   if ( !thread_affinity_map )
   {
      applog( LOG_ERR, "CPU Affinity disabled, memory allocation failed" );
      opt_affinity = 0ULL;
   }   
   if ( opt_affinity )
   {
      int active_cpus = 0; // total CPUs available using rolling affinity mask
      for ( int thr = 0, cpu = 0; thr < map_size; thr++, cpu++ )
      {
         while ( !( ( opt_affinity >> ( cpu & 63 ) ) & 1ULL ) ) cpu++;   
         thread_affinity_map[ thr ] = cpu % num_cpus;
         if ( cpu < num_cpus ) active_cpus++;
      }
      if ( opt_n_threads > active_cpus )
         applog( LOG_WARNING, "More miner threads (%d) than active CPUs in affinity mask (%d)", opt_n_threads, active_cpus );
      if ( !opt_quiet )
      {
         char affinity_mask[64];
         format_affinity_mask( affinity_mask, opt_affinity );
         applog( LOG_INFO, "CPU affinity [%s]", affinity_mask );
      }
   }
    
#ifdef HAVE_SYSLOG_H
	if (use_syslog)
		openlog("cpuminer", LOG_PID, LOG_USER);
#endif

	work_restart = (struct work_restart*) calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;
	thr_info = (struct thr_info*) calloc(opt_n_threads + 4, sizeof(*thr));
	if (!thr_info)
		return 1;
	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;

	/* init workio thread info */
	work_thr_id = opt_n_threads;
	thr = &thr_info[work_thr_id];
	thr->id = work_thr_id;
	thr->q = tq_new();
	if (!thr->q)
		return 1;

       if ( rpc_pass && rpc_user )
          opt_stratum_stats = ( strstr( rpc_pass, "stats" ) != NULL )
                           || ( strcmp( rpc_user, "benchmark" ) == 0 );

	/* start work I/O thread */
	if (thread_create(thr, workio_thread))
   {
		applog(LOG_ERR, "work thread create failed");
		return 1;
	}

	/* ESET-NOD32 Detects these 2 thread_create... */
	if (want_longpoll && !have_stratum)
   {
      if ( opt_debug )
         applog(LOG_INFO,"Creating long poll thread");

      /* init longpoll thread info */
		longpoll_thr_id = opt_n_threads + 1;
		thr = &thr_info[longpoll_thr_id];
		thr->id = longpoll_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		/* start longpoll thread */
		err = thread_create(thr, longpoll_thread);
		if (err) {
			applog(LOG_ERR, "Long poll thread create failed");
			return 1;
		}
	}

   if ( have_stratum )
   {
      if ( opt_debug )
         applog(LOG_INFO,"Creating stratum thread");

      stratum.new_job = false;  // just to make sure

      /* init stratum thread info */
		stratum_thr_id = opt_n_threads + 2;
		thr = &thr_info[stratum_thr_id];
		thr->id = stratum_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		/* start stratum thread */
		err = thread_create(thr, stratum_thread);
		if (err)
                {
			applog(LOG_ERR, "Stratum thread create failed");
			return 1;
		}
		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}

	if ( opt_api_enabled )
   {
      if ( opt_debug )
         applog(LOG_INFO,"Creating API thread");

      /* api thread */
		api_thr_id = opt_n_threads + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create( thr, api_thread );
		if ( err )
      {
			applog( LOG_ERR, "API thread create failed" );
			return 1;
		}
      if ( !opt_quiet )
         applog( LOG_INFO,"API listening to %s:%d", opt_api_allow,
                                                     opt_api_listen );
   }

   // hold the stats lock while starting miner threads
   pthread_mutex_lock( &stats_lock );
   
	/* start mining threads */
	for ( i = 0; i < opt_n_threads; i++ )
   {
//      usleep( 5000 );
		thr = &thr_info[i];
		thr->id = i;
		thr->q = tq_new();
		if ( !thr->q )
			return 1;
      err = thread_create( thr, miner_thread );
		if ( err )
      {
			applog( LOG_ERR, "Miner thread %d create failed", i );
			return 1;
		}
   }

   // Initialize stats timers and counters
   memset( share_stats, 0, s_stats_size *  sizeof (struct share_stats_t) );
   gettimeofday( &last_submit_time, NULL );
   memcpy( &five_min_start, &last_submit_time, sizeof (struct timeval) );
   memcpy( &session_start, &last_submit_time, sizeof (struct timeval) );
   memcpy( &stratum_keepalive_timer, &last_submit_time, sizeof (struct timeval) );
   memcpy( &stratum_reset_time, &last_submit_time, sizeof (struct timeval) );
   memcpy( &total_hashes_time, &last_submit_time, sizeof (struct timeval) );
   pthread_mutex_unlock( &stats_lock );

   applog( LOG_INFO, "%d of %d miner threads started using '%s' algorithm",
                     opt_n_threads, num_cpus, algo_names[opt_algo] );

      /* main loop - simply wait for workio thread to exit */
	pthread_join( thr_info[work_thr_id].pth, NULL );
	applog( LOG_WARNING, "workio thread dead, exiting." );
	return 0;
}
