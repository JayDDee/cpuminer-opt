/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014-2016 Tanguy Pruvot
 * Copyright 2016-2020 Jay D Dee
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
#include <openssl/sha.h>
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
int opt_timeout = 300;
static int opt_scantime = 5;
const int min_scantime = 1;
//static const bool opt_time = true;
enum algos opt_algo = ALGO_NULL;
char* opt_param_key = NULL;
int opt_param_n = 0;
int opt_param_r = 0;
int opt_n_threads = 0;
bool opt_sapling = false;

// Windows doesn't support 128 bit affinity mask.
// Need compile time and run time test.
#if defined(__linux) && defined(GCC_INT128)  
#define AFFINITY_USES_UINT128 1
static uint128_t opt_affinity = -1;
static bool affinity_uses_uint128 = true;
#else
static uint64_t opt_affinity = -1;
static bool affinity_uses_uint128 = false;
#endif

int opt_priority = 0;  // deprecated
int num_cpus = 1;
int num_cpugroups = 1;
char *rpc_url = NULL;;
char *rpc_userpass = NULL;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
char *coinbase_address;
char *opt_data_file = NULL;
bool opt_verify = false;

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
struct stratum_ctx stratum;
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
double *thr_hashrates;
double global_hashrate = 0.;
double total_hashes = 0.;
struct timeval total_hashes_time = {0,0};
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
uint32_t opt_work_size = 0;

// conditional mining
bool conditional_state[MAX_CPUS] = { 0 };
double opt_max_temp = 0.0;
double opt_max_diff = 0.0;
double opt_max_rate = 0.0;

// API
static bool opt_api_enabled = false;
char *opt_api_allow = NULL;
int opt_api_listen = 0;
int opt_api_remote = 0;
char *default_api_allow = "127.0.0.1";
int default_api_listen = 4048; 

  pthread_mutex_t applog_lock;
  pthread_mutex_t stats_lock;

static struct   timeval session_start;
static struct   timeval five_min_start;
static uint64_t session_first_block = 0;
static double   latency_sum = 0.;
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
#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32))
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

static void format_affinity_map( char *map_str, uint64_t map )
{
   int n = num_cpus < 64 ? num_cpus : 64;
   int i;

   for ( i = 0; i < n; i++ )
   {
      if ( map & 1 )  map_str[i] = '!';
      else            map_str[i] = '.';
      map >>= 1;
   }
   memset( &map_str[i], 0, 64 - i );
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

// Linux affinity can use int128.
#if AFFINITY_USES_UINT128
static void affine_to_cpu_mask( int id, uint128_t mask )
#else
static void affine_to_cpu_mask( int id, uint64_t mask )
#endif
{
   cpu_set_t set;
   CPU_ZERO( &set );
   uint8_t ncpus = (num_cpus > 256) ? 256 : num_cpus;       

   for ( uint8_t i = 0; i < ncpus; i++ ) 
   {
      // cpu mask
#if AFFINITY_USES_UINT128
      if( ( mask & ( (uint128_t)1 << i ) ) )  CPU_SET( i, &set );
#else
      if( (ncpus > 64) || ( mask & (1 << i) ) )  CPU_SET( i, &set );
#endif
   }
   if ( id == -1 )
   {
      // process affinity
      sched_setaffinity(0, sizeof(&set), &set);
   }
   else
   {
      // thread only
      pthread_setaffinity_np(thr_info[id].pth, sizeof(&set), &set);
   }
}

#elif defined(WIN32) /* Windows */
static inline void drop_policy(void) { }

// Windows CPU groups to manage more than 64 CPUs.
static void affine_to_cpu_mask( int id, uint64_t mask )
{
   bool success;
   unsigned long last_error;    
//   BOOL success;
//   DWORD last_error;

   if ( id == -1 )
      success = SetProcessAffinityMask( GetCurrentProcess(), mask );

// Are Windows CPU Groups supported?
#if _WIN32_WINNT==0x0601
   else if ( num_cpugroups == 1 )
	   success = SetThreadAffinityMask( GetCurrentThread(), mask );
   else
   {
	   // Find the correct cpu group
	   int cpu = id % num_cpus;
	   int group;
	   for( group = 0; group < num_cpugroups; group++ )
	   {
	      int cpus = GetActiveProcessorCount( group );
 	      if ( cpu < cpus )  break;
  	      cpu -= cpus;
      }

	   if (opt_debug)
         applog(LOG_DEBUG, "Binding thread %d to cpu %d on cpu group %d (mask %x)",
               id, cpu, group, (1ULL << cpu));

	   GROUP_AFFINITY affinity;
	   affinity.Group = group;
	   affinity.Mask = 1ULL << cpu;
	   success = SetThreadGroupAffinity( GetCurrentThread(), &affinity, NULL );
   }
#else
   else 
      success = SetThreadAffinityMask( GetCurrentThread(), mask );
#endif

   if (!success)
   {
	   last_error = GetLastError();
	   applog(LOG_WARNING, "affine_to_cpu_mask for %u returned %x",
               id, last_error);
   }
}

#else
static inline void drop_policy(void) { }
static void affine_to_cpu_mask(int id, unsigned long mask) { }
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
    const int atarget_sz  = ARRAY_SIZE(work->target);

    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = le32dec( work->data + i );
    for ( i = 0; i < atarget_sz; i++ )
          work->target[i] = le32dec( work->target + i );
    return true;
}

bool std_be_work_decode( struct work *work )
{
    int i;
    const int adata_sz    = algo_gate.get_work_data_size() / 4;
    const int atarget_sz  = ARRAY_SIZE(work->target);

    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = be32dec( work->data + i );
    for ( i = 0; i < atarget_sz; i++ )
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

    if ( !allow_mininginfo )
        net_diff = algo_gate.calc_network_diff( work );
    else
        net_diff = hash_to_diff( work->target );

    work->targetdiff = net_diff;
    stratum_diff = last_targetdiff = work->targetdiff;
    work->sharediff = 0;
    algo_gate.decode_extra_data( work, &net_blocks );

    return true;
}

// good alternative for wallet mining, difficulty and net hashrate
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
      // net_diff is a global that is set from the work hash target by
      // both getwork and GBT. Don't overwrite it, define a local to override
      // the global.
      double net_diff = 0.;
  		json_t *key = json_object_get( res, "difficulty" );
   	if ( key )
      {
	   	if ( json_is_object( key ) )
		   	key = json_object_get( key, "proof-of-work" );
		   if ( json_is_real( key ) )
			   net_diff = json_real_value( key );
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
         applog(LOG_INFO,"Mining info: diff %.5g, net_hashrate %f, height %d",
                              net_diff, net_hashrate, net_blocks );
      
      if ( !work->height )
      {
	      // complete missing data from getwork
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
   int i, n;
   uint32_t version, curtime, bits;
   uint32_t prevhash[8];
   uint32_t target[8];
   unsigned char final_sapling_hash[32];
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

// Segwit BEGIN
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
// Segwit END
   
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

// Segwit BEGIN
      //cbtx[cbtx_size++] = 1; /* out-counter */
        cbtx[cbtx_size++] = segwit ? 2 : 1; /* out-counter */
// Segwit END

      le32enc( (uint32_t *)( cbtx+cbtx_size) , (uint32_t)cbvalue ); /* value */
      le32enc( (uint32_t *)( cbtx+cbtx_size+4 ), cbvalue >> 32 );
      cbtx_size += 8;
      cbtx[ cbtx_size++ ] = (uint8_t) pk_script_size; /* txout-script length */
      memcpy( cbtx+cbtx_size, pk_script, pk_script_size );
      cbtx_size += (int) pk_script_size;

// Segwit BEGIN
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
         memset( wtree[1], 0, 32 );  /* witness reserved value = 0 */
         sha256d( cbtx+cbtx_size, wtree[0], 64 );
         cbtx_size += 32;
         free( wtree );
      }
// Segwit END

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
         {
            applog( LOG_WARNING,
                        "Signature does not fit in coinbase, skipping" );
         }
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
         int push_len = cbtx[41] + xsig_len < 76 ? 1 :
		               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
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

// Segwit BEGIN      
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
// Segwit END

         unsigned char *tx = (uchar*) malloc( tx_size );
         if ( !tx_hex || !hex2bin( tx, tx_hex, tx_size ) )
         {
            applog( LOG_ERR, "JSON invalid transactions" );
            free( tx );
            goto out;
         }
         sha256d( merkle_tree[1 + i], tx, tx_size );
         free( tx );

// Segwit BEGIN      
      }
// Segwit END

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

   /* assemble block header */
   algo_gate.build_block_header( work, swab32( version ),
                                 (uint32_t*) prevhash, (uint32_t*) merkle_tree,
                                 swab32( curtime ), le32dec( &bits ),
                                 final_sapling_hash );

   if ( unlikely( !jobj_binary( val, "target", target, sizeof(target) ) ) )
   {
      applog( LOG_ERR, "JSON invalid target" );
      goto out;
   }
   for ( i = 0; i < ARRAY_SIZE( work->target ); i++ )
      work->target[7 - i] = be32dec( target + i );
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

// returns the unit prefix and the hashrate appropriately scaled.
void scale_hash_for_display ( double* hashrate, char* prefix )
{
       if ( *hashrate < 1e4  )    *prefix =  0;
  else if ( *hashrate < 1e7  )  { *prefix = 'k';  *hashrate /= 1e3;  }
  else if ( *hashrate < 1e10 )  { *prefix = 'M';  *hashrate /= 1e6;  }  
  else if ( *hashrate < 1e13 )  { *prefix = 'G';  *hashrate /= 1e9;  }
  else if ( *hashrate < 1e16 )  { *prefix = 'T';  *hashrate /= 1e12; }
  else if ( *hashrate < 1e19 )  { *prefix = 'P';  *hashrate /= 1e15; }
  else if ( *hashrate < 1e22 )  { *prefix = 'E';  *hashrate /= 1e18; }
  else if ( *hashrate < 1e25 )  { *prefix = 'Z';  *hashrate /= 1e21; } 
  else                          { *prefix = 'Y';  *hashrate /= 1e24; }
}

static inline void sprintf_et( char *str, long unsigned int seconds )
{
   long unsigned int min = seconds / 60;
   long unsigned int sec = seconds % 60;
   long unsigned int hrs = min / 60;
   
   if ( unlikely( hrs ) )   
   {
      long unsigned int days = hrs / 24;
      long unsigned int years = days / 365;
      if ( years )      // 0y000d
         sprintf( str, "%luy%lud", years, years % 365 );
      else if ( days )  // 0d00h
         sprintf( str, "%lud%02luh", days, hrs % 24 );
      else         // 0h00m  
         sprintf( str, "%luh%02lum", hrs, min % 60 );
   }
   else         // 0m00s
      sprintf( str, "%lum%02lus", min, sec );
}

const long double exp32 = EXP32;                                  // 2**32
const long double exp48 = EXP32 * EXP16;                          // 2**48
const long double exp64 = EXP32 * EXP32;                          // 2**64
const long double exp96 = EXP32 * EXP32 * EXP32;                  // 2**96
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

   gettimeofday( &now, NULL );
   timeval_subtract( &et, &now, &five_min_start );

#if !(defined(__WINDOWS__) || defined(_WIN64) || defined(_WIN32))

   // Display CPU temperature and clock rate.
   int curr_temp = cpu_temp(0); 
   static struct timeval cpu_temp_time = {0};
   struct timeval diff;

   if ( !opt_quiet || ( curr_temp >= 80 ) )
   {
      int wait_time = curr_temp >= 90 ? 5 : curr_temp >= 80 ? 30 :
                                            curr_temp >= 70 ? 60 : 120;
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

   if ( !( force && ( submit_sum || ( et.tv_sec > 5 ) ) )
     && ( et.tv_sec < 300 ) )
      return;
   
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
   
   double share_time = (double)et.tv_sec + (double)et.tv_usec / 1e6;
   double ghrate = safe_div( total_hashes, (double)uptime.tv_sec, 0. );
   double target_diff = exp32 * last_targetdiff;
   double shrate = safe_div( target_diff * (double)(accepts),
                             share_time, 0. );
//   global_hashrate = ghrate;
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

   applog( LOG_BLUE, "%s: %s", algo_names[ opt_algo ], short_url );
   applog2( LOG_NOTICE, "Periodic Report     %s        %s", et_str, upt_str );
   applog2( LOG_INFO, "Share rate        %.2f/min     %.2f/min",
            submit_rate, (double)submitted_share_count*60. /
            ( (double)uptime.tv_sec + (double)uptime.tv_usec / 1e6 ) );
   applog2( LOG_INFO, "Hash rate       %7.2f%sh/s   %7.2f%sh/s   (%.2f%sh/s)",
            shrate, shr_units, sess_hrate, sess_hr_units, ghrate, ghr_units );

   if ( accepted_share_count < submitted_share_count )
   {
      double lost_ghrate = uptime.tv_sec == 0 ? 0.
                : target_diff
                       * (double)(submitted_share_count - accepted_share_count )
                  / (double)uptime.tv_sec;
      double lost_shrate = share_time == 0. ? 0.
               : target_diff  * (double)(submits - accepts ) / share_time;
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
   applog2( LOG_INFO, "Hi/Lo Share Diff  %.5g /  %.5g",
            highest_share, lowest_share );

   int mismatch = submitted_share_count
         - ( accepted_share_count + stale_share_count + rejected_share_count );
   if ( mismatch )
   {
      if ( mismatch != 1 )
         applog2(LOG_MINR, "Count mismatch: %d, stats may be inaccurate", mismatch );
      else
         applog2(LOG_INFO, CL_LBL "Count mismatch, submitted share may still be pending" CL_N );
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
   latency_sum += latency;

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

   applog( LOG_INFO, "%d %s%s %s%s %s%s %s%s" CL_WHT ", %.3f sec (%dms)",
           my_stats.share_count, acol, ares, scol, sres, rcol, rres, bcol,
           bres, share_time, latency );

   if ( unlikely( opt_debug || !result || solved ) )
   {
      if ( have_stratum )
         applog2( LOG_INFO, "Diff %.5g, Block %d, Job %s",
               my_stats.share_diff, my_stats.height, my_stats.job_id );
      else
         applog2( LOG_INFO, "Diff %.5g, Block %d",
               my_stats.share_diff, work ? work->height : last_block_height );
   }

   if ( unlikely( !( opt_quiet || result || stale ) ) )
   {
      uint32_t str[8];
      uint32_t *targ;

      if ( reason ) applog( LOG_MINR, "Reject reason: %s", reason );
         
      diff_to_hash( str, my_stats.share_diff );
      applog2( LOG_INFO, "Hash:   %08x%08x%08x%08x%08x%08x", str[7], str[6],
               str[5], str[4], str[3],str[2], str[1], str[0] );

      if ( work )
         targ = work->target;
      else
      {
         diff_to_hash( str, my_stats.target_diff );
         targ = &str[0];
      }
      applog2( LOG_INFO, "Target: %08x%08x%08x%08x%08x%08x", targ[7], targ[6],
               targ[5], targ[4], targ[3], targ[2], targ[1], targ[0] );
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

// Segwit BEGIN
#define GBT_RULES "[\"segwit\"]"
static const char *gbt_req =
   "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
   GBT_CAPABILITIES ", \"rules\": " GBT_RULES "}], \"id\":0}\r\n";
const char *gbt_lp_req =
   "{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
   GBT_CAPABILITIES ", \"rules\": " GBT_RULES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

/*
static const char *gbt_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES "}], \"id\":0}\r\n";
const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";
*/
// Segwit END

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
   } 
   else
      rc = work_decode( json_object_get( val, "result" ), work );

   if ( rc ) 
   {
      json_decref( val );

      get_mininginfo( curl, work );
      report_summary_log( false );
      
      if ( opt_protocol | opt_debug )
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

         applog( LOG_BLUE, "New Block %d, Net Diff %.5g, Ntime %08x",
                                work->height, net_diff,
                                work->data[ algo_gate.ntime_index ] );

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
      }  // work->height > last_block_height
      else if ( memcmp( &work->data[1], &g_work.data[1], 32 ) )
         applog( LOG_BLUE, "New Work: Block %d, Net Diff %.5g, Ntime %08x",
                                      work->height, net_diff,
                                      work->data[ algo_gate.ntime_index ] );
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
   struct work *ret_work;
   int failures = 0;

   ret_work = (struct work*) calloc( 1, sizeof(*ret_work) );
   if ( !ret_work )
	return false;

   /* obtain new work from bitcoin via JSON-RPC */
   while ( !get_upstream_work( curl, ret_work ) )
   {
      if ( unlikely( ( opt_retries >= 0 ) && ( ++failures > opt_retries ) ) )
      {
         applog( LOG_ERR, "json_rpc_call failed, terminating workio thread" );
         free( ret_work );
	      return false;
      }

      /* pause, then restart work-request loop */
	   applog( LOG_ERR, "json_rpc_call failed, retry after %d seconds",
		        opt_fail_pause );
      sleep( opt_fail_pause );
   }

   /* send work to requesting thread */
   if ( !tq_push(wc->thr->q, ret_work ) )
   	free( ret_work );

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

      work->data[algo_gate.ntime_index] = swab32(ts);  // ntime
  
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
	if (!work_heap)
		return false;
	/* copy returned work into storage provided by caller */
	memcpy(work, work_heap, sizeof(*work));
	free(work_heap);
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
   if ( !opt_quiet && work_restart[ thr->id ].restart )
      applog( LOG_INFO, CL_LBL "Share may be stale, submitting anyway..." CL_N );
   
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
           applog( LOG_INFO, "%d Submitted Diff %.5g, Block %d, Job %s",
                   submitted_share_count, work->sharediff, work->height,
                   work->job_id );
        else
           applog( LOG_INFO, "%d Submitted Diff %.5g, Block %d, Ntime %08x",
                   submitted_share_count, work->sharediff, work->height,
                   work->data[ algo_gate.ntime_index ] );
     }

     if ( opt_debug )
     {
        uint32_t* h = (uint32_t*)hash;
        uint32_t* t = (uint32_t*)work->target;
        uint32_t* d = (uint32_t*)work->data;

        unsigned char *xnonce2str = abin2hex( work->xnonce2,
                                              work->xnonce2_len );
        applog(LOG_INFO,"Thread %d, Nonce %08x, Xnonce2 %s", thr->id,
                       work->data[ algo_gate.nonce_index ], xnonce2str );
        free( xnonce2str );
        applog(LOG_INFO,"Data[0:19]: %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x", d[0],d[1],d[2],d[3],d[4],d[5],d[6],d[7],d[8],d[9] );
        applog(LOG_INFO,"          : %08x %08x %08x %08x %08x %08x %08x %08x %08x %08x", d[10],d[11],d[12],d[13],d[14],d[15],d[16],d[17],d[18],d[19]);
        applog(LOG_INFO,"Hash[7:0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                    h[7],h[6],h[5],h[4],h[3],h[2],h[1],h[0]);
        applog(LOG_INFO,"Targ[7:0]: %08x %08x %08x %08x %08x %08x %08x %08x",
                                    t[7],t[6],t[5],t[4],t[3],t[2],t[1],t[0]);
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

	if (opt_max_temp > 0.0)
   {
		float temp = cpu_temp(0);
		if (temp > opt_max_temp)
      {
			if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
				applog(LOG_INFO, "temperature too high (%.0fC), waiting...", temp);
			state = false;
		}
	}
	if (opt_max_diff > 0.0 && net_diff > opt_max_diff)
   {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
			applog(LOG_INFO, "network diff too high, waiting...");
		state = false;
	}
	if (opt_max_rate > 0.0 && net_hashrate > opt_max_rate)
   {
		if (!thr_id && !conditional_state[thr_id] && !opt_quiet)
      {
			char rate[32];
			format_hashrate(opt_max_rate, rate);
			applog(LOG_INFO, "network hashrate too high, waiting %s...", rate);
		}
		state = false;
	}
	if (thr_id < MAX_CPUS)
		conditional_state[thr_id] = (uint8_t) !state;
	return state;
}

// Common target functions, default usually listed first.

// default
void sha256d_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha256d( merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size );
  for ( int i = 0; i < sctx->job.merkle_count; i++ )
  {
     memcpy( merkle_root + 32, sctx->job.merkle[i], 32 );
     sha256d( merkle_root, merkle_root, 64 );
  }
}
void SHA256_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  SHA256( sctx->job.coinbase, (int)sctx->job.coinbase_size, merkle_root );
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

// calculate net diff from nbits.
double std_calc_network_diff( struct work* work )
{
   // sample for diff 43.281 : 1c05ea29
   // todo: endian reversed on longpoll could be zr5 specific...
   int nbits_index = algo_gate.nbits_index;
   uint32_t nbits = have_longpoll ? work->data[ nbits_index]
                                  : swab32( work->data[ nbits_index ] );
   uint32_t bits  = ( nbits & 0xffffff );
   int16_t  shift = ( swab32(nbits) & 0xff ); // 0x1c = 28
   int m;
   double d = (double)0x0000ffff / (double)bits;
   for ( m = shift; m < 29; m++ )
       d *= 256.0;
   for ( m = 29; m < shift; m++ )
       d /= 256.0;
   if ( opt_debug_diff )
      applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);
   return d;
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

bool std_ready_to_mine( struct work* work, struct stratum_ctx* stratum,
                           int thr_id )
{
   if ( have_stratum && !work->data[0] && !opt_benchmark )
   {
      sleep(1);
      return false;
   }
   return true;
}

static void stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   bool new_job;

   pthread_rwlock_wrlock( &g_work_lock );
   pthread_mutex_lock( &sctx->work_lock );

   new_job =  sctx->new_job;  // otherwise just increment extranonce2
   sctx->new_job = false;
   
   free( g_work->job_id );
   g_work->job_id = strdup( sctx->job.job_id );
   g_work->xnonce2_len = sctx->xnonce2_size;
   g_work->xnonce2 = (uchar*) realloc( g_work->xnonce2, sctx->xnonce2_size );
   memcpy( g_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size );
   algo_gate.build_extraheader( g_work, sctx );
   net_diff = algo_gate.calc_network_diff( g_work );
   algo_gate.set_work_data_endian( g_work );
   g_work->height = sctx->block_height;
   g_work->targetdiff = sctx->job.diff
                           / ( opt_target_factor * opt_diff_factor );
   diff_to_hash( g_work->target, g_work->targetdiff );

   // Pre increment extranonce2 in case of being called again before receiving
   // a new job
   for ( int t = 0;
         t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] );
         t++ );

   g_work_time = time(NULL);
   restart_threads();

   pthread_mutex_unlock( &sctx->work_lock );
   pthread_rwlock_unlock( &g_work_lock );

   pthread_mutex_lock( &stats_lock );

   double hr = 0.;
   for ( int i = 0; i < opt_n_threads; i++ )
      hr += thr_hashrates[i];
   global_hashrate = hr;

   pthread_mutex_unlock( &stats_lock );

   if ( stratum_diff != sctx->job.diff )
      applog( LOG_BLUE, "New Stratum Diff %g, Block %d, Job %s",
                        sctx->job.diff, sctx->block_height, g_work->job_id );
   else if ( last_block_height != sctx->block_height )
      applog( LOG_BLUE, "New Block %d, Net diff %.5g, Job %s",
                        sctx->block_height, net_diff, g_work->job_id );
   else if ( g_work->job_id && new_job )
      applog( LOG_BLUE, "New Work: Block %d, Net diff %.5g, Job %s",
                         sctx->block_height, net_diff, g_work->job_id );
   else if ( !opt_quiet )
   {
      unsigned char *xnonce2str = bebin2hex( g_work->xnonce2,
                                             g_work->xnonce2_len );
      applog( LOG_INFO, "Extranonce2 %s, Block %d, Job %s",
                        xnonce2str, sctx->block_height, g_work->job_id );
      free( xnonce2str );
   }

   // Update data and calculate new estimates.
   if ( ( stratum_diff != sctx->job.diff )
   || ( last_block_height != sctx->block_height ) )
   {
      static bool multipool = false;
      if ( stratum.block_height < last_block_height ) multipool = true;
      if ( unlikely( !session_first_block ) )
         session_first_block = stratum.block_height;
      last_block_height = stratum.block_height;
      stratum_diff      = sctx->job.diff;
      last_targetdiff   = g_work->targetdiff;
      if ( lowest_share < last_targetdiff )
         lowest_share = 9e99;

      if ( !opt_quiet )
      {
         applog2( LOG_INFO, "Diff: Net %.5g, Stratum %.5g, Target %.5g",
                            net_diff, stratum_diff, g_work->targetdiff );

         if ( likely( hr > 0. ) )
         {
            double nd = net_diff * exp32;
            char hr_units[4] = {0};
            char block_ttf[32];
            char share_ttf[32];

            sprintf_et( block_ttf, nd /  hr );
            sprintf_et( share_ttf, ( g_work->targetdiff * exp32 ) / hr );
            scale_hash_for_display ( &hr, hr_units );
            applog2( LOG_INFO, "TTF @ %.2f %sh/s: Block %s, Share %s",
                               hr, hr_units, block_ttf, share_ttf );

            if ( !multipool && last_block_height > session_first_block )
            {
               struct timeval now, et;
               gettimeofday( &now, NULL );
               timeval_subtract( &et, &now, &session_start );
               uint64_t net_ttf =
                    ( last_block_height - session_first_block ) == 0 ? 0
                    : et.tv_sec / ( last_block_height - session_first_block );
               if ( net_diff && net_ttf )
               {
                  double net_hr = nd / net_ttf;
                  char net_hr_units[4] = {0};
                  scale_hash_for_display ( &net_hr, net_hr_units );
                  applog2( LOG_INFO, "Net hash rate (est) %.2f %sh/s",
                                     net_hr, net_hr_units );
               }
            }
         }  // hr > 0
      } // !quiet
   }  // new diff/block

   if ( new_job && !opt_quiet )
   {
      int mismatch = submitted_share_count - ( accepted_share_count
                                             + stale_share_count
                                             + rejected_share_count );
      if ( mismatch )
         applog( LOG_INFO,
                 CL_LBL "%d Submitted share pending, maybe stale" CL_N,
                 submitted_share_count );
   }
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
   uint32_t end_nonce = 0xffffffffU / opt_n_threads  * (thr_id + 1) - 0x20;

   time_t   firstwork_time = 0;
   int  i;
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
   if ( num_cpus > 1 )
   {
#if AFFINITY_USES_UINT128
      // Default affinity
      if ( (opt_affinity == (uint128_t)(-1) ) && opt_n_threads > 1 )
      {  
         affine_to_cpu_mask( thr_id, (uint128_t)1 << (thr_id % num_cpus) );
         if ( opt_debug )
            applog( LOG_INFO, "Binding thread %d to cpu %d.",
                    thr_id, thr_id % num_cpus,
	                 u128_hi64( (uint128_t)1 << (thr_id % num_cpus) ),
		              u128_lo64( (uint128_t)1 << (thr_id % num_cpus) ) );
      }
#else
      if ( ( opt_affinity == -1 ) && ( opt_n_threads > 1 ) ) 
      {
         affine_to_cpu_mask( thr_id, 1 << (thr_id % num_cpus) );
         if (opt_debug)
            applog( LOG_DEBUG, "Binding thread %d to cpu %d.",
                thr_id, thr_id % num_cpus, 1 << (thr_id % num_cpus)) ;
      }
#endif
      else   // Custom affinity
      {
         affine_to_cpu_mask( thr_id, opt_affinity );
         if ( opt_debug )
         {
#if AFFINITY_USES_UINT128
            if ( num_cpus > 64 )
               applog( LOG_INFO, "Binding thread %d to mask %016llx %016llx",
                                thr_id, u128_hi64( opt_affinity ), 
                                        u128_lo64( opt_affinity ) );
            else
               applog( LOG_INFO, "Binding thread %d to mask %016llx",
                                 thr_id, opt_affinity );
#else
            applog( LOG_INFO, "Binding thread %d to mask %016llx",
                                 thr_id, opt_affinity );
#endif
         }
      }
   }  // num_cpus > 1

   if ( !algo_gate.miner_thread_init( thr_id ) )
   {
      applog( LOG_ERR, "FAIL: thread %u failed to initialize", thr_id );
      exit (1);
   }

   // wait for stratum to send first job
   if ( have_stratum ) while ( unlikely( stratum_down ) )
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
//       int64_t max64 = 1000;
       int nonce_found = 0;

       if ( likely( algo_gate.do_this_thread( thr_id ) ) )
       {
          if ( have_stratum ) 
          {
             while ( unlikely( stratum_down ) )
                sleep( 1 );
             if ( *nonceptr >= end_nonce )
                stratum_gen_work( &stratum, &g_work );
          }
          else
          {
             pthread_rwlock_wrlock( &g_work_lock );

             if ( ( ( time(NULL) - g_work_time )
                 >= ( have_longpoll ? LP_SCANTIME : opt_scantime ) )
               || ( *nonceptr >= end_nonce ) )
             {
                if ( unlikely( !get_work( mythr, &g_work ) ) )
                {
                   pthread_rwlock_unlock( &g_work_lock );
		             applog( LOG_ERR, "work retrieval failed, exiting "
		                              "mining thread %d", thr_id );
		             goto out;
	             }
                g_work_time = time(NULL);
                restart_threads();
             }

             pthread_rwlock_unlock( &g_work_lock );
          }

          pthread_rwlock_rdlock( &g_work_lock );

          algo_gate.get_new_work( &work, &g_work, thr_id, &end_nonce );
          work_restart[thr_id].restart = 0;

          pthread_rwlock_unlock( &g_work_lock );

       } // do_this_thread
       algo_gate.resync_threads( thr_id, &work );

       if ( unlikely( !algo_gate.ready_to_mine( &work, &stratum, thr_id ) ) )
          continue;

// LP_SCANTIME overrides opt_scantime option, is this right?

       // adjust max_nonce to meet target scan time. Stratum and longpoll
       // can go longer because they can rely on restart_threads to signal
       // an early abort. get_work on the other hand can't rely on
       // restart_threads so need a much shorter scantime
       if ( have_stratum )
          max64 = 60 * thr_hashrates[thr_id];
       else if ( have_longpoll )
          max64 = LP_SCANTIME * thr_hashrates[thr_id];
       else  // getwork inline
          max64 = opt_scantime * thr_hashrates[thr_id];   

       // time limit
       if ( unlikely( opt_time_limit && firstwork_time ) )
       {
          int passed = (int)( time(NULL) - firstwork_time );
          int remain = (int)( opt_time_limit - passed );
          if ( remain < 0 )
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
                fprintf(stderr, "%llu\n", (unsigned long long)global_hashrate);
             }
             else
                applog( LOG_NOTICE,
	          "Mining timeout of %ds reached, exiting...", opt_time_limit);
	       proper_exit(0);
          }
          if ( remain < max64 ) max64 = remain;
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
       if ( firstwork_time == 0 )
          firstwork_time = time(NULL);
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
//          applog( LOG_WARNING, "BUG: See RELEASE_NOTES for reporting bugs. Algo = %s.",
//                               algo_names[ opt_algo ] );
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
             applog( LOG_INFO, "CPU #%d: %s %sh/s",
                               thr_id, hr, hr_units );
          }
       }

       // Display benchmark total
       // Update hashrate for API if no shares accepted yet.
       if ( unlikely( ( opt_benchmark || !accepted_share_count ) 
            && thr_id == opt_n_threads - 1 ) )
       {
          double hashrate  = 0.;
          pthread_mutex_lock( &stats_lock );
          for ( i = 0; i < opt_n_threads; i++ )
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

             scale_hash_for_display( &hashrate,  hr_units );
             sprintf( hr, "%.2f", hashrate );
#if (defined(_WIN64) || defined(__WINDOWS__) || defined(_WIN32))
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
       }  // benchmark

       // conditional mining
       if ( unlikely( !wanna_mine( thr_id ) ) )
       {
          sleep(5);
          continue;
       }

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
	         if (net_diff > 0.)
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

static void *stratum_thread(void *userdata )
{
   struct thr_info *mythr = (struct thr_info *) userdata;
   char *s = NULL;

   stratum.url = (char*) tq_pop(mythr->q, NULL);
   if (!stratum.url)
      goto out;
   applog( LOG_BLUE, "Stratum connect %s", short_url );

   while (1)
   {
      int failures = 0;

      if ( unlikely( stratum_need_reset ) )
      {
          stratum_need_reset = false;
          stratum_down = true;
          stratum_disconnect( &stratum );
          if ( strcmp( stratum.url, rpc_url ) )
          {
	          free( stratum.url );
	          stratum.url = strdup( rpc_url );
	          applog(LOG_BLUE, "Connection changed to %s", short_url);
          }
          else 
	          applog(LOG_WARNING, "Stratum connection reset");
          // reset stats queue as well
          restart_threads();
          if ( s_get_ptr != s_put_ptr ) s_get_ptr = s_put_ptr = 0;
      }

      while ( !stratum.curl )
      {
         stratum_down = true;
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
            stratum_down = false;
            restart_threads();
            applog(LOG_BLUE,"Stratum connection established" );
         }
      }

      report_summary_log( ( stratum_diff != stratum.job.diff )
                       && ( stratum_diff != 0. ) );
      
      if ( stratum.new_job )
         stratum_gen_work( &stratum, &g_work );

      if ( likely( stratum_socket_full( &stratum, opt_timeout ) ) )
      {
         if ( likely( s = stratum_recv_line( &stratum ) ) )
         {
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

   }  // loop
out:
  return NULL;
}

static void show_credits()
{
   printf("\n         **********  "PACKAGE_NAME" "PACKAGE_VERSION"  *********** \n");
   printf("     A CPU miner with multi algo support and optimized for CPUs\n");
   printf("     with AVX512, SHA and VAES extensions by JayDDee.\n");
   printf("     BTC donation address: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT\n\n");
}

#define check_cpu_capability() cpu_capability( false )
#define display_cpu_capability() cpu_capability( true )
static bool cpu_capability( bool display_only )
{
     char cpu_brand[0x40];
     bool cpu_has_sse2   = has_sse2();
     bool cpu_has_aes    = has_aes_ni();
     bool cpu_has_sse42  = has_sse42();
     bool cpu_has_avx    = has_avx();
     bool cpu_has_avx2   = has_avx2();
     bool cpu_has_sha    = has_sha();
     bool cpu_has_avx512 = has_avx512();
     bool cpu_has_vaes   = has_vaes();
     bool sw_has_aes    = false;
     bool sw_has_sse2   = false;
     bool sw_has_sse42  = false;
     bool sw_has_avx    = false;
     bool sw_has_avx2   = false;
     bool sw_has_avx512 = false;
     bool sw_has_sha    = false;
     bool sw_has_vaes   = false;
     set_t algo_features = algo_gate.optimizations;
     bool algo_has_sse2    = set_incl( SSE2_OPT,    algo_features );
     bool algo_has_aes     = set_incl( AES_OPT,     algo_features );
     bool algo_has_sse42   = set_incl( SSE42_OPT,   algo_features );
     bool algo_has_avx2    = set_incl( AVX2_OPT,    algo_features );
     bool algo_has_avx512  = set_incl( AVX512_OPT,  algo_features );
     bool algo_has_sha     = set_incl( SHA_OPT,     algo_features );
     bool algo_has_vaes    = set_incl( VAES_OPT,    algo_features );
     bool algo_has_vaes256 = set_incl( VAES256_OPT, algo_features );
     bool use_aes;
     bool use_sse2;
     bool use_avx2;
     bool use_avx512;
     bool use_sha;
     bool use_vaes;
     bool use_none;

     #ifdef __AES__
       sw_has_aes = true;
     #endif
     #ifdef __SSE2__
         sw_has_sse2 = true;
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
     #ifdef __SHA__
         sw_has_sha = true;
     #endif
     #ifdef __VAES__
         sw_has_vaes = true;
     #endif


//     #if !((__AES__) || (__SSE2__))
//         printf("Neither __AES__ nor __SSE2__ defined.\n");
//     #endif

     cpu_brand_string( cpu_brand );
     printf( "CPU: %s\n", cpu_brand );

     printf("SW built on " __DATE__
     #ifdef _MSC_VER
         " with VC++ 2013\n");
     #elif defined(__GNUC__)
         " with GCC");
        printf(" %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
     #else
        printf("\n");
     #endif

     printf("CPU features: ");
     if      ( cpu_has_avx512 )    printf( " AVX512" );
     else if ( cpu_has_avx2   )    printf( " AVX2  " );
     else if ( cpu_has_avx    )    printf( " AVX   " );
     else if ( cpu_has_sse42  )    printf( " SSE4.2" );
     else if ( cpu_has_sse2   )    printf( " SSE2  " );
     if      ( cpu_has_vaes   )    printf( " VAES"   );
     else if ( cpu_has_aes    )    printf( "  AES"   );
     if      ( cpu_has_sha    )    printf( " SHA"    );

     printf("\nSW features:  ");
     if      ( sw_has_avx512 )    printf( " AVX512" );
     else if ( sw_has_avx2   )    printf( " AVX2  " );
     else if ( sw_has_avx    )    printf( " AVX   " );
     else if ( sw_has_sse42  )    printf( " SSE4.2" );
     else if ( sw_has_sse2   )    printf( " SSE2  " );
     if      ( sw_has_vaes   )    printf( " VAES"   );
     else if ( sw_has_aes    )    printf( "  AES"   );
     if      ( sw_has_sha    )    printf( " SHA"    );

     printf("\nAlgo features:");
     if ( algo_features == EMPTY_SET ) printf( " None" );
     else
     {
        if      ( algo_has_avx512  )  printf( " AVX512" );
        else if ( algo_has_avx2    )  printf( " AVX2  " );
        else if ( algo_has_sse42   )  printf( " SSE4.2" );
        else if ( algo_has_sse2    )  printf( " SSE2  " );
        if      ( algo_has_vaes ||
                  algo_has_vaes256 )  printf( " VAES"   );
        else if ( algo_has_aes     )  printf( "  AES"   );
        if      ( algo_has_sha     )  printf( " SHA"    );
     }
     printf("\n");

     if ( display_only ) return true;

     // Check for CPU and build incompatibilities
     if ( !cpu_has_sse2 )
     {
        printf( "A CPU with SSE2 is required to use cpuminer-opt\n" );
        return false;
     }
     if ( sw_has_avx2 && !( cpu_has_avx2 && cpu_has_aes ) )
     {
        printf( "The SW build requires a CPU with AES and AVX2!\n" );
        return false;
     }
     if ( sw_has_sse42 && !cpu_has_sse42 )
     {
        printf( "The SW build requires a CPU with SSE4.2!\n" );
        return false;
     }
     if ( sw_has_aes && !cpu_has_aes )
     {
        printf( "The SW build requires a CPU with AES!\n" );
        return false;
     }
     if ( sw_has_sha && !cpu_has_sha )
     {
        printf( "The SW build requires a CPU with SHA!\n" );
        return false;
     }

     // Determine mining options
     use_sse2   = cpu_has_sse2   && algo_has_sse2;
     use_aes    = cpu_has_aes    && sw_has_aes    && algo_has_aes;
     use_avx2   = cpu_has_avx2   && sw_has_avx2   && algo_has_avx2;
     use_avx512 = cpu_has_avx512 && sw_has_avx512 && algo_has_avx512;
     use_sha    = cpu_has_sha    && sw_has_sha    && algo_has_sha;
     use_vaes   = cpu_has_vaes   && sw_has_vaes   && ( algo_has_vaes
                                                    || algo_has_vaes256 );
     use_none = !( use_sse2 || use_aes || use_avx512 || use_avx2 ||
                   use_sha || use_vaes );

     // Display best options
     printf( "\nStarting miner with" );
     if         ( use_none ) printf( " no optimizations" );
     else
     {
        if      ( use_avx512 ) printf( " AVX512" );
        else if ( use_avx2   ) printf( " AVX2"   );
        else if ( use_sse2   ) printf( " SSE2"   );
        if      ( use_vaes   ) printf( " VAES"   );
        else if ( use_aes    ) printf( " AES"    );
        if      ( use_sha    ) printf( " SHA"    );
     }
     printf( "...\n\n" );

     return true;
}
        
void show_version_and_exit(void)
{
        printf("\n built on " __DATE__
#ifdef _MSC_VER
         " with VC++ 2013\n");
#elif defined(__GNUC__)
         " with GCC");
        printf(" %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

        printf(" features:"
#if defined(USE_ASM) && defined(__i386__)
                " i386"
#endif
#if defined(USE_ASM) && defined(__x86_64__)
                " x86_64"
#endif
#if defined(USE_ASM) && (defined(__i386__) || defined(__x86_64__))
                " SSE2"
#endif
#if defined(__x86_64__) && defined(USE_AVX)
                " AVX"
#endif
#if defined(__x86_64__) && defined(USE_AVX2)
                " AVX2"
#endif
#if defined(__x86_64__) && defined(USE_XOP)
                " XOP"
#endif
#if defined(USE_ASM) && defined(__arm__) && defined(__APCS_32__)
                " ARM"
#if defined(__ARM_ARCH_5E__) || defined(__ARM_ARCH_5TE__) || \
        defined(__ARM_ARCH_5TEJ__) || defined(__ARM_ARCH_6__) || \
        defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || \
        defined(__ARM_ARCH_6M__) || defined(__ARM_ARCH_6T2__) || \
        defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || \
        defined(__ARM_ARCH_7__) || \
        defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || \
        defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7EM__)
                " ARMv5E"
#endif
#if defined(__ARM_NEON__)
                " NEON"
#endif
#endif
                "\n\n");

        printf("%s\n", curl_version());
#ifdef JANSSON_VERSION
        printf("jansson/%s ", JANSSON_VERSION);
#endif
#ifdef PTW32_VERSION
        printf("pthreads/%d.%d.%d.%d ", PTW32_VERSION);
#endif
        printf("\n");
        exit(0);
}

void show_usage_and_exit(int status)
{
	if (status)
                fprintf(stderr, "Try `--help' for more information.\n");
//		fprintf(stderr, "Try `" PACKAGE_NAME " --help' for more information.\n");
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
	uint64_t ul;
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
         opt_api_allow = default_api_allow;      
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
		if ( !( opt_debug || opt_protocol ) ) opt_quiet = true;
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
		p = strstr(arg, "0x");
		if ( p )
			ul = strtoull( p, NULL, 16 );
		else
			ul = atoll( arg );
#if AFFINITY_USES_UINT128
// replicate the low 64 bits to make a full 128 bit mask if there are more
// than 64 CPUs, otherwise zero extend the upper half.
         opt_affinity = (uint128_t)ul;
         if ( num_cpus > 64 )
            opt_affinity |= opt_affinity << 64;
#else
         opt_affinity = ul;
#endif
		break;
	case 1021:  // cpu-priority
		v = atoi(arg);
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
		break;
   case 1027:  // data-file
      opt_data_file = strdup( arg );
      break;
   case 1028:  // verify
      opt_verify = true;
      break;
	case 'V':
      display_cpu_capability();
      exit(0);
	case 'h':
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
	if (key < 0)
		break;

	parse_arg(key, optarg);
   }
   if (optind < argc)
   {
	fprintf(stderr, "%s: unsupported non-option argument -- '%s'\n",
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

   parse_cmdline(argc, argv);

#if defined(WIN32)
//	SYSTEM_INFO sysinfo;
//	GetSystemInfo(&sysinfo);
//	num_cpus = sysinfo.dwNumberOfProcessors;
// What happens if GetActiveProcessorGroupCount called if groups not enabled?

// Are Windows CPU Groups supported?
#if _WIN32_WINNT==0x0601
 	num_cpus = 0;
	num_cpugroups = GetActiveProcessorGroupCount();
	for(  i = 0; i < num_cpugroups; i++ )
	{
 	   int cpus = GetActiveProcessorCount(i);
	   num_cpus += cpus;

	   if (opt_debug)
         applog(LOG_DEBUG, "Found %d cpus on cpu group %d", cpus, i);
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
	if (num_cpus < 1)
		num_cpus = 1;

   if (!opt_n_threads)
      opt_n_threads = num_cpus;

   if ( opt_algo == ALGO_NULL )
   {
      fprintf(stderr, "%s: no algo supplied\n", argv[0]);
      show_usage_and_exit(1);
   }

   // need to register to get algo optimizations for cpu capabilities
   // but that causes register logs before cpu capabilities is output.
   // Would need to split register into 2 parts. First part sets algo
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

   // All options must be set before starting the gate
//   if ( !register_algo_gate( opt_algo, &algo_gate ) )  exit(1);

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

//   if ( !check_cpu_capability() ) exit(1);

	pthread_mutex_init( &stats_lock, NULL );
   pthread_rwlock_init( &g_work_lock, NULL );
	pthread_mutex_init( &stratum.sock_lock, NULL );
	pthread_mutex_init( &stratum.work_lock, NULL );

   flags = CURL_GLOBAL_ALL;
   if ( !opt_benchmark )
     if ( strncasecmp( rpc_url, "https:", 6 )
       && strncasecmp( rpc_url, "stratum+tcps://", 15 ) )
         flags &= ~CURL_GLOBAL_SSL;

   if ( curl_global_init( flags ) )
   {
		applog(LOG_ERR, "CURL initialization failed");
		return 1;
	}

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

// To be confirmed with more than 64 cpus
   if ( opt_affinity != -1 )
   {
      if ( !affinity_uses_uint128 && num_cpus > 64 )
      {
          applog(LOG_WARNING,"Setting CPU affinity with more than 64 CPUs is only");
          applog(LOG_WARNING,"available on Linux. Using default affinity.");
          opt_affinity = -1;
      }
/*
      else	
      {
         affine_to_cpu_mask( -1, opt_affinity );
         if ( !opt_quiet )
         {
#if AFFINITY_USES_UINT128
            if ( num_cpus > 64 )
               applog(LOG_DEBUG, "Binding process to cpu mask %x",
                      u128_hi64( opt_affinity ), u128_lo64( opt_affinity ) );
            else 
               applog(LOG_DEBUG, "Binding process to cpu mask %x",
                      opt_affinity );
#else
               applog(LOG_DEBUG, "Binding process to cpu mask %x",
                      opt_affinity );
#endif
         }
      }
*/
   }

   if ( !opt_quiet && ( opt_n_threads < num_cpus ) )
   {
      char affinity_map[64];
      format_affinity_map( affinity_map, opt_affinity );
      applog( LOG_INFO, "CPU affinity [%s]", affinity_map );
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
         applog( LOG_INFO,"API listnening to %s:%d", opt_api_allow,
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

   // Initialize stats times and counters
   memset( share_stats, 0, s_stats_size *  sizeof (struct share_stats_t) );
   gettimeofday( &last_submit_time, NULL );
   memcpy( &five_min_start, &last_submit_time, sizeof (struct timeval) );
   memcpy( &session_start, &last_submit_time, sizeof (struct timeval) );
   memcpy( &total_hashes_time, &last_submit_time, sizeof (struct timeval) );
   pthread_mutex_unlock( &stats_lock );

   applog( LOG_INFO, "%d of %d miner threads started using '%s' algorithm",
                     opt_n_threads, num_cpus, algo_names[opt_algo] );

	/* main loop - simply wait for workio thread to exit */
	pthread_join( thr_info[work_thr_id].pth, NULL );
	applog( LOG_WARNING, "workio thread dead, exiting." );
	return 0;
}
