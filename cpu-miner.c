/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012-2014 pooler
 * Copyright 2014 Lucas Jones
 * Copyright 2014 Tanguy Pruvot
 * Copyright 2016 Jay D Dee
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


#ifdef _MSC_VER
#include <windows.h>
#include <stdint.h>
#else
#include <errno.h>
#if HAVE_SYS_SYSCTL_H
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/sysctl.h>
#endif
#endif

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
bool opt_showdiff = true;
bool opt_extranonce = true;
bool want_longpoll = true;
bool have_longpoll = false;
bool have_gbt = true;
bool allow_getwork = true;
bool want_stratum = true;
bool have_stratum = false;
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
static const bool opt_time = true;
enum algos opt_algo = ALGO_NULL;
//int opt_scrypt_n = 0;
char* opt_param_key = NULL;
int opt_param_n = 0;
int opt_param_r = 0;
int opt_pluck_n = 128;
int opt_n_threads = 0;
int64_t opt_affinity = -1;
int opt_priority = 0;
int num_cpus;
char *rpc_url = NULL;;
char *rpc_userpass = NULL;
char *rpc_user, *rpc_pass;
char *short_url = NULL;
static unsigned char pk_script[25] = { 0 };
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
bool jsonrpc_2 = false;
char rpc2_id[64] = "";
char *rpc2_blob = NULL;
size_t rpc2_bloblen = 0;
uint32_t rpc2_target = 0;
char *rpc2_job_id = NULL;
double opt_diff_factor = 1.0;
double opt_target_factor = 1.0;
uint32_t zr5_pok = 0;
bool opt_stratum_stats = false;

uint32_t accepted_count = 0L;
uint32_t rejected_count = 0L;
double *thr_hashrates;
double *thr_hashcount;
double global_hashcount = 0;
double global_hashrate = 0;
double stratum_diff = 0.;
double net_diff = 0.;
double net_hashrate = 0.;
uint64_t net_blocks = 0;
// conditional mining
  bool conditional_state[MAX_CPUS] = { 0 };
  double opt_max_temp = 0.0;
  double opt_max_diff = 0.0;
  double opt_max_rate = 0.0;

  uint32_t opt_work_size = 0;
  char *opt_api_allow = NULL;
  int opt_api_remote = 0;
  int opt_api_listen = 4048; 

  pthread_mutex_t rpc2_job_lock;
  pthread_mutex_t rpc2_login_lock;
  pthread_mutex_t applog_lock;
  pthread_mutex_t stats_lock;


static char const short_options[] =
#ifdef HAVE_SYSLOG_H
	"S"
#endif
	"a:b:Bc:CDf:hm:n:p:Px:qr:N:R:K:s:t:T:o:u:O:V";

static struct work g_work = {{ 0 }};
//static struct work tmp_work;
time_t g_work_time = 0;
static        pthread_mutex_t g_work_lock;
static bool   submit_old = false;
static char*  lp_id;

static void   workio_cmd_free(struct workio_cmd *wc);

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

static void affine_to_cpu_mask( int id, unsigned long long mask )
{
   cpu_set_t set;
   CPU_ZERO(&set);
   uint8_t ncpus = (num_cpus > 256) ? 256 : num_cpus;       

   for ( uint8_t i = 0; i < ncpus; i++ ) 
   {
      // cpu mask
      if( (ncpus > 64) || ( mask & (1ULL << i) ) )  CPU_SET( i, &set );
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
static void affine_to_cpu_mask(int id, unsigned long mask) {
	if (id == -1)
		SetProcessAffinityMask(GetCurrentProcess(), mask);
	else
		SetThreadAffinityMask(GetCurrentThread(), mask);
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

bool jr2_work_decode( const json_t *val, struct work *work )
{ return rpc2_job_decode( val, work ); }

// Default
bool std_le_work_decode( const json_t *val, struct work *work )
{
    int i;
    const int data_size   = algo_gate.work_data_size;
    const int target_size = sizeof(work->target);
    const int adata_sz    = data_size / 4;
    const int atarget_sz  = ARRAY_SIZE(work->target);

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
    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = le32dec( work->data + i );
    for ( i = 0; i < atarget_sz; i++ )
          work->target[i] = le32dec( work->target + i );
    return true;
}

bool std_be_work_decode( const json_t *val, struct work *work )
{
    int i;
    const int data_size   = algo_gate.work_data_size;
    const int target_size = sizeof(work->target);
    const int adata_sz    = data_size / 4;
    const int atarget_sz  = ARRAY_SIZE(work->target);

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
    for ( i = 0; i < adata_sz; i++ )
          work->data[i] = be32dec( work->data + i );
    for ( i = 0; i < atarget_sz; i++ )
          work->target[i] = le32dec( work->target + i );
    return true;
}

static bool work_decode( const json_t *val, struct work *work )
{
    if ( !algo_gate.work_decode( val, work ) )
        return false;
    if ( !allow_mininginfo )
        net_diff = algo_gate.calc_network_diff( work );
    work->targetdiff = target_to_diff( work->target );
    // for api stats, on longpoll pools
    stratum_diff = work->targetdiff;
    work->sharediff = 0;
    algo_gate.display_extra_data( work, &net_blocks );
    return true;
}

// good alternative for wallet mining, difficulty and net hashrate
static const char *info_req =
"{\"method\": \"getmininginfo\", \"params\": [], \"id\":8}\r\n";

static bool get_mininginfo(CURL *curl, struct work *work)
{
	if (have_stratum || !allow_mininginfo)
		return false;

	int curl_err = 0;
	json_t *val = json_rpc_call(curl, rpc_url, rpc_userpass, info_req, &curl_err, 0);

	if (!val && curl_err == -1) {
		allow_mininginfo = false;
		if (opt_debug) {
			applog(LOG_DEBUG, "getmininginfo not supported");
		}
		return false;
	}
	else
        {
	   json_t *res = json_object_get(val, "result");
	   // "blocks": 491493 (= current work height - 1)
	   // "difficulty": 0.99607860999999998
	   // "networkhashps": 56475980
	   if (res)
           {
		json_t *key = json_object_get(res, "difficulty");
		if (key) {
			if (json_is_object(key))
				key = json_object_get(key, "proof-of-work");
			if (json_is_real(key))
				net_diff = json_real_value(key);
		}
		key = json_object_get(res, "networkhashps");
		if (key && json_is_integer(key)) {
			net_hashrate = (double) json_integer_value(key);
		}
		key = json_object_get(res, "blocks");
		if (key && json_is_integer(key)) {
			net_blocks = json_integer_value(key);
		}
		if (!work->height)
                {
		   // complete missing data from getwork
		   work->height = (uint32_t) net_blocks + 1;
		   if (work->height > g_work.height)
                   {
			restart_threads();
			if (!opt_quiet) {
			   char netinfo[64] = { 0 };
			   char srate[32] = { 0 };
			   sprintf(netinfo, "diff %.2f", net_diff);
			   if (net_hashrate) {
				format_hashrate(net_hashrate, srate);
				strcat(netinfo, ", net ");
				strcat(netinfo, srate);
			   }
			   applog(LOG_BLUE, "%s block %d, %s",
				algo_names[opt_algo], work->height, netinfo);
			}
		   }
		}
	   }
	}
	json_decref(val);
	return true;
}

#define BLOCK_VERSION_CURRENT 3

static bool gbt_work_decode(const json_t *val, struct work *work)
{
	int i, n;
	uint32_t version, curtime, bits;
	uint32_t prevhash[8];
	uint32_t target[8];
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

	tmp = json_object_get(val, "mutable");
	if (tmp && json_is_array(tmp)) {
           n = (int) json_array_size(tmp);
	   for (i = 0; i < n; i++) {
		const char *s = json_string_value(json_array_get(tmp, i));
		if (!s)
			continue;
		if (!strcmp(s, "coinbase/append"))
			coinbase_append = true;
		else if (!strcmp(s, "submit/coinbase"))
			submit_coinbase = true;
		else if (!strcmp(s, "version/force"))
			version_force = true;
		else if (!strcmp(s, "version/reduce"))
			version_reduce = true;
	   }
	}

	tmp = json_object_get(val, "height");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid height");
		goto out;
	}
	work->height = (int) json_integer_value(tmp);
	applog(LOG_BLUE, "Current block is %d", work->height);

	tmp = json_object_get(val, "version");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid version");
		goto out;
	}
	version = (uint32_t) json_integer_value(tmp);
	if ((version & 0xffU) > BLOCK_VERSION_CURRENT) {
	   if (version_reduce) {
		version = (version & ~0xffU) | BLOCK_VERSION_CURRENT;
	   } else if (have_gbt && allow_getwork && !version_force) {
		applog(LOG_DEBUG, "Switching to getwork, gbt version %d",
                             version);
		have_gbt = false;
		goto out;
	   } else if (!version_force) {
		applog(LOG_ERR, "Unrecognized block version: %u", version);
		goto out;
	   }
	}

	if ( unlikely( !jobj_binary(val, "previousblockhash", prevhash,
                             sizeof(prevhash)) ) )
        {
		applog(LOG_ERR, "JSON invalid previousblockhash");
		goto out;
	}

	tmp = json_object_get(val, "curtime");
	if (!tmp || !json_is_integer(tmp)) {
		applog(LOG_ERR, "JSON invalid curtime");
		goto out;
	}
	curtime = (uint32_t) json_integer_value(tmp);

	if (unlikely(!jobj_binary(val, "bits", &bits, sizeof(bits)))) {
		applog(LOG_ERR, "JSON invalid bits");
		goto out;
	}

	/* find count and size of transactions */
	txa = json_object_get(val, "transactions");
	if (!txa || !json_is_array(txa)) {
		applog(LOG_ERR, "JSON invalid transactions");
		goto out;
	}
	tx_count = (int) json_array_size(txa);
	tx_size = 0;
	for (i = 0; i < tx_count; i++) {
		const json_t *tx = json_array_get(txa, i);
		const char *tx_hex = json_string_value(json_object_get(tx, "data"));
		if (!tx_hex) {
			applog(LOG_ERR, "JSON invalid transactions");
			goto out;
		}
		tx_size += (int) (strlen(tx_hex) / 2);
	}

	/* build coinbase transaction */
	tmp = json_object_get(val, "coinbasetxn");
	if (tmp) {
		const char *cbtx_hex = json_string_value(json_object_get(tmp, "data"));
		cbtx_size = cbtx_hex ? (int) strlen(cbtx_hex) / 2 : 0;
		cbtx = (uchar*) malloc(cbtx_size + 100);
		if (cbtx_size < 60 || !hex2bin(cbtx, cbtx_hex, cbtx_size)) {
			applog(LOG_ERR, "JSON invalid coinbasetxn");
			goto out;
		}
	} else {
		int64_t cbvalue;
		if (!pk_script_size) {
			if (allow_getwork) {
				applog(LOG_INFO, "No payout address provided, switching to getwork");
				have_gbt = false;
			} else
				applog(LOG_ERR, "No payout address provided");
			goto out;
		}
		tmp = json_object_get(val, "coinbasevalue");
		if (!tmp || !json_is_number(tmp)) {
			applog(LOG_ERR, "JSON invalid coinbasevalue");
			goto out;
		}
		cbvalue = (int64_t) (json_is_integer(tmp) ? json_integer_value(tmp) : json_number_value(tmp));
		cbtx = (uchar*) malloc(256);
		le32enc((uint32_t *)cbtx, 1); /* version */
		cbtx[4] = 1; /* in-counter */
		memset(cbtx+5, 0x00, 32); /* prev txout hash */
		le32enc((uint32_t *)(cbtx+37), 0xffffffff); /* prev txout index */
		cbtx_size = 43;
		/* BIP 34: height in coinbase */
		for (n = work->height; n; n >>= 8)
			cbtx[cbtx_size++] = n & 0xff;
		cbtx[42] = cbtx_size - 43;
		cbtx[41] = cbtx_size - 42; /* scriptsig length */
		le32enc((uint32_t *)(cbtx+cbtx_size), 0xffffffff); /* sequence */
		cbtx_size += 4;
		cbtx[cbtx_size++] = 1; /* out-counter */
		le32enc((uint32_t *)(cbtx+cbtx_size), (uint32_t)cbvalue); /* value */
		le32enc((uint32_t *)(cbtx+cbtx_size+4), cbvalue >> 32);
		cbtx_size += 8;
		cbtx[cbtx_size++] = (uint8_t) pk_script_size; /* txout-script length */
		memcpy(cbtx+cbtx_size, pk_script, pk_script_size);
		cbtx_size += (int) pk_script_size;
		le32enc((uint32_t *)(cbtx+cbtx_size), 0); /* lock time */
		cbtx_size += 4;
		coinbase_append = true;
	}
	if (coinbase_append)
        {
	   unsigned char xsig[100];
	   int xsig_len = 0;
	   if (*coinbase_sig) {
		n = (int) strlen(coinbase_sig);
		if (cbtx[41] + xsig_len + n <= 100) {
			memcpy(xsig+xsig_len, coinbase_sig, n);
			xsig_len += n;
		} else {
			applog(LOG_WARNING, "Signature does not fit in coinbase, skipping");
		}
	   }
	   tmp = json_object_get(val, "coinbaseaux");
	   if (tmp && json_is_object(tmp))
           {
		void *iter = json_object_iter(tmp);
		while (iter)
                {
			unsigned char buf[100];
			const char *s = json_string_value(json_object_iter_value(iter));
			n = s ? (int) (strlen(s) / 2) : 0;
			if (!s || n > 100 || !hex2bin(buf, s, n)) {
				applog(LOG_ERR, "JSON invalid coinbaseaux");
				break;
			}
			if (cbtx[41] + xsig_len + n <= 100) {
				memcpy(xsig+xsig_len, buf, n);
				xsig_len += n;
			}
			iter = json_object_iter_next(tmp, iter);
		 }
	   }
	   if (xsig_len)
           {
		unsigned char *ssig_end = cbtx + 42 + cbtx[41];
		int push_len = cbtx[41] + xsig_len < 76 ? 1 :
		               cbtx[41] + 2 + xsig_len > 100 ? 0 : 2;
		n = xsig_len + push_len;
		memmove(ssig_end + n, ssig_end, cbtx_size - 42 - cbtx[41]);
		cbtx[41] += n;
		if (push_len == 2)
			*(ssig_end++) = 0x4c; /* OP_PUSHDATA1 */
		if (push_len)
			*(ssig_end++) = xsig_len;
		memcpy(ssig_end, xsig, xsig_len);
		cbtx_size += n;
	   }
	}

	n = varint_encode(txc_vi, 1 + tx_count);
	work->txs = (char*) malloc(2 * (n + cbtx_size + tx_size) + 1);
	bin2hex(work->txs, txc_vi, n);
	bin2hex(work->txs + 2*n, cbtx, cbtx_size);

	/* generate merkle root */
	merkle_tree = (uchar(*)[32]) calloc(((1 + tx_count + 1) & ~1), 32);
	sha256d(merkle_tree[0], cbtx, cbtx_size);
	for (i = 0; i < tx_count; i++)
        {
	   tmp = json_array_get(txa, i);
	   const char *tx_hex = json_string_value(json_object_get(tmp, "data"));
	   const int tx_size = tx_hex ? (int) (strlen(tx_hex) / 2) : 0;
	   unsigned char *tx = (uchar*) malloc(tx_size);
	   if (!tx_hex || !hex2bin(tx, tx_hex, tx_size))
           {
		applog(LOG_ERR, "JSON invalid transactions");
		free(tx);
		goto out;
	   }
  	   sha256d(merkle_tree[1 + i], tx, tx_size);
	   if (!submit_coinbase)
		strcat(work->txs, tx_hex);
	}
	n = 1 + tx_count;
	while (n > 1)
        {
	   if (n % 2)
           {
		memcpy(merkle_tree[n], merkle_tree[n-1], 32);
		++n;
	   }
	   n /= 2;
	   for (i = 0; i < n; i++)
		sha256d(merkle_tree[i], merkle_tree[2*i], 64);
	}

	/* assemble block header */
	work->data[0] = swab32(version);
	for (i = 0; i < 8; i++)
		work->data[8 - i] = le32dec(prevhash + i);
	for (i = 0; i < 8; i++)
		work->data[9 + i] = be32dec((uint32_t *)merkle_tree[0] + i);
	work->data[17] = swab32(curtime);
	work->data[18] = le32dec(&bits);
	memset(work->data + 19, 0x00, 52);
	work->data[20] = 0x80000000;
	work->data[31] = 0x00000280;

	if ( unlikely( !jobj_binary(val, "target", target, sizeof(target)) ) )
        {
		applog(LOG_ERR, "JSON invalid target");
		goto out;
	}
	for (i = 0; i < ARRAY_SIZE(work->target); i++)
		work->target[7 - i] = be32dec(target + i);

	tmp = json_object_get(val, "workid");
	if (tmp)
        {
	   if (!json_is_string(tmp)) {
		applog(LOG_ERR, "JSON invalid workid");
		goto out;
	   }
	   work->workid = strdup(json_string_value(tmp));
	}

	rc = true;
out:
	/* Long polling */
	tmp = json_object_get(val, "longpollid");
	if (want_longpoll && json_is_string(tmp))
        {
	   free(lp_id);
	   lp_id = strdup(json_string_value(tmp));
	   if (!have_longpoll)
           {
	   	char *lp_uri;
		tmp = json_object_get(val, "longpolluri");
		lp_uri = json_is_string(tmp) ? strdup(json_string_value(tmp)) : rpc_url;
		have_longpoll = true;
		tq_push(thr_info[longpoll_thr_id].q, lp_uri);
	   }
	}

	free(merkle_tree);
	free(cbtx);
	return rc;
}

void scale_hash_for_display ( double* hashrate, char* units )
{
     if ( *hashrate < 1e4 )
       // 0 H/s to 9999 H/s
       *units = 0;
     else if ( *hashrate < 1e7 )
     {
       // 10 kH/s to 9999 kH/s
       *units = 'k';
       *hashrate /= 1e3;
     }
     else if ( *hashrate < 1e10 )
     {
       // 10 Mh/s to 9999 Mh/s
       *units = 'M';
       *hashrate /= 1e6;
     }
     else if ( *hashrate < 1e13 )
     {
       // 10 iGh/s to 9999 Gh/s
       *units = 'G';
       *hashrate /= 1e9;
     }
     else
     {
       // 10 Th/s and higher
       *units = 'T';
       *hashrate /= 1e12;
     }
}

static int share_result( int result, struct work *work, const char *reason )
{
   char hc[16];
   char hr[16];
   const char *sres;
   double hashcount = 0.;
   double hashrate = 0.;
   char hc_units[4] = {0};
   char hr_units[4] = {0};
   uint32_t total_submits;
   float rate;
   char rate_s[8] = {0};
   double sharediff = work ? work->sharediff : stratum.sharediff;
   int i;

   pthread_mutex_lock(&stats_lock);
   for (i = 0; i < opt_n_threads; i++)
   {
       hashcount += thr_hashcount[i];
       hashrate += thr_hashrates[i];
   }
   result ? accepted_count++ : rejected_count++;
   pthread_mutex_unlock(&stats_lock);
   global_hashcount = hashcount;
   global_hashrate = hashrate;
   total_submits = accepted_count + rejected_count;

   rate = ( result ? ( 100. * accepted_count / total_submits )  
                   : ( 100. * rejected_count / total_submits ) );

   if (use_colors)
        sres = (result ? CL_GRN "Accepted" CL_WHT : CL_RED "Rejected" CL_WHT );
   else
        sres = (result ? "Accepted" : "Rejected" );

   // Contrary to rounding convention 100% means zero rejects, exactly 100%. 
   // Rates > 99% and < 100% (rejects>0) display 99.9%.
   if ( result )
   {
      rate = 100. * accepted_count / total_submits;
      if ( rate == 100.0 )
         sprintf( rate_s, "%.0f", rate );
      else
          sprintf( rate_s, "%.1f", ( rate < 99.9 ) ? rate : 99.9 );
   }
   else
   {
      rate = 100. * rejected_count / total_submits;
      if ( rate < 0.1 )
         sprintf( rate_s, "%.1f", 0.10 );
      else
         sprintf( rate_s, "%.1f", rate );
   }

   scale_hash_for_display ( &hashcount, hc_units );
   scale_hash_for_display ( &hashrate, hr_units );
   if ( hc_units[0] )
   {
      sprintf(hc, "%.2f", hashcount );
      if ( hashrate < 10 )
         // very low hashrate, add digits
         sprintf(hr, "%.4f", hashrate );
      else
         sprintf(hr, "%.2f", hashrate );
   }
   else
   {
      // no fractions of a hash
      sprintf(hc, "%.0f", hashcount );
      sprintf(hr, "%.2f", hashrate );
   }

   if ( sharediff == 0 )
   {
#if ((defined(_WIN64) || defined(__WINDOWS__)))
   applog( LOG_NOTICE, "%s %lu/%lu (%s%%), %s %sH, %s %sH/s",
                       sres, ( result ? accepted_count : rejected_count ),
                       total_submits, rate_s, hc, hc_units, hr, hr_units );
#else
   applog( LOG_NOTICE, "%s %lu/%lu (%s%%), %s %sH, %s %sH/s, %dC",
                       sres, ( result ? accepted_count : rejected_count ),
                       total_submits, rate_s, hc, hc_units, hr, hr_units,
                       (uint32_t)cpu_temp(0) );
#endif
   }
   else
   {
#if ((defined(_WIN64) || defined(__WINDOWS__)))
   applog( LOG_NOTICE, "%s %lu/%lu (%s%%), diff %.3g, %s %sH/s",
                       sres, ( result ? accepted_count : rejected_count ),
                       total_submits, rate_s, sharediff, hr, hr_units );
#else
   applog( LOG_NOTICE, "%s %lu/%lu (%s%%), diff %.3g, %s %sH/s, %dC",
                       sres, ( result ? accepted_count : rejected_count ),
                       total_submits, rate_s, sharediff, hr, hr_units,
                       (uint32_t)cpu_temp(0) );
#endif
   }

   if (reason)
   {
	applog(LOG_WARNING, "reject reason: %s", reason);
	if (strncmp(reason, "low difficulty share", 20) == 0)
        {
           opt_diff_factor = (opt_diff_factor * 2.0) / 3.0;
	   applog(LOG_WARNING, "factor reduced to : %0.2f", opt_diff_factor);
           return 0;
        }
   }
	return 1;
}

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
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
         rpc_user, work->job_id, xnonce2str, ntimestr, noncestr );
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
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"mining.submit\", \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"], \"id\":4}",
         rpc_user, work->job_id, xnonce2str, ntimestr, noncestr );
   free( xnonce2str );
}

void jr2_build_stratum_request( char *req, struct work *work )
{
   uchar hash[32];
   char noncestr[9];
   bin2hex( noncestr, (char*) algo_gate.get_nonceptr( work->data ),
                      sizeof(uint32_t) );
   algo_gate.hash_suw( hash, work->data );
   char *hashhex = abin2hex(hash, 32);
   snprintf( req, JSON_BUF_LEN,
        "{\"method\": \"submit\", \"params\": {\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"}, \"id\":4}",
          rpc2_id, work->job_id, noncestr, hashhex );
   free( hashhex );
}

bool std_le_submit_getwork_result( CURL *curl, struct work *work )
{
   char req[JSON_BUF_LEN];
   json_t *val, *res, *reason;
   char* gw_str;
   int data_size = algo_gate.work_data_size;

   for ( int i = 0; i < data_size / sizeof(uint32_t); i++ )
     le32enc( &work->data[i], work->data[i] );
   gw_str = abin2hex( (uchar*)work->data, data_size );
   if ( unlikely(!gw_str) )
   {
      applog(LOG_ERR, "submit_upstream_work OOM");
      return false;
   }
   // build JSON-RPC request 
   snprintf( req, JSON_BUF_LEN,
     "{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n", gw_str );
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
   int data_size = algo_gate.work_data_size;

   for ( int i = 0; i < data_size / sizeof(uint32_t); i++ )
     be32enc( &work->data[i], work->data[i] );
   gw_str = abin2hex( (uchar*)work->data, data_size );
   if ( unlikely(!gw_str) )
   {
      applog(LOG_ERR, "submit_upstream_work OOM");
      return false;
   }
   // build JSON-RPC request 
   snprintf( req, JSON_BUF_LEN,
     "{\"method\": \"getwork\", \"params\": [\"%s\"], \"id\":4}\r\n", gw_str );
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


bool jr2_submit_getwork_result( CURL *curl, struct work *work )
{
   json_t *val, *res;
   char req[JSON_BUF_LEN];
   char noncestr[9];
   uchar hash[32];
   char *hashhex;
   bin2hex( noncestr, (char*) algo_gate.get_nonceptr( work->data ),
                      sizeof(uint32_t) );
   algo_gate.hash_suw( hash, work->data );
   hashhex = abin2hex( &hash[0], 32 );
   snprintf( req, JSON_BUF_LEN, "{\"method\": \"submit\", \"params\": "
       "{\"id\": \"%s\", \"job_id\": \"%s\", \"nonce\": \"%s\", \"result\": \"%s\"},"
       "\"id\":4}\r\n",
       rpc2_id, work->job_id, noncestr, hashhex );
   free( hashhex );
   // issue JSON-RPC request 
   val = json_rpc2_call( curl, rpc_url, rpc_userpass, req, NULL, 0 );
   if (unlikely( !val ))
   {
      applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
      return false;
   }
   res = json_object_get( val, "result" );
   json_t *status = json_object_get( res, "status" );
   bool valid = !strcmp( status ? json_string_value( status ) : "", "OK" );
   if (valid)
       share_result( valid, work, NULL );
   else
   {
       json_t *err = json_object_get( res, "error" );
       const char *sreason = json_string_value( json_object_get(
                                                      err, "message" ) );
       share_result( valid, work, sreason );
       if ( !strcasecmp( "Invalid job id", sreason ) )
       {
            work_free( work );
            work_copy( work, &g_work );
            g_work_time = 0;
            restart_threads();
       }
   }
   json_decref(val);
   return true;
}

static bool submit_upstream_work( CURL *curl, struct work *work )
{
   json_t *val, *res;
   char req[JSON_BUF_LEN];
   int i;

   /* pass if the previous hash is not the current previous hash */
   if ( !submit_old && memcmp( &work->data[1], &g_work.data[1], 32 ) )
   {
      if (opt_debug)
         applog(LOG_DEBUG, "DEBUG: stale work detected, discarding");
      return true;
   }
   if ( !have_stratum && allow_mininginfo )
   {
      struct work wheight;
      get_mininginfo( curl, &wheight );
      if ( work->height && work->height <= net_blocks )
      {
         if (opt_debug)
	    applog(LOG_WARNING, "block %u was already solved", work->height);
	 return true;
      }
   }
   if ( have_stratum )
   {
       stratum.sharediff = work->sharediff;
       algo_gate.build_stratum_request( req, work, &stratum );
       if ( unlikely( !stratum_send_line( &stratum, req ) ) )
       {
          applog(LOG_ERR, "submit_upstream_work stratum_send_line failed");
          return false;
       }
       return true;
   }
   else if (work->txs)
   {
      char data_str[2 * sizeof(work->data) + 1];
      char *req;

      for (i = 0; i < ARRAY_SIZE(work->data); i++)
         be32enc(work->data + i, work->data[i]);
      bin2hex(data_str, (unsigned char *)work->data, 80);
      if (work->workid)
      {
         char *params;
	 val = json_object();
	 json_object_set_new(val, "workid", json_string(work->workid));
	 params = json_dumps(val, 0);
	 json_decref(val);
	 req = (char*) malloc(128 + 2 * 80 + strlen(work->txs) + strlen(params));
	 sprintf( req,
             "{\"method\": \"submitblock\", \"params\": [\"%s%s\", %s], \"id\":4}\r\n",
             data_str, work->txs, params);
         free(params);
       }
       else
       {
          req = (char*) malloc(128 + 2 * 80 + strlen(work->txs));
          sprintf(req,
             "{\"method\": \"submitblock\", \"params\": [\"%s%s\"], \"id\":4}\r\n",
	     data_str, work->txs);
       }

       val = json_rpc_call(curl, rpc_url, rpc_userpass, req, NULL, 0);
       free(req);
       if (unlikely(!val))
       {
          applog(LOG_ERR, "submit_upstream_work json_rpc_call failed");
          return false;
       }
       res = json_object_get(val, "result");
       if (json_is_object(res))
       {
          char *res_str;
	  bool sumres = false;
	  void *iter = json_object_iter(res);
	  while (iter)
          {
 	     if (json_is_null(json_object_iter_value(iter)))
             {
        	sumres = true;
 	        break;
             }
             iter = json_object_iter_next(res, iter);
	  }
	  res_str = json_dumps(res, 0);
	  share_result(sumres, work, res_str);
	  free(res_str);
       }
       else
          share_result(json_is_null(res), work, json_string_value(res));
       json_decref(val);
       return true;     
   }
   else
       return algo_gate.submit_getwork_result( curl, work );
}

static const char *getwork_req =
	"{\"method\": \"getwork\", \"params\": [], \"id\":0}\r\n";

#define GBT_CAPABILITIES "[\"coinbasetxn\", \"coinbasevalue\", \"longpoll\", \"workid\"]"

static const char *gbt_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES "}], \"id\":0}\r\n";
static const char *gbt_lp_req =
	"{\"method\": \"getblocktemplate\", \"params\": [{\"capabilities\": "
	GBT_CAPABILITIES ", \"longpollid\": \"%s\"}], \"id\":0}\r\n";

static bool get_upstream_work(CURL *curl, struct work *work)
{
	json_t *val;
	int err;
	bool rc;
	struct timeval tv_start, tv_end, diff;

start:
	gettimeofday(&tv_start, NULL);

	if (jsonrpc_2)
        {
		char s[128];
		snprintf(s, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id);
		val = json_rpc2_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	}
        else
        {
		val = json_rpc_call(curl, rpc_url, rpc_userpass,
		                    have_gbt ? gbt_req : getwork_req,
		                    &err, have_gbt ? JSON_RPC_QUIET_404 : 0);
	}
	gettimeofday(&tv_end, NULL);

	if (have_stratum)
        {
		if (val)
			json_decref(val);

		return true;
	}

	if (!have_gbt && !allow_getwork)
        {
		applog(LOG_ERR, "No usable protocol");
		if (val)
			json_decref(val);
		return false;
	}

	if (have_gbt && allow_getwork && !val && err == CURLE_OK)
        {
		applog(LOG_NOTICE, "getblocktemplate failed, falling back to getwork");
		have_gbt = false;
		goto start;
	}

	if (!val)
		return false;

	if (have_gbt)
        {
		rc = gbt_work_decode(json_object_get(val, "result"), work);
		if (!have_gbt)
                {
			json_decref(val);
			goto start;
		}
	} 
        else
		rc = work_decode(json_object_get(val, "result"), work);

	if (opt_protocol && rc)
        {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "got new work in %.2f ms",
		       (1000.0 * diff.tv_sec) + (0.001 * diff.tv_usec));
	}

	json_decref(val);
	// store work height in solo
	get_mininginfo(curl, work);
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

static bool workio_get_work(struct workio_cmd *wc, CURL *curl)
{
   struct work *ret_work;
   int failures = 0;

   ret_work = (struct work*) calloc(1, sizeof(*ret_work));
   if (!ret_work)
	return false;

   /* obtain new work from bitcoin via JSON-RPC */
   while (!get_upstream_work(curl, ret_work))
   {
	if (unlikely((opt_retries >= 0) && (++failures > opt_retries)))
        {
           applog(LOG_ERR, "json_rpc_call failed, terminating workio thread");
           free(ret_work);
	   return false;
        }

	/* pause, then restart work-request loop */
	applog(LOG_ERR, "json_rpc_call failed, retry after %d seconds",
			opt_fail_pause);
	sleep(opt_fail_pause);
   }

   /* send work to requesting thread */
   if (!tq_push(wc->thr->q, ret_work))
	free(ret_work);

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

bool rpc2_login(CURL *curl)
{
	json_t *val;
	bool rc = false;
	struct timeval tv_start, tv_end, diff;
	char s[JSON_BUF_LEN];

	if (!jsonrpc_2)
		return false;
	snprintf(s, JSON_BUF_LEN, "{\"method\": \"login\", \"params\": {"
		"\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
		rpc_user, rpc_pass, USER_AGENT);
	gettimeofday(&tv_start, NULL);
	val = json_rpc_call(curl, rpc_url, rpc_userpass, s, NULL, 0);
	gettimeofday(&tv_end, NULL);
	if (!val)
		goto end;
	rc = rpc2_login_decode(val);
	json_t *result = json_object_get(val, "result");
	if (!result)
		goto end;
	json_t *job = json_object_get(result, "job");
	if (!rpc2_job_decode(job, &g_work))
		goto end;
	if (opt_debug && rc)
        {
		timeval_subtract(&diff, &tv_end, &tv_start);
		applog(LOG_DEBUG, "DEBUG: authenticated in %d ms",
				diff.tv_sec * 1000 + diff.tv_usec / 1000);
	}
	json_decref(val);
end:
	return rc;
}

bool rpc2_workio_login(CURL *curl)
{
   int failures = 0;
   if (opt_benchmark)
	return true;
   /* submit solution to bitcoin via JSON-RPC */
   pthread_mutex_lock(&rpc2_login_lock);
   while (!rpc2_login(curl))
   {
      if (unlikely((opt_retries >= 0) && (++failures > opt_retries)))
      {
	applog(LOG_ERR, "...terminating workio thread");
	pthread_mutex_unlock(&rpc2_login_lock);
	return false;
      }

      /* pause, then restart work-request loop */
      if (!opt_benchmark)
          applog(LOG_ERR, "...retry after %d seconds", opt_fail_pause);
      sleep(opt_fail_pause);
      pthread_mutex_unlock(&rpc2_login_lock);
      pthread_mutex_lock(&rpc2_login_lock);
   }
   pthread_mutex_unlock(&rpc2_login_lock);
   return true;
}

static void *workio_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info *) userdata;
	CURL *curl;
	bool ok = true;

	curl = curl_easy_init();
	if (unlikely(!curl))
        {
		applog(LOG_ERR, "CURL initialization failed");
		return NULL;
	}
	if(jsonrpc_2 && !have_stratum)
		ok = rpc2_workio_login(curl);
	while (ok)
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

	if (opt_benchmark)
        {
		uint32_t ts = (uint32_t) time(NULL);

                // why 74? std cmp_size is 76, std data is 128
		for ( int n = 0; n < 74; n++ ) ( (char*)work->data )[n] = n;

                work->data[algo_gate.ntime_index] = swab32(ts);  // ntime
  
              // this overwrites much of the for loop init
                memset( work->data + algo_gate.nonce_index, 0x00, 52);  // nonce..nonce+52
		work->data[20] = 0x80000000;  // extraheader not used for jr2
		work->data[31] = 0x00000280;  // extraheader not used for jr2
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

static bool submit_work(struct thr_info *thr, const struct work *work_in)
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

bool rpc2_stratum_job( struct stratum_ctx *sctx, json_t *params )
{
	bool ret = false;
	pthread_mutex_lock(&sctx->work_lock);
	ret = rpc2_job_decode(params, &sctx->work);
	if (ret)
        {
           if (sctx->job.job_id)
		free(sctx->job.job_id);
	   sctx->job.job_id = strdup(sctx->work.job_id);
 	}

	pthread_mutex_unlock(&sctx->work_lock);
	return ret;
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

void std_wait_for_diff()
{
   while ( time(NULL) >= g_work_time + 120 )
     sleep(1);
}

// Common target functions, default usually listed first.

// pick your favorite or define your own
int64_t get_max64_0x1fffffLL() { return 0x1fffffLL; } // default
int64_t get_max64_0x40LL()     { return 0x40LL;     }
int64_t get_max64_0x3ffff()    { return 0x3ffff;    }
int64_t get_max64_0x3fffffLL() { return 0x3fffffLL; }
int64_t get_max64_0x1ffff()    { return 0x1ffff;    }
int64_t get_max64_0xffffLL()   { return 0xffffLL;   };

// default
void sha256d_gen_merkle_root( char* merkle_root, struct stratum_ctx* sctx )
{
  sha256d(merkle_root, sctx->job.coinbase, (int) sctx->job.coinbase_size);
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

void std_set_target( struct work* work, double job_diff )
{
   work_set_target( work, job_diff / opt_diff_factor );
}
// most scrypt based algos
void scrypt_set_target( struct work* work, double job_diff )
{
   work_set_target( work, job_diff / (65536.0 * opt_diff_factor) );
}

void alt_set_target( struct work* work, double job_diff )
{
   work_set_target( work, job_diff / (256.0 * opt_diff_factor) );
}

// Default is do_nothing (assumed LE)
void set_work_data_big_endian( struct work *work )
{
   int nonce_index = algo_gate.nonce_index;
   for ( int i = 0; i < nonce_index; i++ )
        be32enc( work->data + i, work->data[i] );
}

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

uint32_t* std_get_nonceptr( uint32_t *work_data )
{
   return work_data + algo_gate.nonce_index;
}

uint32_t* jr2_get_nonceptr( uint32_t *work_data )
{
   // nonce is misaligned, use byte offset
   return (uint32_t*) ( ((uint8_t*) work_data) + algo_gate.nonce_index );
}

void std_get_new_work( struct work* work, struct work* g_work, int thr_id,
                     uint32_t *end_nonce_ptr, bool clean_job )
{
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );

   if ( memcmp( work->data, g_work->data, algo_gate.work_cmp_size )
      && ( clean_job || ( *nonceptr >= *end_nonce_ptr )
         || ( work->job_id != g_work->job_id ) ) )
   {
     work_free( work );
     work_copy( work, g_work );
     *nonceptr = 0xffffffffU / opt_n_threads * thr_id;
     if ( opt_randomize )
       *nonceptr += ( (rand() *4 ) & UINT32_MAX ) / opt_n_threads;
     *end_nonce_ptr = ( 0xffffffffU / opt_n_threads ) * (thr_id+1) - 0x20; 
   }
   else
       ++(*nonceptr);
}

void jr2_get_new_work( struct work* work, struct work* g_work, int thr_id,
                     uint32_t *end_nonce_ptr )
{
   uint32_t *nonceptr = algo_gate.get_nonceptr( work->data );

   // byte data[ 0..38, 43..75 ], skip over misaligned nonce [39..42]
   if ( memcmp( work->data, g_work->data, algo_gate.nonce_index )
     || memcmp( ((uint8_t*) work->data)   + JR2_WORK_CMP_INDEX_2,
                ((uint8_t*) g_work->data) + JR2_WORK_CMP_INDEX_2,
                                                    JR2_WORK_CMP_SIZE_2 ) )
   {
      work_free( work );
      work_copy( work, g_work );
      *nonceptr = ( 0xffffffU / opt_n_threads ) * thr_id
                   + ( *nonceptr & 0xff000000U );
      *end_nonce_ptr = ( 0xffffffU / opt_n_threads ) * (thr_id+1)
                        + ( *nonceptr & 0xff000000U ) - 0x20;
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

static void *miner_thread( void *userdata )
{
   struct   thr_info *mythr = (struct thr_info *) userdata;
   int      thr_id = mythr->id;
   struct   work work;
   uint32_t max_nonce;

   // end_nonce gets read before being set so it needs to be initialized
   // what is an appropriate value that is completely neutral?
   // zero seems to work. No, it breaks benchmark.
//   uint32_t end_nonce = 0;
   uint32_t end_nonce = opt_benchmark
                      ? ( 0xffffffffU / opt_n_threads ) * (thr_id + 1) - 0x20
                      : 0;
   time_t   firstwork_time = 0;
   int  i;
   memset( &work, 0, sizeof(work) );
 
   /* Set worker threads to nice 19 and then preferentially to SCHED_IDLE
    * and if that fails, then SCHED_BATCH. No need for this to be an
    * error if it fails */
   if (!opt_benchmark && opt_priority == 0)
   {
	setpriority(PRIO_PROCESS, 0, 19);
	drop_policy();
   }
   else
   {
	int prio = 0;
#ifndef WIN32
	prio = 18;
	// note: different behavior on linux (-19 to 19)
	switch (opt_priority)
        {
	   case 1:
		prio = 5;
		break;
	   case 2:
		prio = 0;
		break;
	   case 3:
		prio = -5;
		break;
	   case 4:
		prio = -10;
		break;
	   case 5:
		prio = -15;
	}
	if (opt_debug)
	   applog(LOG_DEBUG, "Thread %d priority %d (nice %d)", thr_id,
                              opt_priority, prio );
#endif
	setpriority(PRIO_PROCESS, 0, prio);
	if (opt_priority == 0)
	   drop_policy();
   }
   // CPU thread affinity
   if ( num_cpus > 64 )
   {
      // opt_affinity ignored with more than 64 cpus.
      if (opt_debug)
           applog( LOG_DEBUG, "Binding thread %d to cpu %d",
                   thr_id, thr_id % num_cpus );
      affine_to_cpu_mask( thr_id, -1 );
   }
   else if ( num_cpus > 1 )
   {
      if ( (opt_affinity == -1) && (opt_n_threads) > 1 ) 
      {
         if (opt_debug)
            applog( LOG_DEBUG, "Binding thread %d to cpu %d (mask %x)",
                   thr_id, thr_id % num_cpus, ( 1ULL << (thr_id % num_cpus) ) );

         affine_to_cpu_mask( thr_id, 1ULL << (thr_id % num_cpus) );
      }
      else if (opt_affinity != -1)
      {
         if (opt_debug)
             applog( LOG_DEBUG, "Binding thread %d to cpu mask %x",
                                 thr_id, opt_affinity);
         affine_to_cpu_mask( thr_id, opt_affinity );
      }
   }

   if ( !algo_gate.miner_thread_init( thr_id ) )
   {
      applog( LOG_ERR, "FAIL: thread %u failed to initialize", thr_id );
      exit (1);
   }

   while (1)
   {
       uint64_t hashes_done;
       struct timeval tv_start, tv_end, diff;
       int64_t max64;
       int nonce_found = 0;

       if ( algo_gate.do_this_thread( thr_id ) )
       {
          if ( have_stratum )
          {
              algo_gate.wait_for_diff( &stratum );
 	      pthread_mutex_lock( &g_work_lock );
              algo_gate.get_new_work( &work, &g_work, thr_id, &end_nonce,
                                      stratum.job.clean );
              pthread_mutex_unlock( &g_work_lock );
          }
          else
          {
             int min_scantime = have_longpoll ? LP_SCANTIME : opt_scantime;
	     pthread_mutex_lock( &g_work_lock );

             if ( time(NULL) - g_work_time >= min_scantime
                  || *algo_gate.get_nonceptr( work.data ) >= end_nonce )
             {
	        if ( unlikely( !get_work( mythr, &g_work ) ) )
                {
		   applog( LOG_ERR, "work retrieval failed, exiting "
		           "mining thread %d", thr_id );
                   pthread_mutex_unlock( &g_work_lock );
		   goto out;
	        }
                g_work_time = time(NULL);
	     }
             algo_gate.get_new_work( &work, &g_work, thr_id, &end_nonce, true );

             pthread_mutex_unlock( &g_work_lock );
          }
       } // do_this_thread
       algo_gate.resync_threads( &work );

       if ( !algo_gate.ready_to_mine( &work, &stratum, thr_id ) )
          continue;
       // conditional mining
       if (!wanna_mine(thr_id))
       {
          sleep(5);
	  continue;
       }
       // adjust max_nonce to meet target scan time
       if (have_stratum)
          max64 = LP_SCANTIME;
       else
          max64 = g_work_time + ( have_longpoll ? LP_SCANTIME : opt_scantime )
	                      - time(NULL);
       // time limit
       if ( opt_time_limit && firstwork_time )
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
          if (remain < max64) max64 = remain;
       }
       // max64
       uint32_t work_nonce = *( algo_gate.get_nonceptr( work.data ) );
       max64 *= thr_hashrates[thr_id];
       if ( max64 <= 0)
          max64 = (int64_t)algo_gate.get_max64();
       if ( work_nonce + max64 > end_nonce )
          max_nonce = end_nonce;
       else
          max_nonce = work_nonce + (uint32_t)max64;
       // init time
       if ( firstwork_time == 0 )
          firstwork_time = time(NULL);
       work_restart[thr_id].restart = 0;
       hashes_done = 0;
       gettimeofday( (struct timeval *) &tv_start, NULL );

       // Scan for nonce
       nonce_found = (bool) algo_gate.scanhash( thr_id, &work, max_nonce,
                                                &hashes_done );

       // record scanhash elapsed time
       gettimeofday(&tv_end, NULL);
       timeval_subtract(&diff, &tv_end, &tv_start);
       if (diff.tv_usec || diff.tv_sec)
       {
          pthread_mutex_lock(&stats_lock);
          thr_hashcount[thr_id] = hashes_done;
	  thr_hashrates[thr_id] =
		hashes_done / (diff.tv_sec + diff.tv_usec * 1e-6);
	  pthread_mutex_unlock(&stats_lock);
       }
       // if nonce(s) submit work 
       if ( nonce_found && !opt_benchmark )
       {
          int num_submitted = 0;
          // look for 4way nonces
          for ( int n = 0; n < 4; n++ )
             if ( work.nfound[n] )
             {
                 *algo_gate.get_nonceptr( work.data ) = work.nonces[n]; 
                 if ( !submit_work(mythr, &work) )
                 {
                    applog(LOG_WARNING, "Failed to submit share." );
                    break;
                 }
                 num_submitted++;
             }
#if FOUR_WAY
if (num_submitted > 1)
 applog(LOG_NOTICE,  "4 WAY hash nonces submitted: %u" CL_MAG " BONUS!" CL_N, num_submitted);
else
 applog(LOG_NOTICE,  "4 WAY hash nonces submitted: %u", num_submitted);
#endif
          // must be a one way algo, nonce is already in work data
          if ( !num_submitted )
          {
             if ( !submit_work(mythr, &work) )
             {
                applog(LOG_WARNING, "Failed to submir share.");
                break;
             }
#if FOUR_WAY
applog(LOG_NOTICE,  "1 WAY hash nonce submitted");
#endif

          }

          // prevent stale work in solo
          // we can't submit twice a block!
          if (!have_stratum && !have_longpoll)
          {
             pthread_mutex_lock(&g_work_lock);
             // will force getwork
             g_work_time = 0;
             pthread_mutex_unlock(&g_work_lock);
          }
       }
       // display hashrate
       if (!opt_quiet)
       {
          char hc[16];
          char hr[16];
          char hc_units[2] = {0,0};
          char hr_units[2] = {0,0};
          double hashcount = thr_hashcount[thr_id];
          double hashrate  = thr_hashrates[thr_id];
          if ( hashcount )
          {
             scale_hash_for_display( &hashcount, hc_units );
             scale_hash_for_display( &hashrate,  hr_units );
             if ( hc_units[0] )
                sprintf( hc, "%.2f", hashcount );
             else // no fractions of a hash
                sprintf( hc, "%.0f", hashcount );
             sprintf( hr, "%.2f", hashrate );
             applog( LOG_INFO, "CPU #%d: %s %sH, %s %sH/s %dC",
                               thr_id, hc, hc_units, hr, hr_units, (uint32_t)cpu_temp(0) );
          }
       }
       // Display benchmark total
       if ( opt_benchmark && thr_id == opt_n_threads - 1 )
       {
          double hashrate  = 0.;
          double hashcount = 0.;
          for ( i = 0; i < opt_n_threads; i++ )
          {
              hashrate  += thr_hashrates[i];
              hashcount += thr_hashcount[i];
          }
          if ( hashcount )
          {
             char hc[16];
             char hc_units[2] = {0,0};
             char hr[16];
             char hr_units[2] = {0,0};
             global_hashcount = hashcount;
             global_hashrate  = hashrate;
             scale_hash_for_display( &hashcount, hc_units );
             scale_hash_for_display( &hashrate,  hr_units );
             if ( hc_units[0] )
                sprintf( hc, "%.2f", hashcount );
             else  // no fractions of a hash
                sprintf( hc, "%.0f", hashcount );
             sprintf( hr, "%.2f", hashrate );
#if ((defined(_WIN64) || defined(__WINDOWS__)))
             applog( LOG_NOTICE, "Total: %s %sH, %s %sH/s",
                                  hc, hc_units, hr, hr_units );
#else
             applog( LOG_NOTICE, "Total: %s %sH, %s %sH/s, %dC",
                         hc, hc_units, hr, hr_units, (uint32_t)cpu_temp(0) );
#endif
          }
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

json_t *jr2_longpoll_rpc_call( CURL *curl, int *err )
{
   json_t *val;
   char req[128];

   pthread_mutex_lock( &rpc2_login_lock );
   if ( !strlen(rpc2_id) )
   {
     pthread_mutex_unlock( &rpc2_login_lock );
     sleep(1);
     return NULL;
   }
   snprintf( req, 128, "{\"method\": \"getjob\", \"params\": {\"id\": \"%s\"}, \"id\":1}\r\n", rpc2_id );
   pthread_mutex_unlock( &rpc2_login_lock );
   val = json_rpc2_call( curl, rpc_url, rpc_userpass, req, err,
                         JSON_RPC_LONGPOLL );
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
	 if (!jsonrpc_2)
         {
           soval = json_object_get(res, "submitold");
	   submit_old = soval ? json_is_true(soval) : false;
	 }
	 pthread_mutex_lock(&g_work_lock);
	 start_job_id = g_work.job_id ? strdup(g_work.job_id) : NULL;
	 if (have_gbt)
	   rc = gbt_work_decode(res, &g_work);
	 else
	   rc = work_decode(res, &g_work);
	 if (rc)
         {
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
	       if (opt_showdiff)
	 	 sprintf( &netinfo[strlen(netinfo)], ", target %.3f",
                          g_work.targetdiff );
               applog(LOG_BLUE, "%s detected new block%s", short_url, netinfo);
	     }
	     time(&g_work_time);
	     restart_threads();
	   }
         }
         free(start_job_id);
         pthread_mutex_unlock(&g_work_lock);
         json_decref(val);
      }
      else   // !val
      {
         pthread_mutex_lock(&g_work_lock);
	 g_work_time -= LP_SCANTIME;
	 pthread_mutex_unlock(&g_work_lock);
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

bool std_stratum_handle_response( json_t *val )
{
    bool valid = false;
    json_t *err_val, *res_val, *id_val;
    res_val = json_object_get( val, "result" );
    err_val = json_object_get( val, "error" );
    id_val  = json_object_get( val, "id" );

    if ( !res_val || json_integer_value(id_val) < 4 )
         return false;
    valid = json_is_true( res_val );
    share_result( valid, NULL, err_val ?
                  json_string_value( json_array_get(err_val, 1) ) : NULL );
    return true;
}

bool jr2_stratum_handle_response( json_t *val )
{
    bool valid = false;
    json_t *err_val, *res_val;
    res_val = json_object_get( val, "result" );
    err_val = json_object_get( val, "error" );

    if ( !res_val && !err_val )
        return false;
    json_t *status = json_object_get( res_val, "status" );
    if ( status ) 
    {
        const char *s = json_string_value( status );
        valid = !strcmp( s, "OK" ) && json_is_null( err_val );
    }
    else
        valid = json_is_null( err_val );
    share_result( valid, NULL, err_val ? json_string_value(err_val) : NULL );
    return true;
}

static bool stratum_handle_response( char *buf )
{
	json_t *val, *id_val;
	json_error_t err;
	bool ret = false;

	val = JSON_LOADS( buf, &err );
	if (!val)
        {
           applog(LOG_INFO, "JSON decode failed(%d): %s", err.line, err.text);
	   goto out;
	}
        json_object_get( val, "result" );
	id_val = json_object_get( val, "id" );
	if ( !id_val || json_is_null(id_val) )
		goto out;
        if ( !algo_gate.stratum_handle_response( val ) )
                goto out;
	ret = true;
out:
	if (val)
		json_decref(val);
	return ret;
}

void std_build_extraheader( struct work* g_work, struct stratum_ctx* sctx )
{
   uchar merkle_root[64] = { 0 };
   size_t t;
   int i;

   algo_gate.gen_merkle_root( merkle_root, sctx );
   // Increment extranonce2
   for ( t = 0; t < sctx->xnonce2_size && !( ++sctx->job.xnonce2[t] ); t++ );
   // Assemble block header
   memset( g_work->data, 0, sizeof(g_work->data) );
   g_work->data[0] = le32dec( sctx->job.version );
   for ( i = 0; i < 8; i++ )
      g_work->data[1 + i] = le32dec( (uint32_t *) sctx->job.prevhash + i );
   for ( i = 0; i < 8; i++ )
      g_work->data[9 + i] = be32dec( (uint32_t *) merkle_root + i );

   g_work->data[ algo_gate.ntime_index ] = le32dec(sctx->job.ntime);
   g_work->data[ algo_gate.nbits_index ] = le32dec(sctx->job.nbits);
   g_work->data[20] = 0x80000000;
   g_work->data[31] = 0x00000280;
}

void std_stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   pthread_mutex_lock( &sctx->work_lock );
   free( g_work->job_id );
   g_work->job_id = strdup( sctx->job.job_id );
   g_work->xnonce2_len = sctx->xnonce2_size;
   g_work->xnonce2 = (uchar*) realloc( g_work->xnonce2, sctx->xnonce2_size );
   memcpy( g_work->xnonce2, sctx->job.xnonce2, sctx->xnonce2_size );

   algo_gate.build_extraheader( g_work, sctx );

   net_diff = algo_gate.calc_network_diff( g_work );
   algo_gate.set_work_data_endian( g_work );
   pthread_mutex_unlock( &sctx->work_lock );

   if ( opt_debug )
   {
     unsigned char *xnonce2str = abin2hex( g_work->xnonce2,
                                           g_work->xnonce2_len );
     applog( LOG_DEBUG, "DEBUG: job_id='%s' extranonce2=%s ntime=%08x",
                    g_work->job_id, xnonce2str, swab32( g_work->data[17] ) );
       free( xnonce2str );
   }

   algo_gate.set_target( g_work, sctx->job.diff );

   if ( stratum_diff != sctx->job.diff )
   {
     char sdiff[32] = { 0 };
     // store for api stats
     stratum_diff = sctx->job.diff;
     if ( opt_showdiff && g_work->targetdiff != stratum_diff )
     {
        snprintf( sdiff, 32, " (%.5f)", g_work->targetdiff );
        applog( LOG_WARNING, "Stratum difficulty set to %g%s", stratum_diff,
                        sdiff );
     }
   }
}

void jr2_stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   pthread_mutex_lock( &sctx->work_lock );
   work_free( g_work );
   work_copy( g_work, &sctx->work );
   pthread_mutex_unlock( &sctx->work_lock );
}

static void *stratum_thread(void *userdata )
{
    struct thr_info *mythr = (struct thr_info *) userdata;
    char *s;

    stratum.url = (char*) tq_pop(mythr->q, NULL);
    if (!stratum.url)
	goto out;
    applog(LOG_INFO, "Starting Stratum on %s", stratum.url);

    while (1)
    {
	int failures = 0;

	if ( stratum_need_reset )
        {
           stratum_need_reset = false;
	   stratum_disconnect( &stratum );
	   if ( strcmp( stratum.url, rpc_url ) )
           {
		free( stratum.url );
		stratum.url = strdup( rpc_url );
		applog(LOG_BLUE, "Connection changed to %s", short_url);
	   }
           else if ( !opt_quiet )
		applog(LOG_DEBUG, "Stratum connection reset");
	}

        while ( !stratum.curl )
        {
           pthread_mutex_lock( &g_work_lock );
           g_work_time = 0;
           pthread_mutex_unlock( &g_work_lock );
           restart_threads();
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

           if (jsonrpc_2)
           {
              work_free(&g_work);
	      work_copy(&g_work, &stratum.work);
           }
        }

        if ( stratum.job.job_id &&
             ( !g_work_time || strcmp( stratum.job.job_id, g_work.job_id ) ) )
        {
           pthread_mutex_lock(&g_work_lock);
           algo_gate.stratum_gen_work( &stratum, &g_work );
           time(&g_work_time);
           pthread_mutex_unlock(&g_work_lock);
//           restart_threads();

           if (stratum.job.clean || jsonrpc_2)
           {
              static uint32_t last_bloc_height;
              if ( last_bloc_height != stratum.bloc_height )
              {
                 last_bloc_height = stratum.bloc_height;
                 if ( !opt_quiet )
                 {
                    if (net_diff > 0.)
	               applog(LOG_BLUE, "%s block %d, diff %.3f",
                           algo_names[opt_algo], stratum.bloc_height, net_diff);
                    else
	               applog(LOG_BLUE, "%s %s block %d", short_url,
                           algo_names[opt_algo], stratum.bloc_height);
	         }
              }
              restart_threads();
           }
           else if (opt_debug && !opt_quiet)
           {
		applog(LOG_BLUE, "%s asks job %d for block %d", short_url,
		strtoul(stratum.job.job_id, NULL, 16), stratum.bloc_height);
           }
        }  // stratum.job.job_id

       if ( !stratum_socket_full( &stratum, opt_timeout ) )
       {
          applog(LOG_ERR, "Stratum connection timeout");
	  s = NULL;
       }
       else
           s = stratum_recv_line(&stratum);
       if ( !s )
       {
          stratum_disconnect(&stratum);
//	  applog(LOG_WARNING, "Stratum connection interrupted");
	  continue;
       }
       if (!stratum_handle_method(&stratum, s))
          stratum_handle_response(s);
       free(s);
   }  // loop
out:
	return NULL;
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

        /* dependencies versions */
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

	switch(key)
        {
	   case 'a':
              get_algo_alias( &arg );
              for (i = 1; i < ALGO_COUNT; i++)
              {
	          v = (int) strlen(algo_names[i]);
		  if (v && !strncasecmp(arg, algo_names[i], v))
                  {
			if (arg[v] == '\0')
                        {
				opt_algo = (enum algos) i;
				break;
			}
			if (arg[v] == ':')
                        {
				char *ep;
				v = strtol(arg+v+1, &ep, 10);
                                if (*ep || v < 2)
					continue;
				opt_algo = (enum algos) i;
				opt_param_n = v;
				break;
			}
		  }
	      }
              if (i == ALGO_COUNT)
              {
                 applog(LOG_ERR,"Unknown algo: %s",arg);
                 show_usage_and_exit(1);
              }
           break;

	case 'b':
		p = strstr(arg, ":");
		if (p) {
			/* ip:port */
			if (p - arg > 0) {
				free(opt_api_allow);
				opt_api_allow = strdup(arg);
				opt_api_allow[p - arg] = '\0';
			}
			opt_api_listen = atoi(p + 1);
		}
		else if (arg && strstr(arg, ".")) {
			/* ip only */
			free(opt_api_allow);
			opt_api_allow = strdup(arg);
		}
		else if (arg) {
			/* port or 0 to disable */
			opt_api_listen = atoi(arg);
		}
		break;
	case 1030: /* --api-remote */
		opt_api_remote = 1;
		break;
	case 'B':
		opt_background = true;
		use_colors = false;
		break;
	case 'c': {
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
				fprintf(stderr, "%s:%d: %s\n",
					arg, err.line, err.text);
		}
                else
                {
			parse_config(config, arg);
			json_decref(config);
		}
		break;
	}
	case 'q':
		opt_quiet = true;
		break;
	case 'D':
		opt_debug = true;
		break;
	case 'p':
		free(rpc_pass);
		rpc_pass = strdup(arg);
		strhide(arg);
		break;
	case 'P':
		opt_protocol = true;
		break;
	case 'r':
		v = atoi(arg);
		if (v < -1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_retries = v;
		break;
/*
	case 'R':
		v = atoi(arg);
		if (v < 1 || v > 9999)
			show_usage_and_exit(1);
		opt_fail_pause = v;
		break;
*/
	case 's':
		v = atoi(arg);
		if (v < 1 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_scantime = v;
		break;
	case 'T':
		v = atoi(arg);
		if (v < 1 || v > 99999) /* sanity check */
			show_usage_and_exit(1);
		opt_timeout = v;
		break;
	case 't':
		v = atoi(arg);
		if (v < 0 || v > 9999) /* sanity check */
			show_usage_and_exit(1);
		opt_n_threads = v;
		break;
	case 'u':
		free(rpc_user);
		rpc_user = strdup(arg);
		break;
	case 'o': {			/* --url */
		char *ap, *hp;
		ap = strstr(arg, "://");
		ap = ap ? ap + 3 : arg;
		hp = strrchr(arg, '@');
		if (hp) {
			*hp = '\0';
			p = strchr(ap, ':');
			if (p) {
				free(rpc_userpass);
				rpc_userpass = strdup(ap);
				free(rpc_user);
				rpc_user = (char*) calloc(p - ap + 1, 1);
				strncpy(rpc_user, ap, p - ap);
				free(rpc_pass);
				rpc_pass = strdup(++p);
				if (*p) *p++ = 'x';
				v = (int) strlen(hp + 1) + 1;
				memmove(p + 1, hp + 1, v);
				memset(p + v, 0, hp - p);
				hp = p;
			} else {
				free(rpc_user);
				rpc_user = strdup(ap);
			}
			*hp++ = '@';
		} else
			hp = ap;
		if (ap != arg) {
			if (strncasecmp(arg, "http://", 7) &&
			    strncasecmp(arg, "https://", 8) &&
			    strncasecmp(arg, "stratum+tcp://", 14)) {
				fprintf(stderr, "unknown protocol -- '%s'\n", arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = strdup(arg);
			strcpy(rpc_url + (ap - arg), hp);
			short_url = &rpc_url[ap - arg];
		} else {
			if (*hp == '\0' || *hp == '/') {
				fprintf(stderr, "invalid URL -- '%s'\n",
					arg);
				show_usage_and_exit(1);
			}
			free(rpc_url);
			rpc_url = (char*) malloc( strlen(hp) + 15 );
			sprintf( rpc_url, "stratum+tcp://%s", hp );
			short_url = &rpc_url[ sizeof("stratum+tcp://") - 1 ];
		}
		have_stratum = !opt_benchmark && !strncasecmp(rpc_url, "stratum", 7);
		break;
	}
	case 'O':			/* --userpass */
		p = strchr(arg, ':');
		if (!p) {
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
	case 'x':			/* --proxy */
		if (!strncasecmp(arg, "socks4://", 9))
			opt_proxy_type = CURLPROXY_SOCKS4;
		else if (!strncasecmp(arg, "socks5://", 9))
			opt_proxy_type = CURLPROXY_SOCKS5;
#if LIBCURL_VERSION_NUM >= 0x071200
		else if (!strncasecmp(arg, "socks4a://", 10))
			opt_proxy_type = CURLPROXY_SOCKS4A;
		else if (!strncasecmp(arg, "socks5h://", 10))
			opt_proxy_type = CURLPROXY_SOCKS5_HOSTNAME;
#endif
		else
			opt_proxy_type = CURLPROXY_HTTP;
		free(opt_proxy);
		opt_proxy = strdup(arg);
		break;
	case 1001:
		free(opt_cert);
		opt_cert = strdup(arg);
		break;
	case 1002:
		use_colors = false;
		break;
	case 1003:
		want_longpoll = false;
		break;
	case 1005:
		opt_benchmark = true;
		want_longpoll = false;
		want_stratum = false;
		have_stratum = false;
		break;
	case 1006:
		print_hash_tests();
		exit(0);
	case 1007:
		want_stratum = false;
		opt_extranonce = false;
		break;
	case 1008:
		opt_time_limit = atoi(arg);
		break;
	case 1009:
		opt_redirect = false;
		break;
	case 1010:
		allow_getwork = false;
		break;
	case 1011:
		have_gbt = false;
		break;
	case 1012:
		opt_extranonce = false;
		break;
	case 1013:
		opt_showdiff = false;
		break;
	case 1016:			/* --coinbase-addr */
		pk_script_size = address_to_script(pk_script, sizeof(pk_script), arg);
		if (!pk_script_size) {
			fprintf(stderr, "invalid address -- '%s'\n", arg);
			show_usage_and_exit(1);
		}
		break;
	case 1015:			/* --coinbase-sig */
		if (strlen(arg) + 1 > sizeof(coinbase_sig)) {
			fprintf(stderr, "coinbase signature too long\n");
			show_usage_and_exit(1);
		}
		strcpy(coinbase_sig, arg);
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
	case 'S':
		use_syslog = true;
		use_colors = false;
		break;
	case 1020:
		p = strstr(arg, "0x");
		if (p)
			ul = strtoul(p, NULL, 16);
		else
			ul = atol(arg);
		if (ul > (1UL<<num_cpus)-1)
			ul = -1;
		opt_affinity = ul;
		break;
	case 1021:
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
	case 'V':
		show_version_and_exit();
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

static void show_credits()
{
   printf("\n         **********  "PACKAGE_NAME" "PACKAGE_VERSION"  *********** \n");
   printf("     A CPU miner with multi algo support and optimized for CPUs\n");
   printf("     with AES_NI and AVX2 and SHA extensions.\n");
   printf("     BTC donation address: 12tdvfF7KmAsihBXQXynT6E6th2c2pByTT\n\n");
}

bool check_cpu_capability ()
{
     char cpu_brand[0x40];
     // there is no CPU related feature specific to 4way, just AVX2 and AES
     bool cpu_has_sse2 = has_sse2();
     bool cpu_has_aes  = has_aes_ni();
     bool cpu_has_avx  = has_avx1();
     bool cpu_has_avx2 = has_avx2();
     bool cpu_has_sha  = has_sha();
     // no need to check if sw has sse2,
     // the code won't compile without it.
//     bool sw_has_sse2  = false;
     bool sw_has_aes   = false;
     bool sw_has_avx   = false;
     bool sw_has_avx2  = false;
     bool sw_has_sha   = false;
     bool sw_has_4way  = false;
     set_t algo_features = algo_gate.optimizations;
     bool algo_has_sse2 = set_incl( SSE2_OPT,     algo_features );
     bool algo_has_aes  = set_incl( AES_OPT,      algo_features );
     bool algo_has_avx  = set_incl( AVX_OPT,      algo_features );
     bool algo_has_avx2 = set_incl( AVX2_OPT,     algo_features );
     bool algo_has_sha  = set_incl( SHA_OPT,      algo_features );
     bool algo_has_4way = set_incl( FOUR_WAY_OPT, algo_features );
     bool use_aes;
     bool use_sse2;
     bool use_avx;
     bool use_avx2;
     bool use_sha;
     bool use_4way;
     bool use_none;

	 #if defined(__arm__) || defined(__aarch64__)
     printf( "CPU: ARM or AARCH64 no SSE2!\n" );
     return true;
     #endif

     #ifdef __AES__
       sw_has_aes = true;
     #endif
//     #ifdef __SSE2__
//         sw_has_sse2 = true;
//     #endif
     #ifdef __AVX__
         sw_has_avx = true;
     #endif
     #ifdef __AVX2__
         sw_has_avx2 = true;
     #endif
     #ifdef __SHA__
         sw_has_sha = true;
     #endif
     #ifdef HASH_4WAY
         sw_has_4way = true;
     #endif

     #if !((__AES__) || (__SSE2__))
         printf("Neither __AES__ nor __SSE2__ defined.\n");
     #endif

     cpu_brand_string( cpu_brand );
     printf( "CPU: %s.\n", cpu_brand );
     
     printf("SW built on " __DATE__
     #ifdef _MSC_VER
         " with VC++ 2013\n");
     #elif defined(__GNUC__)
         " with GCC");
        printf(" %d.%d.%d.\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
     #else
        printf(".\n");
     #endif

     printf("CPU features:");
     if ( cpu_has_sse2 )  printf( " SSE2" );
     if ( cpu_has_aes  )  printf( " AES"  );
     if ( cpu_has_avx  )  printf( " AVX"  );
     if ( cpu_has_avx2 )  printf( " AVX2" );
     if ( cpu_has_sha  )  printf( " SHA"  );

     printf(".\nSW features: SSE2");
     if ( sw_has_aes  )    printf( " AES"  );
     if ( sw_has_avx  )    printf( " AVX"  );
     if ( sw_has_avx2 )    printf( " AVX2" );
     if ( sw_has_4way )    printf( " 4WAY" );
     if ( sw_has_sha  )    printf( " SHA"  );
    

     printf(".\nAlgo features:");
     if ( algo_features == EMPTY_SET ) printf( " None" );
     else
     {
        if ( algo_has_sse2 )           printf( " SSE2" );
        if ( algo_has_aes  )           printf( " AES"  );
        if ( algo_has_avx  )           printf( " AVX"  );
        if ( algo_has_avx2 )           printf( " AVX2" );
        if ( algo_has_4way )           printf( " 4WAY" );
        if ( algo_has_sha  )           printf( " SHA"  );
     }
     printf(".\n");

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
     if ( sw_has_avx && !cpu_has_avx )
     {
        printf( "The SW build requires a CPU with AVX!\n" );
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
     use_sse2 = cpu_has_sse2 && algo_has_sse2;
     use_aes  = cpu_has_aes  && sw_has_aes  && algo_has_aes;
     use_avx  = cpu_has_avx  && sw_has_avx  && algo_has_avx;
     use_avx2 = cpu_has_avx2 && sw_has_avx2 && algo_has_avx2;
     use_sha  = cpu_has_sha  && sw_has_sha  && algo_has_sha;
     use_4way = cpu_has_avx2 && sw_has_4way && algo_has_4way;
     use_none = !( use_sse2 || use_aes || use_avx || use_avx2 || use_sha
                   || use_4way );
      
     // Display best options
     printf( "Start mining with" );
     if         ( use_none ) printf( " no optimizations" );
     else
     {
        if      ( use_aes  ) printf( " AES"  );
        if      ( use_avx2 ) printf( " AVX2" );
        else if ( use_avx  ) printf( " AVX"  );
        else if ( use_sse2 ) printf( " SSE2" );
        if      ( use_4way ) printf( " 4WAY" );
        if      ( use_sha  ) printf( " SHA"  );
     }
     printf( ".\n\n" );

     return true;
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
	opt_api_allow = strdup("127.0.0.1"); /* 0.0.0.0 for all ips */

#if defined(WIN32)
	SYSTEM_INFO sysinfo;
	GetSystemInfo(&sysinfo);
	num_cpus = sysinfo.dwNumberOfProcessors;
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

	parse_cmdline(argc, argv);

        if (!opt_n_threads)
                opt_n_threads = num_cpus;

        if ( opt_algo == ALGO_NULL )
        {
            fprintf(stderr, "%s: no algo supplied\n", argv[0]);
            show_usage_and_exit(1);
        }
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
        if ( !register_algo_gate( opt_algo, &algo_gate ) )
           exit(1);

        if ( !check_cpu_capability() )
           exit(1);

	pthread_mutex_init(&stats_lock, NULL);
	pthread_mutex_init(&g_work_lock, NULL);
	pthread_mutex_init(&rpc2_job_lock, NULL);
	pthread_mutex_init(&rpc2_login_lock, NULL);
	pthread_mutex_init(&stratum.sock_lock, NULL);
	pthread_mutex_init(&stratum.work_lock, NULL);

	flags = !opt_benchmark && strncmp(rpc_url, "https:", 6)
	        ? (CURL_GLOBAL_ALL & ~CURL_GLOBAL_SSL)
	        : CURL_GLOBAL_ALL;
	if (curl_global_init(flags))
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
		switch (opt_priority) {
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

   if ( num_cpus != opt_n_threads )   
     applog( LOG_INFO,"%u CPU cores available, %u miner threads selected.",
             num_cpus, opt_n_threads );
   if ( opt_affinity != -1 )
   {
      if ( num_cpus > 64 )
      {
          applog(LOG_WARNING,"--cpu-affinity argument is not supported with more");
          applog(LOG_WARNING," than 64 CPUs, using default affinity.");
          opt_affinity = -1;
      }
      else	
      {
         if (!opt_quiet)
            applog(LOG_DEBUG, "Binding process to cpu mask %x", opt_affinity);
         affine_to_cpu_mask( -1, (unsigned long)opt_affinity );
      }
   }

//#ifdef HAVE_SYSLOG_H
//	if (use_syslog)
//		openlog("cpuminer", LOG_PID, LOG_USER);
//#endif

	work_restart = (struct work_restart*) calloc(opt_n_threads, sizeof(*work_restart));
	if (!work_restart)
		return 1;
	thr_info = (struct thr_info*) calloc(opt_n_threads + 4, sizeof(*thr));
	if (!thr_info)
		return 1;
	thr_hashrates = (double *) calloc(opt_n_threads, sizeof(double));
	if (!thr_hashrates)
		return 1;
        thr_hashcount = (double *) calloc(opt_n_threads, sizeof(double));
        if (!thr_hashcount)
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
			applog(LOG_ERR, "long poll thread create failed");
			return 1;
		}
	}
	if (want_stratum)
        {
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
			applog(LOG_ERR, "stratum thread create failed");
			return 1;
		}
		if (have_stratum)
			tq_push(thr_info[stratum_thr_id].q, strdup(rpc_url));
	}

	if (opt_api_listen)
        {
		/* api thread */
		api_thr_id = opt_n_threads + 3;
		thr = &thr_info[api_thr_id];
		thr->id = api_thr_id;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create(thr, api_thread);
		if (err) {
			applog(LOG_ERR, "api thread create failed");
			return 1;
		}
	}

	/* start mining threads */
	for (i = 0; i < opt_n_threads; i++)
        {
		thr = &thr_info[i];
		thr->id = i;
		thr->q = tq_new();
		if (!thr->q)
			return 1;
		err = thread_create(thr, miner_thread);
		if (err) {
			applog(LOG_ERR, "thread %d create failed", i);
			return 1;
		}
	}

	applog(LOG_INFO, "%d miner threads started, "
		"using '%s' algorithm.",
		opt_n_threads,
		algo_names[opt_algo]);

	/* main loop - simply wait for workio thread to exit */
	pthread_join(thr_info[work_thr_id].pth, NULL);
	applog(LOG_WARNING, "workio thread dead, exiting.");
	return 0;
}
