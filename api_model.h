#ifndef API_MODEL_H__
#define API_MODEL_H__ 1

/*
 * Neutral snapshots, decoupled from rendering, so every renderer reports the
 * same numbers:
 *
 *     api_collect_*()        live miner state -> snapshot
 *     api_format_*_binary()  legacy K=V;K=V;| form
 *     api_build_*_json()     JSON, docs/api-rest.md
 *
 * Rules: collect_*() reads each value exactly once, so two renderers cannot
 * see different states of a moving counter; format_*_binary() must reproduce
 * the legacy bytes exactly (api/tests/golden.py is the gate); strings are
 * copied, never pointed at, since a pool reset can free short_url mid-format.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <float.h>       /* DBL_MAX_10_EXP -- see diff_str below */
#include <time.h>

#include <jansson.h>

#include "api_metrics.h"

#ifdef __cplusplus
extern "C" {
#endif

struct api_summary_snapshot
{
   const char *name;             /* PACKAGE_NAME    -- static storage */
   const char *ver;              /* PACKAGE_VERSION -- static storage */
   const char *api;              /* APIVERSION      -- static storage */
   char        algo[64];
   int         cpus;
   char        url[256];
   double      hashrate;         /* H/s */
   uint32_t    accepted;
   uint32_t    rejected;
   uint32_t    solved;
   double      acc_per_min;
   /* Preformatted: the legacy renderer prints no decimals for an integral
    * difficulty. Kept as a string so both renderers agree on the rounding
    * instead of each re-deriving it. Sized for "%.6f" of any finite double,
    * not for a plausible difficulty: at char[16] a net_diff above ~1e8
    * overflowed and aborted the miner. */
   char        diff_str[DBL_MAX_10_EXP + 16];
   double      diff;             /* the same value, unformatted */
   /* diff above collapses net-or-else-stratum into one number; JSON reports
    * the two separately, so keep both. */
   double      diff_pool;
   double      diff_net;
   bool        has_monitoring;
   float       cpu_temp;
   int         cpu_fan;
   uint32_t    cpu_clock;
   double      uptime;
   uint32_t    ts;

   /* Tracked by the miner but NOT part of the legacy `summary` record. Present
    * here for the JSON renderer, which must not report them as null. */
   uint32_t    submitted;
   uint32_t    stale;
   double      net_hashrate;     /* H/s, 0 when the pool does not report it */
   double      best_share;       /* highest accepted share difficulty */
};

struct api_thread_snapshot
{
   int      id;
   double   hashrate;            /* H/s, unscaled */
   bool     have_shares;         /* false before the counters are allocated */
   uint32_t accepted;
   uint32_t rejected;
};

/* The single pool: no array by design, so only index 0 exists and
 * /pools/switch is 501 permanently (section 10). Do not grow it into an array
 * for symmetry with the GPU miner -- the manager owns pool selection. */
struct api_pool_snapshot
{
   char     name[128];           /* short_url -- there are no named pools here */
   char     url[512];            /* never contains a password */
   char     user[192];
   char     algo[64];
   uint32_t accepted, rejected, stale, solved;
   uint32_t disconnects;         /* unintentional only */
   uint32_t session_s;           /* this pool session, NOT process uptime */
   bool     have_session;        /* false => report null, never 0 */
   bool     stratum;             /* false = getwork/GBT */
   bool     connected;
   double   diff;
   double   best_share;
   char     job_id[128];
   int      height;
   int      xnonce2_size;
};

struct api_system_snapshot
{
   char     os[80];
   int      cpus;                /* logical */
   float    cpu_temp;            /* 0 = no sensor */
   uint32_t cpu_clock_khz;       /* 0 = unknown */
   int      cpu_fan_pct;         /* <0 = no sensor */
};

/* One completed scanhash call, for GET /api/v1/history. Written from the
 * mining loop, so every field is one the loop already has. */
#define API_HISTORY_PER_THREAD 50

struct api_history_record
{
   uint32_t id;                  /* monotonic across all threads */
   int      thread_id;
   uint32_t height;
   double   hashrate;            /* H/s for this scan */
   double   difficulty;          /* share target difficulty, pool scale */
   uint64_t hashcount;
   bool     found;               /* this scan submitted a share */
   uint32_t ts;                  /* unix seconds, scan end */
};

/* The one CPU device. Same shell as the GPU miner's so the JSON matches; the
 * typed sub-object is `cpu`, never `gpu`. */
struct api_device_snapshot
{
   char     name[128];           /* CPU brand string */
   int      threads;             /* logical CPUs */
   float    cpu_temp;
   uint32_t cpu_clock_khz;
   int      cpu_fan_pct;
   double   hashrate;            /* H/s, device total */
   char     features[256];       /* instruction sets this build can use */
};

/* Uptime origin. The model owns it rather than reading api.c's file-local
 * `startup`, a name too generic to export. Call once from the API thread. */
void api_model_set_start_time( time_t t );

/* Fill from live miner state. */
void api_collect_summary( struct api_summary_snapshot *s );
bool api_collect_thread( int thr_id, struct api_thread_snapshot *t );
void api_collect_pool( struct api_pool_snapshot *p );
void api_collect_system( struct api_system_snapshot *s );
void api_collect_device( struct api_device_snapshot *d );

/* From the mining loop when a scan returns. Allocates on first use and never
 * fails: a refused allocation just leaves history empty. */
void api_history_add( int thr_id, uint32_t height, double hashrate,
                      double difficulty, uint64_t hashcount, bool found );
/* Newest first. thr_id < 0 means every thread, interleaved newest first.
 * Returns how many records were written, at most max. */
int  api_history_get( int thr_id, struct api_history_record *out, int max );
/* Discard every sample; samples either side of an algo switch are not
 * comparable. */
void api_history_reset( void );

/* Drop the stats describing the run that just ended: share counters, hashrates,
 * best/lowest share, the share ring. Defined in cpu-miner.c, which owns those
 * statics. Safe only with every miner thread parked, so api_control.c is the
 * sole caller. Process-lifetime figures survive it. */
void api_reset_session_stats( void );

/* Render exactly as the legacy binary protocol always has. Returns the number
 * of bytes written, excluding the terminator. */
int api_format_summary_binary( char *out, size_t len,
                               const struct api_summary_snapshot *s );
int api_format_thread_binary( char *out, size_t len,
                              const struct api_thread_snapshot *t );

/* Second renderer over the same snapshots. Two rules from the contract: JSON
 * reports H/s where the binary reported kH/s (the _hs suffix makes that safe),
 * and an unavailable value is null, never 0. Caller owns the result; NULL
 * means allocation failed. */
json_t *api_build_miner_json( void );
json_t *api_build_summary_json( const struct api_summary_snapshot *s );
json_t *api_build_thread_json( const struct api_thread_snapshot *t );
json_t *api_build_pool_json( int index, bool active,
                             const struct api_pool_snapshot *p );
json_t *api_build_system_json( const struct api_system_snapshot *s );
json_t *api_build_device_json( int id, const struct api_device_snapshot *d );
json_t *api_build_history_json( const struct api_history_record *r );

/* Third renderer, GET /metrics: fills the Prometheus input struct from the
 * same state the JSON builders read, so a scrape and a poll cannot disagree.
 * Cheap by contract -- a scraper hits this every 15-60 s. */
void api_collect_metrics( api_metrics_input *in );

#ifdef __cplusplus
}
#endif

#endif
