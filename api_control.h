/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Runtime stop/start/pause and re-targeting, without restarting the process.
 * Contract: docs/api-rest.md section 7.
 *
 * Safety comes from the parking protocol, not the state machine: a mutation
 * asks every mining thread to park, waits for all of them, and only then
 * touches the gate, algo or pool. A thread that misses the timeout aborts the
 * mutation rather than being forced.
 *
 * Off unless --api-control; every entry point answers CTL_DISABLED then.
 */

#ifndef API_CONTROL_H
#define API_CONTROL_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* CLI, defined in api_control.c so an unset option cannot silently mean 0. */
extern int opt_api_control;                 /* --api-control                  */
extern int opt_api_control_min_interval;    /* seconds, anti-flap             */
extern int opt_api_control_park_timeout;    /* ms to wait for threads to idle */

typedef enum {
   CTL_RUNNING = 0,
   CTL_PAUSED,
   CTL_STOPPED,
   CTL_SWITCHING
} ctl_state_t;

/* Maps onto the contract's status codes; the route layer does the translation
 * so this file never mentions HTTP. */
typedef enum {
   CTL_OK = 0,
   CTL_ACCEPTED,        /* 202: did not finish inside wait_ms              */
   CTL_DISABLED,        /* 403: --api-control not given                    */
   CTL_BUSY,            /* 409: a mutation is already in progress          */
   CTL_THROTTLED,       /* 429: inside --api-control-min-interval          */
   CTL_BAD_REQUEST,     /* 400                                             */
   CTL_FAILED           /* 409 with last_error set                         */
} ctl_result_t;

/* A snapshot for GET /control/state, taken under the control lock. */
struct ctl_status
{
   ctl_state_t state;
   uint64_t    epoch;             /* increments once per ACCEPTED mutation */
   double      since_s;
   char        algo[64];
   int         threads_total;
   int         threads_parked;
   uint64_t    switch_count;
   double      last_switch_age_s;
   int         min_interval_s;
   bool        ready_for_switch;
   char        last_error[256];   /* empty when none */
};

/* ------------------------------------------------- algorithm parameters
 *
 * Section 9. The per-algo set comes from what register_*_algo() actually
 * reads: scrypt takes n; yespower/yescrypt/yespower-b2b take n, r, key;
 * verthash takes data_file. The fixed-parameter variants (yespowerr16,
 * yescryptr8/r16/r32, power2b) advertise nothing on purpose -- their values
 * are consensus, so an accepted override would mine rejects. */

typedef enum { CTLP_INT = 0, CTLP_STRING } ctl_param_type_t;

typedef struct {
   const char      *name;
   ctl_param_type_t type;
   bool             slow;   /* needs file or network I/O; section 9 tier */
} ctl_param_def_t;

/* Names this algorithm accepts, for GET /api/v1/algos. */
const char **api_ctl_algo_params( int algo, size_t *count );
/* Definition by name, or NULL when the name is not a parameter at all. */
const ctl_param_def_t *api_ctl_param_find( const char *name );
/* Value in effect for the CURRENT algo, for GET /control/state. Returns false
 * when this algo does not take that parameter, or it is unset. */
bool api_ctl_param_get_int( const char *name, long *out );
bool api_ctl_param_get_str( const char *name, const char **out );

void        api_ctl_init( void );          /* once, from main */
bool        api_ctl_enabled( void );
ctl_state_t api_ctl_get_state( void );
void        api_ctl_get_status( struct ctl_status *out );

/* Paused, stopped or mid-mutation. Every hashrate surface reports 0 while this
 * is true -- docs/api-rest.md section 6.1. Safe when control is off. */
bool        api_ctl_mining_parked( void );

/* Should this thread be hashing right now? Called by the mining loop, which
 * parks itself when the answer is false -- that is how a thread acknowledges
 * a pending mutation. */
bool        api_ctl_thread_should_run( int thr_id );

/* Called by a PARKED thread to service its own algo buffers. Must run on the
 * owning thread: they are __thread, so a free from the control thread releases
 * its own empty pointers and leaves the real ones dangling. Two steps -- all
 * free under the OLD gate, gate swaps, all re-init under the NEW one -- since
 * a free from the wrong gate pairs the wrong deallocator with the buffer. */
void        api_ctl_thread_service( int thr_id );

/* start / pause / stop. wait_ms <= 0 means "do not wait", which returns
 * CTL_ACCEPTED and leaves the caller to poll. */
ctl_result_t api_ctl_set_state( ctl_state_t target, int wait_ms );

/* A parameter assignment for api_ctl_profile(). `reset` means the client sent
 * an explicit null: restore the algorithm's own default. Omitted parameters are
 * simply not in the array and keep their current value (section 9). */
typedef struct {
   const char *name;
   bool        reset;
   long        ival;
   const char *sval;
} ctl_param_set_t;

/* One atomic algo + params + pool + run-state change, rolled back as a unit.
 * Any part may be absent; the route layer has already validated that an algo
 * change carries a pool (section 7.4). */
ctl_result_t api_ctl_profile( const char *algo, const char *pool_url,
                              const char *pool_user, const char *pool_pass,
                              const ctl_param_set_t *params, size_t nparams,
                              const bool *run, int wait_ms );

#ifdef __cplusplus
}
#endif

#endif /* API_CONTROL_H */
