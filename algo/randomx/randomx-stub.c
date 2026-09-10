/* Stand-in for algo/randomx/ when configured --disable-randomx.
 *
 * This file exists so the shared code needs no #ifdefs. cpu-miner.c and util.c
 * call seven RandomX entry points, all of them gated behind
 * rx_algo_uses_monero_stratum(), which here always answers false -- so those call sites
 * take the bitcoin-stratum path and the bodies below only have to satisfy the
 * linker. The one that does run is register_randomx_algo(), when a user asks
 * for an algo this build does not contain, so it names the flag instead of
 * failing obscurely.
 */

#include <stdbool.h>
#include <stddef.h>

#include "miner.h"
#include "algo-gate-api.h"
#include "randomx-gate.h"

bool register_randomx_algo( algo_gate_t *gate )
{
   (void)gate;
   applog( LOG_ERR, "%s: this build was configured with --disable-randomx",
           algo_names[ opt_algo ] );
   applog( LOG_ERR, "Rebuild without that flag to mine RandomX algorithms." );
   return false;
}

/* False for every algo, which is what makes the call sites in cpu-miner.c and
 * util.c fall through to the bitcoin-stratum path and never reach the rest of
 * this file. */
bool rx_algo_uses_monero_stratum( int algo )
{
   (void)algo;
   return false;
}

/* Lets register_k12_algo() refuse up front: k12 borrows this dialect, so in a
 * --disable-randomx build it has no wire to speak and must not fall back to
 * the bitcoin stratum. */
bool rx_stratum_available( void ) { return false; }

unsigned rx_algo_nonce_bytes( int algo )
{
   (void)algo;
   return 4;
}

bool rx_algo_needs_seed( int algo )
{
   (void)algo;
   return false;
}

bool rx_variant_select_plain( int algo )
{
   (void)algo;
   return false;
}

bool rx_stratum_login( struct stratum_ctx *sctx, const char *user,
                       const char *pass )
{
   (void)sctx; (void)user; (void)pass;
   return false;
}

bool rx_stratum_job( struct stratum_ctx *sctx, json_t *params )
{
   (void)sctx; (void)params;
   return false;
}

bool rx_stratum_prepare_seed( struct stratum_ctx *sctx )
{
   (void)sctx;
   return false;
}

void rx_stratum_gen_work( struct stratum_ctx *sctx, struct work *g_work )
{
   (void)sctx; (void)g_work;
}

bool rx_stratum_parse_response( json_t *val, bool *accepted,
                                const char **reason )
{
   (void)val; (void)accepted; (void)reason;
   return false;
}

/* Never called, but register_k12_algo() takes their addresses for the gate
 * before it can discover the dialect is missing, and taking an address needs
 * the symbol at link time. It refuses on rx_stratum_available() above, so the
 * gate it would have populated is discarded. */
void rx_get_new_work( struct work *work, struct work *g_work,
                      int thr_id, uint32_t *end_nonce_ptr )
{
   (void)work; (void)g_work; (void)thr_id; (void)end_nonce_ptr;
}

void rx_build_stratum_request( char *req, struct work *work,
                               struct stratum_ctx *sctx )
{
   (void)req; (void)work; (void)sctx;
}
