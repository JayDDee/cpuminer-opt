#ifndef EQUIHASH_GATE_H
#define EQUIHASH_GATE_H

#include "algo-gate-api.h"
#include "miner.h"

/* Gate registration — one per variant */
bool register_equihash_algo(algo_gate_t *gate);    /* 200/9 — ZCash default */
bool register_equihash96_algo(algo_gate_t *gate);  /*  96/5 — small variant */
bool register_equihash144_algo(algo_gate_t *gate); /* 144/5 — Bitcoin Gold  */
bool register_equihash192_algo(algo_gate_t *gate); /* 192/7                 */
bool register_equihash125_algo(algo_gate_t *gate); /* 125/4 — Flux/ZelCash  */

/* Shared functions used by all variants */
int  scanhash_equihash(struct work *work, uint32_t max_nonce,
                       uint64_t *hashes_done, struct thr_info *mythr);

void equihash_build_extraheader(struct work *g_work, struct stratum_ctx *sctx);

void equihash_build_stratum_request(char *req, struct work *work,
                                    struct stratum_ctx *sctx);

int  equihash_get_work_data_size(void);

#endif /* EQUIHASH_GATE_H */
