/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Prometheus text exposition for GET /metrics — contract: docs/api-rest.md
 * section 11.
 *
 * Renderer only: no miner state, no calls. The caller fills a POD struct from
 * the same snapshots the JSON builders use, so the two cannot disagree, and the
 * output is testable without a miner.
 *
 * Two conventions differ from the JSON side on purpose: base units and a
 * `_total` suffix on counters. A value the miner cannot supply is an omitted
 * series, never a zero.
 */

#ifndef API_METRICS_H
#define API_METRICS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define API_METRICS_MAX_DEVICES 32
#define API_METRICS_MAX_POOLS 8

/* Per-device sample, from the monitor thread's cache only: the vendor
 * telemetry calls are the expensive part of /devices. */
typedef struct {
	bool valid;
	int  device;
	char type[32];            /* device kind, e.g. "gpu"                    */
	char algo[64];
	double hashrate_hs;
	bool has_temp;   double temp_c;
	bool has_power;  double power_w;
	bool has_fan;    double fan_pct;
	bool has_hw_errors; uint64_t hw_errors;
} api_metrics_device;

typedef struct {
	int  index;
	bool active;
	char url[512];
	bool stratum;             /* false -> connected series is omitted        */
	bool connected;
	uint64_t disconnects;     /* unintentional only                          */
	bool has_last_share; double last_share_age_s;
} api_metrics_pool;

typedef struct {
	const char *name;
	const char *version;
	const char *kind;         /* "gpu" | "cpu"                               */
	const char *algo;
	const char *control_state;/* running | paused | stopped | switching      */

	bool mining_active;
	double uptime_s;
	double hashrate_hs;
	double net_difficulty;
	double pool_difficulty;

	/* Process-lifetime monotonic: the miner's own counters are reset by some
	 * paths, and a decrease mid-window corrupts rate(). */
	uint64_t shares_accepted, shares_rejected, shares_stale;
	uint64_t blocks_solved;

	api_metrics_device devices[API_METRICS_MAX_DEVICES];
	int ndevices;
	api_metrics_pool pools[API_METRICS_MAX_POOLS];
	int npools;
} api_metrics_input;

/* Bytes written, or 0 when buf was too small — never a truncated exposition,
 * which a scraper would parse as a half-missing family. */
size_t api_metrics_render(const api_metrics_input *in, char *buf, size_t buflen);

#define API_METRICS_CONTENT_TYPE "text/plain; version=0.0.4; charset=utf-8"

#ifdef __cplusplus
}
#endif

#endif /* API_METRICS_H */
