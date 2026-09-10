// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * Prometheus text exposition — see api_metrics.h and docs/api-rest.md section 11.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "api_metrics.h"

/* --------------------------------------------------------------- buffer */

typedef struct {
	char  *buf;
	size_t cap;
	size_t len;
	bool   overflow;
} sink;

static void emit(sink *s, const char *fmt, ...)
#if defined(__GNUC__)
	__attribute__((format(printf, 2, 3)))
#endif
;

static void emit(sink *s, const char *fmt, ...)
{
	if (s->overflow)
		return;
	va_list ap;
	va_start(ap, fmt);
	const int n = vsnprintf(s->buf + s->len, s->cap - s->len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t) n >= s->cap - s->len) {
		s->overflow = true;
		return;
	}
	s->len += (size_t) n;
}

/* A label value may not contain a backslash, quote or newline. An unescaped one
 * does not give a wrong value, it makes the scraper reject the whole
 * exposition — every metric from this rig, gone. */
static const char *esc(const char *in, char *out, size_t outlen)
{
	size_t j = 0;
	if (!in) in = "";
	for (size_t i = 0; in[i] && j + 2 < outlen; i++) {
		const char c = in[i];
		if (c == '\\' || c == '"') {
			out[j++] = '\\';
			out[j++] = c;
		} else if (c == '\n') {
			out[j++] = '\\';
			out[j++] = 'n';
		} else {
			out[j++] = c;
		}
	}
	out[j] = '\0';
	return out;
}

static void family(sink *s, const char *name, const char *type, const char *help)
{
	emit(s, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, type);
}

/* Plain decimal: %g would emit 1e+09 for a hashrate, legal but unreadable. */
static void num(char *out, size_t outlen, double v)
{
	snprintf(out, outlen, "%.6f", v);
	char *dot = strchr(out, '.');
	if (!dot)
		return;
	size_t l = strlen(out);
	while (l > 1 && out[l-1] == '0') out[--l] = '\0';
	if (l > 1 && out[l-1] == '.') out[--l] = '\0';
}

/* ---------------------------------------------------------------- render */

size_t api_metrics_render(const api_metrics_input *in, char *buf, size_t buflen)
{
	if (!in || !buf || buflen < 64)
		return 0;

	sink s = { buf, buflen, 0, false };
	char v[64], l1[600], l2[128];

	family(&s, "miner_info", "gauge",
		"Build and configuration labels; the value is always 1.");
	emit(&s, "miner_info{version=\"%s\",algo=\"%s\",kind=\"%s\",name=\"%s\"} 1\n",
		esc(in->version, l1, sizeof(l1)), esc(in->algo, l2, sizeof(l2)),
		in->kind ? in->kind : "", in->name ? in->name : "");

	family(&s, "miner_uptime_seconds", "gauge", "Seconds since the miner started.");
	num(v, sizeof(v), in->uptime_s);
	emit(&s, "miner_uptime_seconds %s\n", v);

	/* Phrased to avoid "name value" in the HELP text itself, which a naive
	 * grep over the exposition matches instead of the sample. */
	family(&s, "miner_mining_active", "gauge",
		"Whether the miner is currently hashing.");
	emit(&s, "miner_mining_active %d\n", in->mining_active ? 1 : 0);

	/* One series per state, exactly one set to 1, so a query selects by label.
	 * Without it hashrate == 0 cannot tell a fault from a deliberate stop. */
	family(&s, "miner_control_state", "gauge",
		"Runtime control state; exactly one series is 1.");
	static const char *states[] = { "running", "paused", "stopped", "switching" };
	for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
		emit(&s, "miner_control_state{state=\"%s\"} %d\n", states[i],
			(in->control_state && !strcmp(in->control_state, states[i])) ? 1 : 0);

	family(&s, "miner_hashrate_hashes_per_second", "gauge",
		"Total hashrate. The algo label ends the series on a switch, which is intended.");
	num(v, sizeof(v), in->hashrate_hs);
	emit(&s, "miner_hashrate_hashes_per_second{algo=\"%s\"} %s\n",
		esc(in->algo, l1, sizeof(l1)), v);

	family(&s, "miner_network_difficulty", "gauge", "Network difficulty.");
	num(v, sizeof(v), in->net_difficulty);
	emit(&s, "miner_network_difficulty %s\n", v);

	family(&s, "miner_pool_difficulty", "gauge", "Share difficulty set by the pool.");
	num(v, sizeof(v), in->pool_difficulty);
	emit(&s, "miner_pool_difficulty %s\n", v);

	family(&s, "miner_shares_total", "counter",
		"Shares by outcome since process start; monotonic by construction.");
	emit(&s, "miner_shares_total{result=\"accepted\"} %llu\n",
		(unsigned long long) in->shares_accepted);
	emit(&s, "miner_shares_total{result=\"rejected\"} %llu\n",
		(unsigned long long) in->shares_rejected);
	emit(&s, "miner_shares_total{result=\"stale\"} %llu\n",
		(unsigned long long) in->shares_stale);

	family(&s, "miner_blocks_solved_total", "counter", "Blocks solved since process start.");
	emit(&s, "miner_blocks_solved_total %llu\n", (unsigned long long) in->blocks_solved);

	/* --- per device ---------------------------------------------------- */

	if (in->ndevices > 0) {
		family(&s, "miner_device_hashrate_hashes_per_second", "gauge",
			"Hashrate per device.");
		for (int i = 0; i < in->ndevices; i++) {
			const api_metrics_device *d = &in->devices[i];
			if (!d->valid) continue;
			num(v, sizeof(v), d->hashrate_hs);
			emit(&s, "miner_device_hashrate_hashes_per_second"
				"{device=\"%d\",type=\"%s\",algo=\"%s\"} %s\n",
				d->device, esc(d->type, l2, sizeof(l2)),
				esc(d->algo, l1, sizeof(l1)), v);
		}

		/* Only where the monitor thread has a sample: it does not run under
		 * --quiet, so hashrate without temperature is a legitimate state. */
		family(&s, "miner_device_temperature_celsius", "gauge", "Device temperature.");
		for (int i = 0; i < in->ndevices; i++) {
			const api_metrics_device *d = &in->devices[i];
			if (!d->valid || !d->has_temp) continue;
			num(v, sizeof(v), d->temp_c);
			emit(&s, "miner_device_temperature_celsius{device=\"%d\"} %s\n", d->device, v);
		}

		family(&s, "miner_device_power_watts", "gauge", "Device power draw.");
		for (int i = 0; i < in->ndevices; i++) {
			const api_metrics_device *d = &in->devices[i];
			if (!d->valid || !d->has_power) continue;
			num(v, sizeof(v), d->power_w);
			emit(&s, "miner_device_power_watts{device=\"%d\"} %s\n", d->device, v);
		}

		family(&s, "miner_device_fan_percent", "gauge", "Device fan speed.");
		for (int i = 0; i < in->ndevices; i++) {
			const api_metrics_device *d = &in->devices[i];
			if (!d->valid || !d->has_fan) continue;
			num(v, sizeof(v), d->fan_pct);
			emit(&s, "miner_device_fan_percent{device=\"%d\"} %s\n", d->device, v);
		}

		family(&s, "miner_device_hw_errors_total", "counter",
			"Hardware errors reported by the device since process start.");
		for (int i = 0; i < in->ndevices; i++) {
			const api_metrics_device *d = &in->devices[i];
			if (!d->valid || !d->has_hw_errors) continue;
			emit(&s, "miner_device_hw_errors_total{device=\"%d\"} %llu\n",
				d->device, (unsigned long long) d->hw_errors);
		}
	}

	/* --- per pool ------------------------------------------------------ */

	if (in->npools > 0) {
		/* Absent, not 0, for getwork/GBT: no connection to report on, and
		 * "disconnected" would be a different claim. */
		family(&s, "miner_pool_connected", "gauge",
			"Whether the stratum connection is up. Absent for getwork/GBT pools.");
		for (int i = 0; i < in->npools; i++) {
			const api_metrics_pool *p = &in->pools[i];
			if (!p->stratum) continue;
			emit(&s, "miner_pool_connected{pool=\"%s\"} %d\n",
				esc(p->url, l1, sizeof(l1)), p->connected ? 1 : 0);
		}

		family(&s, "miner_pool_disconnects_total", "counter",
			"Unintentional disconnects; deliberate control stops are not counted.");
		for (int i = 0; i < in->npools; i++) {
			const api_metrics_pool *p = &in->pools[i];
			emit(&s, "miner_pool_disconnects_total{pool=\"%s\"} %llu\n",
				esc(p->url, l1, sizeof(l1)), (unsigned long long) p->disconnects);
		}

		family(&s, "miner_pool_last_share_age_seconds", "gauge",
			"Age of the last accepted share; catches connected-but-idle.");
		for (int i = 0; i < in->npools; i++) {
			const api_metrics_pool *p = &in->pools[i];
			if (!p->has_last_share) continue;
			num(v, sizeof(v), p->last_share_age_s);
			emit(&s, "miner_pool_last_share_age_seconds{pool=\"%s\"} %s\n",
				esc(p->url, l1, sizeof(l1)), v);
		}
	}

	if (s.overflow)
		return 0;
	return s.len;
}
