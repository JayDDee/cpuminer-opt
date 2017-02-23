#include <ccminer-config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <math.h>
#include <sys/time.h>
#include <time.h>
#include <signal.h>
#include <curl/curl.h>
#include <miner.h>

#include "sia-rpc.h"

static bool sia_debug_diff = false;

extern int share_result(int result, int pooln, double sharediff, const char *reason);

/* compute nbits to get the network diff */
static void calc_network_diff(struct work *work)
{
	uint32_t nbits = work->data[11]; // unsure if correct
	uint32_t bits = (nbits & 0xffffff);
	int16_t shift = (swab32(nbits) & 0xff); // 0x1c = 28

	uint64_t diffone = 0x0000FFFF00000000ull;
	double d = (double)0x0000ffff / (double)bits;

	for (int m=shift; m < 29; m++) d *= 256.0;
	for (int m=29; m < shift; m++) d /= 256.0;
	if (sia_debug_diff)
		applog(LOG_DEBUG, "net diff: %f -> shift %u, bits %08x", d, shift, bits);

	net_diff = d;
}

// ---- SIA LONGPOLL --------------------------------------------------------------------------------

struct data_buffer {
	void *buf;
	size_t len;
};

static size_t sia_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = (struct data_buffer *)user_data;
	size_t len = size * nmemb;
	size_t oldlen, newlen;
	void *newmem;
	static const uchar zero = 0;

	oldlen = db->len;
	newlen = oldlen + len;

	newmem = realloc(db->buf, newlen + 1);
	if (!newmem)
		return 0;

	db->buf = newmem;
	db->len = newlen;
	memcpy((char*)db->buf + oldlen, ptr, len);
	memcpy((char*)db->buf + newlen, &zero, 1);	/* null terminate */

	return len;
}

char* sia_getheader(CURL *curl, struct pool_infos *pool)
{
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	struct data_buffer all_data = { 0 };
	struct curl_slist *headers = NULL;
	char data[256] = { 0 };
	char url[512];

	// nanopool
	snprintf(url, 512, "%s/miner/header?address=%s&worker=%s", //&longpoll
		pool->url, pool->user, pool->pass);

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_POST, 0);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, opt_timeout);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sia_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);

	headers = curl_slist_append(headers, "Accept: application/octet-stream");
	headers = curl_slist_append(headers, "Expect:"); // disable Expect hdr
	headers = curl_slist_append(headers, "User-Agent: Sia-Agent"); // required for now
//	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
//	headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll");

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	int rc = curl_easy_perform(curl);
	if (rc && strlen(curl_err_str)) {
		applog(LOG_WARNING, "%s", curl_err_str);
	}

	if (all_data.len >= 112)
		cbin2hex(data, (const char*) all_data.buf, 112);
	if (opt_protocol || all_data.len != 112)
		applog(LOG_DEBUG, "received %d bytes: %s", (int) all_data.len, data);

	curl_slist_free_all(headers);

	return rc == 0 && all_data.len ? strdup(data) : NULL;
}

bool sia_work_decode(const char *hexdata, struct work *work)
{
	uint8_t target[32];
	if (!work) return false;

	hex2bin((uchar*)target, &hexdata[0], 32);
	swab256(work->target, target);
	work->targetdiff = target_to_diff(work->target);

	hex2bin((uchar*)work->data, &hexdata[64], 80);
	// high 16 bits of the 64 bits nonce
	work->data[9] = rand() << 16;

	// use work ntime as job id
	cbin2hex(work->job_id, (const char*)&work->data[10], 4);
	calc_network_diff(work);

	if (stratum_diff != work->targetdiff) {
		stratum_diff = work->targetdiff;
		applog(LOG_WARNING, "Pool diff set to %g", stratum_diff);
	}

	return true;
}

bool sia_submit(CURL *curl, struct pool_infos *pool, struct work *work)
{
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	struct data_buffer all_data = { 0 };
	struct curl_slist *headers = NULL;
	char buf[256] = { 0 };
	char url[512];

	if (opt_protocol)
		applog_hex(work->data, 80);
	//applog_hex(&work->data[8], 16);
	//applog_hex(&work->data[10], 4);

	// nanopool
	snprintf(url, 512, "%s/miner/header?address=%s&worker=%s",
		pool->url, pool->user, pool->pass);

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10);

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, sia_data_cb);

	memcpy(buf, work->data, 80);
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 80);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (void*) buf);

//	headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
//	headers = curl_slist_append(headers, "Content-Length: 80");
	headers = curl_slist_append(headers, "Accept:"); // disable Accept hdr
	headers = curl_slist_append(headers, "Expect:"); // disable Expect hdr
	headers = curl_slist_append(headers, "User-Agent: Sia-Agent");
//	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	int res = curl_easy_perform(curl) == 0;
	long errcode;
	CURLcode c = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &errcode);
	if (errcode != 204) {
		if (strlen(curl_err_str))
			applog(LOG_ERR, "submit err %ld %s", errcode, curl_err_str);
		res = 0;
	}
	share_result(res, work->pooln, work->sharediff[0], res ? NULL : (char*) all_data.buf);

	curl_slist_free_all(headers);
	return true;
}

// ---- END SIA LONGPOLL ----------------------------------------------------------------------------
