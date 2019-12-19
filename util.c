/*
 * Copyright 2010 Jeff Garzik
 * Copyright 2012 Luke Dashjr
 * Copyright 2012-2014 pooler
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define _GNU_SOURCE
#include <cpuminer-config.h>

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>
#include <jansson.h>
#include <curl/curl.h>
#include "sysinfos.c"
#include <time.h>
#include <sys/stat.h>
#include <math.h>
//#include <syslog.h>
#if defined(WIN32)
#include <winsock2.h>
#include <mstcpip.h>
#include "compat/winansi.h"
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#endif

#ifndef _MSC_VER
/* dirname() linux/mingw, else in compat.h */
#include <libgen.h>
#endif

#include "miner.h"
#include "elist.h"
#include "algo-gate-api.h"

//extern pthread_mutex_t stats_lock;

struct data_buffer {
	void		*buf;
	size_t		len;
};

struct upload_buffer {
	const void	*buf;
	size_t		len;
	size_t		pos;
};

struct header_info {
	char		*lp_path;
	char		*reason;
	char		*stratum_url;
};

struct tq_ent {
	void			*data;
	struct list_head	q_node;
};

struct thread_q {
	struct list_head	q;

	bool frozen;

	pthread_mutex_t		mutex;
	pthread_cond_t		cond;
};


void applog2( int prio, const char *fmt, ... )
{
   va_list ap;

   va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
   if (use_syslog) {
      va_list ap2;
      char *buf;
      int len;

      /* custom colors to syslog prio */
      if (prio > LOG_DEBUG) {
         switch (prio) {
            case LOG_BLUE: prio = LOG_NOTICE; break;
         }
      }

      va_copy(ap2, ap);
      len = vsnprintf(NULL, 0, fmt, ap2) + 1;
      va_end(ap2);
      buf = alloca(len);
      if (vsnprintf(buf, len, fmt, ap) >= 0)
         syslog(prio, "%s", buf);
   }
#else
   if (0) {}
#endif
   else {
      const char* color = "";
      char *f;
      int len;
//    struct tm tm;
//    time_t now = time(NULL);

//    localtime_r(&now, &tm);

      switch (prio) {
         case LOG_ERR:     color = CL_RED; break;
         case LOG_WARNING: color = CL_YLW; break;
         case LOG_NOTICE:  color = CL_WHT; break;
         case LOG_INFO:    color = ""; break;
         case LOG_DEBUG:   color = CL_GRY; break;

         case LOG_BLUE:
            prio = LOG_NOTICE;
            color = CL_CYN;
            break;
      }
      if (!use_colors)
         color = "";

      len = 64 + (int) strlen(fmt) + 2;
      f = (char*) malloc(len);
      sprintf(f, "                     %s %s%s\n",
//      sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
//         tm.tm_year + 1900,
//         tm.tm_mon + 1,
//         tm.tm_mday,
//         tm.tm_hour,
//         tm.tm_min,
//         tm.tm_sec,
         color,
         fmt,
         use_colors ? CL_N : ""
      );
      pthread_mutex_lock(&applog_lock);
      vfprintf(stdout, f, ap);   /* atomic write to stdout */
      fflush(stdout);
      free(f);
      pthread_mutex_unlock(&applog_lock);
   }
   va_end(ap);
}




void applog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);

#ifdef HAVE_SYSLOG_H
	if (use_syslog) {
		va_list ap2;
		char *buf;
		int len;

		/* custom colors to syslog prio */
		if (prio > LOG_DEBUG) {
			switch (prio) {
				case LOG_BLUE: prio = LOG_NOTICE; break;
			}
		}

		va_copy(ap2, ap);
		len = vsnprintf(NULL, 0, fmt, ap2) + 1;
		va_end(ap2);
		buf = alloca(len);
		if (vsnprintf(buf, len, fmt, ap) >= 0)
			syslog(prio, "%s", buf);
	}
#else
	if (0) {}
#endif
	else {
		const char* color = "";
		char *f;
		int len;
		struct tm tm;
		time_t now = time(NULL);

		localtime_r(&now, &tm);

		switch (prio) {
			case LOG_ERR:     color = CL_RED; break;
			case LOG_WARNING: color = CL_YLW; break;
			case LOG_NOTICE:  color = CL_WHT; break;
			case LOG_INFO:    color = ""; break;
			case LOG_DEBUG:   color = CL_GRY; break;

			case LOG_BLUE:
				prio = LOG_NOTICE;
				color = CL_CYN;
				break;
		}
		if (!use_colors)
			color = "";

		len = 64 + (int) strlen(fmt) + 2;
		f = (char*) malloc(len);
		sprintf(f, "[%d-%02d-%02d %02d:%02d:%02d]%s %s%s\n",
			tm.tm_year + 1900,
			tm.tm_mon + 1,
			tm.tm_mday,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec,
			color,
			fmt,
			use_colors ? CL_N : ""
		);
		pthread_mutex_lock(&applog_lock);
		vfprintf(stdout, f, ap);	/* atomic write to stdout */
		fflush(stdout);
		free(f);
		pthread_mutex_unlock(&applog_lock);
	}
	va_end(ap);
}

void log_sw_err( char* filename, int line_number, char* msg )
{
  applog( LOG_ERR, "SW_ERR: %s:%d, %s", filename, line_number, msg );
}

/* Get default config.json path (will be system specific) */
void get_defconfig_path(char *out, size_t bufsize, char *argv0)
{
	char *cmd = strdup(argv0);
	char *dir = dirname(cmd);
	const char *sep = strstr(dir, "\\") ? "\\" : "/";
	struct stat info = { 0 };
#ifdef WIN32
	snprintf(out, bufsize, "%s\\cpuminer\\cpuminer-conf.json", getenv("APPDATA"));
#else
	snprintf(out, bufsize, "%s\\.cpuminer\\cpuminer-conf.json", getenv("HOME"));
#endif
	if (dir && stat(out, &info) != 0) {
		snprintf(out, bufsize, "%s%scpuminer-conf.json", dir, sep);
	}
	if (stat(out, &info) != 0) {
		out[0] = '\0';
		return;
	}
	out[bufsize - 1] = '\0';
	free(cmd);
}


void format_hashrate(double hashrate, char *output)
{
	char prefix = '\0';

	if (hashrate < 10000) {
		// nop
	}
	else if (hashrate < 1e7) {
		prefix = 'k';
		hashrate *= 1e-3;
	}
	else if (hashrate < 1e10) {
		prefix = 'M';
		hashrate *= 1e-6;
	}
	else if (hashrate < 1e13) {
		prefix = 'G';
		hashrate *= 1e-9;
	}
	else {
		prefix = 'T';
		hashrate *= 1e-12;
	}

	sprintf(
		output,
		prefix ? "%.2f %cH/s" : "%.2f H/s%c",
		hashrate, prefix
	);
}

/* Modify the representation of integer numbers which would cause an overflow
 * so that they are treated as floating-point numbers.
 * This is a hack to overcome the limitations of some versions of Jansson. */
static char *hack_json_numbers(const char *in)
{
	char *out;
	int i, off, intoff;
	bool in_str, in_int;

	out = (char*) calloc(2 * strlen(in) + 1, 1);
	if (!out)
		return NULL;
	off = intoff = 0;
	in_str = in_int = false;
	for (i = 0; in[i]; i++) {
		char c = in[i];
		if (c == '"') {
			in_str = !in_str;
		} else if (c == '\\') {
			out[off++] = c;
			if (!in[++i])
				break;
		} else if (!in_str && !in_int && isdigit(c)) {
			intoff = off;
			in_int = true;
		} else if (in_int && !isdigit(c)) {
			if (c != '.' && c != 'e' && c != 'E' && c != '+' && c != '-') {
				in_int = false;
				if (off - intoff > 4) {
					char *end;
#if JSON_INTEGER_IS_LONG_LONG
					errno = 0;
					strtoll(out + intoff, &end, 10);
					if (!*end && errno == ERANGE) {
#else
					long l;
					errno = 0;
					l = strtol(out + intoff, &end, 10);
					if (!*end && (errno == ERANGE || l > INT_MAX)) {
#endif
						out[off++] = '.';
						out[off++] = '0';
					}
				}
			}
		}
		out[off++] = in[i];
	}
	return out;
}

static void databuf_free(struct data_buffer *db)
{
	if (!db)
		return;

	free(db->buf);

	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb,
			  void *user_data)
{
	struct data_buffer *db = (struct data_buffer *) user_data;
	size_t len = size * nmemb;
	size_t oldlen, newlen;
	void *newmem;
	static const unsigned char zero = 0;

	oldlen = db->len;
	newlen = oldlen + len;

	newmem = realloc(db->buf, newlen + 1);
	if (!newmem)
		return 0;

	db->buf = newmem;
	db->len = newlen;
	memcpy((uchar*) db->buf + oldlen, ptr, len);
	memcpy((uchar*) db->buf + newlen, &zero, 1);	/* null terminate */

	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb,
			     void *user_data)
{
	struct upload_buffer *ub = (struct upload_buffer *) user_data;
	size_t len = size * nmemb;

	if (len > ub->len - ub->pos)
		len = ub->len - ub->pos;

	if (len) {
		memcpy(ptr, ((uchar*)ub->buf) + ub->pos, len);
		ub->pos += len;
	}

	return len;
}

#if LIBCURL_VERSION_NUM >= 0x071200
static int seek_data_cb(void *user_data, curl_off_t offset, int origin)
{
	struct upload_buffer *ub = (struct upload_buffer *) user_data;
	
	switch (origin) {
	case SEEK_SET:
		ub->pos = (size_t) offset;
		break;
	case SEEK_CUR:
		ub->pos += (size_t) offset;
		break;
	case SEEK_END:
		ub->pos = ub->len + (size_t) offset;
		break;
	default:
		return 1; /* CURL_SEEKFUNC_FAIL */
	}

	return 0; /* CURL_SEEKFUNC_OK */
}
#endif

static size_t resp_hdr_cb(void *ptr, size_t size, size_t nmemb, void *user_data)
{
	struct header_info *hi = (struct header_info *) user_data;
	size_t remlen, slen, ptrlen = size * nmemb;
	char *rem, *val = NULL, *key = NULL;
	void *tmp;

	val = (char*) calloc(1, ptrlen);
	key = (char*) calloc(1, ptrlen);
	if (!key || !val)
		goto out;

	tmp = memchr(ptr, ':', ptrlen);
	if (!tmp || (tmp == ptr))	/* skip empty keys / blanks */
		goto out;
	slen = (char*)tmp - (char*)ptr;
	if ((slen + 1) == ptrlen)	/* skip key w/ no value */
		goto out;
	memcpy(key, ptr, slen);		/* store & nul term key */
	key[slen] = 0;

	rem = (char*)ptr + slen + 1;		/* trim value's leading whitespace */
	remlen = ptrlen - slen - 1;
	while ((remlen > 0) && (isspace(*rem))) {
		remlen--;
		rem++;
	}

	memcpy(val, rem, remlen);	/* store value, trim trailing ws */
	val[remlen] = 0;
	while ((*val) && (isspace(val[strlen(val) - 1]))) {
		val[strlen(val) - 1] = 0;
	}

	if (!strcasecmp("X-Long-Polling", key)) {
		hi->lp_path = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Reject-Reason", key)) {
		hi->reason = val;	/* steal memory reference */
		val = NULL;
	}

	if (!strcasecmp("X-Stratum", key)) {
		hi->stratum_url = val;	/* steal memory reference */
		val = NULL;
	}

out:
	free(key);
	free(val);
	return ptrlen;
}

#if LIBCURL_VERSION_NUM >= 0x070f06
static int sockopt_keepalive_cb(void *userdata, curl_socket_t fd,
	curlsocktype purpose)
{
#ifdef __linux
	int tcp_keepcnt = 3;
#endif
	int tcp_keepintvl = 50;
	int tcp_keepidle = 50;
#ifndef WIN32
	int keepalive = 1;
	if (unlikely(setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
		sizeof(keepalive))))
		return 1;
#ifdef __linux
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPCNT,
		&tcp_keepcnt, sizeof(tcp_keepcnt))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPIDLE,
		&tcp_keepidle, sizeof(tcp_keepidle))))
		return 1;
	if (unlikely(setsockopt(fd, SOL_TCP, TCP_KEEPINTVL,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __linux */
#ifdef __APPLE_CC__
	if (unlikely(setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE,
		&tcp_keepintvl, sizeof(tcp_keepintvl))))
		return 1;
#endif /* __APPLE_CC__ */
#else /* WIN32 */
	struct tcp_keepalive vals;
	vals.onoff = 1;
	vals.keepalivetime = tcp_keepidle * 1000;
	vals.keepaliveinterval = tcp_keepintvl * 1000;
	DWORD outputBytes;
	if (unlikely(WSAIoctl(fd, SIO_KEEPALIVE_VALS, &vals, sizeof(vals),
		NULL, 0, &outputBytes, NULL, NULL)))
		return 1;
#endif /* WIN32 */

	return 0;
}
#endif

json_t *json_rpc_call(CURL *curl, const char *url,
		      const char *userpass, const char *rpc_req,
		      int *curl_err, int flags)
{
	json_t *val, *err_val, *res_val;
	int rc;
	long http_rc;
	struct data_buffer all_data = {0};
	struct upload_buffer upload_data;
	char *json_buf;
	json_error_t err;
	struct curl_slist *headers = NULL;
	char len_hdr[64];
	char curl_err_str[CURL_ERROR_SIZE] = { 0 };
	long timeout = (flags & JSON_RPC_LONGPOLL) ? opt_timeout : 30;
	struct header_info hi = {0};

	/* it is assumed that 'curl' is freshly [re]initialized at this pt */

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, url);
	if (opt_cert)
		curl_easy_setopt(curl, CURLOPT_CAINFO, opt_cert);
//
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, false);

	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
#if LIBCURL_VERSION_NUM >= 0x071200
	curl_easy_setopt(curl, CURLOPT_SEEKFUNCTION, &seek_data_cb);
	curl_easy_setopt(curl, CURLOPT_SEEKDATA, &upload_data);
#endif
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	if (opt_redirect)
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, resp_hdr_cb);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &hi);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
#if LIBCURL_VERSION_NUM >= 0x070f06
	if (flags & JSON_RPC_LONGPOLL)
		curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
	curl_easy_setopt(curl, CURLOPT_POST, 1);

	if (opt_protocol)
		applog(LOG_DEBUG, "JSON protocol request:\n%s\n", rpc_req);

	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	upload_data.pos = 0;
	sprintf(len_hdr, "Content-Length: %lu",
		(unsigned long) upload_data.len);

	headers = curl_slist_append(headers, "Content-Type: application/json");
	headers = curl_slist_append(headers, len_hdr);
	headers = curl_slist_append(headers, "User-Agent: " USER_AGENT);
	headers = curl_slist_append(headers, "X-Mining-Extensions: longpoll reject-reason");
	//headers = curl_slist_append(headers, "Accept:"); /* disable Accept hdr*/
	//headers = curl_slist_append(headers, "Expect:"); /* disable Expect hdr*/

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

	rc = curl_easy_perform(curl);
	if (curl_err != NULL)
		*curl_err = rc;
	if (rc) {
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rc);
		if (!((flags & JSON_RPC_LONGPOLL) && rc == CURLE_OPERATION_TIMEDOUT) &&
		    !((flags & JSON_RPC_QUIET_404) && http_rc == 404))
			applog(LOG_ERR, "HTTP request failed: %s", curl_err_str);
		if (curl_err && (flags & JSON_RPC_QUIET_404) && http_rc == 404)
			*curl_err = CURLE_OK;
		goto err_out;
	}

	/* If X-Stratum was found, activate Stratum */
	if (want_stratum && hi.stratum_url &&
	    !strncasecmp(hi.stratum_url, "stratum+tcp://", 14)) {
		have_stratum = true;
		tq_push(thr_info[stratum_thr_id].q, hi.stratum_url);
		hi.stratum_url = NULL;
	}

	/* If X-Long-Polling was found, activate long polling */
	if (!have_longpoll && want_longpoll && hi.lp_path && !have_gbt &&
	    allow_getwork && !have_stratum) {
		have_longpoll = true;
		tq_push(thr_info[longpoll_thr_id].q, hi.lp_path);
		hi.lp_path = NULL;
	}

	if (!all_data.buf) {
		applog(LOG_ERR, "Empty data received in json_rpc_call.");
		goto err_out;
	}

	json_buf = hack_json_numbers((char*) all_data.buf);
	errno = 0; /* needed for Jansson < 2.1 */
	val = JSON_LOADS(json_buf, &err);
	free(json_buf);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}

	if (opt_protocol) {
		char *s = json_dumps(val, JSON_INDENT(3));
		applog(LOG_DEBUG, "JSON protocol response:\n%s", s);
		free(s);
	}

	/* JSON-RPC valid response returns a 'result' and a null 'error'. */
	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || (err_val && !json_is_null(err_val)
		&& !(flags & JSON_RPC_IGNOREERR))) {

		char *s = NULL;

		if (err_val) {
			s = json_dumps(err_val, 0);
			json_t *msg = json_object_get(err_val, "message");
			json_t *err_code = json_object_get(err_val, "code");
			if (curl_err && json_integer_value(err_code))
				*curl_err = (int)json_integer_value(err_code);

			if (msg && json_is_string(msg)) {
				free(s);
				s = strdup(json_string_value(msg));
				if (have_longpoll && s && !strcmp(s, "method not getwork")) {
					json_decref(err_val);
					free(s);
					goto err_out;
				}
			}
			json_decref(err_val);
		}
		else
			s = strdup("(unknown reason)");

		if (!curl_err || opt_debug)
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);

		free(s);

		goto err_out;
	}

	if (hi.reason)
		json_object_set_new(val, "reject-reason", json_string(hi.reason));

	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	free(hi.lp_path);
	free(hi.reason);
	free(hi.stratum_url);
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

/* used to load a remote config */
json_t* json_load_url(char* cfg_url, json_error_t *err)
{
	char err_str[CURL_ERROR_SIZE] = { 0 };
	struct data_buffer all_data = { 0 };
	int rc = 0; json_t *cfg = NULL;
	CURL *curl = curl_easy_init();
	if (unlikely(!curl)) {
		applog(LOG_ERR, "Remote config init failed!");
		return NULL;
	}
	curl_easy_setopt(curl, CURLOPT_URL, cfg_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 15);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	} else if (getenv("http_proxy")) {
		if (getenv("all_proxy"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("all_proxy"));
		else if (getenv("ALL_PROXY"))
			curl_easy_setopt(curl, CURLOPT_PROXY, getenv("ALL_PROXY"));
		else
			curl_easy_setopt(curl, CURLOPT_PROXY, "");
	}
	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Remote config read failed: %s", err_str);
		goto err_out;
	}
	if (!all_data.buf || !all_data.len) {
		applog(LOG_ERR, "Empty data received for config");
		goto err_out;
	}

	cfg = JSON_LOADS((char*)all_data.buf, err);
err_out:
	curl_easy_cleanup(curl);
	return cfg;
}

void cbin2hex(char *out, const char *in, size_t len)
{
   if (out) {
      unsigned int i;
      for (i = 0; i < len; i++)
         sprintf(out + (i * 2), "%02x", (uint8_t)in[i]);
   }
}

void bin2hex(char *s, const unsigned char *p, size_t len)
{
	for (size_t i = 0; i < len; i++)
		sprintf(s + (i * 2), "%02x", (unsigned int) p[i]);
}

char *abin2hex(const unsigned char *p, size_t len)
{
	char *s = (char*) malloc((len * 2) + 1);
	if (!s)
		return NULL;
	bin2hex(s, p, len);
	return s;
}

bool hex2bin(unsigned char *p, const char *hexstr, size_t len)
{
	char hex_byte[3];
	char *ep;

	hex_byte[2] = '\0';

	while (*hexstr && len) {
		if (!hexstr[1]) {
			applog(LOG_ERR, "hex2bin str truncated");
			return false;
		}
		hex_byte[0] = hexstr[0];
		hex_byte[1] = hexstr[1];
		*p = (unsigned char) strtol(hex_byte, &ep, 16);
		if (*ep) {
			applog(LOG_ERR, "hex2bin failed on '%s'", hex_byte);
			return false;
		}
		p++;
		hexstr += 2;
		len--;
	}

	return(!len) ? true : false;
/*	return (len == 0 && *hexstr == 0) ? true : false; */
}

int varint_encode(unsigned char *p, uint64_t n)
{
	int i;
	if (n < 0xfd) {
		p[0] = (uchar) n;
		return 1;
	}
	if (n <= 0xffff) {
		p[0] = 0xfd;
		p[1] = n & 0xff;
		p[2] = (uchar) (n >> 8);
		return 3;
	}
	if (n <= 0xffffffff) {
		p[0] = 0xfe;
		for (i = 1; i < 5; i++) {
			p[i] = n & 0xff;
			n >>= 8;
		}
		return 5;
	}
	p[0] = 0xff;
	for (i = 1; i < 9; i++) {
		p[i] = n & 0xff;
		n >>= 8;
	}
	return 9;
}

static const char b58digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static bool b58dec(unsigned char *bin, size_t binsz, const char *b58)
{
	size_t i, j;
	uint64_t t;
	uint32_t c;
	uint32_t *outi;
	size_t outisz = (binsz + 3) / 4;
	int rem = binsz % 4;
	uint32_t remmask = 0xffffffff << (8 * rem);
	size_t b58sz = strlen(b58);
	bool rc = false;

	outi = (uint32_t *) calloc(outisz, sizeof(*outi));

	for (i = 0; i < b58sz; ++i) {
		for (c = 0; b58digits[c] != b58[i]; c++)
			if (!b58digits[c])
				goto out;
		for (j = outisz; j--; ) {
			t = (uint64_t)outi[j] * 58 + c;
			c = t >> 32;
			outi[j] = t & 0xffffffff;
		}
		if (c || outi[0] & remmask)
			goto out;
	}

	j = 0;
	switch (rem) {
		case 3:
			*(bin++) = (outi[0] >> 16) & 0xff;
		case 2:
			*(bin++) = (outi[0] >> 8) & 0xff;
		case 1:
			*(bin++) = outi[0] & 0xff;
			++j;
		default:
			break;
	}
	for (; j < outisz; ++j) {
		be32enc((uint32_t *)bin, outi[j]);
		bin += sizeof(uint32_t);
	}

	rc = true;
out:
	free(outi);
	return rc;
}

static int b58check(unsigned char *bin, size_t binsz, const char *b58)
{
	unsigned char buf[32];
	int i;

	sha256d(buf, bin, (int) (binsz - 4));
	if (memcmp(&bin[binsz - 4], buf, 4))
		return -1;

	/* Check number of zeros is correct AFTER verifying checksum
	 * (to avoid possibility of accessing the string beyond the end) */
	for (i = 0; bin[i] == '\0' && b58[i] == '1'; ++i);
	if (bin[i] == '\0' || b58[i] == '1')
		return -3;

	return bin[0];
}

bool jobj_binary(const json_t *obj, const char *key, void *buf, size_t buflen)
{
	const char *hexstr;
	json_t *tmp;

	tmp = json_object_get(obj, key);
	if (unlikely(!tmp)) {
		applog(LOG_ERR, "JSON key '%s' not found", key);
		return false;
	}
	hexstr = json_string_value(tmp);
	if (unlikely(!hexstr)) {
		applog(LOG_ERR, "JSON key '%s' is not a string", key);
		return false;
	}
	if (!hex2bin((uchar*) buf, hexstr, buflen))
		return false;

	return true;
}

size_t address_to_script(unsigned char *out, size_t outsz, const char *addr)
{
	unsigned char addrbin[25];
	int addrver;
	size_t rv;

	if (!b58dec(addrbin, sizeof(addrbin), addr))
		return 0;
	addrver = b58check(addrbin, sizeof(addrbin), addr);
	if (addrver < 0)
		return 0;
	switch (addrver) {
		case 5:    /* Bitcoin script hash */
		case 196:  /* Testnet script hash */
			if (outsz < (rv = 23))
				return rv;
			out[ 0] = 0xa9;  /* OP_HASH160 */
			out[ 1] = 0x14;  /* push 20 bytes */
			memcpy(&out[2], &addrbin[1], 20);
			out[22] = 0x87;  /* OP_EQUAL */
			return rv;
		default:
			if (outsz < (rv = 25))
				return rv;
			out[ 0] = 0x76;  /* OP_DUP */
			out[ 1] = 0xa9;  /* OP_HASH160 */
			out[ 2] = 0x14;  /* push 20 bytes */
			memcpy(&out[3], &addrbin[1], 20);
			out[23] = 0x88;  /* OP_EQUALVERIFY */
			out[24] = 0xac;  /* OP_CHECKSIG */
			return rv;
	}
}

/* Subtract the `struct timeval' values X and Y,
   storing the result in RESULT.
   Return 1 if the difference is negative, otherwise 0.  */
int timeval_subtract(struct timeval *result, struct timeval *x,
	struct timeval *y)
{
	/* Perform the carry for the later subtraction by updating Y. */
	if (x->tv_usec < y->tv_usec) {
		int nsec = (y->tv_usec - x->tv_usec) / 1000000 + 1;
		y->tv_usec -= 1000000 * nsec;
		y->tv_sec += nsec;
	}
	if (x->tv_usec - y->tv_usec > 1000000) {
		int nsec = (x->tv_usec - y->tv_usec) / 1000000;
		y->tv_usec += 1000000 * nsec;
		y->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * `tv_usec' is certainly positive. */
	result->tv_sec = x->tv_sec - y->tv_sec;
	result->tv_usec = x->tv_usec - y->tv_usec;

	/* Return 1 if result is negative. */
	return x->tv_sec < y->tv_sec;
}

bool fulltest(const uint32_t *hash, const uint32_t *target)
{
	int i;
	bool rc = true;
	
	for (i = 7; i >= 0; i--) {
		if (hash[i] > target[i]) {
			rc = false;
			break;
		}
		if (hash[i] < target[i]) {
			rc = true;
			break;
		}
	}

	if (opt_debug) {
		uint32_t hash_be[8], target_be[8];
		char hash_str[65], target_str[65];
		
		for (i = 0; i < 8; i++) {
			be32enc(hash_be + i, hash[7 - i]);
			be32enc(target_be + i, target[7 - i]);
		}
		bin2hex(hash_str, (unsigned char *)hash_be, 32);
		bin2hex(target_str, (unsigned char *)target_be, 32);

		applog(LOG_DEBUG, "DEBUG: %s\nHash:   %s\nTarget: %s",
			rc ? "hash <= target"
			   : "hash > target (false positive)",
			hash_str,
			target_str);
	}

	return rc;
}

void diff_to_target(uint32_t *target, double diff)
{
	uint64_t m;
	int k;
	
	for (k = 6; k > 0 && diff > 1.0; k--)
		diff /= 4294967296.0;
	m = (uint64_t)(4294901760.0 / diff);
	if (m == 0 && k == 6)
		memset(target, 0xff, 32);
	else {
		memset(target, 0, 32);
		target[k] = (uint32_t)m;
		target[k + 1] = (uint32_t)(m >> 32);
	}
}

// Only used by stratum pools
void work_set_target(struct work* work, double diff)
{
	diff_to_target(work->target, diff);
	work->targetdiff = diff;
}

// Only used by longpoll pools
double target_to_diff(uint32_t* target)
{
	uchar* tgt = (uchar*) target;
	uint64_t m =
		(uint64_t)tgt[29] << 56 |
		(uint64_t)tgt[28] << 48 |
		(uint64_t)tgt[27] << 40 |
		(uint64_t)tgt[26] << 32 |
		(uint64_t)tgt[25] << 24 |
		(uint64_t)tgt[24] << 16 |
		(uint64_t)tgt[23] << 8  |
		(uint64_t)tgt[22] << 0;

	if (!m)
		return 0.;
	else
		return (double)0x0000ffff00000000/m;
}

#ifdef WIN32
#define socket_blocks() (WSAGetLastError() == WSAEWOULDBLOCK)
#else
#define socket_blocks() (errno == EAGAIN || errno == EWOULDBLOCK)
#endif

static bool send_line(struct stratum_ctx *sctx, char *s)
{
	size_t sent = 0;
	int len;

	len = (int) strlen(s);
	s[len++] = '\n';

	while (len > 0) {
		struct timeval timeout = {0, 0};
		int n;
		fd_set wd;

		FD_ZERO(&wd);
		FD_SET(sctx->sock, &wd);
		if (select((int) (sctx->sock + 1), NULL, &wd, NULL, &timeout) < 1)
			return false;
#if LIBCURL_VERSION_NUM >= 0x071802
                 CURLcode rc = curl_easy_send(sctx->curl, s + sent, len, (size_t *)&n);
                 if (rc != CURLE_OK) {
                         if (rc != CURLE_AGAIN)
#else
                 n = send(sctx->sock, s + sent, len, 0);
                 if (n < 0) {
                         if (!socket_blocks())
#endif
				return false;
			n = 0;
		}
		sent += n;
		len -= n;
	}

	return true;
}

bool stratum_send_line(struct stratum_ctx *sctx, char *s)
{
	bool ret = false;

	if (opt_protocol)
		applog(LOG_DEBUG, "> %s", s);

	pthread_mutex_lock(&sctx->sock_lock);
	ret = send_line(sctx, s);
	pthread_mutex_unlock(&sctx->sock_lock);

	return ret;
}

static bool socket_full(curl_socket_t sock, int timeout)
{
	struct timeval tv;
	fd_set rd;

	FD_ZERO(&rd);
	FD_SET(sock, &rd);
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
	if (select((int)(sock + 1), &rd, NULL, NULL, &tv) > 0)
		return true;
	return false;
}

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout)
{
	return strlen(sctx->sockbuf) || socket_full(sctx->sock, timeout);
}

#define RBUFSIZE 2048
#define RECVSIZE (RBUFSIZE - 4)

static void stratum_buffer_append(struct stratum_ctx *sctx, const char *s)
{
	size_t old, n;

	old = strlen(sctx->sockbuf);
	n = old + strlen(s) + 1;
	if (n >= sctx->sockbuf_size) {
		sctx->sockbuf_size = n + (RBUFSIZE - (n % RBUFSIZE));
		sctx->sockbuf = (char*) realloc(sctx->sockbuf, sctx->sockbuf_size);
	}
	strcpy(sctx->sockbuf + old, s);
}

char *stratum_recv_line(struct stratum_ctx *sctx)
{
	ssize_t len, buflen;
	char *tok, *sret = NULL;

	if (!strstr(sctx->sockbuf, "\n")) {
		bool ret = true;
		time_t rstart;

		time(&rstart);
		if (!socket_full(sctx->sock, 60)) {
			applog(LOG_WARNING, "stratum_recv_line timed out");
			goto out;
		}
		do {
			char s[RBUFSIZE];
			ssize_t n;

			memset(s, 0, RBUFSIZE);
#if LIBCURL_VERSION_NUM >= 0x071802
			CURLcode rc = curl_easy_recv(sctx->curl, s, RECVSIZE, (size_t *)&n);
			if (rc == CURLE_OK && !n) {
				ret = false;
				break;
			}
			if (rc != CURLE_OK) {
				if (rc != CURLE_AGAIN || !socket_full(sctx->sock, 1)) {
#else
			n = recv(sctx->sock, s, RECVSIZE, 0);
			if (!n) {
				ret = false;
				break;
			}
			if (n < 0) {
				if (!socket_blocks() || !socket_full(sctx->sock, 1)) {
#endif
					ret = false;
					break;
				}
			} else
				stratum_buffer_append(sctx, s);
		} while (time(NULL) - rstart < 60 && !strstr(sctx->sockbuf, "\n"));

		if (!ret) {
			applog(LOG_WARNING, "stratum_recv_line failed");
			goto out;
		}
	}

	buflen = (ssize_t) strlen(sctx->sockbuf);
	tok = strtok(sctx->sockbuf, "\n");
	if (!tok) {
		applog(LOG_ERR, "stratum_recv_line failed to parse a newline-terminated string");
		goto out;
	}
	sret = strdup(tok);
	len = (ssize_t) strlen(sret);

	if (buflen > len + 1)
		memmove(sctx->sockbuf, sctx->sockbuf + len + 1, buflen - len + 1);
	else
		sctx->sockbuf[0] = '\0';

out:
	if (sret && opt_protocol)
		applog(LOG_DEBUG, "< %s", sret);
	return sret;
}

#if LIBCURL_VERSION_NUM >= 0x071101
static curl_socket_t opensocket_grab_cb(void *clientp, curlsocktype purpose,
	struct curl_sockaddr *addr)
{
	curl_socket_t *sock = (curl_socket_t*) clientp;
	*sock = socket(addr->family, addr->socktype, addr->protocol);
	return *sock;
}
#endif

bool stratum_connect(struct stratum_ctx *sctx, const char *url)
{
	CURL *curl;
	int rc;

	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl)
		curl_easy_cleanup(sctx->curl);
	sctx->curl = curl_easy_init();
	if (!sctx->curl) {
		applog(LOG_ERR, "CURL initialization failed");
		pthread_mutex_unlock(&sctx->sock_lock);
		return false;
	}
	curl = sctx->curl;
	if (!sctx->sockbuf) {
		sctx->sockbuf = (char*) calloc(RBUFSIZE, 1);
		sctx->sockbuf_size = RBUFSIZE;
	}
	sctx->sockbuf[0] = '\0';
	pthread_mutex_unlock(&sctx->sock_lock);
	if (url != sctx->url) {
		free(sctx->url);
		sctx->url = strdup(url);
	}
	free(sctx->curl_url);
	sctx->curl_url = (char*) malloc(strlen(url));
	sprintf(sctx->curl_url, "http%s", strstr(url, "s://") ? strstr(url, "s://") : strstr(url, "://"));

	if (opt_protocol)
		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1);
	curl_easy_setopt(curl, CURLOPT_URL, sctx->curl_url);
	curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 1);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, sctx->curl_err_str);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0);
	if (opt_proxy) {
		curl_easy_setopt(curl, CURLOPT_PROXY, opt_proxy);
		curl_easy_setopt(curl, CURLOPT_PROXYTYPE, opt_proxy_type);
	}
	curl_easy_setopt(curl, CURLOPT_HTTPPROXYTUNNEL, 1);
#if LIBCURL_VERSION_NUM >= 0x070f06
	curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, sockopt_keepalive_cb);
#endif
#if LIBCURL_VERSION_NUM >= 0x071101
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, opensocket_grab_cb);
	curl_easy_setopt(curl, CURLOPT_OPENSOCKETDATA, &sctx->sock);
#endif
	curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 1);

	rc = curl_easy_perform(curl);
	if (rc) {
		applog(LOG_ERR, "Stratum connection failed: %s", sctx->curl_err_str);
		curl_easy_cleanup(curl);
		sctx->curl = NULL;
		return false;
	}

#if LIBCURL_VERSION_NUM < 0x071101
	/* CURLINFO_LASTSOCKET is broken on Win64; only use it as a last resort */
	curl_easy_getinfo(curl, CURLINFO_LASTSOCKET, (long *)&sctx->sock);
#endif

	return true;
}

void stratum_disconnect(struct stratum_ctx *sctx)
{
	pthread_mutex_lock(&sctx->sock_lock);
	if (sctx->curl) {
		curl_easy_cleanup(sctx->curl);
		sctx->curl = NULL;
		sctx->sockbuf[0] = '\0';
	}
	pthread_mutex_unlock(&sctx->sock_lock);
}

static const char *get_stratum_session_id(json_t *val)
{
	json_t *arr_val;
	int i, n;

	arr_val = json_array_get(val, 0);
	if (!arr_val || !json_is_array(arr_val))
		return NULL;
	n = (int) json_array_size(arr_val);
	for (i = 0; i < n; i++) {
		const char *notify;
		json_t *arr = json_array_get(arr_val, i);

		if (!arr || !json_is_array(arr))
			break;
		notify = json_string_value(json_array_get(arr, 0));
		if (!notify)
			continue;
		if (!strcasecmp(notify, "mining.notify"))
			return json_string_value(json_array_get(arr, 1));
	}
	return NULL;
}

static bool stratum_parse_extranonce(struct stratum_ctx *sctx, json_t *params, int pndx)
{
	const char* xnonce1;
	int xn2_size;

	xnonce1 = json_string_value(json_array_get(params, pndx));
	if (!xnonce1) {
		applog(LOG_ERR, "Failed to get extranonce1");
		goto out;
	}
	xn2_size = (int) json_integer_value(json_array_get(params, pndx+1));
	if (!xn2_size) {
		applog(LOG_ERR, "Failed to get extranonce2_size");
		goto out;
	}
	if (xn2_size < 2 || xn2_size > 16) {
		applog(LOG_INFO, "Failed to get valid n2size in parse_extranonce");
		goto out;
	}

	pthread_mutex_lock(&sctx->work_lock);
	if (sctx->xnonce1)
		free(sctx->xnonce1);
	sctx->xnonce1_size = strlen(xnonce1) / 2;
	sctx->xnonce1 = (uchar*) calloc(1, sctx->xnonce1_size);
	if (unlikely(!sctx->xnonce1)) {
		applog(LOG_ERR, "Failed to alloc xnonce1");
		pthread_mutex_unlock(&sctx->work_lock);
		goto out;
	}
	hex2bin(sctx->xnonce1, xnonce1, sctx->xnonce1_size);
	sctx->xnonce2_size = xn2_size;
	pthread_mutex_unlock(&sctx->work_lock);

        if (pndx == 0 && opt_debug) /* pool dynamic change */
		applog(LOG_DEBUG, "Stratum set nonce %s with extranonce2 size=%d",
			xnonce1, xn2_size);

	return true;
out:
	return false;
}

bool stratum_subscribe(struct stratum_ctx *sctx)
{
	char *s, *sret = NULL;
	const char *sid;
	json_t *val = NULL, *res_val, *err_val;
	json_error_t err;
	bool ret = false, retry = false;

	if (jsonrpc_2)
		return true;

start:
	s = (char*) malloc(128 + (sctx->session_id ? strlen(sctx->session_id) : 0));
	if (retry)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": []}");
	else if (sctx->session_id)
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\", \"%s\"]}", sctx->session_id);
	else
		sprintf(s, "{\"id\": 1, \"method\": \"mining.subscribe\", \"params\": [\"" USER_AGENT "\"]}");

	if (!stratum_send_line(sctx, s)) {
		applog(LOG_ERR, "stratum_subscribe send failed");
		goto out;
	}

	if (!socket_full(sctx->sock, 30)) {
		applog(LOG_ERR, "stratum_subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (!sret)
		goto out;

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_null(res_val) ||
	    (err_val && !json_is_null(err_val))) {
		if (opt_debug || retry) {
			free(s);
			if (err_val)
				s = json_dumps(err_val, JSON_INDENT(3));
			else
				s = strdup("(unknown reason)");
			applog(LOG_ERR, "JSON-RPC call failed: %s", s);
		}
		goto out;
	}

	sid = get_stratum_session_id(res_val);
	if (opt_debug && sid)
		applog(LOG_DEBUG, "Stratum session id: %s", sid);

	pthread_mutex_lock(&sctx->work_lock);
	if (sctx->session_id)
		free(sctx->session_id);
	sctx->session_id = sid ? strdup(sid) : NULL;
	sctx->next_diff = 1.0;
	pthread_mutex_unlock(&sctx->work_lock);

	// sid is param 1, extranonce params are 2 and 3
	if (!stratum_parse_extranonce(sctx, res_val, 1)) {
		goto out;
	}

	ret = true;

out:
	free(s);
	if (val)
		json_decref(val);

	if (!ret) {
		if (sret && !retry) {
			retry = true;
			goto start;
		}
	}

	return ret;
}

extern bool opt_extranonce;

bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass)
{
	json_t *val = NULL, *res_val, *err_val;
	char *s, *sret;
	json_error_t err;
	bool ret = false;

	if (jsonrpc_2) {
		s = (char*) malloc(300 + strlen(user) + strlen(pass));
		sprintf(s, "{\"method\": \"login\", \"params\": {"
			"\"login\": \"%s\", \"pass\": \"%s\", \"agent\": \"%s\"}, \"id\": 1}",
			user, pass, USER_AGENT);
	} else {
		s = (char*) malloc(80 + strlen(user) + strlen(pass));
		sprintf(s, "{\"id\": 2, \"method\": \"mining.authorize\", \"params\": [\"%s\", \"%s\"]}",
			user, pass);
	}

	if (!stratum_send_line(sctx, s))
		goto out;

	while (1) {
		sret = stratum_recv_line(sctx);
		if (!sret)
			goto out;
		if (!stratum_handle_method(sctx, sret))
			break;
		free(sret);
	}

	val = JSON_LOADS(sret, &err);
	free(sret);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	res_val = json_object_get(val, "result");
	err_val = json_object_get(val, "error");

	if (!res_val || json_is_false(res_val) ||
	    (err_val && !json_is_null(err_val)))  {
		applog(LOG_ERR, "Stratum authentication failed");
		goto out;
	}

	if (jsonrpc_2) {
		rpc2_login_decode(val);
		json_t *job_val = json_object_get(res_val, "job");
		pthread_mutex_lock(&sctx->work_lock);
		if(job_val) rpc2_job_decode(job_val, &sctx->work);
                sctx->job.job_id = strdup(sctx->work.job_id);
		pthread_mutex_unlock(&sctx->work_lock);
	}

	ret = true;

	if (!opt_extranonce)
		goto out;

	// subscribe to extranonce (optional)
	sprintf(s, "{\"id\": 3, \"method\": \"mining.extranonce.subscribe\", \"params\": []}");

	if (!stratum_send_line(sctx, s))
		goto out;

	if (!socket_full(sctx->sock, 3)) {
		if (opt_debug)
			applog(LOG_DEBUG, "stratum extranonce subscribe timed out");
		goto out;
	}

	sret = stratum_recv_line(sctx);
	if (sret) {
		json_t *extra = JSON_LOADS(sret, &err);
		if (!extra) {
			applog(LOG_WARNING, "JSON decode failed(%d): %s", err.line, err.text);
		} else {
			if (json_integer_value(json_object_get(extra, "id")) != 3) {
				// we receive a standard method if extranonce is ignored
				if (!stratum_handle_method(sctx, sret))
					applog(LOG_WARNING, "Stratum answer id is not correct!");
			}
//			res_val = json_object_get(extra, "result");
//			if (opt_debug && (!res_val || json_is_false(res_val)))
//				applog(LOG_DEBUG, "extranonce subscribe not supported");
			json_decref(extra);
		}
		free(sret);
	}

out:
	free(s);
	if (val)
		json_decref(val);

	return ret;
}

// -------------------- RPC 2.0 (XMR/AEON) -------------------------

//extern pthread_mutex_t rpc2_login_lock;
//extern pthread_mutex_t rpc2_job_lock;

bool rpc2_login_decode(const json_t *val)
{
	const char *id;
	const char *s;

	json_t *res = json_object_get(val, "result");
	if(!res) {
		applog(LOG_ERR, "JSON invalid result");
		goto err_out;
	}

	json_t *tmp;
	tmp = json_object_get(res, "id");
	if(!tmp) {
		applog(LOG_ERR, "JSON inval id");
		goto err_out;
	}
	id = json_string_value(tmp);
	if(!id) {
		applog(LOG_ERR, "JSON id is not a string");
		goto err_out;
	}

	memcpy(&rpc2_id, id, 64);

	if(opt_debug)
		applog(LOG_DEBUG, "Auth id: %s", id);

	tmp = json_object_get(res, "status");
	if(!tmp) {
		applog(LOG_ERR, "JSON inval status");
		goto err_out;
	}
	s = json_string_value(tmp);
	if(!s) {
		applog(LOG_ERR, "JSON status is not a string");
		goto err_out;
	}
	if(strcmp(s, "OK")) {
		applog(LOG_ERR, "JSON returned status \"%s\"", s);
		return false;
	}

	return true;

err_out:
	applog(LOG_WARNING,"%s: fail", __func__);
	return false;
}

json_t* json_rpc2_call_recur(CURL *curl, const char *url, const char *userpass,
	json_t *rpc_req, int *curl_err, int flags, int recur)
{
	if(recur >= 5) {
		if(opt_debug)
			applog(LOG_DEBUG, "Failed to call rpc command after %i tries", recur);
		return NULL;
	}
	if(!strcmp(rpc2_id, "")) {
		if(opt_debug)
			applog(LOG_DEBUG, "Tried to call rpc2 command before authentication");
		return NULL;
	}
	json_t *params = json_object_get(rpc_req, "params");
	if (params) {
		json_t *auth_id = json_object_get(params, "id");
		if (auth_id) {
			json_string_set(auth_id, rpc2_id);
		}
	}
	json_t *res = json_rpc_call(curl, url, userpass, json_dumps(rpc_req, 0),
			curl_err, flags | JSON_RPC_IGNOREERR);
	if(!res) goto end;
	json_t *error = json_object_get(res, "error");
	if(!error) goto end;
	json_t *message;
	if(json_is_string(error))
		message = error;
	else
		message = json_object_get(error, "message");
	if(!message || !json_is_string(message)) goto end;
	const char *mes = json_string_value(message);
	if(!strcmp(mes, "Unauthenticated")) {
		pthread_mutex_lock(&rpc2_login_lock);
		rpc2_login(curl);
		sleep(1);
		pthread_mutex_unlock(&rpc2_login_lock);
		return json_rpc2_call_recur(curl, url, userpass, rpc_req,
				curl_err, flags, recur + 1);
	} else if(!strcmp(mes, "Low difficulty share") || !strcmp(mes, "Block expired") || !strcmp(mes, "Invalid job id") || !strcmp(mes, "Duplicate share")) {
		json_t *result = json_object_get(res, "result");
		if(!result) {
			goto end;
		}
		json_object_set(result, "reject-reason", json_string(mes));
	} else {
		applog(LOG_ERR, "json_rpc2.0 error: %s", mes);
		return NULL;
	}
	end:
	return res;
}

json_t *json_rpc2_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req, int *curl_err, int flags)
{
	json_t* req_json = JSON_LOADS(rpc_req, NULL);
	json_t* res = json_rpc2_call_recur(curl, url, userpass, req_json, curl_err, flags, 0);
	json_decref(req_json);
	return res;
}

bool rpc2_job_decode(const json_t *job, struct work *work)
{
	if (!jsonrpc_2) {
		applog(LOG_ERR, "Tried to decode job without JSON-RPC 2.0");
		return false;
	}
	json_t *tmp;
	tmp = json_object_get(job, "job_id");
	if (!tmp) {
		applog(LOG_ERR, "JSON invalid job id");
		goto err_out;
	}
	const char *job_id = json_string_value(tmp);
	tmp = json_object_get(job, "blob");
	if (!tmp) {
		applog(LOG_ERR, "JSON invalid blob");
		goto err_out;
	}
	const char *hexblob = json_string_value(tmp);
	size_t blobLen = strlen(hexblob);
	if (blobLen % 2 != 0 || ((blobLen / 2) < 40 && blobLen != 0) || (blobLen / 2) > 128) {
		applog(LOG_ERR, "JSON invalid blob length");
		goto err_out;
	}
	if (blobLen != 0) {
		uint32_t target = 0;
		pthread_mutex_lock(&rpc2_job_lock);
		uchar *blob = (uchar*) malloc(blobLen / 2);
		if (!hex2bin(blob, hexblob, blobLen / 2)) {
			applog(LOG_ERR, "JSON invalid blob");
			pthread_mutex_unlock(&rpc2_job_lock);
			goto err_out;
		}
		rpc2_bloblen = blobLen / 2;
		if (rpc2_blob) free(rpc2_blob);
		rpc2_blob = (char*) malloc(rpc2_bloblen);
		if (!rpc2_blob)  {
			applog(LOG_ERR, "RPC2 OOM!");
			goto err_out;
		}
		memcpy(rpc2_blob, blob, blobLen / 2);
		free(blob);

		jobj_binary(job, "target", &target, 4);
		if(rpc2_target != target)
                {
   		   double hashrate = 0.0;
                   pthread_mutex_lock(&stats_lock);
		   for (int i = 0; i < opt_n_threads; i++)
		      hashrate += thr_hashrates[i];
                   pthread_mutex_unlock(&stats_lock);
		   double diff = trunc( ( ((double)0xffffffff) / target ) );
		   if ( !opt_quiet )
		      // xmr pool diff can change a lot...
		      applog(LOG_WARNING, "Stratum difficulty set to %g", diff);
		   stratum_diff = diff;
		   rpc2_target = target;
		}

		if (rpc2_job_id) free(rpc2_job_id);
		rpc2_job_id = strdup(job_id);
		pthread_mutex_unlock(&rpc2_job_lock);
	}
	if(work) {
		if (!rpc2_blob) {
			applog(LOG_WARNING, "Work requested before it was received");
			goto err_out;
		}
		memcpy(work->data, rpc2_blob, rpc2_bloblen);
		memset(work->target, 0xff, sizeof(work->target));
		work->target[7] = rpc2_target;
		if (work->job_id) free(work->job_id);
		work->job_id = strdup(rpc2_job_id);
	}
	return true;

err_out:
	applog(LOG_WARNING, "%s", __func__);
	return false;
}

/**
 * Extract bloc height     L H... here len=3, height=0x1333e8
 * "...0000000000ffffffff2703e83313062f503253482f043d61105408"
 */
static uint32_t getblocheight(struct stratum_ctx *sctx)
{
	uint32_t height = 0;
	uint8_t hlen = 0, *p, *m;

	// find 0xffff tag
	p = (uint8_t*) sctx->job.coinbase + 32;
	m = p + 128;
	while (*p != 0xff && p < m) p++;
	while (*p == 0xff && p < m) p++;
	if (*(p-1) == 0xff && *(p-2) == 0xff) {
		p++; hlen = *p;
		p++; height = le16dec(p);
		p += 2;
		switch (hlen) {
			case 4:
				height += 0x10000UL * le16dec(p);
				break;
			case 3:
				height += 0x10000UL * (*p);
				break;
		}
	}
	return height;
}

static bool stratum_notify(struct stratum_ctx *sctx, json_t *params)
{
	const char *job_id, *prevhash, *coinb1, *coinb2, *version, *nbits, *stime;
   const char *denom10 = NULL, *denom100 = NULL, *denom1000 = NULL,
              *denom10000 = NULL, *prooffullnode = NULL;
   const char *extradata = NULL;
	size_t coinb1_size, coinb2_size;
	bool clean, ret = false;
	int merkle_count, i, p = 0;
	json_t *merkle_arr;
	uchar **merkle = NULL;
	int jsize = json_array_size(params);
   bool has_claim = ( opt_algo == ALGO_LBRY ) && ( jsize == 10 );
   bool has_roots = ( opt_algo == ALGO_PHI2 ) && ( jsize == 10 );
   bool is_veil  = ( opt_algo == ALGO_X16RT_VEIL );

   job_id = json_string_value(json_array_get(params, p++));
	prevhash = json_string_value(json_array_get(params, p++));
   if ( has_claim )
   {
       extradata = json_string_value(json_array_get(params, p++));
       if ( !extradata || strlen( extradata ) != 64 ) 
       {
           applog(LOG_ERR, "Stratum notify: invalid claim parameter");
           goto out;
       }
   }
   else if ( has_roots )
   {
       extradata = json_string_value(json_array_get(params, p++));
       if ( !extradata || strlen( extradata ) != 128 )
       {
           applog(LOG_ERR, "Stratum notify: invalid UTXO root parameter");
           goto out;
       }
   }
   if ( is_veil )
   {
      denom10 = json_string_value(json_array_get(params, p++));
      denom100 = json_string_value(json_array_get(params, p++));
      denom1000 = json_string_value(json_array_get(params, p++));
      denom10000 = json_string_value(json_array_get(params, p++));
      prooffullnode = json_string_value(json_array_get(params, p++));
   }

	coinb1 = json_string_value(json_array_get(params, p++));
	coinb2 = json_string_value(json_array_get(params, p++));
	merkle_arr = json_array_get(params, p++);
	if (!merkle_arr || !json_is_array(merkle_arr))
		goto out;
	merkle_count = (int) json_array_size(merkle_arr);
	version = json_string_value(json_array_get(params, p++));
	nbits = json_string_value(json_array_get(params, p++));
	stime = json_string_value(json_array_get(params, p++));
	clean = json_is_true(json_array_get(params, p)); p++;
   
	if (!job_id || !prevhash || !coinb1 || !coinb2 || !version || !nbits || !stime ||
	    strlen(prevhash) != 64 || strlen(version) != 8 ||
	    strlen(nbits) != 8 || strlen(stime) != 8) {
		applog(LOG_ERR, "Stratum notify: invalid parameters");
		goto out;
	}

   if ( is_veil )
   {
      if ( !denom10 || !denom100 || !denom1000 || !denom10000
        || !prooffullnode || strlen(denom10) != 64 || strlen(denom100) != 64
        || strlen(denom1000) != 64 || strlen(denom10000) != 64
        || strlen(prooffullnode) != 64 )
      {
         applog(LOG_ERR, "Stratum notify: invalid veil parameters");
         goto out;
      }
   }

   if ( merkle_count )
      merkle = (uchar**) malloc(merkle_count * sizeof(char *));
	for ( i = 0; i < merkle_count; i++ )
   {
		const char *s = json_string_value(json_array_get(merkle_arr, i));
		if (!s || strlen(s) != 64) {
			while (i--)
				free(merkle[i]);
			free(merkle);
			applog(LOG_ERR, "Stratum notify: invalid Merkle branch");
			goto out;
		}
		merkle[i] = (uchar*) malloc(32);
		hex2bin(merkle[i], s, 32);
	}

	pthread_mutex_lock(&sctx->work_lock);

	coinb1_size = strlen(coinb1) / 2;
	coinb2_size = strlen(coinb2) / 2;
	sctx->job.coinbase_size = coinb1_size + sctx->xnonce1_size +
	                          sctx->xnonce2_size + coinb2_size;
	sctx->job.coinbase = (uchar*) realloc(sctx->job.coinbase, sctx->job.coinbase_size);
	sctx->job.xnonce2 = sctx->job.coinbase + coinb1_size + sctx->xnonce1_size;
	hex2bin(sctx->job.coinbase, coinb1, coinb1_size);
	memcpy(sctx->job.coinbase + coinb1_size, sctx->xnonce1, sctx->xnonce1_size);
	if (!sctx->job.job_id || strcmp(sctx->job.job_id, job_id))
		memset(sctx->job.xnonce2, 0, sctx->xnonce2_size);
	hex2bin(sctx->job.xnonce2 + sctx->xnonce2_size, coinb2, coinb2_size);
	free(sctx->job.job_id);
	sctx->job.job_id = strdup(job_id);
	hex2bin(sctx->job.prevhash, prevhash, 32);
        if (has_claim) hex2bin(sctx->job.extra, extradata, 32);
        if (has_roots) hex2bin(sctx->job.extra, extradata, 64);

   if ( is_veil )
   {
      hex2bin(sctx->job.denom10, denom10, 32);
      hex2bin(sctx->job.denom100, denom100, 32);
      hex2bin(sctx->job.denom1000, denom1000, 32);
      hex2bin(sctx->job.denom10000, denom10000, 32);
      hex2bin(sctx->job.proofoffullnode, prooffullnode, 32);
   }

	sctx->block_height = getblocheight(sctx);

	for (i = 0; i < sctx->job.merkle_count; i++)
		free(sctx->job.merkle[i]);

	free(sctx->job.merkle);
	sctx->job.merkle = merkle;
	sctx->job.merkle_count = merkle_count;

	hex2bin(sctx->job.version, version, 4);
	hex2bin(sctx->job.nbits, nbits, 4);
	hex2bin(sctx->job.ntime, stime, 4);
	sctx->job.clean = clean;

	sctx->job.diff = sctx->next_diff;

	pthread_mutex_unlock(&sctx->work_lock);

	ret = true;

out:
	return ret;
}

static bool stratum_set_difficulty(struct stratum_ctx *sctx, json_t *params)
{
	double diff;

	diff = json_number_value(json_array_get(params, 0));
	if (diff == 0)
		return false;

	pthread_mutex_lock(&sctx->work_lock);
	sctx->next_diff = diff;
	pthread_mutex_unlock(&sctx->work_lock);
	return true;
}

static bool stratum_reconnect(struct stratum_ctx *sctx, json_t *params)
{
	json_t *port_val;
	char *url;
	const char *host;
	int port;

	host = json_string_value(json_array_get(params, 0));
	port_val = json_array_get(params, 1);
	if (json_is_string(port_val))
		port = atoi(json_string_value(port_val));
	else
		port = (int) json_integer_value(port_val);
	if (!host || !port)
		return false;

	url = (char*) malloc(32 + strlen(host));
	strncpy(url, sctx->url, 15);
	sprintf(strstr(url, "://") + 3, "%s:%d", host, port);

	if (!opt_redirect) {
		applog(LOG_INFO, "Ignoring request to reconnect to %s", url);
		free(url);
		return true;
	}

	applog(LOG_NOTICE, "Server requested reconnection to %s", url);

	free(sctx->url);
	sctx->url = url;
	stratum_disconnect(sctx);

	return true;
}

static bool json_object_set_error(json_t *result, int code, const char *msg)
{
	json_t *val = json_object();
	json_object_set_new(val, "code", json_integer(code));
	json_object_set_new(val, "message", json_string(msg));
	return json_object_set_new(result, "error", val) != -1;
}

/* allow to report algo perf to the pool for algo stats */
static bool stratum_benchdata(json_t *result, json_t *params, int thr_id)
{
	char algo[64] = { 0 };
	char cpuname[80] = { 0 };
	char vendorid[32] = { 0 };
	char compiler[32] = { 0 };
	char arch[16] = { 0 };
	char os[8];
	char *p;
	double cpufreq = 0;
	json_t *val;

	if (!opt_stratum_stats) return false;

	get_currentalgo(algo, sizeof(algo));

#if defined(WIN32) && (defined(_M_X64) || defined(__x86_64__))
	strcpy(os, "win64");
#else
	strcpy(os, is_windows() ? "win32" : "linux");
#endif

#ifdef _MSC_VER
	sprintf(compiler, "MSVC %d\n", msver());
#elif defined(__clang__)
	sprintf(compiler, "clang %s\n", __clang_version__);
#elif defined(__GNUC__)
	sprintf(compiler, "GCC %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#endif

#ifdef __AVX2__
	strcat(compiler, " AVX2");
#elif defined(__AVX__)
	strcat(compiler, " AVX");
#elif defined(__FMA4__)
	strcat(compiler, " FMA4");
#elif defined(__FMA3__)
	strcat(compiler, " FMA3");
#elif defined(__SSE4_2__)
	strcat(compiler, " SSE4.2");
#elif defined(__SSE4_1__)
	strcat(compiler, " SSE4");
#elif defined(__SSE3__)
	strcat(compiler, " SSE3");
#elif defined(__SSE2__)
	strcat(compiler, " SSE2");
#elif defined(__SSE__)
	strcat(compiler, " SSE");
#endif

	cpu_bestfeature(arch, 16);
	if (has_aes_ni()) strcat(arch, " NI");

	cpu_getmodelid(vendorid, 32);
	cpu_getname(cpuname, 80);
	p = strstr(cpuname, " @ ");
	if (p) {
		// linux only
		char freq[32] = { 0 };
		*p = '\0'; p += 3;
		snprintf(freq, 32, "%s", p);
		cpufreq = atof(freq);
		p = strstr(freq, "GHz"); if (p) cpufreq *= 1000;
		applog(LOG_NOTICE, "sharing CPU stats with freq %s", freq);
	}

	compiler[31] = '\0';

	val = json_object();
	json_object_set_new(val, "algo", json_string(algo));
	json_object_set_new(val, "type", json_string("cpu"));
	json_object_set_new(val, "device", json_string(cpuname));
	json_object_set_new(val, "vendorid", json_string(vendorid));
	json_object_set_new(val, "arch", json_string(arch));
	json_object_set_new(val, "freq", json_integer((uint64_t)cpufreq));
	json_object_set_new(val, "memf", json_integer(0));
	json_object_set_new(val, "power", json_integer(0));
	json_object_set_new(val, "khashes", json_real((double)global_hashrate / 1000.0));
	json_object_set_new(val, "intensity", json_real(opt_priority));
	json_object_set_new(val, "throughput", json_integer(opt_n_threads));
	json_object_set_new(val, "client", json_string(PACKAGE_NAME "/" PACKAGE_VERSION));
	json_object_set_new(val, "os", json_string(os));
	json_object_set_new(val, "driver", json_string(compiler));

	json_object_set_new(result, "result", val);

	return true;
}

static bool stratum_get_stats(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);

	ret = stratum_benchdata(val, params, 0);

	if (!ret) {
		json_object_set_error(val, 1, "disabled"); //EPERM
	} else {
		json_object_set_new(val, "error", json_null());
	}

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_unknown_method(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "result", json_false());
	json_object_set_error(val, 38, "unknown method"); // ENOSYS

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_pong(struct stratum_ctx *sctx, json_t *id)
{
	char buf[64];
	bool ret = false;

	if (!id || json_is_null(id))
		return ret;

	sprintf(buf, "{\"id\":%d,\"result\":\"pong\",\"error\":null}",
		(int) json_integer_value(id));
	ret = stratum_send_line(sctx, buf);

	return ret;
}

static bool stratum_get_algo(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char algo[64] = { 0 };
	char *s;
	json_t *val;
	bool ret = true;

	if (!id || json_is_null(id))
		return false;

	get_currentalgo(algo, sizeof(algo));

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(algo));

	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}


static bool stratum_get_version(struct stratum_ctx *sctx, json_t *id)
{
	char *s;
	json_t *val;
	bool ret;
	
	if (!id || json_is_null(id))
		return false;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_string(USER_AGENT));
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

static bool stratum_show_message(struct stratum_ctx *sctx, json_t *id, json_t *params)
{
	char *s;
	json_t *val;
	bool ret;

	val = json_array_get(params, 0);
	if (val)
		applog(LOG_NOTICE, "MESSAGE FROM SERVER: %s", json_string_value(val));
	
	if (!id || json_is_null(id))
		return true;

	val = json_object();
	json_object_set(val, "id", id);
	json_object_set_new(val, "error", json_null());
	json_object_set_new(val, "result", json_true());
	s = json_dumps(val, 0);
	ret = stratum_send_line(sctx, s);
	json_decref(val);
	free(s);

	return ret;
}

bool stratum_handle_method(struct stratum_ctx *sctx, const char *s)
{
	json_t *val, *id, *params;
	json_error_t err;
	const char *method;
	bool ret = false;

	val = JSON_LOADS(s, &err);
	if (!val) {
		applog(LOG_ERR, "JSON decode failed(%d): %s", err.line, err.text);
		goto out;
	}

	method = json_string_value(json_object_get(val, "method"));
	if (!method)
		goto out;

	params = json_object_get(val, "params");

	if (jsonrpc_2) {
		if (!strcasecmp(method, "job")) {
			ret = rpc2_stratum_job(sctx, params);
		}
		goto out;
	}

	id = json_object_get(val, "id");

	if (!strcasecmp(method, "mining.notify")) {
		ret = stratum_notify(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "mining.ping")) { // cgminer 4.7.1+
		if (opt_debug) applog(LOG_DEBUG, "Pool ping");
		ret = stratum_pong(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_difficulty")) {
		ret = stratum_set_difficulty(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "mining.set_extranonce")) {
		ret = stratum_parse_extranonce(sctx, params, 0);
		goto out;
	}
	if (!strcasecmp(method, "client.reconnect")) {
		ret = stratum_reconnect(sctx, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_algo")) {
		// will prevent wrong algo parameters on a pool, will be used as test on rejects
		if (!opt_quiet) applog(LOG_NOTICE, "Pool asked your algo parameter");
		ret = stratum_get_algo(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_stats")) {
		// optional to fill device benchmarks
		ret = stratum_get_stats(sctx, id, params);
		goto out;
	}
	if (!strcasecmp(method, "client.get_version")) {
		ret = stratum_get_version(sctx, id);
		goto out;
	}
	if (!strcasecmp(method, "client.show_message")) {
		ret = stratum_show_message(sctx, id, params);
		goto out;
	}

	if (!ret) {
		// don't fail = disconnect stratum on unknown (and optional?) methods
		if (opt_debug) applog(LOG_WARNING, "unknown stratum method %s!", method);
		ret = stratum_unknown_method(sctx, id);
	}
out:
	if (val)
		json_decref(val);

	return ret;
}

struct thread_q *tq_new(void)
{
	struct thread_q *tq;

	tq = (struct thread_q*) calloc(1, sizeof(*tq));
	if (!tq)
		return NULL;

	INIT_LIST_HEAD(&tq->q);
	pthread_mutex_init(&tq->mutex, NULL);
	pthread_cond_init(&tq->cond, NULL);

	return tq;
}

void tq_free(struct thread_q *tq)
{
	struct tq_ent *ent, *iter;

	if (!tq)
		return;

	list_for_each_entry_safe(ent, iter, &tq->q, q_node, struct tq_ent) {
		list_del(&ent->q_node);
		free(ent);
	}

	pthread_cond_destroy(&tq->cond);
	pthread_mutex_destroy(&tq->mutex);

	memset(tq, 0, sizeof(*tq));	/* poison */
	free(tq);
}

static void tq_freezethaw(struct thread_q *tq, bool frozen)
{
	pthread_mutex_lock(&tq->mutex);

	tq->frozen = frozen;

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);
}

void tq_freeze(struct thread_q *tq)
{
	tq_freezethaw(tq, true);
}

void tq_thaw(struct thread_q *tq)
{
	tq_freezethaw(tq, false);
}

bool tq_push(struct thread_q *tq, void *data)
{
	struct tq_ent *ent;
	bool rc = true;

	ent = (struct tq_ent*) calloc(1, sizeof(*ent));
	if (!ent)
		return false;

	ent->data = data;
	INIT_LIST_HEAD(&ent->q_node);

	pthread_mutex_lock(&tq->mutex);

	if (!tq->frozen) {
		list_add_tail(&ent->q_node, &tq->q);
	} else {
		free(ent);
		rc = false;
	}

	pthread_cond_signal(&tq->cond);
	pthread_mutex_unlock(&tq->mutex);

	return rc;
}

void *tq_pop(struct thread_q *tq, const struct timespec *abstime)
{
	struct tq_ent *ent;
	void *rval = NULL;
	int rc;

	pthread_mutex_lock(&tq->mutex);

	if (!list_empty(&tq->q))
		goto pop;

	if (abstime)
		rc = pthread_cond_timedwait(&tq->cond, &tq->mutex, abstime);
	else
		rc = pthread_cond_wait(&tq->cond, &tq->mutex);
	if (rc)
		goto out;
	if (list_empty(&tq->q))
		goto out;

pop:
	ent = list_entry(tq->q.next, struct tq_ent, q_node);
 	rval = ent->data;

	list_del(&ent->q_node);
	free(ent);

out:
	pthread_mutex_unlock(&tq->mutex);
	return rval;
}

/* sprintf can be used in applog */
static char* format_hash(char* buf, uint8_t *hash)
{
	int len = 0;
	for (int i=0; i < 32; i += 4) {
		len += sprintf(buf+len, "%02x%02x%02x%02x ",
			hash[i], hash[i+1], hash[i+2], hash[i+3]);
	}
	return buf;
}

void applog_compare_hash(void *hash, void *hash_ref)
{
        char s[256] = "";
        int len = 0;
        uchar* hash1 = (uchar*)hash;
        uchar* hash2 = (uchar*)hash_ref;
        for (int i=0; i < 32; i += 4) {
                const char *color = memcmp(hash1+i, hash2+i, 4) ? CL_WHT : CL_GRY;
                len += sprintf(s+len, "%s%02x%02x%02x%02x " CL_GRY, color,
                        hash1[i], hash1[i+1], hash1[i+2], hash1[i+3]);
                s[len] = '\0';
        }
        applog(LOG_DEBUG, "%s", s);
}

void applog_hash(void *hash)
{
	char s[128] = {'\0'};
	applog(LOG_DEBUG, "%s", format_hash(s, (uchar*) hash));
}

void applog_hex(void *data, int len)
{
        char* hex = abin2hex((uchar*)data, len);
        applog(LOG_DEBUG, "%s", hex);
        free(hex);
}

void applog_hash64(void *hash)
{
        char s[128] = {'\0'};
        char t[128] = {'\0'};
        applog(LOG_DEBUG, "%s %s", format_hash(s, (uchar*)hash), format_hash(t, &((uchar*)hash)[32]));
}

#define printpfx(n,h) \
	printf("%s%11s%s: %s\n", CL_CYN, n, CL_N, format_hash(s, (uint8_t*) h))

void print_hash_tests(void)
{
	uchar *scratchbuf = NULL;
	char hash[128], s[80];
	char buf[192] = { 0 };
        int algo;
	scratchbuf = (uchar*) calloc(128, 1024);

	printf(CL_WHT "CPU HASH ON EMPTY BUFFER RESULTS:" CL_N "\n\n");

	//buf[0] = 1; buf[64] = 2; // for endian tests
   for ( algo=0; algo < ALGO_COUNT; algo++ )
   {
      exec_hash_function( algo, &hash[0], &buf[0] );
      printpfx( algo_names[algo], hash );
   }

	printf("\n");

	free(scratchbuf);
}

