/*
 * Copyright 2014 ccminer team
 *
 * Implementation by tpruvot (based on cgminer)
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#define APIVERSION "1.0"

#ifdef WIN32
# define  _WINSOCK_DEPRECATED_NO_WARNINGS
# include <winsock2.h>
#endif

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <math.h>
#include <stdarg.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "algo/sha/sha1-hash.h"

#include "miner.h"
#include "api_model.h"
#include "api_http.h"
#include "api_routes.h"
#include "api_control.h"
#include "sysinfos.c"
#ifndef WIN32
# include <errno.h>
# include <sys/socket.h>
# include <netinet/in.h>
# include <arpa/inet.h>
# include <netdb.h>
# define SOCKETTYPE long
# define SOCKETFAIL(a) ((a) < 0)
# define INVSOCK -1 /* INVALID_SOCKET */
# define INVINETADDR -1 /* INADDR_NONE */
# define CLOSESOCKET close
# define SOCKETINIT {}
# define SOCKERRMSG strerror(errno)
#else
# define SOCKETTYPE SOCKET
# define SOCKETFAIL(a) ((a) == SOCKET_ERROR)
# define INVSOCK INVALID_SOCKET
# define INVINETADDR INADDR_NONE
# define CLOSESOCKET closesocket
# define in_addr_t uint32_t
/* winsock reports through WSAGetLastError(), not errno, so there is no useful
 * strerror() here. Only used in ignored-failure debug logs. */
# define SOCKERRMSG "winsock error"
#endif

#define GROUP(g) (toupper(g))
#define PRIVGROUP GROUP('W')
#define NOPRIVGROUP GROUP('R')
#define ISPRIVGROUP(g) (GROUP(g) == PRIVGROUP)
#define GROUPOFFSET(g) (GROUP(g) - GROUP('A'))
#define VALIDGROUP(g) (GROUP(g) >= GROUP('A') && GROUP(g) <= GROUP('Z'))
#define COMMANDS(g) (apigroups[GROUPOFFSET(g)].commands)
#define DEFINEDGROUP(g) (ISPRIVGROUP(g) || COMMANDS(g) != NULL)
struct APIGROUPS {
	// This becomes a string like: "|cmd1|cmd2|cmd3|" so it's quick to search
	char *commands;
} apigroups['Z' - 'A' + 1]; // only A=0 to Z=25 (R: noprivs, W: allprivs)

struct IP4ACCESS {
	in_addr_t ip;
	in_addr_t mask;
	char group;
};

static int ips = 1;
static struct IP4ACCESS *ipaccess = NULL;

// Socket data buffers
#define MYBUFSIZ	16384
#define SOCK_REC_BUFSZ	1024

// Socket is on 127.0.0.1
#define QUEUE	10

#define ALLIP4 "0.0.0.0"

static const char *localaddr = "127.0.0.1";
static const char *UNAVAILABLE = " - API will not be available";
static char *buffer = NULL;
static time_t startup = 0;
static int bye = 0;

/* NOT an allow-list despite the name: --api-bind stores one IP here and it
 * serves as both the bind address and the whole access list, so
 *   0.0.0.0:P  allows everyone, <addr>:P allows ONLY <addr>, absent = 127.0.0.1.
 * The cgminer list syntax setup_ipaccess() parses is unreachable. ccminer's
 * --api-allow is a different thing. */
extern char *opt_api_allow;
extern int opt_api_listen; /* port */
extern int opt_api_remote;
extern double global_hashrate;
//extern uint32_t accepted_count;
//extern uint32_t rejected_count;
//extern uint32_t solved_count;

#define cpu_threads opt_n_threads

/* No USE_MONITORING gate here: the temp/fan/clock reads live in api_model.c,
 * where a #define in this file cannot reach them. */
extern float cpu_temp(int);
extern uint32_t cpu_clock(int);

/***************************************************************/

static void cpustatus(int thr_id)
{
   struct api_thread_snapshot t;
   char buf[512]; *buf = '\0';

   if ( !api_collect_thread( thr_id, &t ) )
      return;
   api_format_thread_binary( buf, sizeof(buf), &t );
   // append to buffer
   strcat( buffer, buf );
}

/*****************************************************************************/

/**
* Returns miner global infos
*/
static char *getsummary( char *params )
{
   struct api_summary_snapshot s;

   api_collect_summary( &s );
   *buffer = '\0';
   api_format_summary_binary( buffer, MYBUFSIZ, &s );
   return buffer;
}

/**
 * Returns cpu/thread specific stats
 */
static char *getthreads(char *params)
{
	*buffer = '\0';
	for (int i = 0; i < opt_n_threads; i++)
		cpustatus(i);
	return buffer;
}

/**
 * Is remote control allowed ?
 */
static bool check_remote_access(void)
{
	return (opt_api_remote > 0);
}

/**
 * Change pool url (see --url parameter)
 * seturl|stratum+tcp://user:pass@host:port|
 *
 * Note: the argument reaches parse_arg('o'), which exits the process on an
 * unrecognised scheme or a url with no host. POST /api/v1/pools/url validates
 * before calling it; this command does not.
 */
extern bool stratum_need_reset;
static char *remote_seturl(char *params)
{
	*buffer = '\0';
	if (!check_remote_access())
		return buffer;
	parse_arg('o', params);
	stratum_need_reset = true;
	sprintf(buffer, "%s", "ok|");
	return buffer;
}

/*-hash*
 * Ask the miner to quit
 */
static char *remote_quit(char *params)
{
	*buffer = '\0';
	if (!check_remote_access())
		return buffer;
	bye = 1;
	sprintf(buffer, "%s", "bye|");
	return buffer;
}

static char *gethelp(char *params);
struct CMDS {
	const char *name;
	char *(*func)(char *);
} cmds[] = {
	{ "summary", getsummary },
	{ "threads", getthreads },
	/* remote functions */
	{ "seturl", remote_seturl },
	{ "quit",    remote_quit },
	/* keep it the last */
	{ "help",    gethelp },
};
#define CMDMAX ARRAY_SIZE(cmds)

static char *gethelp(char *params)
{
	*buffer = '\0';
	char * p = buffer;
	for (int i = 0; i < CMDMAX-1; i++)
		p += sprintf(p, "%s\n", cmds[i].name);
	sprintf(p, "|");
	return buffer;
}


static int send_result(SOCKETTYPE c, char *result)
{
	int n;
	if (!result) {
		n = (int) send(c, "", 1, 0);
	} else {
		// ignore failure - it's closed immediately anyway
		n = (int) send(c, result, (int) strlen(result) + 1, 0);
	}
	return n;
}

/* ---- Base64 Encoding/Decoding Table --- */
static const char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static size_t base64_encode(const uchar *indata, size_t insize, char *outptr, size_t outlen)
{
	uchar ibuf[3];
	uchar obuf[4];
	int i, inputparts, inlen = (int) insize;
	size_t len = 0;
	char *output, *outbuf;

	memset(outptr, 0, outlen);

	outbuf = output = (char*)calloc(1, inlen * 4 / 3 + 4);
	if (outbuf == NULL) {
		/* 0, not -1: the return type is size_t, so -1 was SIZE_MAX -- a
		 * "success" of absurd length to any caller that checked. */
		return 0;
	}

	while (inlen > 0) {
		for (i = inputparts = 0; i < 3; i++) {
			if (inlen  > 0) {
				inputparts++;
				ibuf[i] = (uchar) *indata;
				indata++; inlen--;
			}
			else
				ibuf[i] = 0;
		}

		obuf[0] = (uchar)  ((ibuf[0] & 0xFC) >> 2);
		obuf[1] = (uchar) (((ibuf[0] & 0x03) << 4) | ((ibuf[1] & 0xF0) >> 4));
		obuf[2] = (uchar) (((ibuf[1] & 0x0F) << 2) | ((ibuf[2] & 0xC0) >> 6));
		obuf[3] = (uchar)   (ibuf[2] & 0x3F);

		switch(inputparts) {
		case 1: /* only one byte read */
			snprintf(output, 5, "%c%c==",
				table64[obuf[0]],
				table64[obuf[1]]);
			break;
		case 2: /* two bytes read */
			snprintf(output, 5, "%c%c%c=",
				table64[obuf[0]],
				table64[obuf[1]],
				table64[obuf[2]]);
			break;
		default:
			snprintf(output, 5, "%c%c%c%c",
				table64[obuf[0]],
				table64[obuf[1]],
				table64[obuf[2]],
				table64[obuf[3]] );
			break;
		}
		if ((len+4) > outlen)
			break;
		output += 4; len += 4;
	}
	/* The size argument is the DESTINATION size, not the encoded length --
	 * passing the latter truncated the final character on every call. */
	len = snprintf(outptr, outlen, "%s", outbuf);
	free(outbuf);

	return len;
}

/* SHA-1 for the WebSocket handshake, RFC 3174. Not redundant: sph_sha1_full()
 * fails the FIPS 180-1 vectors, which made Sec-WebSocket-Accept wrong. api.c
 * is its only caller and no mining path uses SHA-1, so replace the call here
 * rather than touch a vendored primitive. Once per connection; speed is
 * irrelevant. */
static void api_sha1( uchar out[20], const void *msg, size_t len )
{
	uint32_t h[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
	const uchar *m = (const uchar*) msg;
	uint64_t bits = (uint64_t) len * 8;
	size_t total = len + 1 + 8;
	size_t padded = ((total + 63) / 64) * 64;
	uchar *buf = (uchar*) calloc( 1, padded );
	if ( !buf ) { memset( out, 0, 20 ); return; }

	memcpy( buf, m, len );
	buf[len] = 0x80;
	for ( int i = 0; i < 8; i++ )
		buf[padded - 1 - i] = (uchar) ( bits >> (8 * i) );

	for ( size_t off = 0; off < padded; off += 64 )
	{
		uint32_t w[80], a, b, c, d, e;
		for ( int i = 0; i < 16; i++ )
			w[i] = ( (uint32_t)buf[off + i*4    ] << 24 )
			     | ( (uint32_t)buf[off + i*4 + 1] << 16 )
			     | ( (uint32_t)buf[off + i*4 + 2] <<  8 )
			     |   (uint32_t)buf[off + i*4 + 3];
		for ( int i = 16; i < 80; i++ )
		{
			uint32_t v = w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16];
			w[i] = ( v << 1 ) | ( v >> 31 );
		}
		a = h[0]; b = h[1]; c = h[2]; d = h[3]; e = h[4];
		for ( int i = 0; i < 80; i++ )
		{
			uint32_t f, k;
			if      ( i < 20 ) { f = (b & c) | (~b & d);            k = 0x5A827999; }
			else if ( i < 40 ) { f = b ^ c ^ d;                     k = 0x6ED9EBA1; }
			else if ( i < 60 ) { f = (b & c) | (b & d) | (c & d);   k = 0x8F1BBCDC; }
			else               { f = b ^ c ^ d;                     k = 0xCA62C1D6; }
			uint32_t t = ( (a << 5) | (a >> 27) ) + f + e + k + w[i];
			e = d; d = c; c = ( b << 30 ) | ( b >> 2 ); b = a; a = t;
		}
		h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
	}
	free( buf );

	for ( int i = 0; i < 5; i++ )
	{
		out[i*4    ] = (uchar) ( h[i] >> 24 );
		out[i*4 + 1] = (uchar) ( h[i] >> 16 );
		out[i*4 + 2] = (uchar) ( h[i] >>  8 );
		out[i*4 + 3] = (uchar)   h[i];
	}
}

/* websocket handshake (tested in Chrome) */
static int websocket_handshake(SOCKETTYPE c, char *result, char *clientkey)
{
	char answer[256];
	char inpkey[128] = { 0 };
	char seckey[64];
	uchar sha1[20];

	if (opt_protocol)
		applog(LOG_DEBUG, "clientkey: %s", clientkey);

	/* clientkey is the client's Sec-WebSocket-Key, so it must be bounded. A
	 * truncated key would hash to the wrong accept value, so fail instead. */
	if (snprintf(inpkey, sizeof(inpkey),
	             "%s258EAFA5-E914-47DA-95CA-C5AB0DC85B11", clientkey)
	    >= (int) sizeof(inpkey))
		return -1;

	// SHA-1 test from rfc, returns in base64 "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
	//sprintf(inpkey, "dGhlIHNhbXBsZSBub25jZQ==258EAFA5-E914-47DA-95CA-C5AB0DC85B11");

   api_sha1( sha1, inpkey, strlen(inpkey) );

	base64_encode(sha1, 20, seckey, sizeof(seckey));

	sprintf(answer,
		"HTTP/1.1 101 Switching Protocol\r\n"
		"Upgrade: WebSocket\r\nConnection: Upgrade\r\n"
		"Sec-WebSocket-Accept: %s\r\n"
		"Sec-WebSocket-Protocol: text\r\n"
		"\r\n", seckey);

	// data result as tcp frame

	uchar hd[10] = { 0 };
	hd[0] = 129; // 0x1 text frame (FIN + opcode)
	uint64_t datalen = (uint64_t) strlen(result);
	uint8_t frames = 2;
	if (datalen <= 125) {
		hd[1] = (uchar) (datalen);
	} else if (datalen <= 65535) {
		hd[1] = (uchar) 126;
		hd[2] = (uchar) (datalen >> 8);
		hd[3] = (uchar) (datalen);
		frames = 4;
	} else {
		hd[1] = (uchar) 127;
		hd[2] = (uchar) (datalen >> 56);
		hd[3] = (uchar) (datalen >> 48);
		hd[4] = (uchar) (datalen >> 40);
		hd[5] = (uchar) (datalen >> 32);
		hd[6] = (uchar) (datalen >> 24);
		hd[7] = (uchar) (datalen >> 16);
		hd[8] = (uchar) (datalen >> 8);
		hd[9] = (uchar) (datalen);
		frames = 10;
	}

	size_t handlen = strlen(answer);
	uchar *data = (uchar*) calloc(1, handlen + frames + (size_t) datalen + 1);
	if (data == NULL)
		return -1;
	else {
		uchar *p = data;
		// HTTP header 101
		memcpy(p, answer, handlen);
		p += handlen;
		// WebSocket Frame - Header + Data
		memcpy(p, hd, frames);
		memcpy(p + frames, result, (size_t)datalen);
		/* Header + payload, nothing more: sending one byte past the payload
		 * appends the calloc'd NUL and corrupts a following frame. */
		send(c, (const char*)data, (int) (handlen + frames + (size_t)datalen), 0);
		free(data);
	}
	return 0;
}

/*
 * N.B. IP4 addresses are by Definition 32bit big endian on all platforms
 */
static void setup_ipaccess()
{
	char *buf = NULL, *ptr, *comma, *slash, *dot;
	int ipcount, mask, octet, i;
	char group;

	buf = (char*) calloc(1, strlen(opt_api_allow) + 1);
	if (unlikely(!buf))
		proper_exit(1);//, "Failed to malloc ipaccess buf");

	strcpy(buf, opt_api_allow);
	ipcount = 1;
	ptr = buf;
	while (*ptr) if (*(ptr++) == ',')
		ipcount++;

	// possibly more than needed, but never less
	ipaccess = (struct IP4ACCESS *) calloc(ipcount, sizeof(struct IP4ACCESS));
	if (unlikely(!ipaccess))
		proper_exit(1);//, "Failed to calloc ipaccess");

	ips = 0;
	ptr = buf;
	while (ptr && *ptr) {
		while (*ptr == ' ' || *ptr == '\t')
			ptr++;

		if (*ptr == ',') {
			ptr++;
			continue;
		}

		comma = strchr(ptr, ',');
		if (comma)
			*(comma++) = '\0';

		group = NOPRIVGROUP;

		if (isalpha(*ptr) && *(ptr+1) == ':') {
			if (DEFINEDGROUP(*ptr))
				group = GROUP(*ptr);
			ptr += 2;
		}

		ipaccess[ips].group = group;

		if (strcmp(ptr, ALLIP4) == 0)
			ipaccess[ips].ip = ipaccess[ips].mask = 0;
		else
		{
			slash = strchr(ptr, '/');
			if (!slash)
				ipaccess[ips].mask = 0xffffffff;
			else {
				*(slash++) = '\0';
				mask = atoi(slash);
				if (mask < 1 || mask > 32)
					goto popipo; // skip invalid/zero

				ipaccess[ips].mask = 0;
				while (mask-- >= 0) {
					octet = 1 << (mask % 8);
					ipaccess[ips].mask |= (octet << (24 - (8 * (mask >> 3))));
				}
			}

			ipaccess[ips].ip = 0; // missing default to '.0'
			for (i = 0; ptr && (i < 4); i++) {
				dot = strchr(ptr, '.');
				if (dot)
					*(dot++) = '\0';
				octet = atoi(ptr);

				if (octet < 0 || octet > 0xff)
					goto popipo; // skip invalid

				ipaccess[ips].ip |= (octet << (24 - (i * 8)));

				ptr = dot;
			}

			ipaccess[ips].ip &= ipaccess[ips].mask;
		}

		ips++;
popipo:
		ptr = comma;
	}

	free(buf);
}

static bool check_connect(struct sockaddr_in *cli, char **connectaddr, char *group)
{
	bool addrok = false;

	*connectaddr = inet_ntoa(cli->sin_addr);

	*group = NOPRIVGROUP;
	if (opt_api_allow) {
		int client_ip = htonl(cli->sin_addr.s_addr);
		for (int i = 0; i < ips; i++) {
			if ((client_ip & ipaccess[i].mask) == ipaccess[i].ip) {
				addrok = true;
				*group = ipaccess[i].group;
				break;
			}
		}
	}
	else
		addrok = (strcmp(*connectaddr, localaddr) == 0);

	return addrok;
}

/* Bound a stalled client on an ACCEPTED socket, not the listener: the API is
 * one thread on a blocking accept(), so a silent peer stalls everyone. Failure
 * is non-fatal, leaving the old unbounded behaviour. */
static void set_sock_timeouts(SOCKETTYPE sock)
{
#ifdef WIN32
	DWORD tv = API_HTTP_SOCK_TIMEOUT_S * 1000;   /* winsock wants milliseconds */
#else
	struct timeval tv;
	tv.tv_sec  = API_HTTP_SOCK_TIMEOUT_S;
	tv.tv_usec = 0;
#endif
	if (SOCKETFAIL(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)(&tv), sizeof(tv))))
		applog(LOG_DEBUG, "API setsockopt SO_RCVTIMEO failed (ignored): %s", SOCKERRMSG);
	if (SOCKETFAIL(setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)(&tv), sizeof(tv))))
		applog(LOG_DEBUG, "API setsockopt SO_SNDTIMEO failed (ignored): %s", SOCKERRMSG);
}

/* ---- REST dispatch (docs/api-rest.md section 2) ------------------------- */

static bool api_mode_serves_http(void)
{
	return opt_api_mode == API_MODE_HTTP || opt_api_mode == API_MODE_BOTH;
}

/* A request line starting with a known method: a superset of the old `GET /`
 * sniff, so `both` mode cannot misroute a POST. Tests the method rather than
 * "HTTP/" so misdetection fails closed. */
static bool api_request_is_http(const char *buf, int len)
{
	static const char *verbs[] = {
		"GET ", "POST ", "HEAD ", "OPTIONS ", "PUT ", "DELETE ", "PATCH "
	};
	for (size_t i = 0; i < ARRAY_SIZE(verbs); i++) {
		int l = (int) strlen(verbs[i]);
		if (len >= l && strncmp(buf, verbs[i], l) == 0)
			return true;
	}
	return false;
}

/* The WebSocket upgrade goes to the legacy handler in EVERY mode, so
 * api/websocket.htm keeps working. It is HTTP-shaped, so it must be excluded
 * explicitly, before the REST router claims it. */
static bool api_request_is_ws_upgrade(const char *buf, int len)
{
	char tmp[SOCK_REC_BUFSZ + 1];
	int n = len < SOCK_REC_BUFSZ ? len : SOCK_REC_BUFSZ;
	if (n < 0) return false;
	memcpy(tmp, buf, (size_t) n);
	tmp[n] = '\0';
	return strstr(tmp, "Sec-WebSocket-Key") != NULL;
}

/* Exact-match --api-token check for a WebSocket upgrade.
 *
 * A substring test on "Bearer <token>" would accept "Bearer <token>EXTRA", which
 * the REST router refuses (api_http.c compares the parsed value), so the header
 * is parsed and the value compared. An over-long value is refused rather than
 * compared truncated. */
static bool api_ws_token_ok(const char *buf, int len)
{
	char tmp[SOCK_REC_BUFSZ + 1];
	int n = len < SOCK_REC_BUFSZ ? len : SOCK_REC_BUFSZ;
	const char *p;

	if (!opt_api_token || !*opt_api_token)
		return true;
	if (n < 0) return false;

	memcpy(tmp, buf, (size_t) n);
	tmp[n] = '\0';

	for (p = tmp; *p; ) {
		const char *eol = strpbrk(p, "\r\n");
		size_t llen = eol ? (size_t) (eol - p) : strlen(p);

		if (llen > 14 && strncasecmp(p, "Authorization:", 14) == 0) {
			const char *v = p + 14;
			size_t vlen;
			char val[288];

			while (v < p + llen && (*v == ' ' || *v == '\t')) v++;
			vlen = (size_t) (p + llen - v);
			if (vlen <= 7 || strncasecmp(v, "Bearer ", 7) != 0)
				return false;
			v += 7; vlen -= 7;
			while (vlen && (*v == ' ' || *v == '\t')) { v++; vlen--; }
			while (vlen && (v[vlen-1] == ' ' || v[vlen-1] == '\t')) vlen--;
			if (vlen >= sizeof(val))
				return false;          /* absurd length: refuse, never truncate */
			memcpy(val, v, vlen);
			val[vlen] = '\0';
			return strcmp(val, opt_api_token) == 0;
		}
		p = eol ? eol + 1 : p + llen;
	}
	return false;
}

/* A refused upgrade answers: silence is indistinguishable from a network stall,
 * and this port already answers 401 for a missing REST token (contract 4). */
static void api_send_early_error(SOCKETTYPE c, int status, const char *msg)
{
	api_http_config cfg;
	char *body;

	memset(&cfg, 0, sizeof(cfg));
	cfg.token = opt_api_token;
	cfg.cors = opt_api_cors != NULL;

	body = api_http_error_body(&cfg, status, msg);
	if (!body)
		return;
	api_http_send((int) c, status, NULL, body, strlen(body), &cfg);
	free(body);
}


static void api_serve_http(SOCKETTYPE c, const char *prefix, size_t prefixlen)
{
	api_http_config cfg;
	api_ctx ctx;
	size_t nroutes = 0;
	const api_route *routes = api_routes_get(&nroutes);
	char *miner_json = api_routes_miner_json_str();

	memset(&cfg, 0, sizeof(cfg));
	memset(&ctx, 0, sizeof(ctx));
	cfg.token = opt_api_token;
	cfg.cors  = opt_api_cors != NULL;
	/* The write gate is --api-remote, not the group letter: opt_api_allow is
	 * the bind address here despite its name, so the group machinery it feeds
	 * is vestigial (docs/api-rest.md section 10). */
	/* --api-control promotes a write-privileged source to control, so the
	 * control verbs need BOTH flags. Without --api-control the transport
	 * answers 403 before the handler runs (docs/api-rest.md section 4). */
	cfg.control_enabled = api_ctl_enabled();
	cfg.granted = opt_api_remote
	              ? ( cfg.control_enabled ? API_PRIV_CONTROL : API_PRIV_WRITE )
	              : API_PRIV_READ;
	cfg.miner_json = miner_json;

	api_http_serve_prefixed((int) c, prefix, prefixlen, routes, nroutes,
		&ctx, &cfg);

	free(miner_json);

	/* /quit only sets a flag, so its 200 is on the wire before the miner is
	 * told to stop (docs/api-rest.md section 6.10). */
	if (ctx.quit_requested)
		bye = 1;
}

/* Extra listener for --api-http-port, kept separate from the main bind block
 * below and its 61-second retry loop. INVSOCK on failure: keep mining on the
 * single sniffing port rather than refuse to start. */
static SOCKETTYPE open_extra_listener(const char *addr, unsigned short port)
{
	struct sockaddr_in serv;
	SOCKETTYPE s = socket(AF_INET, SOCK_STREAM, 0);
	int optval = 1;

	if (s == INVSOCK)
		return INVSOCK;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(addr);
	serv.sin_port = htons(port);
#ifndef WIN32
	setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void *)(&optval), sizeof(optval));
#endif
	if (SOCKETFAIL(bind(s, (struct sockaddr *)(&serv), sizeof(serv)))
	 || SOCKETFAIL(listen(s, QUEUE))) {
		applog(LOG_WARNING, "REST API port %d unavailable (%s) - "
			"falling back to protocol sniffing on port %d",
			port, strerror(errno), (int) opt_api_listen);
		CLOSESOCKET(s);
		return INVSOCK;
	}
	return s;
}

static void api()
{
	const char *addr = opt_api_allow;
	unsigned short port = (unsigned short) opt_api_listen; // 4048
	char buf[MYBUFSIZ];
	int c, n, bound;
	char *connectaddr;
	char *binderror;
	char group;
	time_t bindstart;
	struct sockaddr_in serv;
	struct sockaddr_in cli;
	uint32_t clisiz;
	bool addrok = false;
	long long counter;
	char *result;
	char *params;
	int i;
	bool serve_http = false;

	SOCKETTYPE *apisock;
	/* Optional HTTP-only listener (--api-http-port), and whichever of the two
	 * a given connection arrived on. */
	SOCKETTYPE httpsock = INVSOCK;
	SOCKETTYPE listener;
	if (!opt_api_listen && opt_debug) {
		applog(LOG_DEBUG, "API disabled");
		return;
	}

	if (opt_api_allow) {
		setup_ipaccess();
		if (ips == 0) {
			applog(LOG_WARNING, "API not running (no valid IPs specified)%s", UNAVAILABLE);
		}
		/* A specific bind address is also the only one accepted, which reads
		 * as a dead API from every other host. */
		else if (strcmp(opt_api_allow, ALLIP4) != 0
		         && strcmp(opt_api_allow, localaddr) != 0) {
			applog(LOG_WARNING, "API bound to %s, which is also the only "
			                    "address accepted -- use --api-bind 0.0.0.0:%d "
			                    "to accept the network", opt_api_allow,
			                    (int) opt_api_listen);
		}
	}

	apisock = (SOCKETTYPE*) calloc(1, sizeof(*apisock));
	*apisock = INVSOCK;

	sleep(1);

	*apisock = socket(AF_INET, SOCK_STREAM, 0);
	if (*apisock == INVSOCK) {
		applog(LOG_ERR, "API initialisation failed (%s)%s", strerror(errno), UNAVAILABLE);
		return;
	}

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = inet_addr(addr);
	if (serv.sin_addr.s_addr == (in_addr_t)INVINETADDR) {
		applog(LOG_ERR, "API initialisation 2 failed (%s)%s", strerror(errno), UNAVAILABLE);
		return;
	}

	serv.sin_port = htons(port);

#ifndef WIN32
	// On linux with SO_REUSEADDR, bind will get the port if the previous
	// socket is closed (even if it is still in TIME_WAIT) but fail if
	// another program has it open - which is what we want
	int optval = 1;
	// If it doesn't work, we don't really care - just show a debug message
	if (SOCKETFAIL(setsockopt(*apisock, SOL_SOCKET, SO_REUSEADDR, (void *)(&optval), sizeof(optval))))
	        applog(LOG_DEBUG, "API setsockopt SO_REUSEADDR failed (ignored): %s", SOCKERRMSG);
#else
	// On windows a 2nd program can bind to a port>1024 already in use unless
	// SO_EXCLUSIVEADDRUSE is used - however then the bind to a closed port
	// in TIME_WAIT will fail until the timeout - so we leave the options alone
#endif

	// try for 1 minute ... in case the old one hasn't completely gone yet
	bound = 0;
	bindstart = time(NULL);
	while (bound == 0) {
		if (bind(*apisock, (struct sockaddr *)(&serv), sizeof(serv)) < 0) {
			binderror = strerror(errno);
			if ((time(NULL) - bindstart) > 61)
				break;
			else {
				if (!opt_quiet || opt_debug)
					applog(LOG_WARNING, "API bind to port %d failed - trying again in 20sec", port);
				sleep(20);
			}
		}
		else
			bound = 1;
	}

	if (bound == 0) {
		applog(LOG_WARNING, "API bind to port %d failed (%s)%s", port, binderror, UNAVAILABLE);
		free(apisock);
		return;
	}

	if (SOCKETFAIL(listen(*apisock, QUEUE))) {
		applog(LOG_ERR, "API initialisation 3 failed (%s)%s", strerror(errno), UNAVAILABLE);
		CLOSESOCKET(*apisock);
		free(apisock);
		return;
	}

	buffer = (char *) calloc(1, MYBUFSIZ + 1);

	/* A second listener that speaks HTTP and nothing else, so a deployment
	 * need not rely on sniffing. Only meaningful in `both` mode: in `http`
	 * mode the main port is already HTTP-only. */
	if (opt_api_http_port && opt_api_mode == API_MODE_BOTH)
		httpsock = open_extra_listener(addr, (unsigned short) opt_api_http_port);

	if (api_mode_serves_http()) {
		applog(LOG_INFO, "REST API on http://%s:%d/api/v1/ (%s)", addr,
			httpsock != INVSOCK ? opt_api_http_port : (int) port,
			opt_api_token ? "token" : "no token");
		/* The token is the only thing in front of /quit once --api-remote
		 * is on, so say it out loud. */
		if (opt_api_remote && !opt_api_token)
			applog(LOG_WARNING, "REST API write access (--api-remote) is enabled "
				"without --api-token");
	} else if (opt_api_token || opt_api_cors || opt_api_http_port) {
		applog(LOG_WARNING, "--api-token/--api-cors/--api-http-port ignored: "
			"--api-mode is binary");
	}

	counter = 0;
	while (bye == 0) {
		bool http_only = false;
		bool answered  = false;   /* the REST layer already replied */
		counter++;

		if (httpsock != INVSOCK) {
			/* Two listeners, one thread: wait on both rather than block on
			 * one while the other has a client queued. */
			fd_set rd;
			SOCKETTYPE hi = *apisock > httpsock ? *apisock : httpsock;
			FD_ZERO(&rd);
			FD_SET((int)*apisock, &rd);
			FD_SET((int)httpsock, &rd);
			if (select((int)hi + 1, &rd, NULL, NULL, NULL) < 0) {
				if (errno == EINTR)
					continue;
				applog(LOG_ERR, "API select failed (%s)%s", strerror(errno),
					UNAVAILABLE);
				break;
			}
			listener = FD_ISSET((int)httpsock, &rd) ? httpsock : *apisock;
			http_only = ( listener == httpsock );
		}
		else
			listener = *apisock;

		clisiz = sizeof(cli);
		if (SOCKETFAIL(c = accept((SOCKETTYPE)listener, (struct sockaddr *)(&cli), &clisiz))) {
			applog(LOG_ERR, "API failed (%s)%s", strerror(errno), UNAVAILABLE);
			CLOSESOCKET(*apisock);
			if (httpsock != INVSOCK) CLOSESOCKET(httpsock);
			free(apisock);
			free(buffer);
			return;
		}

		set_sock_timeouts(c);

		addrok = check_connect(&cli, &connectaddr, &group);
		if (opt_debug && opt_protocol)
			applog(LOG_DEBUG, "API: connection from %s - %s",
				connectaddr, addrok ? "Accepted" : "Ignored");

		if (addrok) {
			bool fail;
			char *wskey = NULL;
			n = recv(c, &buf[0], SOCK_REC_BUFSZ, 0);

			fail = SOCKETFAIL(n);
			if (fail)
				buf[0] = '\0';
			if (n >= 0)
				buf[n] = '\0';

			/* Decided on the RAW bytes, before anything else touches them.
			 * --api-http-port moves REST to its own listener and the main port
			 * goes back to binary: "instead of", not "as well as" (section 2). */
			serve_http = !fail && n > 0
			           && ( http_only
			                || ( api_mode_serves_http() && httpsock == INVSOCK ) )
			           && api_request_is_http(buf, n)
			           && !api_request_is_ws_upgrade(buf, n);

			if (serve_http) {
				api_serve_http(c, buf, (size_t) n);
					answered = true;
			}
			/* On an http-only port a binary command is a client error: answer
			 * 400 rather than run it. WebSocket upgrades are exempt in every
			 * mode, being a third protocol. */
			else if (!fail && n > 0
			      && !api_request_is_ws_upgrade(buf, n)
			      && ( http_only
			           || ( opt_api_mode == API_MODE_HTTP && httpsock == INVSOCK ) )) {
				static const char body[] =
					"{\"error\":{\"code\":\"bad_request\",\"message\":"
					"\"this port speaks HTTP only (--api-mode)\",\"status\":400}}";
				api_http_send((int) c, 400, NULL, body, sizeof(body) - 1, NULL);
					answered = true;
			}

			if (!fail && !answered && n > 0 && buf[n-1] == '\n') {
				/* telnet compat. Must run AFTER the dispatch above: it would
				 * eat the "\r\n\r\n" ending an HTTP header block, and the
				 * parser then waits forever -- GET hangs, POST with a body
				 * does not. */
				buf[n-1] = '\0'; n--;
				if (n > 0 && buf[n-1] == '\r')
					buf[n-1] = '\0';
				buf[n] = '\0';
			}

			//if (opt_debug && opt_protocol && n > 0)
			//	applog(LOG_DEBUG, "API: recv command: (%d) '%s'+char(%x)", n, buf, buf[n-1]);

			if (!fail && !answered) {
				char *msg = NULL;
				/* Websocket compat runs a command lifted from the URL through the
				 * legacy table, so `GET /quit` executes `quit` without reaching
				 * the REST router's privilege or token check -- --api-token has
				 * to cover it (section 4). Checked on the RAW buffer, before the
				 * block below rewrites it. Upgrades only: a plain `summary|` is
				 * the legacy protocol, which --api-mode leaves unchanged in
				 * `binary` and `both`. */
				if (n > 0 && api_request_is_ws_upgrade(buf, n)
				    && !api_ws_token_ok(buf, n)) {
					applog(LOG_WARNING, "API: websocket upgrade from %s refused"
						" (missing or invalid token)", connectaddr);
					api_send_early_error(c, 401, "missing or invalid token");
					buf[0] = '\0';
					n = 0;
					answered = true;
				}

				if ((msg = strstr(buf, "GET /")) && strlen(msg) > 5) {
					char cmd[256] = { 0 };
					sscanf(&msg[5], "%s\n", cmd);
					params = strchr(cmd, '/');
					if (params)
						*(params++) = '|';
					params = strchr(cmd, '/');
					if (params)
						*(params++) = '\0';
					wskey = strstr(msg, "Sec-WebSocket-Key");
					if (wskey) {
						char *eol = strchr(wskey, '\r');
						if (eol) *eol = '\0';
						wskey = strchr(wskey, ':');
						wskey++;
						while ((*wskey) == ' ') wskey++; // ltrim
					}
					n = sprintf(buf, "%s", cmd);
				}

				params = strchr(buf, '|');
				if (params != NULL)
					*(params++) = '\0';

				if (opt_debug && opt_protocol && n > 0)
					applog(LOG_DEBUG, "API: exec command %s(%s)", buf, params);

				bool matched = false;
				for (i = 0; i < CMDMAX; i++) {
					if (strcmp(buf, cmds[i].name) == 0 && strlen(buf)) {
						if (params && strlen(params)) {
							// remove possible trailing |
							if (params[strlen(params) - 1] == '|')
								params[strlen(params) - 1] = '\0';
						}
						matched = true;
						result = (cmds[i].func)(params);
						if (wskey) {
							websocket_handshake(c, result, wskey);
							break;
						}
						send_result(c, result);
						break;
					}
				}

				/* Silence here is indistinguishable from a stall or a dead miner.
				 * Same string as the sibling miner: one dashboard talks to both.
				 * Not over a WebSocket, which expects a frame, and not when an earlier
				 * gate already answered -- a refused upgrade sends 401 and must not be
				 * followed by a second reply on the same socket. */
				if (!matched && !wskey && !answered)
					send_result(c, (char*) "ERR=unknown command|");
			}
		}

		/* Every path, not just the one that answered: a rejected address or a
		 * failed recv() used to leak the descriptor, and the timeout above
		 * makes a failed recv routine. websocket_handshake() does not close,
		 * so this is exactly one close per accept. */
		CLOSESOCKET(c);
	}

	CLOSESOCKET(*apisock);
	if (httpsock != INVSOCK)
		CLOSESOCKET(httpsock);
	free(apisock);
	free(buffer);
}

/* external access */
void *api_thread(void *userdata)
{
	struct thr_info *mythr = (struct thr_info*)userdata;

	startup = time(NULL);
	api_model_set_start_time(startup);
	api();
	tq_freeze(mythr->q);

	if (bye) {
		// quit command
		proper_exit(1);
	}

	return NULL;
}

