/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * HTTP transport for the REST API — see api_http.h.
 *
 * SHARED FILE — keep byte-identical with the sibling miner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef WIN32
#include <winsock2.h>
#define API_SEND(s, b, n)  send((SOCKET)(s), (b), (int)(n), 0)
#define API_RECV(s, b, n)  recv((SOCKET)(s), (b), (int)(n), 0)
#else
#include <sys/socket.h>
#include <unistd.h>
#define API_SEND(s, b, n)  send((s), (b), (n), 0)
#define API_RECV(s, b, n)  recv((s), (b), (n), 0)
#endif

#include "api_http.h"

/* ------------------------------------------------------------------ helpers */

static int ci_equal(const char *a, const char *b, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		int ca = tolower((unsigned char) a[i]);
		int cb = tolower((unsigned char) b[i]);
		if (ca != cb || !ca)
			return 0;
	}
	return 1;
}

static void copy_bounded(char *dst, size_t dstsz, const char *src, size_t n)
{
	if (!dstsz) return;
	if (n >= dstsz) n = dstsz - 1;
	memcpy(dst, src, n);
	dst[n] = '\0';
}

static const char *skip_ws(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t')) p++;
	return p;
}

static int hexval(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

bool api_http_percent_decode(char *s)
{
	char *o = s;
	for (char *i = s; *i; ) {
		if (*i == '%') {
			int hi = hexval((unsigned char) i[1]);
			int lo = hi < 0 ? -1 : hexval((unsigned char) i[2]);
			if (lo < 0)
				return false;                  /* malformed escape */
			int v = (hi << 4) | lo;
			if (v == 0)
				return false;                  /* %00: never legitimate here */
			*o++ = (char) v;
			i += 3;
		} else {
			*o++ = *i++;
		}
	}
	*o = '\0';
	return true;
}

static api_method method_of(const char *s, size_t n)
{
	if (n == 3 && ci_equal(s, "GET", 3))     return API_M_GET;
	if (n == 4 && ci_equal(s, "HEAD", 4))    return API_M_HEAD;
	if (n == 4 && ci_equal(s, "POST", 4))    return API_M_POST;
	if (n == 7 && ci_equal(s, "OPTIONS", 7)) return API_M_OPTIONS;
	return API_M_OTHER;
}

/* ------------------------------------------------------------------- parser */

api_parse_status api_http_parse(const char *buf, size_t len, api_request *req)
{
	memset(req, 0, sizeof(*req));

	/* find the end of the header block */
	const char *hdr_end = NULL;
	for (size_t i = 0; i + 3 < len; i++) {
		if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
			hdr_end = buf + i + 4;
			break;
		}
	}
	if (!hdr_end) {
		/* Bound the wait: a client that never sends the terminator must not be
		 * able to make us buffer without limit. */
		if (len > API_HTTP_MAX_REQLINE + API_HTTP_MAX_HEADER_BYTES)
			return API_PARSE_TOO_LARGE;
		return API_PARSE_INCOMPLETE;
	}

	const char *eol = memchr(buf, '\r', (size_t)(hdr_end - buf));
	if (!eol)
		return API_PARSE_BAD;
	size_t reqline_len = (size_t)(eol - buf);
	if (reqline_len > API_HTTP_MAX_REQLINE)
		return API_PARSE_TOO_LARGE;

	/* request line: METHOD SP TARGET SP HTTP/x.y */
	const char *sp1 = memchr(buf, ' ', reqline_len);
	if (!sp1)
		return API_PARSE_BAD;
	const char *sp2 = memchr(sp1 + 1, ' ', reqline_len - (size_t)(sp1 + 1 - buf));
	if (!sp2)
		return API_PARSE_BAD;

	copy_bounded(req->raw_method, sizeof(req->raw_method), buf, (size_t)(sp1 - buf));
	req->method = method_of(buf, (size_t)(sp1 - buf));

	const char *target = sp1 + 1;
	size_t target_len = (size_t)(sp2 - target);
	if (!target_len || target[0] != '/')
		return API_PARSE_BAD;

	const char *q = memchr(target, '?', target_len);
	size_t path_len = q ? (size_t)(q - target) : target_len;
	if (path_len >= API_HTTP_MAX_PATH)
		return API_PARSE_TOO_LARGE;
	copy_bounded(req->path, sizeof(req->path), target, path_len);
	if (q) {
		size_t qlen = target_len - path_len - 1;
		if (qlen >= API_HTTP_MAX_QUERY)
			return API_PARSE_TOO_LARGE;
		copy_bounded(req->query, sizeof(req->query), q + 1, qlen);
	}

	if (!api_http_percent_decode(req->path) || !api_http_percent_decode(req->query))
		return API_PARSE_BAD;
	/* "Trailing slashes are tolerated" (docs/api-rest.md section 3). Normalising
	 * here, once, also keeps them from colliding with the prefix-route
	 * convention below, where a pattern ending in '/' means "/{id}". */
	{
		size_t pl = strlen(req->path);
		while (pl > 1 && req->path[pl-1] == '/')
			req->path[--pl] = '\0';
	}
	/* Nothing is served from disk, but a router that accepts ".." invites a
	 * later handler to trust it. */
	if (strstr(req->path, ".."))
		return API_PARSE_BAD;

	if (strstr(req->query, "pretty=1"))
		req->pretty = true;

	/* headers */
	const char *p = eol + 2;
	size_t lines = 0, hdr_bytes = 0;
	while (p < hdr_end - 2) {
		const char *e = memchr(p, '\r', (size_t)(hdr_end - p));
		if (!e)
			return API_PARSE_BAD;
		size_t linelen = (size_t)(e - p);
		hdr_bytes += linelen;
		if (++lines > API_HTTP_MAX_HEADER_LINES || hdr_bytes > API_HTTP_MAX_HEADER_BYTES)
			return API_PARSE_TOO_LARGE;

		const char *colon = memchr(p, ':', linelen);
		if (colon) {
			size_t namelen = (size_t)(colon - p);
			const char *v = skip_ws(colon + 1, e);
			size_t vlen = (size_t)(e - v);

			if (namelen == 14 && ci_equal(p, "Content-Length", 14)) {
				char tmp[32];
				copy_bounded(tmp, sizeof(tmp), v, vlen);
				char *endp = NULL;
				long cl = strtol(tmp, &endp, 10);
				if (!endp || *endp || cl < 0)
					return API_PARSE_BAD;
				req->has_content_length = true;
				req->content_length = (size_t) cl;
			} else if (namelen == 17 && ci_equal(p, "Transfer-Encoding", 17)) {
				if (vlen >= 7 && ci_equal(v, "chunked", 7))
					req->chunked = true;
			} else if (namelen == 13 && ci_equal(p, "Authorization", 13)) {
				if (vlen > 7 && ci_equal(v, "Bearer ", 7)) {
					const char *t = skip_ws(v + 7, e);
					copy_bounded(req->auth_bearer, sizeof(req->auth_bearer), t, (size_t)(e - t));
				}
			} else if (namelen == 6 && ci_equal(p, "Origin", 6)) {
				copy_bounded(req->origin, sizeof(req->origin), v, vlen);
			} else if (namelen == 7 && ci_equal(p, "Upgrade", 7)) {
				if (vlen >= 9 && ci_equal(v, "websocket", 9))
					req->upgrade_websocket = true;
			} else if (namelen == 17 && ci_equal(p, "Sec-WebSocket-Key", 17)) {
				copy_bounded(req->ws_key, sizeof(req->ws_key), v, vlen);
			}
		}
		p = e + 2;
	}

	if (req->chunked)
		return API_PARSE_UNSUPPORTED;      /* 501, never guess at a body */

	/* body */
	size_t have = (size_t)(len - (size_t)(hdr_end - buf));
	if (req->has_content_length) {
		if (req->content_length > API_HTTP_MAX_BODY)
			return API_PARSE_TOO_LARGE;
		if (have < req->content_length)
			return API_PARSE_INCOMPLETE;
		memcpy(req->body, hdr_end, req->content_length);
		req->body[req->content_length] = '\0';
		req->body_len = req->content_length;
	} else if (req->method == API_M_POST) {
		/* A body without Content-Length cannot be delimited without keep-alive
		 * framing, so it is not accepted rather than silently truncated. */
		if (have)
			return API_PARSE_BAD;
	}

	return API_PARSE_OK;
}

/* -------------------------------------------------------------------- routes */

static bool path_matches(const char *pattern, const char *path)
{
	size_t n = strlen(pattern);
	if (n && pattern[n-1] == '/')                 /* prefix route: /pools/{n} */
		return strncmp(pattern, path, n) == 0 && path[n] != '\0';
	return strcmp(pattern, path) == 0;
}

const api_route *api_http_route(const api_route *routes, size_t nroutes,
                                const api_request *req, int *status)
{
	bool path_seen = false;

	for (size_t i = 0; i < nroutes; i++) {
		if (!path_matches(routes[i].path, req->path))
			continue;
		path_seen = true;
		/* HEAD is served by the GET handler; the body is dropped by the writer. */
		api_method m = req->method == API_M_HEAD ? API_M_GET : req->method;
		if (routes[i].method != m)
			continue;
		if (!routes[i].available) {
			*status = 501;
			return NULL;
		}
		*status = 200;
		return &routes[i];
	}

	*status = path_seen ? 405 : 404;
	return NULL;
}

/* ------------------------------------------------------------------ statuses */

const char *api_http_status_text(int status)
{
	switch (status) {
	case 200: return "OK";
	case 202: return "Accepted";
	case 204: return "No Content";
	case 400: return "Bad Request";
	case 401: return "Unauthorized";
	case 403: return "Forbidden";
	case 404: return "Not Found";
	case 405: return "Method Not Allowed";
	case 409: return "Conflict";
	case 413: return "Payload Too Large";
	case 429: return "Too Many Requests";
	case 500: return "Internal Server Error";
	case 501: return "Not Implemented";
	case 503: return "Service Unavailable";
	default:  return "Error";
	}
}

const char *api_http_error_code(int status)
{
	switch (status) {
	case 400: return "bad_request";
	case 401: return "unauthorized";
	case 403: return "forbidden";
	case 404: return "not_found";
	case 405: return "method_not_allowed";
	case 409: return "conflict";
	case 413: return "payload_too_large";
	case 429: return "too_many_requests";
	case 501: return "not_implemented";
	default:  return "internal_error";
	}
}

char *api_http_error_body(const api_http_config *cfg, int status, const char *message)
{
	json_t *root = json_object();
	json_t *err = json_object();
	if (!root || !err) {
		if (root) json_decref(root);
		if (err) json_decref(err);
		return NULL;
	}
	if (cfg && cfg->miner_json) {
		json_error_t e;
		json_t *m = json_loads(cfg->miner_json, 0, &e);
		if (m) json_object_set_new(root, "miner", m);
	}
	json_object_set_new(err, "code", json_string(api_http_error_code(status)));
	json_object_set_new(err, "message", json_string(message ? message : api_http_status_text(status)));
	json_object_set_new(err, "status", json_integer(status));
	json_object_set_new(root, "error", err);

	char *s = json_dumps(root, JSON_COMPACT);
	json_decref(root);
	return s;
}

/* ------------------------------------------------------------------ response */

static int send_all(int sock, const char *buf, size_t len)
{
	size_t sent = 0;
	while (sent < len) {
		int n = API_SEND(sock, buf + sent, len - sent);
		if (n <= 0)
			return -1;              /* the old send_result() ignored this */
		sent += (size_t) n;
	}
	return 0;
}

int api_http_send(int sock, int status, const char *content_type,
                  const char *body, size_t body_len, const api_http_config *cfg)
{
	char head[512];
	int n = snprintf(head, sizeof(head),
		"HTTP/1.1 %d %s\r\n"
		"Content-Type: %s\r\n"
		"Content-Length: %llu\r\n"
		"Connection: close\r\n"
		"Cache-Control: no-store\r\n"
		"X-Content-Type-Options: nosniff\r\n"
		"%s"
		"%s"
		"\r\n",
		status, api_http_status_text(status),
		content_type ? content_type : "application/json; charset=utf-8",
		(unsigned long long) body_len,
		(cfg && cfg->cors) ? "Access-Control-Allow-Origin: *\r\n" : "",
		status == 401 ? "WWW-Authenticate: Bearer\r\n" : "");

	if (n < 0 || (size_t) n >= sizeof(head))
		return -1;
	if (send_all(sock, head, (size_t) n) != 0)
		return -1;
	if (body_len && body)
		return send_all(sock, body, body_len);
	return 0;
}

static int send_error(int sock, int status, const char *msg, const api_http_config *cfg)
{
	char *body = api_http_error_body(cfg, status, msg);
	if (!body) {
		/* json_dumps failed (OOM) — still answer, with a static body. */
		static const char fallback[] =
			"{\"error\":{\"code\":\"internal_error\",\"message\":\"out of memory\",\"status\":500}}";
		api_http_send(sock, 500, NULL, fallback, sizeof(fallback) - 1, cfg);
		return 500;
	}
	api_http_send(sock, status, NULL, body, strlen(body), cfg);
	free(body);
	return status;
}

/* --------------------------------------------------------------------- serve */

int api_http_serve(int sock, const api_route *routes, size_t nroutes,
                   void *ctx, const api_http_config *cfg)
{
	return api_http_serve_prefixed(sock, NULL, 0, routes, nroutes, ctx, cfg);
}

int api_http_serve_prefixed(int sock, const char *prefix, size_t prefixlen,
                            const api_route *routes, size_t nroutes,
                            void *ctx, const api_http_config *cfg)
{
	char buf[API_HTTP_MAX_REQLINE + API_HTTP_MAX_HEADER_BYTES + API_HTTP_MAX_BODY + 8];
	size_t len = 0;
	api_request req;
	api_parse_status st = API_PARSE_INCOMPLETE;

	if (prefix && prefixlen) {
		if (prefixlen > sizeof(buf))
			return send_error(sock, 413, "request too large", cfg);
		memcpy(buf, prefix, prefixlen);
		len = prefixlen;
		st = api_http_parse(buf, len, &req);   /* it may already be complete */
	}

	/* Read until the parser says it has a whole request. A stalled client is
	 * bounded by SO_RCVTIMEO on the accepted socket, set by the caller. */
	while (st == API_PARSE_INCOMPLETE) {
		if (len >= sizeof(buf)) { st = API_PARSE_TOO_LARGE; break; }
		int n = API_RECV(sock, buf + len, sizeof(buf) - len);
		if (n <= 0)
			break;                      /* timeout or peer closed */
		len += (size_t) n;
		st = api_http_parse(buf, len, &req);
		if (st != API_PARSE_INCOMPLETE)
			break;
	}

	switch (st) {
	case API_PARSE_OK:            break;
	case API_PARSE_TOO_LARGE:     return send_error(sock, 413, "request too large", cfg);
	case API_PARSE_UNSUPPORTED:   return send_error(sock, 501, "chunked bodies are not supported", cfg);
	case API_PARSE_BAD:           return send_error(sock, 400, "malformed request", cfg);
	case API_PARSE_INCOMPLETE:    return -1;   /* timeout: close, no response */
	}

	if (req.method == API_M_OPTIONS && cfg && cfg->cors)
		return api_http_send(sock, 204, NULL, NULL, 0, cfg) == 0 ? 204 : -1;

	/* Token first: it is evaluated before routing, so an unauthenticated
	 * client cannot probe which routes exist. */
	if (cfg && cfg->token && *cfg->token) {
		if (strcmp(req.auth_bearer, cfg->token) != 0)
			return send_error(sock, 401, "missing or invalid token", cfg);
	}

	int status = 200;
	const api_route *r = api_http_route(routes, nroutes, &req, &status);
	if (!r)
		return send_error(sock, status,
			status == 501 ? "not implemented on this miner" : NULL, cfg);

	if (cfg) {
		if (r->priv == API_PRIV_CONTROL && !cfg->control_enabled)
			return send_error(sock, 403, "control API disabled (--api-control)", cfg);
		if ((int) r->priv > (int) cfg->granted)
			return send_error(sock, 403, "insufficient privilege", cfg);
	}

	char errmsg[256] = { 0 };

	if (r->text_handler) {
		char *text = NULL;
		status = r->text_handler(&req, ctx, &text, errmsg, sizeof(errmsg));
		if (status >= 400 || !text) {
			free(text);
			return send_error(sock, status >= 400 ? status : 500,
			                  errmsg[0] ? errmsg : NULL, cfg);
		}
		const size_t tlen = strlen(text);
		int rc = api_http_send(sock, status, r->content_type,
		                       req.method == API_M_HEAD ? NULL : text, tlen, cfg);
		free(text);
		return rc == 0 ? status : -1;
	}

	json_t *out = NULL;
	status = r->handler(&req, ctx, &out, errmsg, sizeof(errmsg));

	/* A handler that fails without a body gets the uniform error envelope. One
	 * that supplies its own keeps it: /health answers 503 carrying
	 * {"status":"degraded","reasons":[...]}, which this used to discard.
	 *
	 * Safe because /health is the only handler that returns >= 400 with a body:
	 * every other path leaves *out NULL, ctl_reply() included. Re-audit the route
	 * table if that stops holding. */
	if (status >= 400 && !out)
		return send_error(sock, status, errmsg[0] ? errmsg : NULL, cfg);

	char *body = out ? json_dumps(out, req.pretty ? JSON_INDENT(2) : JSON_COMPACT) : NULL;
	if (out) json_decref(out);
	if (!body)
		return send_error(sock, 500, "serialization failed", cfg);

	/* HEAD: headers only, but with the Content-Length the GET would carry. */
	size_t blen = strlen(body);
	int rc = api_http_send(sock, status, NULL,
	                       req.method == API_M_HEAD ? NULL : body, blen, cfg);
	free(body);
	return rc == 0 ? status : -1;
}
