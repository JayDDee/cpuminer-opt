/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Route table for the REST API. docs/api-rest.md section 6 is the authority
 * for paths, verbs, privileges and schemas.
 *
 * The capability list in GET /api/v1/ is derived from this table at runtime,
 * so it cannot drift from what is actually routed.
 */

#ifndef API_ROUTES_H
#define API_ROUTES_H

#include "api_http.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Per-connection context handed to the handlers as `ctx`.
 *
 * quit_requested exists so /quit cannot shut the miner down before its own
 * response has been written: the handler only sets the flag, and the caller
 * acts on it after api_http_serve() has returned, i.e. after the 200 is on the
 * wire. That ordering is part of the contract (docs/api-rest.md section 6.10). */
typedef struct {
	bool quit_requested;
} api_ctx;

/* The table, and its length. */
const api_route *api_routes_get(size_t *count);

/* Serialized "miner" object for the transport's error envelope. Caller frees. */
char *api_routes_miner_json_str(void);

#ifdef __cplusplus
}
#endif

#endif /* API_ROUTES_H */
