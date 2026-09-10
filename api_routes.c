/* SPDX-License-Identifier: GPL-3.0-or-later */
/*
 * Route handlers for the REST API - see docs/api-rest.md section 6.
 *
 * Each handler collects a snapshot (api_model.h), builds JSON from it and
 * returns an HTTP status. Handlers never touch the socket.
 *
 * Not shared with the sibling miner: the route table is the same, the state
 * behind it is not. Gates for the parts that must not diverge:
 * api/tests/check-routes.py for paths, verbs and privileges,
 * api/tests/check-fields.py for field names against docs/openapi.yaml.
 *
 * A route this miner cannot serve is registered available = false rather than
 * omitted, so it answers 501 instead of 404 and the capability list in
 * GET /api/v1/ stays truthful.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miner.h"
#include "api_model.h"
#include "api_control.h"
#include "api_routes.h"

/* ------------------------------------------------------------------ helpers */

/* Every reply carries the miner envelope (docs/api-rest.md section 5). */
static json_t *envelope( void )
{
   json_t *root = json_object();
   if ( !root ) return NULL;
   json_t *m = api_build_miner_json();
   if ( !m ) { json_decref( root ); return NULL; }
   json_object_set_new( root, "miner", m );
   return root;
}

static int oom( char *errmsg, size_t errlen )
{
   snprintf( errmsg, errlen, "out of memory" );
   return 500;
}

/* ?id=N / ?index=N */
static bool query_int( const char *query, const char *key, long *out )
{
   size_t klen = strlen( key );
   for ( const char *p = query; p && *p; )
   {
      if ( strncmp( p, key, klen ) == 0 && p[klen] == '=' )
      {
         char *end = NULL;
         long v = strtol( p + klen + 1, &end, 10 );
         if ( end == p + klen + 1 ) return false;
         *out = v;
         return true;
      }
      p = strchr( p, '&' );
      if ( p ) p++;
   }
   return false;
}

/* Trailing path segment of a prefix route: /api/v1/pools/0 -> 0 */
static bool trailing_int( const char *path, long *out )
{
   const char *slash = strrchr( path, '/' );
   if ( !slash || !slash[1] ) return false;
   char *end = NULL;
   long v = strtol( slash + 1, &end, 10 );
   if ( end == slash + 1 || *end ) return false;
   *out = v;
   return true;
}

/* ----------------------------------------------------------------- handlers */

static int h_index( const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n )
{
   (void)req; (void)ctx;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );

   json_t *index = json_object();
   json_t *caps  = json_array();
   json_t *links = json_object();
   if ( !index || !caps || !links )
   {
      json_decref( root );
      if ( index ) json_decref( index );
      if ( caps )  json_decref( caps );
      if ( links ) json_decref( links );
      return oom( e, n );
   }

   /* Derived from the table, so it cannot claim a capability that is not
    * routed nor omit one that is. */
   size_t count = 0;
   const api_route *routes = api_routes_get( &count );
   for ( size_t i = 0; i < count; i++ )
   {
      if ( !routes[i].available ) continue;
      const char *p = routes[i].path;
      if ( strcmp( p, "/metrics" ) == 0 )
      {
         json_array_append_new( caps, json_string( "metrics" ) );
         continue;
      }
      if ( strncmp( p, "/api/v1/", 8 ) != 0 ) continue;
      const char *name = p + 8;
      if ( !*name ) continue;                        /* the index itself */

      char buf[64];
      snprintf( buf, sizeof(buf), "%s", name );
      size_t l = strlen( buf );
      if ( l && buf[l-1] == '/' ) buf[l-1] = '\0';   /* prefix route */
      for ( char *s = buf; *s; s++ ) if ( *s == '/' ) *s = '.';

      /* /pools and /pools/ both map to "pools". */
      bool seen = false;
      size_t na = json_array_size( caps );
      for ( size_t k = 0; k < na; k++ )
      {
         const char *ex = json_string_value( json_array_get( caps, k ) );
         if ( ex && strcmp( ex, buf ) == 0 ) { seen = true; break; }
      }
      if ( !seen ) json_array_append_new( caps, json_string( buf ) );
   }

   json_object_set_new( links, "summary", json_string( "/api/v1/summary" ) );
   json_object_set_new( links, "devices", json_string( "/api/v1/devices" ) );
   json_object_set_new( index, "capabilities", caps );
   json_object_set_new( index, "links", links );
   json_object_set_new( root, "index", index );
   *out = root;
   return 200;
}

static int h_summary( const api_request *req, void *ctx, json_t **out,
                      char *e, size_t n )
{
   (void)req; (void)ctx;
   struct api_summary_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );

   api_collect_summary( &snap );
   json_t *o = api_build_summary_json( &snap );
   if ( !o ) { json_decref( root ); return oom( e, n ); }
   json_object_set_new( root, "summary", o );
   *out = root;
   return 200;
}

static int h_threads( const api_request *req, void *ctx, json_t **out,
                      char *e, size_t n )
{
   (void)ctx;
   long want = -1;
   bool filtered = query_int( req->query, "id", &want );

   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *arr = json_array();
   if ( !arr ) { json_decref( root ); return oom( e, n ); }

   for ( int i = 0; i < opt_n_threads; i++ )
   {
      struct api_thread_snapshot snap;
      if ( filtered && i != (int)want ) continue;
      if ( !api_collect_thread( i, &snap ) ) continue;
      json_t *t = api_build_thread_json( &snap );
      if ( t ) json_array_append_new( arr, t );
   }
   if ( filtered && json_array_size( arr ) == 0 )
   {
      json_decref( root );
      json_decref( arr );
      snprintf( e, n, "no such thread" );
      return 404;
   }
   json_object_set_new( root, "threads", arr );
   *out = root;
   return 200;
}

/* One CPU, so /devices is an array of exactly one and /devices/{id} accepts
 * only 0. The array form is kept so a client walks both miners identically. */
static int h_devices( const api_request *req, void *ctx, json_t **out,
                      char *e, size_t n )
{
   (void)req; (void)ctx;
   struct api_device_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *arr = json_array();
   if ( !arr ) { json_decref( root ); return oom( e, n ); }

   api_collect_device( &snap );
   json_t *d = api_build_device_json( 0, &snap );
   if ( d ) json_array_append_new( arr, d );
   json_object_set_new( root, "devices", arr );
   *out = root;
   return 200;
}

static int h_device( const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n )
{
   (void)ctx;
   long idx = 0;
   if ( !trailing_int( req->path, &idx ) || idx != 0 )
   {
      snprintf( e, n, "no such device" );
      return 404;
   }
   struct api_device_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   api_collect_device( &snap );
   json_t *d = api_build_device_json( 0, &snap );
   if ( !d ) { json_decref( root ); return oom( e, n ); }
   json_object_set_new( root, "device", d );
   *out = root;
   return 200;
}

static int h_system( const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n )
{
   (void)req; (void)ctx;
   struct api_system_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   api_collect_system( &snap );
   json_t *o = api_build_system_json( &snap );
   if ( !o ) { json_decref( root ); return oom( e, n ); }
   json_object_set_new( root, "system", o );
   *out = root;
   return 200;
}

static int h_pools( const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n )
{
   (void)ctx;
   long want = -1;
   bool filtered = query_int( req->query, "index", &want );

   if ( filtered && want != 0 )
   {
      snprintf( e, n, "no such pool" );
      return 404;
   }

   struct api_pool_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *arr = json_array();
   if ( !arr ) { json_decref( root ); return oom( e, n ); }

   api_collect_pool( &snap );
   json_t *p = api_build_pool_json( 0, true, &snap );
   if ( p ) json_array_append_new( arr, p );
   json_object_set_new( root, "pools", arr );
   *out = root;
   return 200;
}

static int h_pool( const api_request *req, void *ctx, json_t **out,
                   char *e, size_t n )
{
   (void)ctx;
   long idx = 0;
   /* Single pool: index 0 is the only one that exists. */
   if ( !trailing_int( req->path, &idx ) || idx != 0 )
   {
      snprintf( e, n, "no such pool" );
      return 404;
   }
   struct api_pool_snapshot snap;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   api_collect_pool( &snap );
   json_t *p = api_build_pool_json( 0, true, &snap );
   if ( !p ) { json_decref( root ); return oom( e, n ); }
   json_object_set_new( root, "pool", p );
   *out = root;
   return 200;
}

static int h_health( const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n )
{
   (void)req; (void)ctx;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *h = json_object();
   json_t *reasons = json_array();
   if ( !h || !reasons )
   {
      json_decref( root );
      if ( h ) json_decref( h );
      if ( reasons ) json_decref( reasons );
      return oom( e, n );
   }

   struct api_pool_snapshot pool;
   api_collect_pool( &pool );

   /* A manager-initiated stop is NOT a fault: it stays 200 ok with
    * mining:false, and only an unexpected pool disconnect degrades
    * (section 6.6). */
   const ctl_state_t cs = api_ctl_get_state();
   const bool idle_by_request = ( cs == CTL_PAUSED || cs == CTL_STOPPED );
   const bool mining   = opt_n_threads > 0 && !idle_by_request;
   const bool degraded = pool.stratum && !pool.connected && !idle_by_request;

   if ( degraded )
      json_array_append_new( reasons, json_string( "pool_disconnected" ) );

   json_object_set_new( h, "status", json_string( degraded ? "degraded" : "ok" ) );
   json_object_set_new( h, "mining", json_boolean( mining ) );
   json_object_set_new( h, "pool_connected",
                        pool.stratum ? json_boolean( pool.connected ) : json_null() );
   json_object_set_new( h, "devices_ok", json_integer( mining ? 1 : 0 ) );
   if ( json_array_size( reasons ) )
      json_object_set_new( h, "reasons", reasons );
   else
      json_decref( reasons );

   json_object_set_new( root, "health", h );
   *out = root;
   return degraded ? 503 : 200;
}

static int h_config( const api_request *req, void *ctx, json_t **out,
                     char *e, size_t n )
{
   (void)req; (void)ctx;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *c = json_object();
   if ( !c ) { json_decref( root ); return oom( e, n ); }

   /* Credentials are masked by omission: user, pass and any userinfo inside a
    * URL are never read here (section 6.8). */
   char algo[64] = { 0 };
   get_currentalgo( algo, sizeof(algo) );
   json_object_set_new( c, "algo",      json_string( algo ) );
   json_object_set_new( c, "threads",   json_integer( opt_n_threads ) );
   json_object_set_new( c, "devices",   json_integer( 1 ) );
   json_object_set_new( c, "benchmark", json_boolean( opt_benchmark ) );
   json_object_set_new( c, "debug",     json_boolean( opt_debug ) );
   json_object_set_new( c, "pools",     json_integer( 1 ) );
   json_object_set_new( root, "config", c );
   *out = root;
   return 200;
}

static int h_algos( const api_request *req, void *ctx, json_t **out,
                    char *e, size_t n )
{
   (void)req; (void)ctx;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *arr = json_array();
   if ( !arr ) { json_decref( root ); return oom( e, n ); }

   for ( int i = 0; i < ALGO_COUNT; i++ )
   {
      if ( !algo_names[i] || !*algo_names[i] ) continue;
      json_t *a = json_object();
      if ( !a ) continue;
      json_object_set_new( a, "name", json_string( algo_names[i] ) );

      /* Authoritative, and derived from what registration actually reads: a
       * client must not hardcode this (section 9). The fixed-parameter
       * variants report an empty array on purpose -- their values are
       * consensus, and an accepted override would mine rejects. */
      size_t pcount = 0;
      const char **pnames = api_ctl_algo_params( i, &pcount );
      json_t *params = json_array();
      for ( size_t k = 0; params && k < pcount; k++ )
      {
         const ctl_param_def_t *d = api_ctl_param_find( pnames[k] );
         json_t *pd = json_object();
         if ( !d || !pd ) { if ( pd ) json_decref( pd ); continue; }
         json_object_set_new( pd, "name", json_string( d->name ) );
         json_object_set_new( pd, "type",
                              json_string( d->type == CTLP_INT ? "int"
                                                              : "string" ) );
         /* "slow" tells the client to expect a long call and a 202. */
         json_object_set_new( pd, "tier",
                              json_string( d->slow ? "slow" : "fast" ) );
         json_array_append_new( params, pd );
      }
      json_object_set_new( a, "params", params ? params : json_array() );
      json_array_append_new( arr, a );
   }
   json_object_set_new( root, "algos", arr );
   *out = root;
   return 200;
}

/* ------------------------------------------------------------ write routes */

/* A body is parsed strictly -- a wrong type is 400, never a silent coercion.
 * An absent body is an empty object, so a verb needing no arguments works with
 * or without one. */
static json_t *parse_body( const api_request *req, char *e, size_t n, int *status )
{
   if ( !req->body_len )
   {
      *status = 200;
      return json_object();
   }
   json_error_t err;
   json_t *root = json_loads( req->body, 0, &err );
   if ( !root )
   {
      snprintf( e, n, "invalid JSON: %s", err.text );
      *status = 400;
      return NULL;
   }
   if ( !json_is_object( root ) )
   {
      json_decref( root );
      snprintf( e, n, "body must be a JSON object" );
      *status = 400;
      return NULL;
   }
   *status = 200;
   return root;
}

static json_t *result_ok( void )
{
   json_t *root = envelope();
   if ( !root ) return NULL;
   json_t *res = json_object();
   if ( !res ) { json_decref( root ); return NULL; }
   json_object_set_new( res, "ok", json_true() );
   json_object_set_new( root, "result", res );
   return root;
}

extern bool stratum_need_reset;

/* A safety gate, not input hygiene: parse_arg('o') calls
 * show_usage_and_exit(1) on an unrecognised scheme and on a url with no host,
 * so an unvalidated string from a request would terminate the miner.
 * Everything parse_arg would reject has to be rejected here first, with a 400.
 * The binary seturl command does not do this and remains exposed. */
static bool url_accepted( const char *url )
{
   static const char *scheme[] = {
      "http://", "https://", "stratum+tcp://", "stratum+ssl://", "stratum+tcps://"
   };
   for ( size_t i = 0; i < sizeof(scheme)/sizeof(scheme[0]); i++ )
   {
      size_t l = strlen( scheme[i] );
      if ( strncasecmp( url, scheme[i], l ) != 0 ) continue;
      /* A host must follow, and it may not start the path straight away. */
      return url[l] != '\0' && url[l] != '/';
   }
   return false;
}

static int h_pools_url( const api_request *req, void *ctx, json_t **out,
                        char *e, size_t n )
{
   (void)ctx;
   int status = 200;
   json_t *body = parse_body( req, e, n, &status );
   if ( !body ) return status;

   json_t *jurl  = json_object_get( body, "url" );
   json_t *juser = json_object_get( body, "user" );
   json_t *jpass = json_object_get( body, "pass" );

   if ( !jurl || !json_is_string( jurl ) )
   {
      json_decref( body );
      snprintf( e, n, "url is required and must be a string" );
      return 400;
   }
   if ( ( juser && !json_is_string( juser ) )
     || ( jpass && !json_is_string( jpass ) ) )
   {
      json_decref( body );
      snprintf( e, n, "user and pass must be strings" );
      return 400;
   }

   const char *url  = json_string_value( jurl );
   const char *user = juser ? json_string_value( juser ) : NULL;
   const char *pass = jpass ? json_string_value( jpass ) : NULL;

   if ( !url_accepted( url ) )
   {
      json_decref( body );
      snprintf( e, n, "unsupported url scheme, or no host" );
      return 400;
   }

   /* Assemble the scheme://user:pass@host form parse_arg('o') expects, so a
    * client never builds a packed string itself (section 6.10). parse_arg
    * splits the credentials back out into rpc_user/rpc_pass, which is why
    * /pools can return the url without ever returning the password. */
   char packed[1280];
   int wrote;
   if ( user && *user )
   {
      const char *sep = strstr( url, "://" );
      size_t schemelen = sep ? (size_t)( sep - url ) + 3 : 0;
      wrote = snprintf( packed, sizeof(packed), "%.*s%s:%s@%s",
                        (int)schemelen, url, user, ( pass && *pass ) ? pass : "x",
                        url + schemelen );
   }
   else
      wrote = snprintf( packed, sizeof(packed), "%s", url );

   json_decref( body );

   if ( wrote < 0 || (size_t)wrote >= sizeof(packed) )
   {
      snprintf( e, n, "url too long" );
      return 400;
   }

   /* parse_arg() rewrites its argument in place and frees the previous
    * rpc_url/rpc_user/rpc_pass, so packed must be writable. Inherits the
    * binary command's existing race with the stratum thread reading rpc_url. */
   parse_arg( 'o', packed );
   stratum_need_reset = true;

   json_t *root = result_ok();
   if ( !root ) return oom( e, n );
   *out = root;
   return 200;
}

static int h_quit( const api_request *req, void *ctx, json_t **out,
                   char *e, size_t n )
{
   (void)req;
   json_t *root = result_ok();
   if ( !root ) return oom( e, n );

   /* Only flag it. The caller shuts the miner down after this response is on
    * the wire, so the client always sees its 200 (section 6.10). */
   if ( ctx ) ( (api_ctx *)ctx )->quit_requested = true;

   *out = root;
   return 200;
}

/* GET /api/v1/history?thread=N&limit=50 -- the last scans, newest first.
 * limit is capped at the contract's 50 (section 6). */
static int h_history( const api_request *req, void *ctx, json_t **out,
                      char *e, size_t n )
{
   (void)ctx;
   long thread = -1, limit = 50;
   struct api_history_record recs[ 50 ];   /* the contract's cap */
   int max = (int)( sizeof(recs) / sizeof(recs[0]) );
   int got;

   if ( query_int( req->query, "thread", &thread ) )
   {
      if ( thread < 0 || thread >= opt_n_threads )
      {
         snprintf( e, n, "no such thread" );
         return 404;
      }
   }
   else
      thread = -1;

   if ( query_int( req->query, "limit", &limit ) )
   {
      if ( limit < 1 ) limit = 1;
      if ( limit > 50 ) limit = 50;
   }
   if ( limit < max ) max = (int)limit;

   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *arr = json_array();
   if ( !arr ) { json_decref( root ); return oom( e, n ); }

   got = api_history_get( (int)thread, recs, max );
   for ( int i = 0; i < got; i++ )
   {
      json_t *r = api_build_history_json( &recs[i] );
      if ( r ) json_array_append_new( arr, r );
   }
   json_object_set_new( root, "history", arr );
   *out = root;
   return 200;
}

/* GET /metrics -- Prometheus text, not JSON, so it uses the transport's text
 * handler and names its own content type. The buffer is sized for the whole
 * exposition: api_metrics_render() returns 0 rather than truncating, because a
 * half-written exposition parses as a family that has gone missing. */
static int h_metrics( const api_request *req, void *ctx, char **out,
                      char *e, size_t n )
{
   (void)req; (void)ctx;
   api_metrics_input in;
   const size_t cap = 16384;
   char *buf = (char *) malloc( cap );

   if ( !buf ) return oom( e, n );

   api_collect_metrics( &in );
   if ( !api_metrics_render( &in, buf, cap ) )
   {
      free( buf );
      snprintf( e, n, "metrics buffer too small" );
      return 500;
   }
   *out = buf;                    /* the transport frees it */
   return 200;
}


/* ------------------------------------------------------------ control API */

/* docs/api-rest.md section 7. Both 200 and 202 are success. */
static int ctl_http_status( ctl_result_t rc )
{
   switch ( rc )
   {
      case CTL_OK:          return 200;
      case CTL_ACCEPTED:    return 202;
      case CTL_DISABLED:    return 403;
      case CTL_BUSY:        return 409;
      case CTL_THROTTLED:   return 429;
      case CTL_BAD_REQUEST: return 400;
      case CTL_FAILED:      return 409;
   }
   return 500;
}

static const char *ctl_state_name( ctl_state_t s )
{
   switch ( s )
   {
      case CTL_RUNNING:   return "running";
      case CTL_PAUSED:    return "paused";
      case CTL_STOPPED:   return "stopped";
      case CTL_SWITCHING: return "switching";
   }
   return "running";
}

static json_t *ctl_str_or_null( const char *v )
{
   return ( v && *v ) ? json_string( v ) : json_null();
}

static json_t *ctl_state_object( void )
{
   struct ctl_status st;
   struct api_pool_snapshot pool;
   json_t *o = json_object(), *params = json_object(), *p = json_object();

   if ( !o || !params || !p )
   {
      if ( o )      json_decref( o );
      if ( params ) json_decref( params );
      if ( p )      json_decref( p );
      return NULL;
   }

   api_ctl_get_status( &st );
   api_collect_pool( &pool );

   json_object_set_new( o, "state",   json_string( ctl_state_name( st.state ) ) );
   json_object_set_new( o, "epoch",   json_integer( (json_int_t)st.epoch ) );
   json_object_set_new( o, "since_s", json_integer( (json_int_t)st.since_s ) );
   json_object_set_new( o, "algo",    json_string( st.algo ) );

   /* The parameters in effect for the CURRENT algo. A member is null when it
    * is unset, and absent members are simply ones this algo does not take
    * (section 7.2's example shows n/r/key). */
   {
      long iv; const char *sv;
      json_object_set_new( params, "n",
         api_ctl_param_get_int( "n", &iv ) ? json_integer( iv ) : json_null() );
      json_object_set_new( params, "r",
         api_ctl_param_get_int( "r", &iv ) ? json_integer( iv ) : json_null() );
      json_object_set_new( params, "key",
         api_ctl_param_get_str( "key", &sv ) ? json_string( sv ) : json_null() );
      if ( api_ctl_param_get_str( "data_file", &sv ) )
         json_object_set_new( params, "data_file", json_string( sv ) );
   }
   json_object_set_new( o, "params", params );

   json_object_set_new( p, "index", json_integer( 0 ) );
   json_object_set_new( p, "url",   ctl_str_or_null( pool.url ) );
   json_object_set_new( p, "user",  ctl_str_or_null( pool.user ) );
   json_object_set_new( o, "pool", p );
   json_object_set_new( o, "pool_connected",
                        pool.stratum ? json_boolean( pool.connected )
                                     : json_null() );

   json_object_set_new( o, "threads_total",  json_integer( st.threads_total ) );
   json_object_set_new( o, "threads_parked", json_integer( st.threads_parked ) );
   json_object_set_new( o, "switch_count",   json_integer( (json_int_t)st.switch_count ) );
   json_object_set_new( o, "last_switch_age_s",
                        st.last_switch_age_s < 0. ? json_null()
                        : json_integer( (json_int_t)st.last_switch_age_s ) );
   json_object_set_new( o, "min_interval_s",   json_integer( st.min_interval_s ) );
   json_object_set_new( o, "ready_for_switch", json_boolean( st.ready_for_switch ) );
   json_object_set_new( o, "last_error",
                        st.last_error[0] ? json_string( st.last_error )
                                         : json_null() );
   return o;
}

static int h_control_state( const api_request *req, void *ctx, json_t **out,
                            char *e, size_t n )
{
   (void)req; (void)ctx;
   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *c = ctl_state_object();
   if ( !c ) { json_decref( root ); return oom( e, n ); }
   json_object_set_new( root, "control", c );
   *out = root;
   return 200;
}

/* Optional {"wait_ms": N}. */
static bool ctl_wait_ms( json_t *body, int *wait_ms, char *e, size_t n )
{
   json_t *w = json_object_get( body, "wait_ms" );
   if ( !w ) return true;
   if ( !json_is_integer( w ) )
   {
      snprintf( e, n, "wait_ms must be an integer" );
      return false;
   }
   *wait_ms = (int) json_integer_value( w );
   return true;
}

static int ctl_reply( ctl_result_t rc, json_t **out, char *e, size_t n )
{
   const int status = ctl_http_status( rc );
   if ( status >= 400 )
   {
      struct ctl_status st;
      api_ctl_get_status( &st );
      if ( rc == CTL_DISABLED )
         snprintf( e, n, "control API disabled (--api-control)" );
      else if ( st.last_error[0] )
         snprintf( e, n, "%s", st.last_error );
      return status;
   }

   json_t *root = envelope();
   if ( !root ) return oom( e, n );
   json_t *c = ctl_state_object();
   if ( !c ) { json_decref( root ); return oom( e, n ); }
   /* The result carries the resulting state (section 7.3). */
   json_object_set_new( root, "result", c );
   *out = root;
   return status;
}

static int ctl_verb( const api_request *req, ctl_state_t target, json_t **out,
                     char *e, size_t n )
{
   int status = 200, wait_ms = 0;
   json_t *body = parse_body( req, e, n, &status );
   if ( !body ) return status;
   if ( !ctl_wait_ms( body, &wait_ms, e, n ) )
   {
      json_decref( body );
      return 400;
   }
   json_decref( body );
   return ctl_reply( api_ctl_set_state( target, wait_ms ), out, e, n );
}

static int h_control_start( const api_request *req, void *ctx, json_t **out,
                            char *e, size_t n )
{ (void)ctx; return ctl_verb( req, CTL_RUNNING, out, e, n ); }

static int h_control_pause( const api_request *req, void *ctx, json_t **out,
                            char *e, size_t n )
{ (void)ctx; return ctl_verb( req, CTL_PAUSED, out, e, n ); }

static int h_control_stop( const api_request *req, void *ctx, json_t **out,
                           char *e, size_t n )
{ (void)ctx; return ctl_verb( req, CTL_STOPPED, out, e, n ); }

static int h_control_profile( const api_request *req, void *ctx, json_t **out,
                              char *e, size_t n )
{
   (void)ctx;
   int status = 200, wait_ms = 0;
   json_t *body = parse_body( req, e, n, &status );
   if ( !body ) return status;

   json_t *jalgo = json_object_get( body, "algo" );
   json_t *jpool = json_object_get( body, "pool" );
   json_t *jrun  = json_object_get( body, "run" );

   if ( ( jalgo && !json_is_string( jalgo ) )
     || ( jpool && !json_is_object( jpool ) )
     || ( jrun  && !json_is_boolean( jrun ) ) )
   {
      json_decref( body );
      snprintf( e, n, "algo must be a string, pool an object, run a boolean" );
      return 400;
   }
   /* Structural, not merely validated: mining algorithm X against a pool
    * expecting Y produces all-rejected shares while every other metric looks
    * healthy (section 7.4). */
   if ( jalgo && !jpool )
   {
      json_decref( body );
      snprintf( e, n, "algo requires pool: send both or neither" );
      return 400;
   }
   json_t *jparams = json_object_get( body, "params" );
   if ( jparams && !json_is_object( jparams ) )
   {
      json_decref( body );
      snprintf( e, n, "params must be an object" );
      return 400;
   }
   if ( !jalgo && !jpool && !jrun && !jparams )
   {
      json_decref( body );
      snprintf( e, n, "nothing to do: send algo+pool, pool, params, or run" );
      return 400;
   }

   /* Omitted is not null: a name absent from the object keeps its current
    * value, an explicit null resets it to the algorithm default (section 9). */
   ctl_param_set_t pset[ 8 ];
   size_t npset = 0;
   if ( jparams )
   {
      const char *pk;
      json_t *pv;
      json_object_foreach( jparams, pk, pv )
      {
         if ( npset >= sizeof(pset)/sizeof(pset[0]) )
         {
            json_decref( body );
            snprintf( e, n, "too many parameters" );
            return 400;
         }
         ctl_param_set_t *ps = &pset[ npset++ ];
         memset( ps, 0, sizeof(*ps) );
         ps->name = pk;
         if ( json_is_null( pv ) )              ps->reset = true;
         else if ( json_is_integer( pv ) )      ps->ival  = (long) json_integer_value( pv );
         else if ( json_is_string( pv ) )       ps->sval  = json_string_value( pv );
         else
         {
            json_decref( body );
            snprintf( e, n, "parameter '%s' must be an integer, a string or null", pk );
            return 400;
         }
      }
   }
   if ( !ctl_wait_ms( body, &wait_ms, e, n ) )
   {
      json_decref( body );
      return 400;
   }

   const char *url = NULL, *user = NULL, *pass = NULL;
   if ( jpool )
   {
      json_t *ju = json_object_get( jpool, "url" );
      json_t *jU = json_object_get( jpool, "user" );
      json_t *jP = json_object_get( jpool, "pass" );
      if ( !ju || !json_is_string( ju )
        || ( jU && !json_is_string( jU ) )
        || ( jP && !json_is_string( jP ) ) )
      {
         json_decref( body );
         snprintf( e, n, "pool.url is required and must be a string" );
         return 400;
      }
      url  = json_string_value( ju );
      user = jU ? json_string_value( jU ) : NULL;
      pass = jP ? json_string_value( jP ) : NULL;
      /* The same kill-the-miner gate as POST /pools/url. */
      if ( !url_accepted( url ) )
      {
         json_decref( body );
         snprintf( e, n, "unsupported url scheme, or no host" );
         return 400;
      }
   }

   const bool run_val = jrun ? json_is_true( jrun ) : false;
   ctl_result_t rc = api_ctl_profile( jalgo ? json_string_value( jalgo ) : NULL,
                                      url, user, pass, pset, npset,
                                      jrun ? &run_val : NULL, wait_ms );
   json_decref( body );
   return ctl_reply( rc, out, e, n );
}

/* Registered so the path exists and answers 501 rather than 404. */
static int h_unavailable( const api_request *req, void *ctx, json_t **out,
                          char *e, size_t n )
{
   (void)req; (void)ctx; (void)out;
   snprintf( e, n, "not available on this miner" );
   return 501;
}

/* -------------------------------------------------------------------- table */

static const api_route g_routes[] = {
   { API_M_GET,  "/api/v1",              API_PRIV_READ,  true,  h_index,   NULL, NULL },
   { API_M_GET,  "/api/v1/summary",      API_PRIV_READ,  true,  h_summary, NULL, NULL },
   { API_M_GET,  "/api/v1/threads",      API_PRIV_READ,  true,  h_threads, NULL, NULL },
   { API_M_GET,  "/api/v1/devices",      API_PRIV_READ,  true,  h_devices, NULL, NULL },
   { API_M_GET,  "/api/v1/devices/",     API_PRIV_READ,  true,  h_device,  NULL, NULL },
   { API_M_GET,  "/api/v1/system",       API_PRIV_READ,  true,  h_system,  NULL, NULL },
   { API_M_GET,  "/api/v1/pools",        API_PRIV_READ,  true,  h_pools,   NULL, NULL },
   { API_M_GET,  "/api/v1/pools/",       API_PRIV_READ,  true,  h_pool,    NULL, NULL },
   { API_M_GET,  "/api/v1/health",       API_PRIV_READ,  true,  h_health,  NULL, NULL },
   { API_M_GET,  "/api/v1/config",       API_PRIV_READ,  true,  h_config,  NULL, NULL },
   { API_M_GET,  "/api/v1/algos",        API_PRIV_READ,  true,  h_algos,   NULL, NULL },

   { API_M_GET,  "/api/v1/history",      API_PRIV_READ,  true,  h_history, NULL, NULL },

   /* Permanently 501. Both describe the GPU miner's hashlog: a per-job record
    * of scanned nonce ranges, for resume and dedup. This miner has no such log
    * and needs none -- threads get disjoint nonce ranges by construction -- so
    * /scanlog has nothing to report and 3 of /meminfo's 5 fields would have
    * nothing behind them. */
   { API_M_GET,  "/api/v1/scanlog",      API_PRIV_READ,  false, h_unavailable, NULL, NULL },
   { API_M_GET,  "/api/v1/meminfo",      API_PRIV_READ,  false, h_unavailable, NULL, NULL },

   /* Permanently 501, not "not yet": a single-pool miner has no pool array to
    * switch between, and pool selection belongs to the manager, which sends a
    * pool with every control profile (section 10). */
   { API_M_POST, "/api/v1/pools/switch", API_PRIV_WRITE, false, h_unavailable, NULL, NULL },

   /* Write routes. API_PRIV_WRITE makes the transport answer 403 without
    * --api-remote, and 401 first if --api-token is set and not supplied. */
   { API_M_POST, "/api/v1/pools/url",    API_PRIV_WRITE, true,  h_pools_url, NULL, NULL },
   { API_M_POST, "/api/v1/quit",         API_PRIV_WRITE, true,  h_quit,      NULL, NULL },

   /* Runtime control. GET state is a read; the mutating verbs are
    * API_PRIV_CONTROL, which the transport also gates on --api-control. */
   { API_M_GET,  "/api/v1/control/state",   API_PRIV_READ,    true, h_control_state,   NULL, NULL },
   { API_M_POST, "/api/v1/control/start",   API_PRIV_CONTROL, true, h_control_start,   NULL, NULL },
   { API_M_POST, "/api/v1/control/pause",   API_PRIV_CONTROL, true, h_control_pause,   NULL, NULL },
   { API_M_POST, "/api/v1/control/stop",    API_PRIV_CONTROL, true, h_control_stop,    NULL, NULL },
   { API_M_POST, "/api/v1/control/profile", API_PRIV_CONTROL, true, h_control_profile, NULL, NULL },

   /* Outside /api/v1 by design: not versioned JSON, and every scraper defaults
    * to this path. Read privilege, but --api-token still applies (section 4). */
   { API_M_GET,  "/metrics", API_PRIV_READ, true, NULL, h_metrics,
     API_METRICS_CONTENT_TYPE },
};

const api_route *api_routes_get( size_t *count )
{
   *count = sizeof(g_routes) / sizeof(g_routes[0]);
   return g_routes;
}

char *api_routes_miner_json_str( void )
{
   json_t *m = api_build_miner_json();
   if ( !m ) return NULL;
   char *s = json_dumps( m, JSON_COMPACT );
   json_decref( m );
   return s;
}
