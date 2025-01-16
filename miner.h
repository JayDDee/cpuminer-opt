#ifndef MINER_H__
#define MINER_H__

#include <cpuminer-config.h>

// CPU architecture
#if defined(__x86_64__)
   #define USER_AGENT_ARCH "x64"     // Intel, AMD x86_64
#elif defined(__aarch64__)
   #define USER_AGENT_ARCH "arm"     // AArch64
//#elif
//  #define USER_AGENT_ARCH "r5"     // RISC-V             
#else
   #define USER_AGENT_ARCH
#endif

// Operating system
// __APPLE__ includes MacOS & IOS, no MacOS only macros found.
#if defined(__linux)
   #define USER_AGENT_OS   "L"      // GNU Linux
#elif defined(WIN32)
   #define USER_AGENT_OS   "W"      // MS Windows
#elif defined(__APPLE__)
   #define USER_AGENT_OS   "M"      // Apple MacOS
#elif defined(__bsd__) || defined(__unix__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) 
   #define USER_AGENT_OS   "U"      // BSD unix
#else
   #define USER_AGENT_OS
#endif

#define USER_AGENT PACKAGE_NAME "-" PACKAGE_VERSION "-" USER_AGENT_ARCH USER_AGENT_OS

/*
#ifdef _MSC_VER

#undef USE_ASM 
#ifdef NOASM
#undef USE_ASM
#endif

#if defined(_M_X64)
#define __i386__ 1
#define __x86_64__ 1
#elif defined(_M_X86)
#define __i386__ 1
#endif

#endif
*/

#include <stdbool.h>
#include <inttypes.h>
#include <sys/time.h>
#include <unistd.h>
#include <pthread.h>
#include <jansson.h>
#include <curl/curl.h>

#ifdef STDC_HEADERS
# include <stdlib.h>
# include <stddef.h>
#else
# ifdef HAVE_STDLIB_H
#  include <stdlib.h>
# endif
#endif

// no mm_maloc for Neon
#if !defined(__ARM_NEON)

#include <mm_malloc.h>

#define mm_malloc( nbytes, alignment )    _mm_malloc( nbytes, alignment )
#define mm_free                           _mm_free

#else

#define mm_malloc( nbytes, alignment )    malloc( nbytes )
#define mm_free                           free

#endif

//TODO for windows
static inline bool is_root()
{
#if defined(WIN32)
   return false;
#else
   return !getuid();
#endif
}

/*
#ifndef min
#define min(a,b) (a>b ? (b) :(a))
#endif
#ifndef max 
#define max(a,b) (a<b ? (b) : (a))
#endif
*/

//#ifdef HAVE_ALLOCA_H
//# include <alloca.h>
//#elif !defined alloca
# ifdef __GNUC__
//#  define alloca __builtin_alloca
# elif defined _AIX
#  define alloca __alloca
# elif defined _MSC_VER
#  include <malloc.h>
#  define alloca _alloca
# elif !defined HAVE_ALLOCA
#  ifdef  __cplusplus
extern "C"
#  endif
void *alloca (size_t);
# endif
//#endif

// keyboard beep
static const char ASCII_BELL =  '\a';

#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#define LOG_BLUE  0x10 /* unique value */
#define LOG_MAJR  0x11 /* unique value */
#define LOG_MINR  0x12 /* unique value */
#define LOG_GREEN 0x13 /* unique value */
#define LOG_PINK  0x14 /* unique value */
#else
enum {
   LOG_CRIT,
   LOG_ERR,
	LOG_WARNING,
	LOG_NOTICE,
	LOG_INFO,
	LOG_DEBUG,
   /* custom notices */
	LOG_BLUE  = 0x10,
   LOG_MAJR  = 0x11,
   LOG_MINR  = 0x12,
   LOG_GREEN = 0x13,
   LOG_PINK  = 0x14 };
#endif

#define WORK_ALIGNMENT 64

// When working with dynamically allocated memory to guarantee data alignment
// for large vectors. Physical block size must be extended by alignment number
// of bytes when allocated. free() should use the physical pointer returned by
// malloc(), not the aligned pointer. All others shoujld use the logical,
// aligned, pointer returned by this function. 
static inline void *align_ptr( const void *ptr, const uint64_t alignment )
{
  const uint64_t mask = alignment - 1;
  return (void*)( ( ((const uint64_t)ptr) + mask ) & (~mask) );
}

extern bool is_power_of_2( int n );

static inline bool is_windows(void)
{
#ifdef WIN32
	return true;
#else
	return false;
#endif
}
 
#include "compat.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

// deprecated, see simd-int.h
#if ((__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3))
#define WANT_BUILTIN_BSWAP
/*
#else
#define bswap_32(x) ((((x) << 24) & 0xff000000u) | (((x) << 8) & 0x00ff0000u) \
                   | (((x) >> 8) & 0x0000ff00u) | (((x) >> 24) & 0x000000ffu))
*/
#endif

static inline uint32_t swab32(uint32_t x)
{
#ifdef WANT_BUILTIN_BSWAP
   return __builtin_bswap32(x);
#else
   return ( ( (x) << 24 ) & 0xff000000u ) | ( ( (x) <<  8 ) & 0x00ff0000u )
        | ( ( (x) >>  8 ) & 0x0000ff00u ) | ( ( (x) >> 24 ) & 0x000000ffu );


//   return bswap_32(v);
#endif
}

// Swap any two variables of the same type without using a temp
#define swap_vars(a,b) a^=b; b^=a; a^=b;

#ifdef HAVE_SYS_ENDIAN_H
#include <sys/endian.h>
#endif

typedef unsigned char uchar;

#if !HAVE_DECL_BE32DEC
static inline uint32_t be32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
	    ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}
#endif

#if !HAVE_DECL_LE32DEC
static inline uint32_t le32dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint32_t)(p[0]) + ((uint32_t)(p[1]) << 8) +
	    ((uint32_t)(p[2]) << 16) + ((uint32_t)(p[3]) << 24));
}
#endif

#if !HAVE_DECL_BE32ENC
static inline void be32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[3] = x & 0xff;
	p[2] = (x >> 8) & 0xff;
	p[1] = (x >> 16) & 0xff;
	p[0] = (x >> 24) & 0xff;
}
#endif

// This is a poorman's SIMD instruction, use 64 bit instruction to encode 2
// uint32_t. This function flips endian on two adjacent 32 bit quantities
// aligned to 64 bits. If source is LE output is BE, and vice versa.
static inline void swab32_x2( uint64_t* dst, uint64_t src )
{
   *dst =   ( ( src & 0xff000000ff000000 ) >> 24 )
          | ( ( src & 0x00ff000000ff0000 ) >>  8 )
          | ( ( src & 0x0000ff000000ff00 ) <<  8 )
          | ( ( src & 0x000000ff000000ff ) << 24 );
}

static inline void swab32_array( uint32_t* dst_p, uint32_t* src_p, int n )
{
   for ( int i = 0; i < n/2; i++ )
      swab32_x2( &((uint64_t*)dst_p)[i], ((uint64_t*)src_p)[i] );
}

#if !HAVE_DECL_LE32ENC
static inline void le32enc(void *pp, uint32_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
	p[2] = (x >> 16) & 0xff;
	p[3] = (x >> 24) & 0xff;
}
#endif

#if !HAVE_DECL_LE16DEC
static inline uint16_t le16dec(const void *pp)
{
	const uint8_t *p = (uint8_t const *)pp;
	return ((uint16_t)(p[0]) + ((uint16_t)(p[1]) << 8));
}
#endif

#if !HAVE_DECL_LE16ENC
static inline void le16enc(void *pp, uint16_t x)
{
	uint8_t *p = (uint8_t *)pp;
	p[0] = x & 0xff;
	p[1] = (x >> 8) & 0xff;
}
#endif

#if JANSSON_MAJOR_VERSION >= 2
#define JSON_LOADS(str, err_ptr) json_loads(str, 0, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, 0, err_ptr)
#else
#define JSON_LOADS(str, err_ptr) json_loads(str, err_ptr)
#define JSON_LOADF(path, err_ptr) json_load_file(path, err_ptr)
#endif

json_t* json_load_url(char* cfg_url, json_error_t *err);

struct work;

void work_free(struct work *w);
void work_copy(struct work *dest, const struct work *src);



/* api related */
void *api_thread(void *userdata);

struct cpu_info {
	int thr_id;
	int accepted;
	int rejected;
	double khashes;
	bool has_monitoring;
	float cpu_temp;
	int cpu_fan;
	uint32_t cpu_clock;
};

struct thr_api {
	int id;
	pthread_t pth;
	struct thread_q	*q;
};
/* end of api */


#define JSON_RPC_LONGPOLL	(1 << 0)
#define JSON_RPC_QUIET_404	(1 << 1)
#define JSON_RPC_IGNOREERR  (1 << 2)

#define JSON_BUF_LEN 512

#define CL_N    "\x1B[0m"
#define CL_RED  "\x1B[31m"
#define CL_GRN  "\x1B[32m"
#define CL_YLW  "\x1B[33m"  // dark yellow
#define CL_BLU  "\x1B[34m"
#define CL_MAG  "\x1B[35m"  // purple
#define CL_CYN  "\x1B[36m"

#define CL_BLK  "\x1B[22;30m" /* black */
#define CL_RD2  "\x1B[22;31m" /* red */
#define CL_GR2  "\x1B[22;32m" /* green */
#define CL_BRW  "\x1B[22;33m" /* brown */
#define CL_BL2  "\x1B[22;34m" /* blue */
#define CL_MA2  "\x1B[22;35m" /* purple */
#define CL_CY2  "\x1B[22;36m" /* cyan */
#define CL_SIL  "\x1B[22;37m" /* gray */

#ifdef WIN32
#define CL_GRY  "\x1B[01;30m" /* dark gray */
#else
#define CL_GRY  "\x1B[90m"    /* dark gray selectable in putty */
#endif
#define CL_LRD  "\x1B[01;31m" /* bright red */
#define CL_LGR  "\x1B[01;32m" /* bright green */
#define CL_YL2  "\x1B[01;33m" /* bright yellow */
#define CL_LBL  "\x1B[01;34m" /* light blue */
#define CL_LMA  "\x1B[01;35m" /* light magenta */
#define CL_LCY  "\x1B[01;36m" /* light cyan */

#define CL_WHT  "\x1B[01;37m" /* white */

void   applog(int prio, const char *fmt, ...);
void   applog2(int prio, const char *fmt, ...);
void   applog_nl( const char *fmt, ... );
void   restart_threads(void);
extern json_t *json_rpc_call( CURL *curl, const char *url, const char *userpass,
                	const char *rpc_req, int *curl_err, int flags );
extern void cbin2hex(char *out, const char *in, size_t len);
void   bin2hex( char *s, const unsigned char *p, size_t len );
char  *abin2hex( const unsigned char *p, size_t len );
char  *bebin2hex( const unsigned char *p, size_t len );
bool   hex2bin( unsigned char *p, const char *hexstr, const size_t len );
bool   jobj_binary( const json_t *obj, const char *key, void *buf,
                    size_t buflen );
int    varint_encode( unsigned char *p, uint64_t n );
size_t address_to_script( unsigned char *out, size_t outsz, const char *addr );
int    timeval_subtract( struct timeval *result, struct timeval *x,
                           struct timeval *y);

// Segwit BEGIN
extern void memrev(unsigned char *p, size_t len);
// Segwit END

// Bitcoin formula for converting difficulty to an equivalent
// number of hashes.
//
//     https://en.bitcoin.it/wiki/Difficulty
//     hash = diff * 2**32

#define EXP16 65536.
#define EXP32 4294967296.
extern const long double exp32;  // 2**32
extern const long double exp48;  // 2**48
extern const long double exp64;  // 2**64
extern const long double exp96;  // 2**96
extern const long double exp128; // 2**128
extern const long double exp160; // 2**160

bool   fulltest( const uint32_t *hash, const uint32_t *target );
bool   valid_hash( const void*, const void* );

extern double hash_to_diff( const void* );
extern void diff_to_hash( uint32_t*, const double );
extern double nbits_to_diff( uint32_t );

double hash_target_ratio( uint32_t* hash, uint32_t* target );
void   work_set_target_ratio( struct work* work, const void *hash );

struct thr_info {
        int id;
        pthread_t pth;
        pthread_attr_t attr;
        struct thread_q *q;
        struct cpu_info cpu;
};

//int test_hash_and_submit( struct work *work, const void *hash,
//                           struct thr_info *thr );

bool submit_solution( struct work *work, const void *hash,
                      struct thr_info *thr );

void   get_currentalgo( char* buf, int sz );
/*
bool   has_sha();
bool   has_aes_ni();
bool   has_avx1();
bool   has_avx2();
bool   has_avx512f();
bool   has_sse2();
bool   has_xop();
bool   has_fma3();
bool   has_sse42();
bool   has_sse();
void   cpu_bestfeature( char *outbuf, size_t maxsz );
void   cpu_getname(char *outbuf, size_t maxsz);
void   cpu_getmodelid(char *outbuf, size_t maxsz);
void   cpu_brand_string( char* s );

float cpu_temp( int core );
*/

struct work
{
   uint32_t target[8] __attribute__ ((aligned (64)));
	uint32_t data[48] __attribute__ ((aligned (64)));
	double targetdiff;
	double sharediff;
   double stratum_diff;
	int height;
	char *txs;
   int tx_count;
   char *workid;
	char *job_id;
	size_t xnonce2_len;
	unsigned char *xnonce2;
   bool sapling;
   bool stale;
} __attribute__ ((aligned (WORK_ALIGNMENT)));

struct stratum_job
{
	unsigned char prevhash[32];
   unsigned char final_sapling_hash[32];
   char *job_id;
	size_t coinbase_size;
	unsigned char *coinbase;
	unsigned char *xnonce2;
	int merkle_count;
   int merkle_buf_size;
   unsigned char **merkle;
	unsigned char version[4];
	unsigned char nbits[4];
	unsigned char ntime[4];
	double diff;
   bool clean;
   // for x16rt-veil
   unsigned char extra[64];
   unsigned char denom10[32];
   unsigned char denom100[32];
   unsigned char denom1000[32];
   unsigned char denom10000[32];
   unsigned char proofoffullnode[32];

} __attribute__ ((aligned (64)));

struct stratum_ctx {
	char *url;

	CURL *curl;
	char *curl_url;
	char curl_err_str[CURL_ERROR_SIZE];
	curl_socket_t sock;
	size_t sockbuf_size;
	char *sockbuf;
	pthread_mutex_t sock_lock;

	double next_diff;
	double sharediff;

	char *session_id;
	size_t xnonce1_size;
	unsigned char *xnonce1;
	size_t xnonce2_size;
	struct stratum_job job;
	struct work work __attribute__ ((aligned (64)));
	pthread_mutex_t work_lock;

   int block_height;
   bool new_job;  
} __attribute__ ((aligned (64)));

bool stratum_socket_full(struct stratum_ctx *sctx, int timeout);
bool stratum_send_line(struct stratum_ctx *sctx, char *s);
char *stratum_recv_line(struct stratum_ctx *sctx);
bool stratum_connect(struct stratum_ctx *sctx, const char *url);
void stratum_disconnect(struct stratum_ctx *sctx);
bool stratum_subscribe(struct stratum_ctx *sctx);
bool stratum_authorize(struct stratum_ctx *sctx, const char *user, const char *pass);
bool stratum_handle_method(struct stratum_ctx *sctx, const char *s);
bool stratum_suggest_difficulty( struct stratum_ctx *sctx, double diff );


extern bool aes_ni_supported;
extern char *rpc_user;
extern char *short_url;

struct thread_q;

struct thread_q *tq_new(void);
void tq_free(struct thread_q *tq);
bool tq_push(struct thread_q *tq, void *data);
void *tq_pop(struct thread_q *tq, const struct timespec *abstime);
void tq_freeze(struct thread_q *tq);
void tq_thaw(struct thread_q *tq);

void parse_arg(int key, char *arg);
void parse_config(json_t *config, char *ref);
void proper_exit(int reason);

void applog_hash(void *hash);
void format_hashrate(double hashrate, char *output);
void print_hash_tests(void);

void scale_hash_for_display ( double* hashrate, char* units );
void format_number_si( double* hashrate, char* si_units );
void report_summary_log( bool force );

/*
struct thr_info {
        int id;
        pthread_t pth;
        pthread_attr_t attr;
        struct thread_q *q;
        struct cpu_info cpu;
};
*/

struct work_restart {
        volatile uint8_t restart;
        char padding[128 - sizeof(uint8_t)];
};

enum workio_commands {
        WC_GET_WORK,
        WC_SUBMIT_WORK,
};

struct workio_cmd {
        enum workio_commands cmd;
        struct thr_info *thr;
        union {
                struct work *work;
        } u;
};

uint32_t* get_stratum_job_ntime();

enum algos {
        ALGO_NULL,
        ALGO_ALLIUM,
        ALGO_ANIME,
        ALGO_ARGON2D250,
        ALGO_ARGON2D500,
        ALGO_ARGON2D4096,
        ALGO_AXIOM,       
        ALGO_BLAKE,       
        ALGO_BLAKE2B,
        ALGO_BLAKE2S,     
        ALGO_BLAKECOIN,
        ALGO_BMW,        
        ALGO_BMW512,
        ALGO_C11,         
        ALGO_DEEP,
        ALGO_DMD_GR,
        ALGO_GROESTL,     
        ALGO_HEX,
        ALGO_HMQ1725,
        ALGO_JHA,
        ALGO_KECCAK,
        ALGO_KECCAKC,
        ALGO_LBRY,
        ALGO_LYRA2H,
        ALGO_LYRA2RE,       
        ALGO_LYRA2REV2,   
        ALGO_LYRA2REV3,
        ALGO_LYRA2Z,
        ALGO_LYRA2Z330,
        ALGO_M7M,
        ALGO_MINOTAUR,
        ALGO_MINOTAURX,
        ALGO_MYR_GR,      
        ALGO_NEOSCRYPT,
        ALGO_NIST5,       
        ALGO_PENTABLAKE,  
        ALGO_PHI1612,
        ALGO_PHI2,
        ALGO_POLYTIMOS,
        ALGO_POWER2B,
        ALGO_QUARK,
        ALGO_QUBIT,       
        ALGO_SCRYPT,
        ALGO_SHA256D,
        ALGO_SHA256DT,
        ALGO_SHA256Q,
        ALGO_SHA256T,
        ALGO_SHA3D,
        ALGO_SHA512256D,
        ALGO_SKEIN,       
        ALGO_SKEIN2,      
        ALGO_SKUNK,
        ALGO_SONOA,
        ALGO_TIMETRAVEL,
        ALGO_TIMETRAVEL10,
        ALGO_TRIBUS,
        ALGO_VANILLA,
        ALGO_VELTOR,
        ALGO_VERTHASH,
        ALGO_WHIRLPOOL,
        ALGO_WHIRLPOOLX,
        ALGO_X11,
        ALGO_X11EVO,         
        ALGO_X11GOST,
        ALGO_X12,
        ALGO_X13,         
        ALGO_X13BCD,
        ALGO_X13SM3,
        ALGO_X14,        
        ALGO_X15,       
        ALGO_X16R,
        ALGO_X16RV2,
        ALGO_X16RT,
        ALGO_X16RT_VEIL,
        ALGO_X16S,
        ALGO_X17,
        ALGO_X20R,
        ALGO_X21S,
        ALGO_X22I,
        ALGO_X25X,
        ALGO_XEVAN,
        ALGO_YESCRYPT,
        ALGO_YESCRYPTR8,
        ALGO_YESCRYPTR8G,
        ALGO_YESCRYPTR16,
        ALGO_YESCRYPTR32,
        ALGO_YESPOWER,
        ALGO_YESPOWERR16,
        ALGO_YESPOWER_B2B,
        ALGO_ZR5,
        ALGO_COUNT
};

// This list must be in exactly the same order as above.
static const char* const algo_names[] = {
        NULL,
        "allium",
        "anime",
        "argon2d250",
        "argon2d500",
        "argon2d4096",
        "axiom",
        "blake",
        "blake2b",
        "blake2s",
        "blakecoin",
        "bmw",
        "bmw512",
        "c11",
        "deep",
        "dmd-gr",
        "groestl",
        "hex",
        "hmq1725",
        "jha",
        "keccak",
        "keccakc",
        "lbry",
        "lyra2h",
        "lyra2re",
        "lyra2rev2",
        "lyra2rev3",
        "lyra2z",
        "lyra2z330",
        "m7m",
        "minotaur",
        "minotaurx",
        "myr-gr",
        "neoscrypt",
        "nist5",
        "pentablake",
        "phi1612",
        "phi2",
        "polytimos",
        "power2b",
        "quark",
        "qubit",
        "scrypt",
        "sha256d",
        "sha256dt",
        "sha256q",
        "sha256t",
        "sha3d",
        "sha512256d",
        "skein",
        "skein2",
        "skunk",
        "sonoa",
        "timetravel",
        "timetravel10",
        "tribus",
        "vanilla",
        "veltor",
        "verthash",
        "whirlpool",
        "whirlpoolx",
        "x11",
        "x11evo",
        "x11gost",
        "x12",
        "x13",
        "x13bcd",
        "x13sm3",
        "x14",
        "x15",
        "x16r",
        "x16rv2",
        "x16rt",
        "x16rt-veil",
        "x16s",
        "x17",
        "x20r",
        "x21s",
        "x22i",
        "x25x",
        "xevan",
        "yescrypt",
        "yescryptr8",
        "yescryptr8g",
        "yescryptr16",
        "yescryptr32",
        "yespower",
        "yespowerr16",
        "yespower-b2b",
        "zr5",
        "\0"
};

const char* algo_name( enum algos a );

extern enum algos opt_algo;
extern bool opt_debug;
extern bool opt_debug_diff;
extern bool opt_benchmark;
extern bool opt_protocol;
extern bool opt_extranonce;
extern bool opt_quiet;
extern bool opt_redirect;
extern int opt_timeout;
extern bool want_longpoll;
extern bool have_longpoll;
extern bool have_gbt;
extern char*  lp_id;
extern char *rpc_userpass;
extern const char *gbt_lp_req;
extern const char *getwork_req;
extern bool allow_getwork;
extern bool want_stratum;
extern bool have_stratum;
extern char *opt_cert;
extern char *opt_proxy;
extern long opt_proxy_type;
extern bool use_syslog;
extern bool use_colors;
extern pthread_mutex_t applog_lock;
extern struct thr_info *thr_info;
extern int longpoll_thr_id;
extern int stratum_thr_id;
extern int api_thr_id;
extern int opt_n_threads;
extern struct work_restart *work_restart;
extern uint32_t opt_work_size;
extern double *thr_hashrates;
extern double global_hashrate;
extern double stratum_diff;
extern double net_diff;
extern double net_hashrate;
extern int opt_param_n;
extern int opt_param_r;
extern char* opt_param_key;
extern double opt_diff_factor;
extern double opt_target_factor;
extern bool opt_randomize;
extern bool allow_mininginfo;
extern pthread_rwlock_t g_work_lock;
extern time_t g_work_time;
extern bool opt_stratum_stats;
extern int num_cpus;
extern int num_cpugroups;
extern int opt_priority;
extern bool opt_hash_meter;
extern uint32_t accepted_share_count;
extern uint32_t rejected_share_count;
extern uint32_t solved_block_count;
extern pthread_mutex_t applog_lock;
extern pthread_mutex_t stats_lock;
extern bool opt_sapling;
extern const int pk_buffer_size_max;
extern int pk_buffer_size;
extern char *opt_data_file;
extern bool opt_verify;
extern bool opt_bell;    //  keyboard beep
static char const usage[] = "\
Usage: cpuminer [OPTIONS]\n\
Options:\n\
  -a, --algo=ALGO       specify the algorithm to use\n\
                          allium        Garlicoin (GRLC)\n\
                          anime         Animecoin (ANI)\n\
                          argon2d250\n\
                          argon2d500\n\
                          argon2d4096\n\
                          axiom         Shabal-256 MemoHash\n\
                          blake         blake256r14 (SFR)\n\
                          blake2b       Blake2b 256\n\
                          blake2s       Blake-2 S\n\
                          blakecoin     blake256r8\n\
                          bmw           BMW 256\n\
                          bmw512        BMW 512\n\
                          c11           Chaincoin\n\
                          deep          Deepcoin (DCN)\n\
                          dmd-gr        Diamond\n\
                          groestl       Groestl coin\n\
                          hex           x16r-hex\n\
                          hmq1725       Espers\n\
                          jha           jackppot (Jackpotcoin)\n\
                          keccak        Maxcoin\n\
                          keccakc       Creative Coin\n\
                          lbry          LBC, LBRY Credits\n\
                          lyra2h        Hppcoin\n\
                          lyra2re       lyra2\n\
                          lyra2rev2     lyrav2\n\
                          lyra2rev3     lyrav2v3\n\
                          lyra2z\n\
                          lyra2z330     Lyra2 330 rows\n\
                          m7m           Magi (XMG)\n\
                          myr-gr        Myriad-Groestl\n\
                          minotaur\n\
                          minotaurx\n\
                          neoscrypt     NeoScrypt(128, 2, 1)\n\
                          nist5         Nist5\n\
                          pentablake    5 x blake512\n\
                          phi1612       phi\n\
                          phi2\n\
                          polytimos\n\
                          power2b       MicroBitcoin (MBC)\n\
                          quark         Quark\n\
                          qubit         Qubit\n\
                          scrypt        scrypt(1024, 1, 1) (default)\n\
                          scrypt:N      scrypt(N, 1, 1)\n\
                          scryptn2      scrypt(1048576, 1,1)\n\
                          sha256d       Double SHA-256\n\
                          sha256dt      Modified sha256d (Novo)\n\
                          sha256q       Quad SHA-256, Pyrite (PYE)\n\
                          sha256t       Triple SHA-256, Onecoin (OC)\n\
                          sha3d         Double Keccak256 (BSHA3)\n\
                          sha512256d    Double SHA-512 (Radiant)\n\
                          skein         Skein+Sha (Skeincoin)\n\
                          skein2        Double Skein (Woodcoin)\n\
                          skunk         Signatum (SIGT)\n\
                          sonoa         Sono\n\
                          timetravel    timeravel8, Machinecoin (MAC)\n\
                          timetravel10  Bitcore (BTX)\n\
                          tribus        Denarius (DNR)\n\
                          vanilla       blake256r8vnl (VCash)\n\
                          veltor\n\
                          verthash\n\
                          whirlpool\n\
                          whirlpoolx\n\
                          x11           Dash\n\
                          x11evo        Revolvercoin (XRE)\n\
                          x11gost       sib (SibCoin)\n\
                          x12           Galaxie Cash (GCH)\n\
                          x13           X13\n\
                          x13bcd        bcd \n\
                          x13sm3        hsr (Hshare)\n\
                          x14           X14\n\
                          x15           X15\n\
                          x16r\n\
                          x16rv2\n\
                          x16rt         Gincoin (GIN)\n\
                          x16rt-veil    Veil (VEIL)\n\
                          x16s\n\
                          x17\n\
                          x20r\n\
                          x21s\n\
                          x22i\n\
                          x25x\n\
                          xevan         Bitsend (BSD)\n\
                          yescrypt      Globalboost-Y (BSTY)\n\
                          yescryptr8    BitZeny (ZNY)\n\
                          yescryptr8g   Koto (KOTO)\n\
                          yescryptr16   Eli\n\
                          yescryptr32   WAVI\n\
                          yespower      Cryply\n\
                          yespowerr16   Yenten (YTN)\n\
                          yespower-b2b  generic yespower + blake2b\n\
                          zr5           Ziftr\n\
  -N, --param-n=N       N parameter for scrypt based algos\n\
  -R, --param-r=N       R parameter for scrypt based algos\n\
  -K, --param-key=STRING  Key (pers) parameter for algos that use it\n\
  -o, --url=URL         URL of mining server\n\
  -O, --userpass=U:P    username:password pair for mining server\n\
  -u, --user=USERNAME   username for mining server\n\
  -p, --pass=PASSWORD   password for mining server\n\
      --cert=FILE       certificate for mining server using SSL\n\
  -x, --proxy=[PROTOCOL://]HOST[:PORT]  connect through a proxy\n\
  -t, --threads=N       number of miner threads (default: number of processors)\n\
  -r, --retries=N       number of times to retry if a network call fails\n\
                          (default: retry indefinitely)\n\
      --retry-pause=N   time to pause between retries, in seconds (default: 30)\n\
      --time-limit=N    maximum time [s] to mine before exiting the program.\n\
  -T, --timeout=N       timeout for long poll and stratum (default: 300 seconds)\n\
  -s, --scantime=N      upper bound on time spent scanning current work when\n\
                          long polling is unavailable, in seconds (default: 5)\n\
      --randomize       randomize scan range (deprecated)\n\
  -f, --diff-factor=N   divide req. difficulty by this factor (std is 1.0)\n\
  -m, --diff-multiplier=N Multiply difficulty by this factor (std is 1.0)\n\
      --hash-meter      display thread hash rates\n\
      --coinbase-addr=ADDR  payout address for solo mining\n\
      --coinbase-sig=TEXT  data to insert in the coinbase when possible\n\
      --no-longpoll     disable long polling support\n\
      --no-getwork      disable getwork support\n\
      --no-gbt          disable getblocktemplate support\n\
      --no-stratum      disable X-Stratum support\n\
      --no-extranonce   disable Stratum extranonce subscribe\n\
      --no-redirect     ignore requests to change the URL of the mining server\n\
  -q, --quiet           reduce log verbosity\n\
      --no-color        disable colored output\n\
  -D, --debug           enable debug output\n\
  -P, --protocol-dump   verbose dump of protocol-level activities\n"
#ifdef HAVE_SYSLOG_H
"\
  -S, --syslog          use system log for output messages\n"
#endif
"\
  -B, --background      run the miner in the background\n\
      --benchmark       run in offline benchmark mode\n\
      --cpu-affinity    set process affinity to cpu core(s), mask 0x3 for cores 0 and 1\n\
      --cpu-priority    set process priority (default: 0 idle, 2 normal to 5 highest) (deprecated)\n\
  -b, --api-bind=address[:port]   IP address for the miner API, default port is 4048)\n\
      --api-remote      allow remote control\n\
      --max-temp=N      only mine if cpu temp is less than specified value (linux)\n\
      --max-rate=N[KMG] only mine if net hashrate is less than specified value\n\
      --max-diff=N      only mine if net difficulty is less than specified value\n\
  -c, --config=FILE     load a JSON-format configuration file\n\
      --data-file=FILE  path and name of data file\n\
      --verify          enable additional time consuming start up tests\n\
      --stratum-keepalive  prevent disconnects when difficulty is too high\n\
  -V, --version         display version and CPU information and exit\n\
  -h, --help            display this help text and exit\n\
";

#ifdef HAVE_GETOPT_LONG
#include <getopt.h>
#else
struct option {
        const char *name;
        int has_arg;
        int *flag;
        int val;
};
#endif


static struct option const options[] = {
        { "algo", 1, NULL, 'a' },
        { "api-bind", 1, NULL, 'b' },
        { "api-remote", 0, NULL, 1030 },
        { "background", 0, NULL, 'B' },
        { "benchmark", 0, NULL, 1005 },
        { "cputest", 0, NULL, 1006 },
        { "cert", 1, NULL, 1001 },
        { "coinbase-addr", 1, NULL, 1016 },
        { "coinbase-sig", 1, NULL, 1015 },
        { "config", 1, NULL, 'c' },
        { "cpu-affinity", 1, NULL, 1020 },
        { "cpu-priority", 1, NULL, 1021 },
        { "no-color", 0, NULL, 1002 },
        { "debug", 0, NULL, 'D' },
        { "diff-factor", 1, NULL, 'f' },
        { "diff", 1, NULL, 'f' }, // deprecated (alias)
        { "diff-multiplier", 1, NULL, 'm' },
        { "hash-meter", 0, NULL, 1014 },
        { "help", 0, NULL, 'h' },
        { "key", 1, NULL, 'K' },
        { "no-gbt", 0, NULL, 1011 },
        { "no-getwork", 0, NULL, 1010 },
        { "no-longpoll", 0, NULL, 1003 },
        { "no-redirect", 0, NULL, 1009 },
        { "no-stratum", 0, NULL, 1007 },
        { "no-extranonce", 0, NULL, 1012 },
        { "max-temp", 1, NULL, 1060 },
        { "max-diff", 1, NULL, 1061 },
        { "max-rate", 1, NULL, 1062 },
        { "param-key", 1, NULL, 'K' },
        { "param-n", 1, NULL, 'N' },
        { "param-r", 1, NULL, 'R' },
        { "pass", 1, NULL, 'p' },
        { "protocol", 0, NULL, 'P' },
        { "protocol-dump", 0, NULL, 'P' },
        { "proxy", 1, NULL, 'x' },
        { "quiet", 0, NULL, 'q' },
        { "retries", 1, NULL, 'r' },
        { "retry-pause", 1, NULL, 1025 },
        { "randomize", 0, NULL, 1024 },
        { "scantime", 1, NULL, 's' },
#ifdef HAVE_SYSLOG_H
        { "syslog", 0, NULL, 'S' },
#endif
        { "time-limit", 1, NULL, 1008 },
        { "threads", 1, NULL, 't' },
        { "timeout", 1, NULL, 'T' },
        { "url", 1, NULL, 'o' },
        { "user", 1, NULL, 'u' },
        { "userpass", 1, NULL, 'O' },
        { "data-file", 1, NULL, 1027 },
        { "verify", 0, NULL, 1028 },
        { "stratum-keepalive", 0, NULL, 1029 },
        { "version", 0, NULL, 'V' },
        { "bell", 0, NULL, 1031 },
        { 0, 0, 0, 0 }
};


#endif /* __MINER_H__ */

