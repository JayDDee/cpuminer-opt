#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include "miner.h"

/////////////////////////////
////
////    NEW FEATURE: algo_gate
////
////    algos define targets for their common functions
////    and define a function for miner-thread to call to register
////    their targets. miner thread builds the gate, and array of structs
////    of function pointers, by calling each algo's register function.
//
//
// 
//    So you want to add an algo. Well it is a little easier now.
//    Look at existing algos for guidance.
//
//    1. Define the algo, miner.h, previously in cpu-miner.c
//
//    2.Define custom versions of the mandatory function for the new algo.
//
//    3. Next look through the list of unsafe functions to determine
//    if any apply to the new algo. If so they must also be defined.
//
//    4. Look through the list of safe functions to see if any apply
//    to the new algo. If so look at the null instance of the function
//    to see if it satisfies its needs.
//
//    5. If any of the default safe functions are not fit for the new algo
//    a custom function will have to be defined.
//
//    6. Determine if other non existant functions are required.
//    That is determined by the need to add code in cpu-miner.c
//    that applies only to the new algo. That is forbidden. All
//    algo specific code must be in theh algo's file.
//
//    7. If new functions need to be added to the gate add the type
//    to the structure, declare a null instance in this file and define
//    it in algo-gate-api.c. It must be a safe optional function so the null
//    instance must return a success code and otherwise do nothing.
//
//    8. When all the custom functions are defined write a registration
//    function to initialze the gate's function pointers with the custom
//    functions. It is not necessary to initialze safe optional null
//    instances as they are defined by default, or unsafe functions that
//    are not needed by the algo.
//
//    9. Add an case entry to the switch/case in function register_gate
//    in file algo-gate-api.c for the new algo.
//
//    10 If a new function type was defined add an entry to ini talgo_gate
//    to initialize the new function to its null instance described in step 7.
//
//    11. If the new algo has aliases add them to the alias array in
//    algo-gate-api.c 
//
//    12. Include algo-gate-api.h and miner.h inthe algo's source file.
//
//    13. Inlude any other algo source files required by the new algo.
//
//    14. Done, compile and run. 


// declare some function pointers
// mandatory functions require a custom function specific to the algo
// be defined. 
// otherwise the null instance will return a fail code.
// Optional functions may not be required for certain algos or the null
// instance provides a safe default. If the default is suitable for
//  an algo it is not necessary to define a custom function.
//

// my hack at creating a set data type using bit masks. Set inclusion,
// exclusion union and intersection operations are provided for convenience. In // some cases it may be desireable to use boolean algebra directly on the
// data to perfomr set operations. Sets can be represented as single
// elements, a bitwise OR of multiple elements, a bitwise OR of multiple
// set variables or constants, or combinations of the above.
// Examples:
//
// my_set = set_element;
// another_set = my_set | another_set_element;

typedef  uint32_t set_t;

#define EMPTY_SET       0
#define SSE2_OPT        1
#define AES_OPT         2  
#define AVX_OPT         4
#define AVX2_OPT        8
#define SHA_OPT      0x10
//#define FOUR_WAY_OPT 0x20

// return set containing all elements from sets a & b
inline set_t set_union ( set_t a, set_t b ) { return a | b; }

// return set contained common elements from sets a & b
inline set_t set_intsec ( set_t a, set_t b) { return a & b; }

// all elements in set a are included in set b
inline bool set_incl ( set_t a, set_t b ) { return (a & b) == a; }

// no elements in set a are included in set b
inline bool set_excl ( set_t a, set_t b ) { return (a & b) == 0; }

typedef struct
{
// mandatory functions, must be overwritten
int ( *scanhash ) ( int, struct work*, uint32_t, uint64_t* );

// optional unsafe, must be overwritten if algo uses function
void ( *hash )     ( void*, const void*, uint32_t ) ;
void ( *hash_suw ) ( void*, const void* );

//optional, safe to use default in most cases
bool ( *miner_thread_init )      ( int );
void ( *stratum_gen_work )       ( struct stratum_ctx*, struct work* );
void ( *get_new_work )           ( struct work*, struct work*, int, uint32_t*,
                                   bool );
uint32_t *( *get_nonceptr )      ( uint32_t* );
void ( *display_extra_data )     ( struct work*, uint64_t* );
void ( *wait_for_diff )          ( struct stratum_ctx* );
int64_t ( *get_max64 )           ();
bool ( *work_decode )            ( const json_t*, struct work* );
void ( *set_target)              ( struct work*, double );
bool ( *submit_getwork_result )  ( CURL*, struct work* );
void ( *gen_merkle_root )        ( char*, struct stratum_ctx* );
void ( *build_extraheader )      ( struct work*, struct stratum_ctx* );
void ( *build_stratum_request )  ( char*, struct work*, struct stratum_ctx* );
void ( *set_work_data_endian )   ( struct work* );
double ( *calc_network_diff )    ( struct work* );
bool ( *ready_to_mine )          ( struct work*, struct stratum_ctx*, int );
void ( *resync_threads )         ( struct work* );
bool ( *do_this_thread )         ( int );
json_t* (*longpoll_rpc_call)     ( CURL*, int*, char* );
bool ( *stratum_handle_response )( json_t* );
set_t optimizations;
int  ntime_index;
int  nbits_index;
int  nonce_index;            // use with caution, see warning below
int  work_data_size;
int  work_cmp_size;

} algo_gate_t;

extern algo_gate_t algo_gate;

// Declare generic null targets, default for many gate functions
// Functions that use one of these generic targets do not have
// a default defined below. Some algos may override a defined default
// with a generic.
void do_nothing();
bool return_true();
bool return_false();
void *return_null();
void algo_not_tested();
void algo_not_implemented();
void four_way_not_tested();

// Warning: algo_gate.nonce_index should only be used in targetted code
// due to different behaviours by different targets. The JR2 index uses an
// 8 bit offset while all others user 32 bit offset. c/c++ pointer arithmetic
// conventions results in different behaviour for pointers with different
// target sizes requiring customized casting to make it work consistently.
// Rant mode: yet another thing I hate about c/c++. Array indexes should
// be scaled, pointer offsets should always be bytes. No confusion and no
// hidden math.

#define STD_NTIME_INDEX 17
#define STD_NBITS_INDEX 18
#define STD_NONCE_INDEX 19   // 32 bit offset
#define STD_WORK_DATA_SIZE 128
#define STD_WORK_CMP_SIZE 76

#define JR2_NONCE_INDEX 39  // 8 bit offset

// These indexes are only used with JSON RPC2 and are not gated.
#define JR2_WORK_CMP_INDEX_2 43
#define JR2_WORK_CMP_SIZE_2 33

// allways returns failure
int null_scanhash();

// displays warning
void null_hash    ();
void null_hash_suw();

// optional safe targets, default listed first unless noted.

void std_wait_for_diff();

uint32_t *std_get_nonceptr( uint32_t *work_data );
uint32_t *jr2_get_nonceptr( uint32_t *work_data );

void std_get_new_work( struct work *work, struct work *g_work, int thr_id,
                       uint32_t* end_nonce_ptr, bool clean_job );
void jr2_get_new_work( struct work *work, struct work *g_work, int thr_id,
                       uint32_t* end_nonce_ptr );

void std_stratum_gen_work( struct stratum_ctx *sctx, struct work *work );
void jr2_stratum_gen_work( struct stratum_ctx *sctx, struct work *work );

void sha256d_gen_merkle_root( char *merkle_root, struct stratum_ctx *sctx );
void SHA256_gen_merkle_root ( char *merkle_root, struct stratum_ctx *sctx );

// pick your favorite or define your own
int64_t get_max64_0x1fffffLL(); // default
int64_t get_max64_0x40LL();
int64_t get_max64_0x3ffff();
int64_t get_max64_0x3fffffLL();
int64_t get_max64_0x1ffff();
int64_t get_max64_0xffffLL();

void std_set_target(    struct work *work, double job_diff );
void alt_set_target(    struct work* work, double job_diff );
void scrypt_set_target( struct work *work, double job_diff );

bool std_le_work_decode( const json_t *val, struct work *work );
bool std_be_work_decode( const json_t *val, struct work *work );
bool jr2_work_decode( const json_t *val, struct work *work );

bool std_le_submit_getwork_result( CURL *curl, struct work *work );
bool std_be_submit_getwork_result( CURL *curl, struct work *work );
bool jr2_submit_getwork_result( CURL *curl, struct work *work );

void std_le_build_stratum_request( char *req, struct work *work );
void std_be_build_stratum_request( char *req, struct work *work );
void jr2_build_stratum_request   ( char *req, struct work *work );

// Default is do_nothing (assumed LE)
void set_work_data_big_endian( struct work *work );

double std_calc_network_diff( struct work *work );

void std_build_extraheader( struct work *work, struct stratum_ctx *sctx );

json_t* std_longpoll_rpc_call( CURL *curl, int *err, char *lp_url );
json_t* jr2_longpoll_rpc_call( CURL *curl, int *err );

bool std_stratum_handle_response( json_t *val );
bool jr2_stratum_handle_response( json_t *val );

bool std_ready_to_mine( struct work* work, struct stratum_ctx* stratum,
                        int thr_id );

// Gate admin functions

// Called from main to initialize all gate functions and algo-specific data
// by calling the algo's register function.
bool register_algo_gate( int algo, algo_gate_t *gate );

// Override any default gate functions that are applicable and do any other
// algo-specific initialization.
// The register functions for all the algos can be declared here to reduce
// compiler warnings but that's just more work for devs adding new algos.
bool register_algo( algo_gate_t *gate );

// Overrides a common set of functions used by RPC2 and other RPC2-specific
// init. Called by algo's register function before initializing algo-specific
// functions and data.
bool register_json_rpc2( algo_gate_t *gate );

// use this to call the hash function of an algo directly, ie util.c test.
void exec_hash_function( int algo, void *output, const void *pdata );

void get_algo_alias( char** algo_or_alias );

