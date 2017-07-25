/////////////////////////////
////
////    NEW FEATURE: algo_gate
////
////    algos define targets for their common functions
////    and define a function for miner-thread to call to register
////    their targets. miner thread builds the gate, and array of structs
////    of function pointers, by calling each algo's register function.
//   Functions in this file are used simultaneously by myultiple
//   threads and must therefore be re-entrant.

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <memory.h>
#include <unistd.h>
#include <openssl/sha.h>
#include "miner.h"
#include "algo-gate-api.h"

// Define null and standard functions.
//
// Generic null functions do nothing except satisfy the syntax and
// can be used for optional safe gate functions.
//
// null gate functions are genarally used for mandatory and unsafe functions
// and will usually display an error massage and/or return a fail code.
// They are registered by default and are expected to be overwritten.
//
// std functions are non-null functions used by the most number of algos
// are are default.
//
// aux functions are functions used by many, but not most, algos and must
// be registered by eech algo using them. They usually have descriptive
// names.
//
// custom functions are algo spefic and are defined and registered in the
// algo's source file and are usually named [algo]_[function]. 
//
// In most cases the default is a null or std function. However in some
// cases, for convenience when the null function is not the most popular,
// the std function will be defined as default and the algo must register
// an appropriate null function.
//
// similar algos may share a gate function that may be defined here or
// in a source file common to the similar algos.
//
// gate functions may call other gate functions under the following
// restrictions. Any gate function defined here or used by more than one
// algo must call other functions using the gate: algo_gate.[function]. 
// custom functions may call other custom functions directly using
// [algo]_[function], howver it is recommended to alway use the gate.
//
// If, under rare circumstances, an algo with a custom gate function 
// needs to call a function of another algo it must define and register
// a private gate from its rgistration function and use it to call
// forein functions: [private_gate].[function]. If the algo needs to call
// a utility function defined here it may do so directly.
//
// The algo's gate registration function is caled once from the main thread
// and can do other intialization in addition such as setting options or
// other global or local (to the algo) variables.

// A set of predefined generic null functions that can be used as any null
// gate function with the same signature. 

void do_nothing   () {}
bool return_true  () { return true;  }
bool return_false () { return false; }
void *return_null () { return NULL;  }

void algo_not_tested()
{
  applog( LOG_WARNING,"Algo %s has not been tested live. It may not work",
          algo_names[opt_algo] );
  applog(LOG_WARNING,"and bad things may happen. Use at your own risk.");
}

void algo_not_implemented()
{
  applog(LOG_ERR,"Algo %s has not been Implemented.",algo_names[opt_algo]);
}

// default null functions

int null_scanhash()
{
   applog(LOG_WARNING,"SWERR: undefined scanhash function in algo_gate");
   return 0;
}

void null_hash()
{
   applog(LOG_WARNING,"SWERR: null_hash unsafe null function");
};
void null_hash_suw()
{
  applog(LOG_WARNING,"SWERR: null_hash_suw unsafe null function");
};

void init_algo_gate( algo_gate_t* gate )
{
   gate->miner_thread_init       = (void*)&return_true;
   gate->scanhash                = (void*)&null_scanhash;
   gate->hash                    = (void*)&null_hash;
   gate->hash_suw                = (void*)&null_hash_suw;
   gate->get_new_work            = (void*)&std_get_new_work;
   gate->get_nonceptr            = (void*)&std_get_nonceptr;
   gate->display_extra_data      = (void*)&do_nothing;
   gate->wait_for_diff           = (void*)&std_wait_for_diff;
   gate->get_max64               = (void*)&get_max64_0x1fffffLL;
   gate->gen_merkle_root         = (void*)&sha256d_gen_merkle_root;
   gate->stratum_gen_work        = (void*)&std_stratum_gen_work;
   gate->build_stratum_request   = (void*)&std_le_build_stratum_request;
   gate->set_target              = (void*)&std_set_target;
   gate->work_decode             = (void*)&std_work_decode;
   gate->submit_getwork_result   = (void*)&std_submit_getwork_result;
   gate->build_extraheader       = (void*)&std_build_extraheader;
   gate->set_work_data_endian    = (void*)&do_nothing;
   gate->calc_network_diff       = (void*)&std_calc_network_diff;
   gate->ready_to_mine           = (void*)&std_ready_to_mine;
   gate->resync_threads          = (void*)&do_nothing;
   gate->do_this_thread          = (void*)&return_true;
   gate->longpoll_rpc_call       = (void*)&std_longpoll_rpc_call;
   gate->stratum_handle_response = (void*)&std_stratum_handle_response;
   gate->optimizations           = SSE2_OPT;
   gate->ntime_index             = STD_NTIME_INDEX;
   gate->nbits_index             = STD_NBITS_INDEX;
   gate->nonce_index             = STD_NONCE_INDEX;
   gate->work_data_size          = STD_WORK_DATA_SIZE;
   gate->work_cmp_size           = STD_WORK_CMP_SIZE;
}

// called by each thread that uses the gate
bool register_algo_gate( int algo, algo_gate_t *gate )
{
   if ( NULL == gate )
   {
     applog(LOG_ERR,"FAIL: algo_gate registration failed, NULL gate\n");
     return false;
   }

   init_algo_gate( gate );

   switch (algo)
   {

// Ignore warnings for not yet defined register fucntions
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

     case ALGO_ARGON2:       register_argon2_algo      ( gate ); break;
     case ALGO_AXIOM:        register_axiom_algo       ( gate ); break;
     case ALGO_BASTION:      register_bastion_algo     ( gate ); break;
     case ALGO_BLAKE:        register_blake_algo       ( gate ); break;
     case ALGO_BLAKECOIN:    register_blakecoin_algo   ( gate ); break;
//     case ALGO_BLAKE2B:      register_blake2b_algo    ( gate ); break;
     case ALGO_BLAKE2S:      register_blake2s_algo     ( gate ); break;
     case ALGO_C11:          register_c11_algo         ( gate ); break;
     case ALGO_CRYPTOLIGHT:  register_cryptolight_algo ( gate ); break;
     case ALGO_CRYPTONIGHT:  register_cryptonight_algo ( gate ); break;
     case ALGO_DECRED:       register_decred_algo      ( gate ); break;
     case ALGO_DEEP:         register_deep_algo        ( gate ); break;
     case ALGO_DMD_GR:       register_dmd_gr_algo      ( gate ); break;
     case ALGO_DROP:         register_drop_algo        ( gate ); break;
     case ALGO_FRESH:        register_fresh_algo       ( gate ); break;
     case ALGO_GROESTL:      register_groestl_algo     ( gate ); break;
     case ALGO_HEAVY:        register_heavy_algo       ( gate ); break;
     case ALGO_HMQ1725:      register_hmq1725_algo     ( gate ); break;
     case ALGO_HODL:         register_hodl_algo        ( gate ); break;
     case ALGO_JHA:          register_jha_algo         ( gate ); break;
     case ALGO_KECCAK:       register_keccak_algo      ( gate ); break;
     case ALGO_LBRY:         register_lbry_algo        ( gate ); break;
     case ALGO_LUFFA:        register_luffa_algo       ( gate ); break;
     case ALGO_LYRA2RE:      register_lyra2re_algo     ( gate ); break;
     case ALGO_LYRA2REV2:    register_lyra2rev2_algo   ( gate ); break;
     case ALGO_LYRA2Z:       register_zcoin_algo       ( gate ); break;
     case ALGO_LYRA2Z330:    register_lyra2z330_algo   ( gate ); break;
     case ALGO_M7M:          register_m7m_algo         ( gate ); break;
     case ALGO_MYR_GR:       register_myriad_algo      ( gate ); break;
     case ALGO_NEOSCRYPT:    register_neoscrypt_algo   ( gate ); break;
     case ALGO_NIST5:        register_nist5_algo       ( gate ); break;
     case ALGO_PENTABLAKE:   register_pentablake_algo  ( gate ); break;
     case ALGO_PLUCK:        register_pluck_algo       ( gate ); break;
     case ALGO_QUARK:        register_quark_algo       ( gate ); break;
     case ALGO_QUBIT:        register_qubit_algo       ( gate ); break;
     case ALGO_SCRYPT:       register_scrypt_algo      ( gate ); break;
     case ALGO_SCRYPTJANE:   register_scryptjane_algo  ( gate ); break;
     case ALGO_SHA256D:      register_sha256d_algo     ( gate ); break;
     case ALGO_SHA256T:      register_sha256t_algo     ( gate ); break;
     case ALGO_SHAVITE3:     register_shavite_algo     ( gate ); break;
     case ALGO_SKEIN:        register_skein_algo       ( gate ); break;
     case ALGO_SKEIN2:       register_skein2_algo      ( gate ); break;
     case ALGO_SKUNK:        register_skunk_algo       ( gate ); break;
     case ALGO_TIMETRAVEL:   register_timetravel_algo  ( gate ); break;
     case ALGO_TIMETRAVEL10: register_timetravel10_algo( gate ); break;
     case ALGO_TRIBUS:       register_tribus_algo      ( gate ); break;
     case ALGO_VANILLA:      register_vanilla_algo     ( gate ); break;
     case ALGO_VELTOR:       register_veltor_algo      ( gate ); break;
     case ALGO_WHIRLPOOL:    register_whirlpool_algo   ( gate ); break;
     case ALGO_WHIRLPOOLX:   register_whirlpoolx_algo  ( gate ); break;
     case ALGO_X11:          register_x11_algo         ( gate ); break;
     case ALGO_X11EVO:       register_x11evo_algo      ( gate ); break;
     case ALGO_X11GOST:      register_sib_algo         ( gate ); break;
     case ALGO_X13:          register_x13_algo         ( gate ); break;
     case ALGO_X14:          register_x14_algo         ( gate ); break;
     case ALGO_X15:          register_x15_algo         ( gate ); break;
     case ALGO_X17:          register_x17_algo         ( gate ); break;
     case ALGO_XEVAN:        register_xevan_algo       ( gate ); break;
     case ALGO_YESCRYPT:     register_yescrypt_algo    ( gate ); break;
     case ALGO_ZR5:          register_zr5_algo         ( gate ); break;

// restore warnings
#pragma GCC diagnostic pop

    default:
        applog(LOG_ERR,"FAIL: algo_gate registration failed, unknown algo %s.\n", algo_names[opt_algo] );
        return false;
   } // switch

  // ensure required functions were defined.
  if (  gate->scanhash == (void*)&null_scanhash )
  {
    applog(LOG_ERR, "FAIL: Required algo_gate functions undefined\n");
    return false;
  }
  return true;
}

// override std defaults with jr2 defaults
bool register_json_rpc2( algo_gate_t *gate )
{
  gate->wait_for_diff           = (void*)&do_nothing;
  gate->get_new_work            = (void*)&jr2_get_new_work;
  gate->get_nonceptr            = (void*)&jr2_get_nonceptr;
  gate->stratum_gen_work        = (void*)&jr2_stratum_gen_work;
  gate->build_stratum_request   = (void*)&jr2_build_stratum_request;
  gate->submit_getwork_result   = (void*)&jr2_submit_getwork_result;
  gate->longpoll_rpc_call       = (void*)&jr2_longpoll_rpc_call;
  gate->work_decode             = (void*)&jr2_work_decode;
  gate->stratum_handle_response = (void*)&jr2_stratum_handle_response;
  gate->nonce_index             = JR2_NONCE_INDEX;
  jsonrpc_2 = true;   // still needed
  opt_extranonce = false;
//  have_gbt = false;
  return true;
 }

// run the alternate hash function for a specific algo
void exec_hash_function( int algo, void *output, const void *pdata )
{
  algo_gate_t gate;   
  gate.hash = (void*)&null_hash;
  register_algo_gate( algo, &gate );
  gate.hash( output, pdata, 0 );  
}

#define PROPER (1)
#define ALIAS  (0)

// The only difference between the alias and the proper algo name is the
// proper name is the one that is defined in ALGO_NAMES. There may be
// multiple aliases that map to the same proper name.
// New aliases can be added anywhere in the array as long as NULL is last.
// Alphabetic order of alias is recommended.
const char* const algo_alias_map[][2] =
{
//   alias                proper
  { "bitcore",           "timetravel10" },
  { "blake256r8",        "blakecoin"    },
  { "blake256r8vnl",     "vanilla"      },
  { "blake256r14",       "blake"        },
  { "blake256r14dcr",    "decred"       },
  { "cryptonote",        "cryptonight"  },
  { "cryptonight-light", "cryptolight"  },
  { "diamond",           "dmd-gr"       },
  { "droplp",            "drop"         },
  { "espers",            "hmq1725"      },
  { "flax",              "c11"          },
  { "jackpot",           "jha"          },
  { "jane",              "scryptjane"   }, 
  { "lyra2",             "lyra2re"      },
  { "lyra2v2",           "lyra2rev2"    },
  { "lyra2zoin",         "lyra2z330"    },
  { "myriad",            "myr-gr"       },
  { "neo",               "neoscrypt"    },
//  { "sia",               "blake2b"      },
  { "sib",               "x11gost"      },
  { "timetravel8",       "timetravel"   },
  { "yes",               "yescrypt"     },
  { "ziftr",             "zr5"          },
  { "zcoin",             "lyra2z"       },
  { "zoin",              "lyra2z330"    },
  { NULL,                NULL           }   
};

// if arg is a valid alias for a known algo it is updated with the proper name.
// No validation of the algo or alias is done, It is the responsinility of the
// calling function to validate the algo after return.
void get_algo_alias( char** algo_or_alias )
{
  int i;
  for ( i=0; algo_alias_map[i][ALIAS]; i++ )
    if ( !strcasecmp( *algo_or_alias, algo_alias_map[i][ ALIAS ] ) )
    {
      // found valid alias, return proper name
      *algo_or_alias = (char* const)( algo_alias_map[i][ PROPER ] );
      return;
    }
}

