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
void call_error   () { printf("ERR: Uninitialized function pointer\n"); }

void algo_not_tested()
{
  applog( LOG_WARNING,"Algo %s has not been tested live. It may not work",
          algo_names[opt_algo] );
  applog(LOG_WARNING,"and bad things may happen. Use at your own risk.");
}

void four_way_not_tested()
{
  applog( LOG_WARNING,"Algo %s has not been tested using 4way. It may not", algo_names[opt_algo] );
  applog( LOG_WARNING,"work or may be slower. Please report your results.");
}

void algo_not_implemented()
{
  applog(LOG_ERR,"Algo %s has not been Implemented.",algo_names[opt_algo]);
}

// default null functions
// deprecated, use generic as default
int null_scanhash()
{
   applog(LOG_WARNING,"SWERR: undefined scanhash function in algo_gate");
   return 0;
}

// Default generic scanhash can be used in many cases.
int scanhash_generic( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t edata[20] __attribute__((aligned(64)));
   uint32_t hash[8] __attribute__((aligned(64)));
   uint32_t *pdata = work->data;
   uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 1;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const bool bench = opt_benchmark;

   mm128_bswap32_80( edata, pdata );
   do
   {
      edata[19] = n;
      if ( likely( algo_gate.hash( hash, edata, thr_id ) ) )
      if ( unlikely( valid_hash( hash, ptarget ) && !bench ) )
      {
         pdata[19] = bswap_32( n );
         submit_solution( work, hash, mythr );
      }
      n++;
   } while ( n < last_nonce && !work_restart[thr_id].restart );
   *hashes_done = n - first_nonce;
   pdata[19] = n;
   return 0;
}

#if defined(__AVX2__)

//int scanhash_4way_64_64( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

//int scanhash_4way_64_640( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

int scanhash_4way_64in_32out( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*4] __attribute__ ((aligned (64)));
   uint32_t vdata[20*4] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash32_d7 = &(hash32[ 7*4 ]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 4;
   __m256i  *noncev = (__m256i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const bool bench = opt_benchmark;

   mm256_bswap32_intrlv80_4x64( vdata, pdata );
   *noncev = mm256_intrlv_blend_32(
                   _mm256_set_epi32( n+3, 0, n+2, 0, n+1, 0, n, 0 ), *noncev );
   do
   {
      if ( likely( algo_gate.hash( hash32, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 4; lane++ )
      if ( unlikely( hash32_d7[ lane ] <= targ32_d7 && !bench ) )
      {
         extr_lane_4x32( lane_hash, hash32, lane, 256 );
         if ( valid_hash( lane_hash, ptarget ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm256_add_epi32( *noncev,
                                  m256_const1_64( 0x0000000400000000 ) );
      n += 4;
   } while ( likely( ( n <= last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

//int scanhash_8way_32_32( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

#endif

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

//int scanhash_8way_64_64( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

//int scanhash_8way_64_640( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

int scanhash_8way_64in_32out( struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr )
{
   uint32_t hash32[8*8] __attribute__ ((aligned (128)));
   uint32_t vdata[20*8] __attribute__ ((aligned (64)));
   uint32_t lane_hash[8] __attribute__ ((aligned (64)));
   uint32_t *hash32_d7 = &(hash32[7*8]);
   uint32_t *pdata = work->data;
   const uint32_t *ptarget = work->target;
   const uint32_t first_nonce = pdata[19];
   const uint32_t last_nonce = max_nonce - 8;
   __m512i  *noncev = (__m512i*)vdata + 9;
   uint32_t n = first_nonce;
   const int thr_id = mythr->id;
   const uint32_t targ32_d7 = ptarget[7];
   const bool bench = opt_benchmark;

   mm512_bswap32_intrlv80_8x64( vdata, pdata );
   *noncev = mm512_intrlv_blend_32(
              _mm512_set_epi32( n+7, 0, n+6, 0, n+5, 0, n+4, 0,
                                n+3, 0, n+2, 0, n+1, 0, n,   0 ), *noncev );
   do
   {
      if ( likely( algo_gate.hash( hash32, vdata, thr_id ) ) )
      for ( int lane = 0; lane < 8; lane++ )
      if ( unlikely( ( hash32_d7[ lane ] <= targ32_d7 ) && !bench ) )
      {
         extr_lane_8x32( lane_hash, hash32, lane, 256 );
         if ( likely( valid_hash( lane_hash, ptarget ) ) )
         {
            pdata[19] = bswap_32( n + lane );
            submit_solution( work, lane_hash, mythr );
         }
      }
      *noncev = _mm512_add_epi32( *noncev,
                                  m512_const1_64( 0x0000000800000000 ) );
      n += 8;
   } while ( likely( ( n < last_nonce ) && !work_restart[thr_id].restart ) );
   pdata[19] = n;
   *hashes_done = n - first_nonce;
   return 0;
}

//int scanhash_16way_32_32( struct work *work, uint32_t max_nonce,
//                      uint64_t *hashes_done, struct thr_info *mythr )

#endif



int null_hash()
{
   applog(LOG_WARNING,"SWERR: null_hash unsafe null function");
   return 0;
};

void init_algo_gate( algo_gate_t* gate )
{
   gate->miner_thread_init       = (void*)&return_true;
   gate->scanhash                = (void*)&scanhash_generic;
   gate->hash                    = (void*)&null_hash;
   gate->get_new_work            = (void*)&std_get_new_work;
   gate->work_decode             = (void*)&std_le_work_decode;
   gate->decode_extra_data       = (void*)&do_nothing;
   gate->gen_merkle_root         = (void*)&sha256d_gen_merkle_root;
   gate->build_stratum_request   = (void*)&std_le_build_stratum_request;
   gate->malloc_txs_request      = (void*)&std_malloc_txs_request;
   gate->submit_getwork_result   = (void*)&std_le_submit_getwork_result;
   gate->build_block_header      = (void*)&std_build_block_header;
   gate->build_extraheader       = (void*)&std_build_extraheader;
   gate->set_work_data_endian    = (void*)&do_nothing;
   gate->calc_network_diff       = (void*)&std_calc_network_diff;
   gate->ready_to_mine           = (void*)&std_ready_to_mine;
   gate->resync_threads          = (void*)&do_nothing;
   gate->do_this_thread          = (void*)&return_true;
   gate->longpoll_rpc_call       = (void*)&std_longpoll_rpc_call;
   gate->get_work_data_size      = (void*)&std_get_work_data_size;
   gate->optimizations           = EMPTY_SET;
   gate->ntime_index             = STD_NTIME_INDEX;
   gate->nbits_index             = STD_NBITS_INDEX;
   gate->nonce_index             = STD_NONCE_INDEX;
   gate->work_cmp_size           = STD_WORK_CMP_SIZE;
}

// Ignore warnings for not yet defined register functions
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wimplicit-function-declaration"

// Called once by main
bool register_algo_gate( int algo, algo_gate_t *gate )
{
  bool rc = false;

  if ( NULL == gate )
  {
    applog(LOG_ERR,"FAIL: algo_gate registration failed, NULL gate\n");
    return false;
  }

  init_algo_gate( gate );

  switch ( algo )
  {
    case ALGO_ALLIUM:       rc = register_allium_algo        ( gate ); break;
    case ALGO_ANIME:        rc = register_anime_algo         ( gate ); break;
    case ALGO_ARGON2:       rc = register_argon2_algo        ( gate ); break;
    case ALGO_ARGON2D250:   rc = register_argon2d_crds_algo  ( gate ); break;
    case ALGO_ARGON2D500:   rc = register_argon2d_dyn_algo   ( gate ); break;
    case ALGO_ARGON2D4096:  rc = register_argon2d4096_algo   ( gate ); break;
    case ALGO_AXIOM:        rc = register_axiom_algo         ( gate ); break;
    case ALGO_BLAKE:        rc = register_blake_algo         ( gate ); break;
    case ALGO_BLAKE2B:      rc = register_blake2b_algo       ( gate ); break;
    case ALGO_BLAKE2S:      rc = register_blake2s_algo       ( gate ); break;
    case ALGO_BLAKECOIN:    rc = register_blakecoin_algo     ( gate ); break;
    case ALGO_BMW512:       rc = register_bmw512_algo        ( gate ); break;
    case ALGO_C11:          rc = register_c11_algo           ( gate ); break;
    case ALGO_DECRED:       rc = register_decred_algo        ( gate ); break;
    case ALGO_DEEP:         rc = register_deep_algo          ( gate ); break;
    case ALGO_DMD_GR:       rc = register_dmd_gr_algo        ( gate ); break;
    case ALGO_GROESTL:      rc = register_groestl_algo       ( gate ); break;
    case ALGO_HEX:          rc = register_hex_algo           ( gate ); break;
    case ALGO_HMQ1725:      rc = register_hmq1725_algo       ( gate ); break;
    case ALGO_HODL:         rc = register_hodl_algo          ( gate ); break;
    case ALGO_JHA:          rc = register_jha_algo           ( gate ); break;
    case ALGO_KECCAK:       rc = register_keccak_algo        ( gate ); break;
    case ALGO_KECCAKC:      rc = register_keccakc_algo       ( gate ); break;
    case ALGO_LBRY:         rc = register_lbry_algo          ( gate ); break;
    case ALGO_LYRA2H:       rc = register_lyra2h_algo        ( gate ); break;
    case ALGO_LYRA2RE:      rc = register_lyra2re_algo       ( gate ); break;
    case ALGO_LYRA2REV2:    rc = register_lyra2rev2_algo     ( gate ); break;
    case ALGO_LYRA2REV3:    rc = register_lyra2rev3_algo     ( gate ); break;
    case ALGO_LYRA2Z:       rc = register_lyra2z_algo        ( gate ); break;
    case ALGO_LYRA2Z330:    rc = register_lyra2z330_algo     ( gate ); break;
    case ALGO_M7M:          rc = register_m7m_algo           ( gate ); break;
    case ALGO_MINOTAUR:     rc = register_minotaur_algo      ( gate ); break;
    case ALGO_MYR_GR:       rc = register_myriad_algo        ( gate ); break;
    case ALGO_NEOSCRYPT:    rc = register_neoscrypt_algo     ( gate ); break;
    case ALGO_NIST5:        rc = register_nist5_algo         ( gate ); break;
    case ALGO_PENTABLAKE:   rc = register_pentablake_algo    ( gate ); break;
    case ALGO_PHI1612:      rc = register_phi1612_algo       ( gate ); break;
    case ALGO_PHI2:         rc = register_phi2_algo          ( gate ); break;
    case ALGO_POLYTIMOS:    rc = register_polytimos_algo     ( gate ); break;
    case ALGO_POWER2B:      rc = register_power2b_algo       ( gate ); break;
    case ALGO_QUARK:        rc = register_quark_algo         ( gate ); break;
    case ALGO_QUBIT:        rc = register_qubit_algo         ( gate ); break;
    case ALGO_SCRYPT:       rc = register_scrypt_algo        ( gate ); break;
    case ALGO_SHA256D:      rc = register_sha256d_algo       ( gate ); break;
    case ALGO_SHA256Q:      rc = register_sha256q_algo       ( gate ); break;
    case ALGO_SHA256T:      rc = register_sha256t_algo       ( gate ); break;
    case ALGO_SHA3D:        rc = register_sha3d_algo         ( gate ); break;
    case ALGO_SHAVITE3:     rc = register_shavite_algo       ( gate ); break;
    case ALGO_SKEIN:        rc = register_skein_algo         ( gate ); break;
    case ALGO_SKEIN2:       rc = register_skein2_algo        ( gate ); break;
    case ALGO_SKUNK:        rc = register_skunk_algo         ( gate ); break;
    case ALGO_SONOA:        rc = register_sonoa_algo         ( gate ); break;
    case ALGO_TIMETRAVEL:   rc = register_timetravel_algo    ( gate ); break;
    case ALGO_TIMETRAVEL10: rc = register_timetravel10_algo  ( gate ); break;
    case ALGO_TRIBUS:       rc = register_tribus_algo        ( gate ); break;
    case ALGO_VANILLA:      rc = register_vanilla_algo       ( gate ); break;
    case ALGO_VELTOR:       rc = register_veltor_algo        ( gate ); break;
    case ALGO_VERTHASH:     rc = register_verthash_algo      ( gate ); break;
    case ALGO_WHIRLPOOL:    rc = register_whirlpool_algo     ( gate ); break;
    case ALGO_WHIRLPOOLX:   rc = register_whirlpoolx_algo    ( gate ); break;
    case ALGO_X11:          rc = register_x11_algo           ( gate ); break;
    case ALGO_X11EVO:       rc = register_x11evo_algo        ( gate ); break;
    case ALGO_X11GOST:      rc = register_x11gost_algo       ( gate ); break;
    case ALGO_X12:          rc = register_x12_algo           ( gate ); break;
    case ALGO_X13:          rc = register_x13_algo           ( gate ); break;
    case ALGO_X13BCD:       rc = register_x13bcd_algo        ( gate ); break;
    case ALGO_X13SM3:       rc = register_x13sm3_algo        ( gate ); break;
    case ALGO_X14:          rc = register_x14_algo           ( gate ); break;
    case ALGO_X15:          rc = register_x15_algo           ( gate ); break;
    case ALGO_X16R:         rc = register_x16r_algo          ( gate ); break;
    case ALGO_X16RV2:       rc = register_x16rv2_algo        ( gate ); break;
    case ALGO_X16RT:        rc = register_x16rt_algo         ( gate ); break;
    case ALGO_X16RT_VEIL:   rc = register_x16rt_veil_algo    ( gate ); break;
    case ALGO_X16S:         rc = register_x16s_algo          ( gate ); break;
    case ALGO_X17:          rc = register_x17_algo           ( gate ); break;
    case ALGO_X21S:         rc = register_x21s_algo          ( gate ); break;
    case ALGO_X22I:         rc = register_x22i_algo          ( gate ); break;
    case ALGO_X25X:         rc = register_x25x_algo          ( gate ); break;
    case ALGO_XEVAN:        rc = register_xevan_algo         ( gate ); break;
    case ALGO_YESCRYPT:     rc = register_yescrypt_05_algo   ( gate ); break;
//    case ALGO_YESCRYPT:      register_yescrypt_algo      ( gate ); break;
    case ALGO_YESCRYPTR8:   rc = register_yescryptr8_05_algo ( gate ); break;
//    case ALGO_YESCRYPTR8:    register_yescryptr8_algo    ( gate ); break;
    case ALGO_YESCRYPTR8G:  rc = register_yescryptr8g_algo   ( gate ); break;
    case ALGO_YESCRYPTR16:  rc = register_yescryptr16_05_algo( gate ); break;
//    case ALGO_YESCRYPTR16:   register_yescryptr16_algo   ( gate ); break;
    case ALGO_YESCRYPTR32:  rc = register_yescryptr32_05_algo( gate ); break;
//    case ALGO_YESCRYPTR32:   register_yescryptr32_algo   ( gate ); break;
    case ALGO_YESPOWER:     rc = register_yespower_algo      ( gate ); break;
    case ALGO_YESPOWERR16:  rc = register_yespowerr16_algo   ( gate ); break;
    case ALGO_YESPOWER_B2B: rc = register_yespower_b2b_algo  ( gate ); break;
    case ALGO_ZR5:          rc = register_zr5_algo           ( gate ); break;
   default:
      applog(LOG_ERR,"BUG: unregistered algorithm %s.\n", algo_names[opt_algo] );
      return false;
  } // switch

  if ( !rc )
  {
    applog(LOG_ERR, "FAIL: %s algorithm failed to initialize\n", algo_names[opt_algo] );
    return false;
  }
  return true;
}

// restore warnings
#pragma GCC diagnostic pop

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
  { "argon2d-dyn",       "argon2d500"     },
  { "argon2d-uis",       "argon2d4096"    },
  { "bcd",               "x13bcd"         },
  { "bitcore",           "timetravel10"   },
  { "bitzeny",           "yescryptr8"     },
  { "blake256r8",        "blakecoin"      },
  { "blake256r8vnl",     "vanilla"        },
  { "blake256r14",       "blake"          },
  { "blake256r14dcr",    "decred"         },
  { "diamond",           "dmd-gr"         },
  { "espers",            "hmq1725"        },
  { "flax",              "c11"            },
  { "hsr",               "x13sm3"         },
  { "jackpot",           "jha"            },
  { "lyra2",             "lyra2re"        },
  { "lyra2v2",           "lyra2rev2"      },
  { "lyra2v3",           "lyra2rev3"      },
  { "myrgr",             "myr-gr"         },
  { "myriad",            "myr-gr"         },
  { "neo",               "neoscrypt"      },
  { "phi",               "phi1612"        },
  { "scryptn2",          "scrypt:1048576" },
  { "sib",               "x11gost"        },
  { "timetravel8",       "timetravel"     },
  { "veil",              "x16rt-veil"     },
  { "x16r-hex",          "hex"            },
  { "yenten",            "yescryptr16"    },
  { "ziftr",             "zr5"            },
  { NULL,                NULL             }   
};

// if arg is a valid alias for a known algo it is updated with the proper
// name. No validation of the algo or alias is done, It is the responsinility
// of the calling function to validate the algo after return.
void get_algo_alias( char** algo_or_alias )
{
  int i;
  for ( i=0; algo_alias_map[i][ALIAS]; i++ )
    if ( !strcasecmp( *algo_or_alias, algo_alias_map[i][ ALIAS ] ) )
    {
      // found valid alias, return proper name
      *algo_or_alias = (char*)( algo_alias_map[i][ PROPER ] );
      return;
    }
}

#undef ALIAS
#undef PROPER

