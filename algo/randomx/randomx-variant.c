/* RandomX variant selection.
 *
 * The pool tells us which variant a job is for, and the miner is built for a
 * fixed set. Only variants whose entire difference from rx/0 is the argon2
 * salt can live here: the salt is read once per epoch during cache init and
 * never reaches the VM or the JIT, so it is a runtime parameter. Anything
 * that moves a VM or JIT constant (scratchpad sizes, program size or
 * iterations, instruction frequencies, superscalar latency) is baked into
 * fixed array bounds and hand-written assembly and needs its own compiled
 * core -- do not add such a variant to this table, it would mine rejects.
 *
 * Every salt here must be derived from the coin's own consensus source, with
 * the provenance recorded in config/<variant>.h.
 */

#include <string.h>
#include "randomx-gate.h"
#include "randomx/randomx.h"
#include "miner.h"
#include "config/sfx.h"
#include "randomx-core.h"

/* Set in the vendored core (randomx/dataset.cpp). Defaults to rx/0's salt. */
extern const unsigned char *randomx_argon_salt;
extern unsigned int         randomx_argon_salt_len;

/* Length of a string literal's bytes, excluding the terminator. */
#define RX_SALT( s ) (const unsigned char *)( s ), (unsigned)( sizeof( s ) - 1 )

static const rx_variant_t rx_variants[] =
{
   /* algo, pool string, salt (NULL = core default), startup check, core */
   { ALGO_RANDOMX,     "rx/0",   NULL, 0, NULL,              NULL },

   /* Not a RandomX variant: k12 is here only for the dialect set and the
    * pool's algo string. No salt, no core, no VM; selected with
    * rx_variant_select_plain(), and kept off the dataset path by
    * rx_algo_needs_seed(). */
   { ALGO_K12,         "k12",    NULL, 0, NULL,              NULL },

   /* Tier 1: stock core, salt applied at runtime. */
   { ALGO_RANDOMX_SFX, "rx/sfx", RX_SALT( RANDOMX_ARGON_SALT_SFX ),
                                       rx_kat_sfx_vector, NULL },

   /* Tier 2: its own compiled core, so the salt is already baked in and must
    * NOT also be set at runtime -- config/wow.h supplied it at compile time. */
#if defined(RANDOMX_HAVE_WOW_CORE)
   { ALGO_RANDOMX_WOW, "rx/wow", NULL, 0, NULL,              &rx_core_wow },
#endif
#if defined(RANDOMX_HAVE_GRAFT_CORE)
   { ALGO_RANDOMX_GRAFT, "rx/graft", NULL, 0, rx_variant_graft_vectors,
                                                             &rx_core_graft },
#endif
#if defined(RANDOMX_HAVE_ARQ_CORE)
   { ALGO_RANDOMX_ARQ, "rx/arq", NULL, 0, rx_variant_arq_vectors,
                                                              &rx_core_arq },
#endif

   /* Scala. Not an "rx/" name: its pool string is plain "panthera", and it
    * is more than a configuration -- its core also carries a seed hook that
    * runs yespower and KangarooTwelve (algo/randomx/panthera-seed.c). */
#if defined(RANDOMX_HAVE_PANTHERA_CORE)
   { ALGO_PANTHERA, "panthera", NULL, 0, rx_variant_panthera_vectors,
                                                         &rx_core_panthera },
#endif
};

static const rx_variant_t *rx_cur = &rx_variants[0];

/* Hash one fixed input through `core` with `salt` in force. */
static bool rx_probe( const rx_core_t *core, const unsigned char *salt,
                      unsigned salt_len, unsigned char out[32] )
{
   static const char key[] = "probe key";
   static const char in[]  = "probe input";
   const unsigned char *saved_salt = randomx_argon_salt;
   unsigned int         saved_len  = randomx_argon_salt_len;
   randomx_cache *cache;
   randomx_vm *vm;
   bool ok = false;

   if ( salt ) { randomx_argon_salt = salt; randomx_argon_salt_len = salt_len; }

   cache = core->alloc_cache( core->get_flags()
                              & ( RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2 ) );
   if ( cache )
   {
      core->init_cache( cache, key, sizeof key - 1 );
      vm = core->create_vm( RANDOMX_FLAG_DEFAULT, cache, NULL );
      if ( vm )
      {
         core->calculate_hash( vm, in, sizeof in - 1, out );
         core->destroy_vm( vm );
         ok = true;
      }
      core->release_cache( cache );
   }

   randomx_argon_salt     = saved_salt;
   randomx_argon_salt_len = saved_len;
   return ok;
}

/* Fallback check for a variant with no published or accepted-share vector:
 * the selected variant must not hash identically to rx/0.
 *
 * Compares the two configurations against each other rather than against a
 * baked digest, so it needs no vectors and works for both tiers -- a tier-1
 * variant differs only by the runtime salt, a tier-2 one by its whole core.
 * It cannot prove a digest is CORRECT (only a pool can, until an accepted
 * share is promoted to a vector), but it catches the failure that silently
 * mines rejects: a variant that is really still rx/0 because its salt never
 * reached the core, or because its core was linked to stock internals.
 */
bool rx_variant_differs_from_rx0( void )
{
   unsigned char mine[32], rx0[32];

   if ( !rx_probe( rx_core, rx_cur->salt, rx_cur->salt_len, mine ) )
   {
      applog( LOG_ERR, "RandomX %s: could not build a probe VM",
              rx_cur->pool_algo );
      return false;
   }
   /* rx/0 = the stock core with its compile-time salt, i.e. no override. */
   if ( !rx_probe( &rx_core_stock, NULL, 0, rx0 ) )
   {
      applog( LOG_ERR, "RandomX: could not build an rx/0 probe VM" );
      return false;
   }

   if ( !memcmp( mine, rx0, 32 ) )
   {
      applog( LOG_ERR, "RandomX %s: hashes IDENTICALLY to rx/0 -- the variant "
                       "configuration did not take effect", rx_cur->pool_algo );
      return false;
   }
   applog( LOG_INFO, "RandomX %s: differs from rx/0 (core %s)",
           rx_cur->pool_algo, rx_core->name );
   return true;
}

/* ------------------------------------------- accepted-share vector sets */

/* A vector reconstructed from a share a pool accepted: cache key is the job's
 * seed_hash, input is the job blob with the submitted nonce written at byte
 * 39, expected output is the digest the pool credited. Upstream publishes
 * vectors for rx/0 only, so this is the only ground truth a variant has.
 *
 * These live here rather than in randomx-kat.c because a tier-2 variant must
 * be hashed by its OWN core, and the KAT talks to the stock core. rx/sfx's
 * vector can stay in the KAT because it is tier 1 and runs on the stock core.
 *
 * hex2bin here is miner.h's, taking (out, hex, len) -- the REVERSE argument
 * order of the file-local helper of the same name in randomx-kat.c, which is
 * linked without util.c and so has its own.
 */
typedef struct
{
   const char *blob;   /* hex, any supported blob length; nonce at byte 39 */
   const char *want;   /* 64 hex chars */
   const char *note;
} rx_vector_t;

/* Graft. Two of the three are different nonces on the same job blob, which
 * pins the nonce offset independently of any single share; the third is a
 * different blob under the same seed. All were checked against their job
 * targets when captured. */
static const char RX_GRAFT_SEED[] =
   "bd2a232602c5dcddcdd5994adf502f5120eb57362143d9866348d3eb08d5aa19";

static const rx_vector_t rx_graft_vectors[] =
{
   { "1111d587aed2060d45b2b392925b43203ae59c34c15c6af999680a40764ef6ca"
     "34041b5c31f8e9b80000a0850e1e9341ad40a425970612c4739ddd4809646746"
     "2e326d9c5493d4005ba51601",
     "b6764c79e3df1a69c4dfaaa7cc14971e574e9de70bbc58a40a96545d189c0400",
     "nonce b80000a0" },
   { "1111d587aed2060d45b2b392925b43203ae59c34c15c6af999680a40764ef6ca"
     "34041b5c31f8e9d2000060850e1e9341ad40a425970612c4739ddd4809646746"
     "2e326d9c5493d4005ba51601",
     "48b6ecede61218ac64496330b5fb983a8c89a8adb15fd7a6418f9df546a60400",
     "same blob, nonce d2000060" },
   { "1111d587aed2060d45b2b392925b43203ae59c34c15c6af999680a40764ef6ca"
     "34041b5c31f8e9600400a086567e4babbd7ea44478b77043cb7a85cb6577d1fe"
     "0791f322339a5e2522be1601",
     "4ffacab63f087715d9f129d99a303fe42074b8ef11d284c4a2f513c3df420100",
     "second blob, nonce 600400a0" },
};

/* Verifies every vector in a set against `core`. One cache init for the whole
 * set, so the set must share a seed. */
static bool rx_check_vectors( const rx_core_t *core, const char *seed_hex,
                              const rx_vector_t *v, size_t n,
                              size_t blob_len, const char *label )
{
   unsigned char seed[32], blob[RX_BLOB_MAX], hash[32], want[32];
   randomx_cache *cache;
   randomx_vm *vm;
   size_t i;
   int bad = 0;

   if ( strlen( seed_hex ) != 64 || !hex2bin( seed, seed_hex, 32 ) )
   {
      applog( LOG_ERR, "RandomX %s: bad seed literal in the vector set", label );
      return false;
   }

   cache = core->alloc_cache( core->get_flags()
                              & ( RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2 ) );
   if ( !cache )
   {
      applog( LOG_ERR, "RandomX %s: vector check cache alloc failed", label );
      return false;
   }
   core->init_cache( cache, seed, 32 );

   vm = core->create_vm( RANDOMX_FLAG_DEFAULT, cache, NULL );
   if ( !vm )
   {
      applog( LOG_ERR, "RandomX %s: vector check VM creation failed", label );
      core->release_cache( cache );
      return false;
   }

   for ( i = 0; i < n; i++ )
   {
      /* blob_len is stated by the caller and checked against every literal
       * rather than derived from it. The literals are written as concatenated
       * 64-char pieces, and a dropped run of zeros still yields a plausible
       * length -- derived, that shifts the hashed input and reports a plain
       * MISMATCH, which sends you looking at the algorithm instead of at the
       * transcription. */
      if ( strlen( v[i].blob ) != blob_len * 2 )
      {
         applog( LOG_ERR, "RandomX %s: vector literal is %u hex chars, "
                 "expected %u (%s)", label, (unsigned)strlen( v[i].blob ),
                 (unsigned)( blob_len * 2 ), v[i].note );
         bad++;
         continue;
      }
      if ( strlen( v[i].want ) != 64
           || !hex2bin( blob, v[i].blob, blob_len )
           || !hex2bin( want, v[i].want, 32 ) )
      {
         applog( LOG_ERR, "RandomX %s: malformed vector literal (%s)",
                 label, v[i].note );
         bad++;
         continue;
      }
      core->calculate_hash( vm, blob, blob_len, hash );
      if ( memcmp( hash, want, 32 ) )
      {
         char got[65];
         bin2hex( got, hash, 32 );
         applog( LOG_ERR, "RandomX %s: vector MISMATCH (%s): got %s",
                 label, v[i].note, got );
         bad++;
      }
   }

   core->destroy_vm( vm );
   core->release_cache( cache );

   if ( bad )
      return false;
   applog( LOG_INFO, "RandomX %s: %u accepted-share vectors verified",
           label, (unsigned)n );
   return true;
}

/* ArQmA. Both are different nonces on one blob. Reconstructing that job's
 * target reproduced the stratum difficulty the pool reported, which also
 * confirms rx_target_from_hex(). That pool sends "algo" as null, so the -a
 * choice is what selects the variant, not pool negotiation. */
static const char RX_ARQ_SEED[] =
   "300b0f3b1db6dbdbc0f88f7a29fbe1161a1b8489f6c67019ee296328d3093f39";

static const rx_vector_t rx_arq_vectors[] =
{
   { "13138afbead4068b1ab1607a80d140585d9df342629fb4e99c4d3cdda19cced0"
     "9bb4799b68e3cef00400b08ccb46dda1ff0b1f85024643dd7091cb39ed5d1944"
     "b7d67b4b2365f91eac86f801",
     "3ce9cf7f405ee9d5960b550ed09407b9c3f1fa7f914ec83cc15900ec8c960000",
     "nonce f00400b0" },
   { "13138afbead4068b1ab1607a80d140585d9df342629fb4e99c4d3cdda19cced0"
     "9bb4799b68e3ce641300808ccb46dda1ff0b1f85024643dd7091cb39ed5d1944"
     "b7d67b4b2365f91eac86f801",
     "33527af4d12f4d3194fba3c11af8efa7a4bd94d7f9491ce9b53305093a040000",
     "same blob, nonce 64130080" },
};

/* Scala. Both are different nonces on one blob, so the pair pins the nonce
 * offset independently of either share. The blob is 140 bytes -- longer than
 * a Monero one, which is why RX_BLOB_MAX and RX_NONCE_WORD moved. */
static const char RX_PANTHERA_SEED[] =
   "41dedb6c0f089231a5d648402aa3c5818a38db96a10fe9cd1acf9b7b2a205d2a";

static const rx_vector_t rx_panthera_vectors[] =
{
   { "1010fcdcebd406059c915b18943b99fe9a97f5fce8e1b2cd37425942327db4a9"
     "af523f990937706d020060000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000a4fc40f1a25d11ba5c5c728bc010f60c9a572c4f4f"
     "4aee4d18975e8232a259f201",
     "84e95fa09f9e91bef565991a10591597038561f471c072932d25d6d913320000",
     "nonce 6d020060" },
   { "1010fcdcebd406059c915b18943b99fe9a97f5fce8e1b2cd37425942327db4a9"
     "af523f99093770610f00f0000000000000000000000000000000000000000000"
     "0000000000000000000000000000000000000000000000000000000000000000"
     "0000000000000000000000a4fc40f1a25d11ba5c5c728bc010f60c9a572c4f4f"
     "4aee4d18975e8232a259f201",
     "b66d4cfa08fe231d7da594209fd801661d96a47c7361a132869fc0025d360000",
     "same blob, nonce 610f00f0" },
};

bool rx_variant_panthera_vectors( void )
{
#if defined(RANDOMX_HAVE_PANTHERA_CORE)
   return rx_check_vectors( &rx_core_panthera, RX_PANTHERA_SEED,
                            rx_panthera_vectors,
                            sizeof rx_panthera_vectors / sizeof *rx_panthera_vectors,
                            140, "panthera" );
#else
   return false;
#endif
}

bool rx_variant_arq_vectors( void )
{
#if defined(RANDOMX_HAVE_ARQ_CORE)
   return rx_check_vectors( &rx_core_arq, RX_ARQ_SEED, rx_arq_vectors,
                            sizeof rx_arq_vectors / sizeof *rx_arq_vectors,
                            76, "rx/arq" );
#else
   return false;
#endif
}

bool rx_variant_graft_vectors( void )
{
#if defined(RANDOMX_HAVE_GRAFT_CORE)
   return rx_check_vectors( &rx_core_graft, RX_GRAFT_SEED, rx_graft_vectors,
                            sizeof rx_graft_vectors / sizeof *rx_graft_vectors,
                            76, "rx/graft" );
#else
   return false;
#endif
}

unsigned rx_algo_nonce_bytes( int algo )
{
   /* Aeon's blob zeroes 8 bytes at offset 39 and its reference miner
    * increments a uint64 there; submitting 4 is rejected outright. */
   return algo == ALGO_K12 ? 8 : 4;
}

bool rx_algo_needs_seed( int algo )
{
   /* Every RandomX variant keys a 2080 MiB-class dataset on the job's
    * seed_hash. k12 reuses only the wire: no dataset, and its pool omits the
    * field, so demanding one would reject every job. */
   return algo != ALGO_K12;
}

bool rx_variant_select_plain( int algo )
{
   size_t i;
   for ( i = 0; i < sizeof rx_variants / sizeof *rx_variants; i++ )
      if ( rx_variants[i].algo == algo )
      {
         rx_cur = &rx_variants[i];
         return true;
      }
   return false;
}

bool rx_algo_uses_monero_stratum( int algo )
{
   size_t i;
   for ( i = 0; i < sizeof rx_variants / sizeof *rx_variants; i++ )
      if ( rx_variants[i].algo == algo )
         return true;
   return false;
}

const rx_variant_t *rx_variant( void )
{
   return rx_cur;
}

const char *rx_variant_pool_algo( void )
{
   return rx_cur->pool_algo;
}

/* Applies `algo`'s salt to the core. Must run before the first cache init and
 * not again -- see the note in randomx/dataset.cpp. */
bool rx_variant_select( int algo )
{
   size_t i;

   for ( i = 0; i < sizeof rx_variants / sizeof *rx_variants; i++ )
   {
      if ( rx_variants[i].algo != algo )
         continue;

      rx_cur = &rx_variants[i];

      if ( rx_cur->salt )
      {
         /* The core static_asserts this for the compile-time default only, so
          * a runtime salt needs its own check. Short salts weaken the domain
          * separation that is the whole point of a variant. */
         if ( rx_cur->salt_len < 8 )
         {
            applog( LOG_ERR, "RandomX %s: argon salt is %u bytes, minimum 8",
                    rx_cur->pool_algo, rx_cur->salt_len );
            return false;
         }
         randomx_argon_salt     = rx_cur->salt;
         randomx_argon_salt_len = rx_cur->salt_len;
      }

      /* Point every core call at this variant's core before anything
       * allocates. Tier-1 variants stay on the stock core. */
      if ( rx_cur->core )
         rx_core = rx_cur->core;

      applog( LOG_INFO, "RandomX variant %s (core %s, argon salt %lu bytes, "
                        "cache %lu MiB x%lu, scratchpad %lu KiB, %lu programs "
                        "x %lu iterations of %lu instructions, ssl %lu)",
              rx_cur->pool_algo, rx_core->name,
              rx_core->argon_salt_len(),
              rx_core->argon_memory() / 1024,
              rx_core->argon_iterations(),
              rx_core->scratchpad_size() / 1024,
              rx_core->program_count(), rx_core->program_iterations(),
              rx_core->program_size(),
              rx_core->superscalar_latency() );
      return true;
   }

   /* A known RandomX variant whose core was not compiled in, i.e. a
    * --disable-randomx-variants build. */
   applog( LOG_ERR, "RandomX: %s is not available in this build",
           algo_names[ algo ] );
   applog( LOG_ERR, "Its core is omitted by --disable-randomx-variants" );
   return false;
}
