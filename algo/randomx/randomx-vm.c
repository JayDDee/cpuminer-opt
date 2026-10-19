/* RandomX cache / dataset / VM lifecycle.
 *
 * RandomX is not a stateless hash: every hash reads a 2080 MiB dataset derived
 * (argon2 + superscalar expansion) from the 32-byte "seed_hash" the pool sends
 * with each job. When that key changes -- every 2048 blocks on Monero -- the
 * cache and dataset must both be rebuilt before any further hash is valid.
 *
 * Ownership: ONE shared cache + dataset behind rx_lock; miner threads hold it
 * for reading, a seed change takes it for writing and rebuilds in place. Each
 * miner thread owns a randomx_vm pointing at that dataset.
 *
 * The rebuild is synchronous and stalls mining. Deliberate: a double-buffered
 * background swap needs twice the resident memory and its failure mode is
 * silently hashing against a stale dataset, i.e. rejected shares. Synchronous
 * cannot be subtly wrong -- either the dataset matches the seed or no thread is
 * running. The job's next_seed_hash is the hook for pre-warming later.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "miner.h"
#include "randomx-gate.h"
#include "randomx-core.h"
#include "randomx/randomx.h"
#include "randomx/configuration.h"   /* RANDOMX_ARGON_MEMORY, for the advice */
#include "randomx-buildinfo.h"

/* ------------------------------------------------------------------ state */

static pthread_rwlock_t  rx_lock = PTHREAD_RWLOCK_INITIALIZER;
static randomx_cache    *rx_cache;
static randomx_dataset  *rx_dataset;      /* NULL in light mode */
static randomx_flags     rx_flags;
static unsigned char     rx_seed[32];
static bool              rx_seed_valid;
static bool              rx_full_mode;
static bool              rx_initialised;
static bool              rx_cache_lp;      /* cache got large pages   */
static bool              rx_dataset_lp;    /* dataset got large pages */
static bool              rx_vm_lp_warned;
/* Bumped on every successful seed change. A miner thread compares it against
 * its own copy to know its VM needs re-pointing; that is cheaper and less
 * error-prone than trying to enumerate the threads from the stratum side. */
static uint64_t          rx_epoch;

/* Set while a rebuild is wanted or running; scanhash must check it and NOT take
 * the read lock while it is set.
 *
 * Load-bearing, not defensive. glibc's rwlock defaults to
 * PTHREAD_RWLOCK_PREFER_READER_NP, so the rebuild's writer is starved for as
 * long as readers keep arriving -- and miner threads re-acquire the read lock
 * on every scanhash call. restart_threads() does not break the cycle: a thread
 * kicked out of scanhash re-enters immediately, because g_work cannot be
 * republished until the reseed it is blocking has finished. Without this flag
 * pthread_rwlock_wrlock never returns and the miner hangs.
 *
 * volatile, not atomic: one writer, many readers, and a one-iteration-late
 * read costs nothing. */
static volatile bool     rx_reseed_pending;
/* Test hook (CPUMINER_RX_TEST_RESEED). A flag, not a lock acquisition, for the
 * reason above. */
static volatile bool     rx_force_invalid;

/* --dataset init threading. Uses the miner thread count, which is what the
 * user already tuned for this box. */
struct ds_range { unsigned long start, count; };

static void *ds_init_thread( void *arg )
{
   struct ds_range *r = (struct ds_range*) arg;
   rx_core->init_dataset( rx_dataset, rx_cache, r->start, r->count );
   return NULL;
}

/* ------------------------------------------------------------- allocation */

/* Default huge page size in bytes, or 0 if unsupported. MAP_HUGETLB (used by
 * the vendored LargePageAllocator) allocates at this size. Read, not assumed:
 * it is 2 MiB on x86-64 but an aarch64 kernel with a 64 KiB base page uses
 * 512 MiB, which would make the page count below wrong by 256x. */
static size_t rx_hugepage_size( void )
{
#if defined(__linux__)
   FILE *f = fopen( "/proc/meminfo", "r" );
   char line[256];
   size_t kb = 0;
   if ( !f ) return 0;
   while ( fgets( line, sizeof line, f ) )
      if ( sscanf( line, "Hugepagesize: %zu kB", &kb ) == 1 )
         break;
   fclose( f );
   return kb * 1024;
#else
   return 0;
#endif
}

/* Count the cpus at the highest max frequency and return their mask; 0 if the
 * topology is homogeneous or cpufreq is unreadable. The thread-count hint below
 * needs this because homogeneous and big.LITTLE want opposite advice. */
static int rx_big_cores( uint64_t *mask_out )
{
#if defined(__linux__)
   long maxf = 0, f[64];
   int i, n = 0, nbig = 0;
   uint64_t mask = 0;

   if ( mask_out ) *mask_out = 0;
   n = num_cpus > 0 ? num_cpus : 1;
   if ( n > 64 ) n = 64;

   for ( i = 0; i < n; i++ )
   {
      char path[128];
      FILE *fp;
      f[i] = 0;
      snprintf( path, sizeof path,
                "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_max_freq", i );
      fp = fopen( path, "r" );
      if ( !fp ) return 0;            /* no cpufreq -> assume homogeneous */
      if ( fscanf( fp, "%ld", &f[i] ) != 1 ) f[i] = 0;
      fclose( fp );
      if ( f[i] > maxf ) maxf = f[i];
   }
   if ( maxf <= 0 ) return 0;

   for ( i = 0; i < n; i++ )
      if ( f[i] == maxf ) { mask |= 1ULL << i; nbig++; }

   if ( nbig == n ) return 0;         /* homogeneous */
   if ( mask_out ) *mask_out = mask;
   return nbig;
#else
   if ( mask_out ) *mask_out = 0;
   return 0;
#endif
}

/* Tell the user exactly what to do, with the real numbers for this box and
 * thread count. "hugepages would help" on its own is not actionable. */
static void rx_advise_hugepages( size_t dataset_bytes, int nthreads )
{
   const size_t hp = rx_hugepage_size();
   size_t need;

   if ( !hp )
   {
      applog( LOG_INFO, "RandomX: no huge page support in this kernel" );
      return;
   }

   /* dataset + cache + one scratchpad per thread, rounded up to whole pages,
    * plus headroom for the JIT code buffers.
    *
    * The scratchpad size comes from the SELECTED core, not from
    * RANDOMX_SCRATCHPAD_L3: this file is compiled once against the stock
    * configuration, so that macro says 2 MiB even when a variant core with a
    * 1 MiB scratchpad is in force, and the advice would overstate the need. */
   need = ( dataset_bytes + hp - 1 ) / hp
        + ( (size_t)rx_core->argon_memory() * 1024 + hp - 1 ) / hp
        + ( (size_t)nthreads * rx_core->scratchpad_size() + hp - 1 ) / hp
        + 8;

   applog( LOG_NOTICE, "RandomX: huge pages are unavailable and are worth "
                       "~30-50%% here. As root:" );
   applog( LOG_NOTICE, "    sysctl -w vm.nr_hugepages=%zu", need );
   applog( LOG_NOTICE, "  to persist: echo 'vm.nr_hugepages=%zu' > "
                       "/etc/sysctl.d/60-randomx.conf", need );
   applog( LOG_NOTICE, "  (%zu x %zu MiB pages = %zu MiB, for the dataset, the "
                       "cache and %d scratchpads)",
           need, hp / ( 1024 * 1024 ), need * hp / ( 1024 * 1024 ), nthreads );
}

static bool rx_alloc( void )
{
   randomx_flags cf;
   const size_t ds_bytes = (size_t)rx_core->dataset_item_count()
                         * RANDOMX_DATASET_ITEM_SIZE;
   const int nthr = opt_n_threads > 0 ? opt_n_threads : 1;

   rx_flags = rx_core->get_flags();

   /* Large pages are a big win for RandomX -- 2 GB of dependent random reads
    * punishes the TLB -- but the allocation fails outright rather than
    * degrading, so every one of these is "try large, then plain". */
   cf = rx_flags & ( RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2 );

   rx_cache = rx_core->alloc_cache( cf | RANDOMX_FLAG_LARGE_PAGES );
   rx_cache_lp = ( rx_cache != NULL );
   if ( !rx_cache )
   {
      rx_cache = rx_core->alloc_cache( cf );
      if ( !rx_cache )
      {
         applog( LOG_ERR, "RandomX: cache allocation failed (need %lu MiB)",
                 rx_core->argon_memory() / 1024 );
         return false;
      }
   }
   /* From the selected core, not RANDOMX_ARGON_MEMORY: this file is compiled
    * once against the stock configuration, so the macro says 256 MiB even
    * when a variant core is using 128. */
   applog( LOG_INFO, "RandomX cache:   %lu MiB, %s",
           rx_core->argon_memory() / 1024,
           rx_cache_lp ? "large pages" : "normal pages" );

   /* Fast mode. Fall back to light mode rather than refusing to mine: light
    * mode is 5-10x slower but works on small boxes. */
   rx_dataset = rx_core->alloc_dataset( RANDOMX_FLAG_LARGE_PAGES );
   rx_dataset_lp = ( rx_dataset != NULL );
   if ( !rx_dataset )
      rx_dataset = rx_core->alloc_dataset( RANDOMX_FLAG_DEFAULT );

   rx_full_mode = ( rx_dataset != NULL );
   if ( rx_full_mode )
   {
      rx_flags |= RANDOMX_FLAG_FULL_MEM;
      applog( LOG_INFO, "RandomX dataset: %zu MiB, %s",
              ds_bytes / ( 1024 * 1024 ),
              rx_dataset_lp ? "large pages" : "normal pages" );
   }
   else
      applog( LOG_WARNING, "RandomX: dataset allocation failed, falling back "
                           "to LIGHT mode -- expect roughly 1/5 to 1/10 the "
                           "hashrate. Free ~%zu MiB for fast mode.",
              ( ds_bytes / ( 1024 * 1024 ) ) + 64 );

   applog( LOG_INFO, "RandomX build: %s JIT, %s, hardware AES %s%s",
           randomx_build_jit_arch(), randomx_build_simd(),
           randomx_build_have_aes() ? "compiled" : "NOT compiled",
           ( rx_flags & RANDOMX_FLAG_HARD_AES ) ? " and enabled"
                                                : " / not enabled" );
   if ( randomx_build_have_aes() && !( rx_flags & RANDOMX_FLAG_HARD_AES ) )
      applog( LOG_WARNING, "RandomX: hardware AES compiled but not selected "
                           "at runtime -- soft AES will be used" );

   if ( !rx_cache_lp || ( rx_full_mode && !rx_dataset_lp ) )
      rx_advise_hugepages( ds_bytes, nthr );

   /* Thread-count hint. RandomX saturates memory long before it saturates
    * cores, and the miner needs CPU for its stratum and reporting threads too,
    * so filling every hardware thread loses throughput on a homogeneous box.
    * A hint, not a cap -- overriding an explicit -t would be worse. */
   {
      const int ncpu = num_cpus > 0 ? num_cpus : nthr;
      uint64_t bigmask = 0;
      const int nbig = rx_big_cores( &bigmask );

      if ( nbig > 0 && nbig < ncpu )
      {
         /* Heterogeneous (big.LITTLE): the homogeneous advice is harmful here.
          * cpuminer's default affinity map binds miner thread N to cpu N, so
          * any -t below the core count lands on cpu0..N-1 -- the slow cluster
          * on the usual layouts. Warn about the mask, do not suggest a lower
          * -t. */
         if ( nthr < ncpu )
            applog( LOG_NOTICE, "RandomX: this CPU has %d fast and %d slow "
                                "cores. cpuminer binds miner thread N to cpu N, "
                                "so -t %d without --cpu-affinity 0x%llx runs on "
                                "the SLOW cores -- check the 'CPU affinity' line "
                                "above", nbig, ncpu - nbig, nthr,
                                (unsigned long long)bigmask );
         else
            applog( LOG_INFO, "RandomX: %d fast + %d slow cores; using all of "
                              "them measured best", nbig, ncpu - nbig );
      }
      else if ( ncpu >= 4 && nthr > ncpu - 2 )
         applog( LOG_NOTICE, "RandomX: -t %d on a %d-thread CPU leaves nothing "
                             "for the stratum thread; ~%d is usually 20-25%% "
                             "faster", nthr, ncpu, ncpu - 3 );
   }

   rx_initialised = true;
   return true;
}

/* ------------------------------------------------------------ seed change */

/* Rebuilds cache + dataset for `seed`. Caller must NOT hold rx_lock. */
static bool rx_reseed( const unsigned char *seed )
{
   struct timeval t0, t1, dt;
   char hex[65];

   bin2hex( hex, seed, 32 );
   gettimeofday( &t0, NULL );

   pthread_rwlock_wrlock( &rx_lock );

   rx_core->init_cache( rx_cache, seed, 32 );

   if ( rx_full_mode )
   {
      unsigned long count = rx_core->dataset_item_count();
      int nthr = opt_n_threads > 0 ? opt_n_threads : 1;
      pthread_t *tids;
      struct ds_range *ranges;
      int i, started = 0;

      tids   = (pthread_t*)      calloc( nthr, sizeof *tids );
      ranges = (struct ds_range*)calloc( nthr, sizeof *ranges );

      if ( tids && ranges )
      {
         unsigned long per = count / nthr;
         for ( i = 0; i < nthr; i++ )
         {
            ranges[i].start = per * i;
            ranges[i].count = ( i == nthr - 1 ) ? count - per * i : per;
            if ( pthread_create( &tids[i], NULL, ds_init_thread, &ranges[i] ) )
               break;
            started++;
         }
         for ( i = 0; i < started; i++ )
            pthread_join( tids[i], NULL );
      }

      /* If thread setup failed part-way, finish the rest on this thread rather
       * than leaving a partially built dataset -- a half-built dataset hashes
       * happily and produces nothing but rejects. */
      if ( started < nthr )
      {
         unsigned long done = started ? ranges[started-1].start
                                      + ranges[started-1].count : 0;
         if ( done < count )
            rx_core->init_dataset( rx_dataset, rx_cache, done, count - done );
      }

      free( tids );
      free( ranges );
   }

   memcpy( rx_seed, seed, 32 );
   rx_seed_valid = true;
   rx_epoch++;

   pthread_rwlock_unlock( &rx_lock );

   gettimeofday( &t1, NULL );
   timeval_subtract( &dt, &t1, &t0 );
   applog( LOG_BLUE, "RandomX %s dataset built for seed %.16s... in %.1fs",
           rx_full_mode ? "full" : "light", hex,
           (double)dt.tv_sec + (double)dt.tv_usec / 1e6 );
   return true;
}

/* Test hook. A seed_hash changes every 2048 blocks, so the rebuild path cannot
 * be reached by just running the miner. CPUMINER_RX_TEST_RESEED=<seconds> makes
 * the next job after that many seconds forget the current seed, so the same
 * seed_hash triggers a genuine rebuild. Since it rebuilds for the real seed,
 * shares must keep being accepted afterwards -- that is what makes it a test.
 */
void rx_force_reseed_for_test( void )
{
   rx_force_invalid = true;
   applog( LOG_BLUE, "RandomX: TEST forced seed invalidation "
                     "(CPUMINER_RX_TEST_RESEED)" );
}

bool rx_reseed_is_pending( void ) { return rx_reseed_pending; }

bool rx_seed_update( const unsigned char *seed )
{
   bool need, ok;

   if ( !rx_initialised && !rx_alloc() )
      return false;

   pthread_rwlock_rdlock( &rx_lock );
   need = !rx_seed_valid || rx_force_invalid
          || memcmp( rx_seed, seed, 32 ) != 0;
   pthread_rwlock_unlock( &rx_lock );

   if ( !need )
      return true;

   if ( rx_seed_valid )
      applog( LOG_BLUE, "RandomX seed_hash changed -- rebuilding dataset, "
                        "mining pauses until it is ready" );

   /* Must be set BEFORE asking for the write lock, or the readers starve it.
    * See rx_reseed_pending. */
   rx_reseed_pending = true;
   ok = rx_reseed( seed );
   rx_force_invalid  = false;
   rx_reseed_pending = false;

   return ok;
}

uint64_t rx_current_epoch( void )
{
   uint64_t e;
   pthread_rwlock_rdlock( &rx_lock );
   e = rx_epoch;
   pthread_rwlock_unlock( &rx_lock );
   return e;
}

bool rx_is_full_mode( void ) { return rx_full_mode; }

/* --------------------------------------------------------------- per-VM */

/* One VM per miner thread. Not __thread: the miner_thread_free counterpart has
 * to be able to reach it, and this tree's convention is a thread-indexed
 * array (see the miner_thread_init/free contract in algo-gate-api.h). */
static randomx_vm **rx_vms;
static uint64_t    *rx_vm_epoch;
static int          rx_vm_count;

bool rx_vm_pool_init( int nthreads )
{
   rx_vms      = (randomx_vm**) calloc( nthreads, sizeof *rx_vms );
   rx_vm_epoch = (uint64_t*)    calloc( nthreads, sizeof *rx_vm_epoch );
   rx_vm_count = nthreads;
   return rx_vms && rx_vm_epoch;
}

void rx_vm_free( int thr_id )
{
   if ( !rx_vms || thr_id < 0 || thr_id >= rx_vm_count )
      return;
   if ( rx_vms[thr_id] )
   {
      rx_core->destroy_vm( rx_vms[thr_id] );
      rx_vms[thr_id] = NULL;      /* idempotent: lets a later init remake it */
      rx_vm_epoch[thr_id] = 0;
   }
}

/* This thread's VM, created or re-pointed as needed.
 *
 * CONTRACT: the caller holds the read lock and keeps holding it while hashing.
 * A reseed rebuilds cache and dataset IN PLACE, so hashing across one does not
 * crash -- it silently yields wrong hashes. Each thread only writes its own
 * rx_vms[]/rx_vm_epoch[] slot, so mutating them under a read lock is safe.
 *
 * NULL means no dataset yet: do not hash. */
randomx_vm *rx_vm_get( int thr_id )
{
   randomx_vm *vm;
   uint64_t epoch;

   if ( !rx_vms || thr_id < 0 || thr_id >= rx_vm_count )
      return NULL;

   if ( !rx_seed_valid )
      return NULL;

   epoch = rx_epoch;
   vm    = rx_vms[thr_id];

   if ( !vm )
   {
      randomx_dataset *ds = rx_full_mode ? rx_dataset : NULL;

      /* The VM owns this thread's scratchpad (2 MiB on rx/0, 1 MiB on
       * rx/wow), and it is a THIRD
       * large-page allocation independent of the cache and dataset -- asking
       * only those two leaves the hottest working set on 4 KiB pages.
       * randomx_create_vm catches bad_alloc and returns NULL, so the ladder is
       * safe: large pages, then normal, then without the JIT (which needs an
       * executable mapping and can fail under W^X). */
      vm = rx_core->create_vm( rx_flags | RANDOMX_FLAG_LARGE_PAGES,
                              rx_cache, ds );
      if ( vm )
      {
         if ( !rx_vm_lp_warned )
         {
            rx_vm_lp_warned = true;
            applog( LOG_INFO, "RandomX scratchpad: %lu KiB/thread, large pages",
                    rx_core->scratchpad_size() / 1024 );
         }
      }
      else
      {
         vm = rx_core->create_vm( rx_flags, rx_cache, ds );
         if ( vm && !rx_vm_lp_warned )
         {
            rx_vm_lp_warned = true;
            applog( LOG_INFO, "RandomX scratchpad: %lu KiB/thread, normal pages",
                    rx_core->scratchpad_size() / 1024 );
         }
      }

      if ( !vm )
      {
         /* Most likely the JIT could not get an executable page (W^X, or a
          * hardened kernel). The interpreter always works, so retry without
          * it rather than dropping the thread. */
         vm = rx_core->create_vm( rx_flags & ~RANDOMX_FLAG_JIT, rx_cache, ds );
         if ( vm )
            applog( LOG_WARNING, "RandomX thread %d: JIT unavailable, using "
                                 "the interpreter (much slower)", thr_id );
      }
      rx_vms[thr_id] = vm;
      rx_vm_epoch[thr_id] = epoch;
   }
   else if ( rx_vm_epoch[thr_id] != epoch )
   {
      /* Seed changed under us. The cache and dataset buffers were reused in
       * place, so the pointers are unchanged -- but the VM caches derived
       * state, so it still has to be told. */
      rx_core->vm_set_cache( vm, rx_cache );
      if ( rx_full_mode )
         rx_core->vm_set_dataset( vm, rx_dataset );
      rx_vm_epoch[thr_id] = epoch;
   }

   return vm;
}

/* Held for a whole scanhash call so a reseed cannot rebuild the dataset under a
 * running hash.
 *
 * LOCK ORDER: a miner holds this read lock and then wants g_work_lock, so the
 * reseed must not run while g_work_lock is held -- i.e. never inside
 * stratum_gen_work. It runs in stratum_thread after restart_threads() and
 * before the job is published. See rx_stratum_prepare_seed(). */
void rx_read_lock( void )   { pthread_rwlock_rdlock( &rx_lock ); }
void rx_read_unlock( void ) { pthread_rwlock_unlock( &rx_lock ); }
