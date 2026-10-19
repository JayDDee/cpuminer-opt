/* Per-variant RandomX core dispatch.
 *
 * A tier-2 variant moves constants the core bakes into constexpr values in
 * common.hpp and into an immediate in jit_compiler_x86_static.S, so it cannot
 * share rx/0's compiled core. The core is therefore linked once per such
 * variant, each copy with its configuration injected and every symbol it
 * defines prefixed, and everything on the mining path goes through this table.
 *
 * randomx-kat.c deliberately keeps calling the stock core directly: its
 * vectors are rx/0's, so it validates the shared engine whichever variant is
 * selected.
 *
 * Signatures are copied from randomx/randomx.h. A mismatch is an ABI
 * mismatch, not a compile error, so keep them in step with that header.
 */

#ifndef RANDOMX_CORE_H
#define RANDOMX_CORE_H

#include "randomx/randomx.h"

/* Tagged so randomx-gate.h can forward-declare it without including this. */
typedef struct rx_core_s
{
   const char      *name;              /* for the startup banner */

   randomx_flags  (*get_flags)         ( void );

   randomx_cache *(*alloc_cache)       ( randomx_flags );
   void           (*init_cache)        ( randomx_cache *, const void *, size_t );
   void           (*release_cache)     ( randomx_cache * );

   randomx_dataset *(*alloc_dataset)   ( randomx_flags );
   unsigned long  (*dataset_item_count)( void );
   void           (*init_dataset)      ( randomx_dataset *, randomx_cache *,
                                         unsigned long, unsigned long );
   void           (*release_dataset)   ( randomx_dataset * );

   randomx_vm    *(*create_vm)         ( randomx_flags, randomx_cache *,
                                         randomx_dataset * );
   void           (*destroy_vm)        ( randomx_vm * );
   void           (*vm_set_cache)      ( randomx_vm *, randomx_cache * );
   void           (*vm_set_dataset)    ( randomx_vm *, randomx_dataset * );

   void           (*calculate_hash)      ( randomx_vm *, const void *, size_t,
                                           void * );
   void           (*calculate_hash_first)( randomx_vm *, const void *, size_t );
   void           (*calculate_hash_next) ( randomx_vm *, const void *, size_t,
                                           void * );
   void           (*calculate_hash_last) ( randomx_vm *, void * );

   /* Config this core was compiled with, asked of the core rather than read
    * from configuration.h -- the caller's macros always describe rx/0. The
    * scratchpad size is per THREAD and differs by variant (rx/0 2 MiB,
    * rx/wow 1 MiB), so the huge-page advice needs it from here. */
   unsigned long  (*scratchpad_size)     ( void );
   unsigned long  (*program_count)       ( void );
   unsigned long  (*program_iterations)  ( void );
   unsigned long  (*argon_salt_len)      ( void );
   unsigned long  (*argon_memory)        ( void );   /* KiB */
   unsigned long  (*program_size)        ( void );
   unsigned long  (*argon_iterations)    ( void );
   unsigned long  (*superscalar_latency) ( void );
} rx_core_t;

/* The stock core: rx/0 and any tier-1 (salt-only) variant. */
extern const rx_core_t rx_core_stock;

#if defined(RANDOMX_HAVE_WOW_CORE)
extern const rx_core_t rx_core_wow;
#endif
#if defined(RANDOMX_HAVE_GRAFT_CORE)
extern const rx_core_t rx_core_graft;
#endif
#if defined(RANDOMX_HAVE_ARQ_CORE)
extern const rx_core_t rx_core_arq;
#endif
#if defined(RANDOMX_HAVE_PANTHERA_CORE)
extern const rx_core_t rx_core_panthera;
#endif

/* Selected by rx_variant_select() before anything allocates. Defaults to the
 * stock core so a build that never selects a variant behaves as before. */
extern const rx_core_t *rx_core;

#endif /* RANDOMX_CORE_H */
