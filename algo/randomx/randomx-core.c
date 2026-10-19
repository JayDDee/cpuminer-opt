/* The core instances. See randomx-core.h. */

#include "randomx-core.h"
#include "randomx-buildinfo.h"

const rx_core_t rx_core_stock =
{
   "stock",
   randomx_get_flags,
   randomx_alloc_cache,   randomx_init_cache,    randomx_release_cache,
   randomx_alloc_dataset, randomx_dataset_item_count,
   randomx_init_dataset,  randomx_release_dataset,
   randomx_create_vm,     randomx_destroy_vm,
   randomx_vm_set_cache,  randomx_vm_set_dataset,
   randomx_calculate_hash,
   randomx_calculate_hash_first,
   randomx_calculate_hash_next,
   randomx_calculate_hash_last,
   randomx_build_scratchpad_size,
   randomx_build_program_count,
   randomx_build_program_iterations,
   randomx_build_argon_salt_len,
   randomx_build_argon_memory,
   randomx_build_program_size,
   randomx_build_argon_iterations,
   randomx_build_superscalar_latency
};

/* A variant core is the same sources compiled with its config/<v>.h injected,
 * then run through prefix-syms.sh so every symbol it defines carries a unique
 * prefix. The names are declared here rather than pulled from a renamed
 * header: if a prefix ever stops matching what the build produced, this fails
 * at link time as an undefined reference instead of silently binding to the
 * stock core -- which would mine the wrong algorithm while looking healthy. */
#define RX_VARIANT_CORE( pfx, sym, label )                                     \
   randomx_flags    pfx##randomx_get_flags( void );                            \
   randomx_cache   *pfx##randomx_alloc_cache( randomx_flags );                 \
   void             pfx##randomx_init_cache( randomx_cache *, const void *,    \
                                             size_t );                         \
   void             pfx##randomx_release_cache( randomx_cache * );             \
   randomx_dataset *pfx##randomx_alloc_dataset( randomx_flags );               \
   unsigned long    pfx##randomx_dataset_item_count( void );                   \
   void             pfx##randomx_init_dataset( randomx_dataset *,              \
                                               randomx_cache *,                \
                                               unsigned long, unsigned long ); \
   void             pfx##randomx_release_dataset( randomx_dataset * );         \
   randomx_vm      *pfx##randomx_create_vm( randomx_flags, randomx_cache *,    \
                                            randomx_dataset * );               \
   void             pfx##randomx_destroy_vm( randomx_vm * );                   \
   void             pfx##randomx_vm_set_cache( randomx_vm *, randomx_cache * );\
   void             pfx##randomx_vm_set_dataset( randomx_vm *,                 \
                                                 randomx_dataset * );          \
   void             pfx##randomx_calculate_hash( randomx_vm *, const void *,   \
                                                 size_t, void * );             \
   void             pfx##randomx_calculate_hash_first( randomx_vm *,           \
                                                       const void *, size_t ); \
   void             pfx##randomx_calculate_hash_next( randomx_vm *,            \
                                                      const void *, size_t,    \
                                                      void * );                \
   void             pfx##randomx_calculate_hash_last( randomx_vm *, void * );  \
   unsigned long    pfx##randomx_build_scratchpad_size( void );                \
   unsigned long    pfx##randomx_build_program_count( void );                  \
   unsigned long    pfx##randomx_build_program_iterations( void );             \
   unsigned long    pfx##randomx_build_argon_salt_len( void );                 \
   unsigned long    pfx##randomx_build_argon_memory( void );                   \
   unsigned long    pfx##randomx_build_program_size( void );                   \
   unsigned long    pfx##randomx_build_argon_iterations( void );               \
   unsigned long    pfx##randomx_build_superscalar_latency( void );            \
                                                                               \
   const rx_core_t sym =                                                       \
   {                                                                           \
      label,                                                                   \
      pfx##randomx_get_flags,                                                  \
      pfx##randomx_alloc_cache,   pfx##randomx_init_cache,                     \
      pfx##randomx_release_cache,                                              \
      pfx##randomx_alloc_dataset, pfx##randomx_dataset_item_count,             \
      pfx##randomx_init_dataset,  pfx##randomx_release_dataset,                \
      pfx##randomx_create_vm,     pfx##randomx_destroy_vm,                     \
      pfx##randomx_vm_set_cache,  pfx##randomx_vm_set_dataset,                 \
      pfx##randomx_calculate_hash,                                             \
      pfx##randomx_calculate_hash_first,                                       \
      pfx##randomx_calculate_hash_next,                                        \
      pfx##randomx_calculate_hash_last,                                        \
      pfx##randomx_build_scratchpad_size,                                      \
      pfx##randomx_build_program_count,                                        \
      pfx##randomx_build_program_iterations,                                   \
      pfx##randomx_build_argon_salt_len,                                       \
      pfx##randomx_build_argon_memory,                                         \
      pfx##randomx_build_program_size,                                         \
      pfx##randomx_build_argon_iterations,                                     \
      pfx##randomx_build_superscalar_latency                                   \
   }

#if defined(RANDOMX_HAVE_WOW_CORE)
RX_VARIANT_CORE( rxwow_,  rx_core_wow,   "wow"   );
#endif

#if defined(RANDOMX_HAVE_GRAFT_CORE)
RX_VARIANT_CORE( rxgrft_, rx_core_graft, "graft" );
#endif

#if defined(RANDOMX_HAVE_ARQ_CORE)
RX_VARIANT_CORE( rxarq_,  rx_core_arq,   "arq"   );
#endif

#if defined(RANDOMX_HAVE_PANTHERA_CORE)
RX_VARIANT_CORE( rxpan_,  rx_core_panthera, "panthera" );
#endif

const rx_core_t *rx_core = &rx_core_stock;
