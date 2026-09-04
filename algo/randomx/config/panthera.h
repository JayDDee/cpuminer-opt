/* Panthera (Scala, XLA) -- pool algo "panthera".
 *
 * Tier 2 plus a seed hook. The constants alone are an ordinary tier-2 variant,
 * but Panthera also post-processes the initial seed with yespower and
 * KangarooTwelve, which is why it needed a port rather than just a config
 * header. RANDOMX_SEED_HOOK below is what injects that; the implementation is
 * algo/randomx/panthera-seed.c and the buffer semantics documented there are
 * consensus.
 *
 * Constants from the consensus source:
 *   scala-network/Scala .gitmodules -> external/randomx
 *       -> github.com/scala-network/Panthera
 *   pinned commit cc7425f468d935ba328fba5bbb05f8227f4f22d7, src/configuration.h
 * Everything not listed below matches rx/0, including the AES generator keys
 * and the other 28 instruction frequencies.
 *
 * Mined with RANDOMX_FLAG_V2 clear. Panthera has a single
 * RANDOMX_PROGRAM_SIZE of 64, which maps to our _V1.
 *
 * The dataset is 64 MiB here (32 base + 32 extra), not rx/0's 2080, and the
 * cache is 128 MiB rather than 256. None of rx/0's thread or huge-page
 * guidance transfers -- measure it.
 */

#ifndef CPUMINER_RANDOMX_CONFIG_PANTHERA_H
#define CPUMINER_RANDOMX_CONFIG_PANTHERA_H

/* This header is -included into jit_compiler_x86_static.S as well, and the
 * assembler preprocesses but cannot assemble C. Anything that is not a bare
 * macro must be hidden from it -- the .S only needs the numeric constants
 * below, for its scratchpad/dataset/cache masks. */
#ifndef __ASSEMBLER__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif
void randomx_panthera_seed( void *seed, size_t len );
#ifdef __cplusplus
}
#endif

/* Applied only where the core derives tempHash from an input. */
#define RANDOMX_SEED_HOOK( p, n )   randomx_panthera_seed( (p), (n) )

#endif /* !__ASSEMBLER__ */

#define RANDOMX_ARGON_MEMORY        131072
#define RANDOMX_ARGON_ITERATIONS    2
#define RANDOMX_ARGON_SALT          "DefyXScala\x13"
#define RANDOMX_CACHE_ACCESSES      2

#define RANDOMX_DATASET_BASE_SIZE   33554432

#define RANDOMX_PROGRAM_SIZE_V1     64
#define RANDOMX_PROGRAM_ITERATIONS  1024
#define RANDOMX_PROGRAM_COUNT       4

#define RANDOMX_SCRATCHPAD_L3       262144
#define RANDOMX_SCRATCHPAD_L2       131072
#define RANDOMX_SCRATCHPAD_L1       65536

/* Two of the thirty frequencies differ; the rest match rx/0. */
#define RANDOMX_FREQ_IADD_RS        25
#define RANDOMX_FREQ_CBRANCH        16

#endif
