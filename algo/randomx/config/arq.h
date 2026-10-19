/* RandomARQ (ArQmA) -- pool algo "rx/arq".
 *
 * Tier 2: the scratchpad sizes and the program count/iterations are constexpr
 * in the core, and the L3 size is an immediate in jit_compiler_x86_static.S,
 * so this needs its own compiled core and is injected into it.
 *
 * Constants from the consensus source:
 *   arqma/arqma .gitmodules -> external/randomarq -> github.com/arqma/randomarq
 *   pinned commit 3bcb6bafe63d70f8e6f78a0d431e71be2b638083, src/configuration.h
 * Note the submodule is named "randomarq", not "randomx". Everything not
 * listed below matches rx/0, including all 30 frequencies and the AES keys.
 *
 * ArQmA's single RANDOMX_PROGRAM_SIZE is 256, our _V1 default, so it is not
 * overridden.
 *
 * The scratchpad is 256 KiB rather than 2 MiB, so it is L2-resident and this
 * variant is far less memory-bound than rx/0. Its thread and huge-page
 * behaviour must be measured, not inherited.
 */

#ifndef CPUMINER_RANDOMX_CONFIG_ARQ_H
#define CPUMINER_RANDOMX_CONFIG_ARQ_H

#define RANDOMX_ARGON_ITERATIONS   1
#define RANDOMX_ARGON_SALT         "RandomARQ\x01"

#define RANDOMX_PROGRAM_ITERATIONS 1024
#define RANDOMX_PROGRAM_COUNT      4

#define RANDOMX_SCRATCHPAD_L3      262144
#define RANDOMX_SCRATCHPAD_L2      131072
/* L1 is 16384 in both and is deliberately not overridden. */

#endif
