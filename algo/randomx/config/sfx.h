/* RandomSFX (Safex Cash) -- pool algo "rx/sfx".
 *
 * Tier 1: the only difference from rx/0 is the argon2 salt, which is read
 * once per epoch during cache init and never reaches the VM or the JIT, so it
 * is applied at RUNTIME on the stock core (randomx-variant.c). No separate
 * core is needed here.
 *
 * Constants from the consensus source:
 *   safex/safexcore .gitmodules -> external/randomx -> github.com/safex/RandomSFX
 *   pinned commit 4f7b3a9a8365614ea41c0d865f92a9e855252b66, src/configuration.h
 * Every other constant in that file matches rx/0, so the salt is the whole
 * delta. Do NOT read it from that repo's default branch, which still carries
 * upstream's salt; the pinned commit is the source of truth.
 *
 * Deliberately NOT named RANDOMX_ARGON_SALT: this is applied at runtime, so
 * the name must not collide with the core's own compile-time default. A
 * tier-2 variant does the opposite, defining RANDOMX_ARGON_SALT to be
 * injected with -include.
 */

#ifndef CPUMINER_RANDOMX_CONFIG_SFX_H
#define CPUMINER_RANDOMX_CONFIG_SFX_H

#define RANDOMX_ARGON_SALT_SFX "RandomSFX\x01"

#endif
