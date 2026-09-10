/* RandomX-Graft (Graft) -- pool algo "rx/graft".
 *
 * Tier 2: two instruction frequencies and the program size are constexpr in
 * the core, so this needs its own compiled core and is injected into it.
 *
 * Constants from the consensus source:
 *   graft-project/GraftNetwork .gitmodules -> external/randomx
 *       -> github.com/graft-project/Graft-RandomX
 *   pinned commit 14a466caa209d41509fd6cb30db815d5efd15b90, src/configuration.h
 * Everything not listed below matches rx/0, including the AES generator keys
 * and the other 28 frequencies.
 *
 * Mined with RANDOMX_FLAG_V2 clear. Graft's single RANDOMX_PROGRAM_SIZE maps
 * to our _V1; 280 is within RANDOMX_PROGRAM_MAX_SIZE, so the fixed program
 * buffer still fits.
 */

#ifndef CPUMINER_RANDOMX_CONFIG_GRAFT_H
#define CPUMINER_RANDOMX_CONFIG_GRAFT_H

#define RANDOMX_ARGON_LANES        2
#define RANDOMX_ARGON_SALT         "RandomX-Graft\x01"

#define RANDOMX_PROGRAM_SIZE_V1    280

/* These two swap 8->7 and 2->3, so the frequency total stays 256. */
#define RANDOMX_FREQ_IROR_R        7
#define RANDOMX_FREQ_IROL_R        3

#endif
