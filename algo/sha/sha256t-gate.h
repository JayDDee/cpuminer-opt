#ifndef __SHA256T_GATE_H__
#define __SHA256T_GATE_H__ 1

#include <stdint.h>
#include "algo-gate-api.h"

// Override multi way on ryzen, SHA is better.
#if !defined(RYZEN_)
#if defined(__SSE2__)
  #define SHA256T_4WAY
#endif
#if defined(__AVX2__)
  #define SHA256T_8WAY
//  #define SHA256T_11WAY
#endif
#endif

bool register_sha256t_algo( algo_gate_t* gate );
bool register_sha256q_algo( algo_gate_t* gate );

#if defined(SHA256T_11WAY)

void sha256t_11way_hash( void *outx, void *outy, void *outz, const void *inpx,
	                 const void *inpy, const void *inpz );
int scanhash_sha256t_11way( int thr_id, struct work *work, uint32_t max_nonce,
                            uint64_t *hashes_done, struct thr_info *mythr );
//void sha256q_8way_hash( void *output, const void *input );
//int scanhash_sha256q_11way( int thr_id, struct work *work, uint32_t max_nonce,
//                            uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256T_8WAY)

void sha256t_8way_hash( void *output, const void *input );
int scanhash_sha256t_8way( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_8way_hash( void *output, const void *input );
int scanhash_sha256q_8way( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

#if defined(SHA256T_4WAY)

void sha256t_4way_hash( void *output, const void *input );
int scanhash_sha256t_4way( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_4way_hash( void *output, const void *input );
int scanhash_sha256q_4way( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done, struct thr_info *mythr );
#endif

void sha256t_hash( void *output, const void *input );
int scanhash_sha256t( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );
void sha256q_hash( void *output, const void *input );
int scanhash_sha256q( int thr_id, struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr );

#endif

