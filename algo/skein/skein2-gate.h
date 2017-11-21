#ifndef __SKEIN2GATE_H__
#define __SKEIN2_GATE_H__
#include <stdint.h>

#if defined(__AVX2__)
void skein2hash_4way( void *output, const void *input );
int scanhash_skein2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t* hashes_done );
#endif

void skein2hash( void *output, const void *input );
int scanhash_skein2( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done );
#endif

