#ifndef __SKEIN_GATE_H__
#define __SKEIN_GATE_H__
#include <stdint.h>

#if defined(__AVX2__)

void skeinhash_4way( void *output, const void *input );
int scanhash_skein_4way( int thr_id, struct work *work, uint32_t max_nonce,
                         uint64_t *hashes_done );
#endif

void skeinhash( void *output, const void *input );
int scanhash_skein( int thr_id, struct work *work, uint32_t max_nonce,
                    uint64_t *hashes_done );

#endif
