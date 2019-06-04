#ifndef LYRA2_GATE_H__
#define LYRA2_GATE_H__ 1

#include "algo-gate-api.h"
#include <stdint.h>
#include "lyra2.h"

#if defined(__AVX2__)
  #define LYRA2REV3_4WAY
#endif

extern __thread uint64_t* l2v3_wholeMatrix;

bool register_lyra2rev3_algo( algo_gate_t* gate );

#if defined(LYRA2REV3_4WAY)

void lyra2rev3_4way_hash( void *state, const void *input );
int scanhash_lyra2rev3_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr );
bool init_lyra2rev3_4way_ctx();

#else

void lyra2rev3_hash( void *state, const void *input );
int scanhash_lyra2rev3( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool init_lyra2rev3_ctx();

#endif

//////////////////////////////////

#if defined(__AVX2__)
  #define LYRA2REV2_4WAY
#endif

extern __thread uint64_t* l2v2_wholeMatrix;

bool register_lyra2rev2_algo( algo_gate_t* gate );

#if defined(LYRA2REV2_4WAY)

void lyra2rev2_4way_hash( void *state, const void *input );
int scanhash_lyra2rev2_4way( int thr_id, struct work *work, uint32_t max_nonce,
                             uint64_t *hashes_done, struct thr_info *mythr );
bool init_lyra2rev2_4way_ctx();

#else

void lyra2rev2_hash( void *state, const void *input );
int scanhash_lyra2rev2( int thr_id, struct work *work, uint32_t max_nonce,
                        uint64_t *hashes_done, struct thr_info *mythr );
bool init_lyra2rev2_ctx();

#endif

/////////////////////////

#if defined(__SSE2__)
  #define LYRA2Z_4WAY
#endif
#if defined(__AVX2__)
  #define LYRA2Z_8WAY
#endif


#define LYRA2Z_MATRIX_SIZE  BLOCK_LEN_INT64 * 8 * 8 * 8

#if defined(LYRA2Z_8WAY)

void lyra2z_8way_hash( void *state, const void *input );
int scanhash_lyra2z_8way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
bool lyra2z_8way_thread_init();

#elif defined(LYRA2Z_4WAY)

void lyra2z_4way_hash( void *state, const void *input );
int scanhash_lyra2z_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
bool lyra2z_4way_thread_init();

#else

void lyra2z_hash( void *state, const void *input );
int scanhash_lyra2z( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );
bool lyra2z_thread_init();

#endif

////////////////////

#if defined(__AVX2__)
  #define LYRA2H_4WAY
#endif

#define LYRA2H_MATRIX_SIZE  BLOCK_LEN_INT64 * 16 * 16 * 8

#if defined(LYRA2H_4WAY)

void lyra2h_4way_hash( void *state, const void *input );
int scanhash_lyra2h_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
bool lyra2h_4way_thread_init();

#else

void lyra2h_hash( void *state, const void *input );
int scanhash_lyra2h( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );
bool lyra2h_thread_init();

#endif

//////////////////////////////////

#if defined(__AVX2__) && defined(__AES__)
  #define ALLIUM_4WAY
#endif

bool register_allium_algo( algo_gate_t* gate );

#if defined(ALLIUM_4WAY)

void allium_4way_hash( void *state, const void *input );
int scanhash_allium_4way( int thr_id, struct work *work, uint32_t max_nonce,
                          uint64_t *hashes_done, struct thr_info *mythr );
bool init_allium_4way_ctx();

#else

void allium_hash( void *state, const void *input );
int scanhash_allium( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );
bool init_allium_ctx();

#endif 

/////////////////////////////////////////

bool phi2_has_roots;

bool register_phi2_algo( algo_gate_t* gate );

void phi2_hash( void *state, const void *input );
int scanhash_phi2( int thr_id, struct work *work, uint32_t max_nonce,
                     uint64_t *hashes_done, struct thr_info *mythr );
void init_phi2_ctx();

#endif  // LYRA2_GATE_H__


