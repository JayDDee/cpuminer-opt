#ifndef __CRYPTONIGHT_H_INCLUDED
#define __CRYPTONIGHT_H_INCLUDED

#include <stddef.h>
#include "crypto/oaes_lib.h"
#include "miner.h"

#define MEMORY         (1 << 21) /* 2 MiB */
#define MEMORY_M128I   (MEMORY >> 4) // 2 MiB / 16 = 128 ki * __m128i
#define ITER           (1 << 20)
#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)	// 128
#define INIT_SIZE_M128I (INIT_SIZE_BYTE >> 4) // 8


#pragma pack(push, 1)
union hash_state {
  uint8_t b[200];
  uint64_t w[25];
};
#pragma pack(pop)

#pragma pack(push, 1)
union cn_slow_hash_state {
    union hash_state hs;
    struct {
        uint8_t k[64];
        uint8_t init[INIT_SIZE_BYTE];
    };
};
#pragma pack(pop)

void do_blake_hash(const void* input, size_t len, char* output);
void do_groestl_hash(const void* input, size_t len, char* output);
void do_jh_hash(const void* input, size_t len, char* output);
void do_skein_hash(const void* input, size_t len, char* output);
void cryptonight_hash_ctx(void* output, const void* input, int len);
void keccakf(uint64_t st[25], int rounds);
extern void (* const extra_hashes[4])(const void *, size_t, char *);

int scanhash_cryptonight( int thr_id, struct work *work, uint32_t max_nonce,
                           uint64_t *hashes_done );

void cryptonight_hash_aes( void *restrict output, const void *input, int len );

#endif

