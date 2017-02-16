// Copyright (c) 2012-2013 The Cryptonote developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Modified for CPUminer by Lucas Jones

#include "miner.h"
#include <memory.h>

#if defined(__arm__) || defined(_MSC_VER)
#ifndef NOASM
#define NOASM
#endif
#endif

#include "crypto/oaes_lib.h"
#include "crypto/c_keccak.h"
#include "crypto/c_groestl.h"
#include "crypto/c_blake256.h"
#include "crypto/c_jh.h"
#include "crypto/c_skein.h"
#include "crypto/int-util.h"
#include "crypto/hash-ops.h"
//#include "cryptonight.h"

#if USE_INT128

#if __GNUC__ == 4 && __GNUC_MINOR__ >= 4 && __GNUC_MINOR__ < 6
typedef unsigned int uint128_t __attribute__ ((__mode__ (TI)));
#elif defined (_MSC_VER)
/* only for mingw64 on windows */
#undef  USE_INT128
#define USE_INT128 (0)
#else
typedef __uint128_t uint128_t;
#endif

#endif

#define LITE 0
#if LITE /* cryptonight-light */
#define MEMORY (1 << 20)
#define ITER   (1 << 19)
#else
#define MEMORY (1 << 21) /* 2 MiB */
#define ITER   (1 << 20)
#endif

#define AES_BLOCK_SIZE  16
#define AES_KEY_SIZE    32 /*16*/
#define INIT_SIZE_BLK   8
#define INIT_SIZE_BYTE (INIT_SIZE_BLK * AES_BLOCK_SIZE)

#pragma pack(push, 1)
union cn_slow_hash_state {
	union hash_state hs;
	struct {
		uint8_t k[64];
		uint8_t init[INIT_SIZE_BYTE];
	};
};
#pragma pack(pop)

static void do_blake_hash(const void* input, size_t len, char* output) {
	blake256_hash((uint8_t*)output, input, len);
}

static void do_groestl_hash(const void* input, size_t len, char* output) {
	groestl(input, len * 8, (uint8_t*)output);
}

static void do_jh_hash(const void* input, size_t len, char* output) {
	int r = jh_hash(HASH_SIZE * 8, input, 8 * len, (uint8_t*)output);
	assert(likely(SUCCESS == r));
}

static void do_skein_hash(const void* input, size_t len, char* output) {
	int r = skein_hash(8 * HASH_SIZE, input, 8 * len, (uint8_t*)output);
	assert(likely(SKEIN_SUCCESS == r));
}

extern int aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey);
#if !defined(_MSC_VER) && !defined(NOASM)
extern int fast_aesb_single_round(const uint8_t *in, uint8_t*out, const uint8_t *expandedKey);
extern int fast_aesb_pseudo_round_mut(uint8_t *val, uint8_t *expandedKey);
#else
#define fast_aesb_single_round     aesb_single_round
#define fast_aesb_pseudo_round_mut aesb_pseudo_round_mut
#endif


#if defined(NOASM) || !defined(__x86_64__)
static uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi) {
	// multiplier   = ab = a * 2^32 + b
	// multiplicand = cd = c * 2^32 + d
	// ab * cd = a * c * 2^64 + (a * d + b * c) * 2^32 + b * d
	uint64_t a = hi_dword(multiplier);
	uint64_t b = lo_dword(multiplier);
	uint64_t c = hi_dword(multiplicand);
	uint64_t d = lo_dword(multiplicand);

	uint64_t ac = a * c;
	uint64_t ad = a * d;
	uint64_t bc = b * c;
	uint64_t bd = b * d;

	uint64_t adbc = ad + bc;
	uint64_t adbc_carry = adbc < ad ? 1 : 0;

	// multiplier * multiplicand = product_hi * 2^64 + product_lo
	uint64_t product_lo = bd + (adbc << 32);
	uint64_t product_lo_carry = product_lo < bd ? 1 : 0;
	*product_hi = ac + (adbc >> 32) + (adbc_carry << 32) + product_lo_carry;
	assert(ac <= *product_hi);

	return product_lo;
}
#else
extern uint64_t mul128(uint64_t multiplier, uint64_t multiplicand, uint64_t* product_hi);
#endif

static void (* const extra_hashes[4])(const void *, size_t, char *) = {
		do_blake_hash, do_groestl_hash, do_jh_hash, do_skein_hash
};

static inline size_t e2i(const uint8_t* a) {
#if !LITE
	return ((uint32_t *)a)[0] & 0x1FFFF0;
#else
	return ((uint32_t *)a)[0] & 0xFFFF0;
#endif
}

static inline void mul_sum_xor_dst(const uint8_t* a, uint8_t* c, uint8_t* dst) {
	uint64_t hi, lo = mul128(((uint64_t*) a)[0], ((uint64_t*) dst)[0], &hi) + ((uint64_t*) c)[1];
	hi += ((uint64_t*) c)[0];

	((uint64_t*) c)[0] = ((uint64_t*) dst)[0] ^ hi;
	((uint64_t*) c)[1] = ((uint64_t*) dst)[1] ^ lo;
	((uint64_t*) dst)[0] = hi;
	((uint64_t*) dst)[1] = lo;
}

static inline void xor_blocks(uint8_t* a, const uint8_t* b) {
#if USE_INT128
	*((uint128_t*) a) ^= *((uint128_t*) b);
#else
	((uint64_t*) a)[0] ^= ((uint64_t*) b)[0];
	((uint64_t*) a)[1] ^= ((uint64_t*) b)[1];
#endif
}

static inline void xor_blocks_dst(const uint8_t* a, const uint8_t* b, uint8_t* dst) {
#if USE_INT128
	*((uint128_t*) dst) = *((uint128_t*) a) ^ *((uint128_t*) b);
#else
	((uint64_t*) dst)[0] = ((uint64_t*) a)[0] ^ ((uint64_t*) b)[0];
	((uint64_t*) dst)[1] = ((uint64_t*) a)[1] ^ ((uint64_t*) b)[1];
#endif
}

typedef struct {
	uint8_t _ALIGN(16) long_state[MEMORY];
	union cn_slow_hash_state state;
	uint8_t _ALIGN(16) text[INIT_SIZE_BYTE];
	uint8_t _ALIGN(16) a[AES_BLOCK_SIZE];
	uint8_t _ALIGN(16) b[AES_BLOCK_SIZE];
	uint8_t _ALIGN(16) c[AES_BLOCK_SIZE];
	oaes_ctx* aes_ctx;
} cryptonight_ctx;

static __thread cryptonight_ctx ctx;

void cryptonight_hash_ctx(void* output, const void* input, int len)
{
	hash_process(&ctx.state.hs, (const uint8_t*) input, len);
	ctx.aes_ctx = (oaes_ctx*) oaes_alloc();

    __builtin_prefetch( ctx.text,             0, 3 );
    __builtin_prefetch( ctx.text       +  64, 0, 3 );
    __builtin_prefetch( ctx.long_state,       1, 0 );
    __builtin_prefetch( ctx.long_state +  64, 1, 0 );
    __builtin_prefetch( ctx.long_state + 128, 1, 0 );
    __builtin_prefetch( ctx.long_state + 192, 1, 0 );
    __builtin_prefetch( ctx.long_state + 256, 1, 0 );
    __builtin_prefetch( ctx.long_state + 320, 1, 0 );
    __builtin_prefetch( ctx.long_state + 384, 1, 0 );
    __builtin_prefetch( ctx.long_state + 448, 1, 0 );

	size_t i, j;
	memcpy(ctx.text, ctx.state.init, INIT_SIZE_BYTE);

	oaes_key_import_data(ctx.aes_ctx, ctx.state.hs.b, AES_KEY_SIZE);
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {

    __builtin_prefetch( ctx.long_state + i + 512, 1, 0 );
    __builtin_prefetch( ctx.long_state + i + 576, 1, 0 );

		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 0], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 1], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 2], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 3], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 4], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 5], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 6], ctx.aes_ctx->key->exp_data);
		aesb_pseudo_round_mut(&ctx.text[AES_BLOCK_SIZE * 7], ctx.aes_ctx->key->exp_data);
		memcpy(&ctx.long_state[i], ctx.text, INIT_SIZE_BYTE);
	}

	xor_blocks_dst(&ctx.state.k[0], &ctx.state.k[32], ctx.a);
	xor_blocks_dst(&ctx.state.k[16], &ctx.state.k[48], ctx.b);

	for (i = 0; likely(i < ITER / 4); ++i) {
		/* Dependency chain: address -> read value ------+
		 * written value <-+ hard function (AES or MUL) <+
		 * next address  <-+
		 */
		/* Iteration 1 */
		j = e2i(ctx.a);
		aesb_single_round(&ctx.long_state[j], ctx.c, ctx.a);
		xor_blocks_dst(ctx.c, ctx.b, &ctx.long_state[j]);
		/* Iteration 2 */
		mul_sum_xor_dst(ctx.c, ctx.a, &ctx.long_state[e2i(ctx.c)]);
		/* Iteration 3 */
		j = e2i(ctx.a);
		aesb_single_round(&ctx.long_state[j], ctx.b, ctx.a);
		xor_blocks_dst(ctx.b, ctx.c, &ctx.long_state[j]);
		/* Iteration 4 */
		mul_sum_xor_dst(ctx.b, ctx.a, &ctx.long_state[e2i(ctx.b)]);
	}

    __builtin_prefetch( ctx.text,             0, 3 );
    __builtin_prefetch( ctx.text       +  64, 0, 3 );
    __builtin_prefetch( ctx.long_state,       1, 0 );
    __builtin_prefetch( ctx.long_state +  64, 1, 0 );
    __builtin_prefetch( ctx.long_state + 128, 1, 0 );
    __builtin_prefetch( ctx.long_state + 192, 1, 0 );
    __builtin_prefetch( ctx.long_state + 256, 1, 0 );
    __builtin_prefetch( ctx.long_state + 320, 1, 0 );
    __builtin_prefetch( ctx.long_state + 384, 1, 0 );
    __builtin_prefetch( ctx.long_state + 448, 1, 0 );

	memcpy(ctx.text, ctx.state.init, INIT_SIZE_BYTE);
	oaes_key_import_data(ctx.aes_ctx, &ctx.state.hs.b[32], AES_KEY_SIZE);
	for (i = 0; likely(i < MEMORY); i += INIT_SIZE_BYTE) {

    __builtin_prefetch( ctx.long_state + i + 512, 1, 0 );
    __builtin_prefetch( ctx.long_state + i + 576, 1, 0 );

		xor_blocks(&ctx.text[0 * AES_BLOCK_SIZE], &ctx.long_state[i + 0 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[0 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[1 * AES_BLOCK_SIZE], &ctx.long_state[i + 1 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[1 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[2 * AES_BLOCK_SIZE], &ctx.long_state[i + 2 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[2 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[3 * AES_BLOCK_SIZE], &ctx.long_state[i + 3 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[3 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[4 * AES_BLOCK_SIZE], &ctx.long_state[i + 4 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[4 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[5 * AES_BLOCK_SIZE], &ctx.long_state[i + 5 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[5 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[6 * AES_BLOCK_SIZE], &ctx.long_state[i + 6 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[6 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
		xor_blocks(&ctx.text[7 * AES_BLOCK_SIZE], &ctx.long_state[i + 7 * AES_BLOCK_SIZE]);
		aesb_pseudo_round_mut(&ctx.text[7 * AES_BLOCK_SIZE], ctx.aes_ctx->key->exp_data);
	}
	memcpy(ctx.state.init, ctx.text, INIT_SIZE_BYTE);
	hash_permutation(&ctx.state.hs);
	/*memcpy(hash, &state, 32);*/
	extra_hashes[ctx.state.hs.b[0] & 3](&ctx.state, 200, output);
	oaes_free((OAES_CTX **) &ctx.aes_ctx);
}

