/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0 
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef _WIN32
#include <malloc.h>
#endif

#include "argon2.h"
#include "encoding.h"
#include "core.h"

const char *argon2_type2string(argon2_type type, int uppercase) {
    switch (type) {
        case Argon2_d:
            return uppercase ? "Argon2d" : "argon2d";
    }

    return NULL;
}

int argon2_ctx(argon2_context *context, argon2_type type) {
    /* 1. Validate all inputs */
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    if (ARGON2_OK != result) {
        return result;
    }

    if (Argon2_d != type) {
        return ARGON2_INCORRECT_TYPE;
    }

    /* 2. Align memory size */
    /* Minimum memory_blocks = 8L blocks, where L is the number of lanes */
    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
        memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    /* Ensure that all segments have equal length */
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.limit = 1;
    instance.threads = context->threads;
    instance.type = type;

    if (instance.threads > instance.limit) {
        instance.threads = instance.limit;
    }

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks
     */
    result = initialize(&instance, context);

    if (ARGON2_OK != result) {
        return result;
    }

    /* 4. Filling memory */
    result = fill_memory_blocks(&instance);

    if (ARGON2_OK != result) {
        return result;
    }
    /* 5. Finalization */
    finalize(context, &instance);

    return ARGON2_OK;
}

int argon2_hash(const uint32_t t_cost, const uint32_t m_cost,
                const uint32_t parallelism, const void *pwd,
                const size_t pwdlen, const void *salt, const size_t saltlen,
                void *hash, const size_t hashlen, char *encoded,
                const size_t encodedlen, argon2_type type){

    argon2_context context;
    int result;
    uint8_t *out;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (saltlen > ARGON2_MAX_SALT_LENGTH) {
        return ARGON2_SALT_TOO_LONG;
    }

    if (hashlen > ARGON2_MAX_OUTLEN) {
        return ARGON2_OUTPUT_TOO_LONG;
    }

    if (hashlen < ARGON2_MIN_OUTLEN) {
        return ARGON2_OUTPUT_TOO_SHORT;
    }

    out = malloc(hashlen);
    if (!out) {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)hashlen;
    context.pwd = CONST_CAST(uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = CONST_CAST(uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;

    result = argon2_ctx(&context, type);

    if (result != ARGON2_OK) {
        clear_internal_memory(out, hashlen);
        free(out);
        return result;
    }

    /* if raw hash requested, write it */
    if (hash) {
        memcpy(hash, out, hashlen);
    }

    /* if encoding requested, write it */
    if (encoded && encodedlen) {
        if (encode_string(encoded, encodedlen, &context, type) != ARGON2_OK) {
            clear_internal_memory(out, hashlen); /* wipe buffers if error */
            clear_internal_memory(encoded, encodedlen);
            free(out);
            return ARGON2_ENCODING_FAIL;
        }
    }
    clear_internal_memory(out, hashlen);
    free(out);

    return ARGON2_OK;
}

int argon2d_hash_encoded(const uint32_t t_cost, const uint32_t m_cost,
                         const uint32_t parallelism, const void *pwd,
                         const size_t pwdlen, const void *salt,
                         const size_t saltlen, const size_t hashlen,
                         char *encoded, const size_t encodedlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       NULL, hashlen, encoded, encodedlen, Argon2_d);
}

int argon2d_hash_raw(const uint32_t t_cost, const uint32_t m_cost,
                     const uint32_t parallelism, const void *pwd,
                     const size_t pwdlen, const void *salt,
                     const size_t saltlen, void *hash, const size_t hashlen) {

    return argon2_hash(t_cost, m_cost, parallelism, pwd, pwdlen, salt, saltlen,
                       hash, hashlen, NULL, 0, Argon2_d);
}

static int argon2_compare(const uint8_t *b1, const uint8_t *b2, size_t len) {
    size_t i;
    uint8_t d = 0U;

    for (i = 0U; i < len; i++) {
        d |= b1[i] ^ b2[i];
    }
    return (int)((1 & ((d - 1) >> 8)) - 1);
}

int argon2_verify(const char *encoded, const void *pwd, const size_t pwdlen,
                  argon2_type type) {

    argon2_context ctx;
    uint8_t *desired_result = NULL;

    int ret = ARGON2_OK;

    size_t encoded_len;
    uint32_t max_field_len;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
        return ARGON2_PWD_TOO_LONG;
    }

    if (encoded == NULL) {
        return ARGON2_DECODING_FAIL;
    }

    encoded_len = strlen(encoded);
    if (encoded_len > UINT32_MAX) {
        return ARGON2_DECODING_FAIL;
    }

    /* No field can be longer than the encoded length */
    max_field_len = (uint32_t)encoded_len;

    ctx.saltlen = max_field_len;
    ctx.outlen = max_field_len;

    ctx.salt = malloc(ctx.saltlen);
    ctx.out = malloc(ctx.outlen);
    if (!ctx.salt || !ctx.out) {
        ret = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    ctx.pwd = (uint8_t *)pwd;
    ctx.pwdlen = (uint32_t)pwdlen;

    ret = decode_string(&ctx, encoded, type);
    if (ret != ARGON2_OK) {
        goto fail;
    }

    /* Set aside the desired result, and get a new buffer. */
    desired_result = ctx.out;
    ctx.out = malloc(ctx.outlen);
    if (!ctx.out) {
        ret = ARGON2_MEMORY_ALLOCATION_ERROR;
        goto fail;
    }

    ret = argon2_verify_ctx(&ctx, (char *)desired_result, type);
    if (ret != ARGON2_OK) {
        goto fail;
    }

fail:
    free(ctx.salt);
    free(ctx.out);
    free(desired_result);

    return ret;
}

int argon2d_verify(const char *encoded, const void *pwd, const size_t pwdlen) {

    return argon2_verify(encoded, pwd, pwdlen, Argon2_d);
}

int argon2d_ctx(argon2_context *context) {
    return argon2_ctx(context, Argon2_d);
}

int argon2_verify_ctx(argon2_context *context, const char *hash,
                      argon2_type type) {
    int ret = argon2_ctx(context, type);
    if (ret != ARGON2_OK) {
        return ret;
    }

    if (argon2_compare((uint8_t *)hash, context->out, context->outlen)) {
        return ARGON2_VERIFY_MISMATCH;
    }

    return ARGON2_OK;
}

int argon2d_verify_ctx(argon2_context *context, const char *hash) {
    return argon2_verify_ctx(context, hash, Argon2_d);
}

const char *argon2_error_message(int error_code) {
    switch (error_code) {
    case ARGON2_OK:
        return "OK";
    case ARGON2_OUTPUT_PTR_NULL:
        return "Output pointer is NULL";
    case ARGON2_OUTPUT_TOO_SHORT:
        return "Output is too short";
    case ARGON2_OUTPUT_TOO_LONG:
        return "Output is too long";
    case ARGON2_PWD_TOO_SHORT:
        return "Password is too short";
    case ARGON2_PWD_TOO_LONG:
        return "Password is too long";
    case ARGON2_SALT_TOO_SHORT:
        return "Salt is too short";
    case ARGON2_SALT_TOO_LONG:
        return "Salt is too long";
    case ARGON2_AD_TOO_SHORT:
        return "Associated data is too short";
    case ARGON2_AD_TOO_LONG:
        return "Associated data is too long";
    case ARGON2_SECRET_TOO_SHORT:
        return "Secret is too short";
    case ARGON2_SECRET_TOO_LONG:
        return "Secret is too long";
    case ARGON2_TIME_TOO_SMALL:
        return "Time cost is too small";
    case ARGON2_TIME_TOO_LARGE:
        return "Time cost is too large";
    case ARGON2_MEMORY_TOO_LITTLE:
        return "Memory cost is too small";
    case ARGON2_MEMORY_TOO_MUCH:
        return "Memory cost is too large";
    case ARGON2_LANES_TOO_FEW:
        return "Too few lanes";
    case ARGON2_LANES_TOO_MANY:
        return "Too many lanes";
    case ARGON2_PWD_PTR_MISMATCH:
        return "Password pointer is NULL, but password length is not 0";
    case ARGON2_SALT_PTR_MISMATCH:
        return "Salt pointer is NULL, but salt length is not 0";
    case ARGON2_SECRET_PTR_MISMATCH:
        return "Secret pointer is NULL, but secret length is not 0";
    case ARGON2_AD_PTR_MISMATCH:
        return "Associated data pointer is NULL, but ad length is not 0";
    case ARGON2_MEMORY_ALLOCATION_ERROR:
        return "Memory allocation error";
    case ARGON2_FREE_MEMORY_CBK_NULL:
        return "The free memory callback is NULL";
    case ARGON2_ALLOCATE_MEMORY_CBK_NULL:
        return "The allocate memory callback is NULL";
    case ARGON2_INCORRECT_PARAMETER:
        return "Argon2_Context context is NULL";
    case ARGON2_INCORRECT_TYPE:
        return "There is no such version of Argon2";
    case ARGON2_OUT_PTR_MISMATCH:
        return "Output pointer mismatch";
    case ARGON2_THREADS_TOO_FEW:
        return "Not enough threads";
    case ARGON2_THREADS_TOO_MANY:
        return "Too many threads";
    case ARGON2_MISSING_ARGS:
        return "Missing arguments";
    case ARGON2_ENCODING_FAIL:
        return "Encoding failed";
    case ARGON2_DECODING_FAIL:
        return "Decoding failed";
    case ARGON2_THREAD_FAIL:
        return "Threading failure";
    case ARGON2_DECODING_LENGTH_FAIL:
        return "Some of encoded parameters are too long or too short";
    case ARGON2_VERIFY_MISMATCH:
        return "The password does not match the supplied hash";
    default:
        return "Unknown error code";
    }
}

size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism,
                         uint32_t saltlen, uint32_t hashlen, argon2_type type) {
  return strlen("$$v=$m=,t=,p=$$") + strlen(argon2_type2string(type, 0)) +
         numlen(t_cost) + numlen(m_cost) + numlen(parallelism) +
         b64len(saltlen) + b64len(hashlen);
}

#ifdef __AVX2__

///////////////////////////
// Wolf's Additions
///////////////////////////

#include <stdbool.h>
#include <pthread.h>
#include <x86intrin.h>
#include "../blake2/blake2.h"

typedef struct _Argon2d_Block
{
	union
	{
		uint64_t data[1024 / 8] __attribute__((aligned(32)));
		__m128i dqwords[1024 / 16] __attribute__((aligned(32)));
		__m256i qqwords[1024 / 32] __attribute__((aligned(32)));
	};
} Argon2d_Block;

typedef struct _Argon2ThreadData
{
	Argon2d_Block *Matrix;
	uint32_t slice;
	uint32_t lane;
} Argon2ThreadData;

#define SEGMENT_LENGTH			(250U / (4U * 4U))		// memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
#define LANE_LENGTH				(SEGMENT_LENGTH * 4U)	// segment_length * ARGON2_SYNC_POINTS;
#define CONCURRENT_THREADS		4

static const uint64_t blake2b_IV[8] =
{
	0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
	0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
	0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
	0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const unsigned int blake2b_sigma[12][16] =
{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

#define ROTL64(x, y)		(((x) << (y)) | ((x) >> (64 - (y))))

#define G(r, i, a, b, c, d)                                                    \
    do {                                                                       \
        a = a + b + m[blake2b_sigma[r][2 * i + 0]];                            \
        d = ROTL64(d ^ a, 32);                                                 \
        c = c + d;                                                             \
        b = ROTL64(b ^ c, 40);                                                 \
        a = a + b + m[blake2b_sigma[r][2 * i + 1]];                            \
        d = ROTL64(d ^ a, 48);                                                 \
        c = c + d;                                                             \
        b = ROTL64(b ^ c, 1);                                                 \
    } while ((void)0, 0)

#define ROUND(r)                                                               \
    do {                                                                       \
        G(r, 0, v[0], v[4], v[8], v[12]);                                      \
        G(r, 1, v[1], v[5], v[9], v[13]);                                      \
        G(r, 2, v[2], v[6], v[10], v[14]);                                     \
        G(r, 3, v[3], v[7], v[11], v[15]);                                     \
        G(r, 4, v[0], v[5], v[10], v[15]);                                     \
        G(r, 5, v[1], v[6], v[11], v[12]);                                     \
        G(r, 6, v[2], v[7], v[8], v[13]);                                      \
        G(r, 7, v[3], v[4], v[9], v[14]);                                      \
    } while ((void)0, 0)

void CompressBlock(uint64_t *h, const uint64_t *m, uint64_t t, uint64_t f)
{
	uint64_t v[16];
	
	int i;
	for(i = 0; i < 8; ++i) v[i] = h[i];
	
	for(i = 8; i < 16; ++i) v[i] = blake2b_IV[i - 8];
	
	v[12] ^= t;
	v[14] ^= f;
	
	int r;
	for(r = 0; r < 12; ++r)
	{
		ROUND(r);
	}
	
	for(i = 0; i < 8; ++i) h[i] ^= v[i] ^ v[i + 8];
}

void Argon2dInitHash(void *HashOut, void *Input)
{
	blake2b_state BlakeHash;
	uint32_t InBuf[64];							// Is only 50 uint32_t, but need more space for Blake2B
	
	memset(InBuf, 0x00, 200);
	
	InBuf[0] = 4UL;								// Lanes
	InBuf[1] = 32UL;								// Output Length
	InBuf[2] = 250UL;							// Memory Cost
	InBuf[3] = 1UL;								// Time Cost
	InBuf[4] = 16UL;								// Argon2 Version Number
	InBuf[5] = 0UL;								// Type
	InBuf[6] = 80UL;								// Password Length
	
	memcpy(InBuf + 7, Input, 80);				// Password
	
	InBuf[27] = 80UL;							// Salt Length
	
	memcpy(InBuf + 28, Input, 80);				// Salt
	
	InBuf[48] = 0UL;								// Secret Length
	InBuf[49] = 0UL;								// Associated Data Length
	
	int i;
	for(i = 50; i < 64; ++i) InBuf[i] = 0UL;
		
	uint64_t H[8];
	
	for(i = 0; i < 8; ++i) H[i] = blake2b_IV[i];
	
	H[0] ^= 0x0000000001010040;
	
	CompressBlock(H, (uint64_t *)InBuf, 128ULL, 0ULL);
	CompressBlock(H, (uint64_t *)(InBuf + 32), 200ULL, 0xFFFFFFFFFFFFFFFFULL);
	
	memcpy(HashOut, H, 64U);
}

void Argon2dFillFirstBlocks(Argon2d_Block *Matrix, void *InitHash)
{
	uint32_t lane;
	for(lane = 0; lane < 4; ++lane)
	{
		((uint32_t *)InitHash)[16] = 0;
		((uint32_t *)InitHash)[17] = lane;
		blake2b_long(Matrix[lane * LANE_LENGTH].data, 1024, InitHash, 72);
		((uint32_t *)InitHash)[16] |= 1;
		blake2b_long(Matrix[lane * LANE_LENGTH + 1].data, 1024, InitHash, 72);
	}
}

#include "../blake2/blamka-round-opt.h"

void Argon2dFillSingleBlock(Argon2d_Block *State, Argon2d_Block *RefBlock, Argon2d_Block *NextBlock)
{	
	__m256i XY[32];
	
	int i;
	for(i = 0; i < 32; ++i)
		XY[i] = State->qqwords[i] = _mm256_xor_si256(State->qqwords[i], RefBlock->qqwords[i]);
	
	for(i = 0; i < 8; ++i)
	{
		BLAKE2_ROUND(	State->dqwords[8 * i + 0], State->dqwords[8 * i + 1], State->dqwords[8 * i + 2], State->dqwords[8 * i + 3],
						State->dqwords[8 * i + 4], State->dqwords[8 * i + 5], State->dqwords[8 * i + 6], State->dqwords[8 * i + 7]);
	}
	
	for(i = 0; i < 8; ++i)
	{
		BLAKE2_ROUND(	State->dqwords[8 * 0 + i], State->dqwords[8 * 1 + i], State->dqwords[8 * 2 + i], State->dqwords[8 * 3 + i],
						State->dqwords[8 * 4 + i], State->dqwords[8 * 5 + i], State->dqwords[8 * 6 + i], State->dqwords[8 * 7 + i]);
	}
	
	for(i = 0; i < 32; ++i)
	{
		State->qqwords[i] = _mm256_xor_si256(State->qqwords[i], XY[i]);
		_mm256_store_si256(NextBlock->qqwords + i, State->qqwords[i]);
	}
}

void FillSegment(Argon2d_Block *Matrix, uint32_t slice, uint32_t lane)
{			
	uint32_t startidx, prevoff, curoff;
	Argon2d_Block State;
	
	startidx = (!slice) ? 2 : 0;
	curoff = lane * LANE_LENGTH + slice * SEGMENT_LENGTH + startidx;
	
	//if(!(curoff % LANE_LENGTH)) prevoff = curoff + LANE_LENGTH - 1;
	//else prevoff = curoff - 1;
	
	prevoff = (!(curoff % LANE_LENGTH)) ? curoff + LANE_LENGTH - 1 : curoff - 1;
	
	memcpy(State.data, (Matrix + prevoff)->data, 1024);
	
	int i;
	for(i = startidx; i < SEGMENT_LENGTH; ++i, ++curoff, ++prevoff)
	{
		if((curoff % LANE_LENGTH) == 1) prevoff = curoff - 1;
		
		uint64_t pseudorand = Matrix[prevoff].data[0];
		uint64_t reflane = (!slice) ? lane : (pseudorand >> 32) & 3;		// mod lanes
				
		uint32_t index = i;
		bool samelane = reflane == lane;
		pseudorand &= 0xFFFFFFFFULL;
		uint32_t refareasize = ((reflane == lane) ? slice * SEGMENT_LENGTH + index - 1 : slice * SEGMENT_LENGTH + ((!index) ? -1 : 0));
		
		
		if(!slice) refareasize = index - 1;
		
		uint64_t relativepos = (pseudorand & 0xFFFFFFFFULL);
		relativepos = relativepos * relativepos >> 32;
		relativepos = refareasize - 1 - (refareasize * relativepos >> 32);
		
		uint32_t startpos = 0;
				
		uint32_t abspos = (startpos + relativepos) % LANE_LENGTH;
		
		uint32_t refidx = abspos;
		
		Argon2dFillSingleBlock(&State, Matrix + (LANE_LENGTH * reflane + refidx), Matrix + curoff);
	}
}

void *ThreadedSegmentFill(void *ThrData)
{
	Argon2ThreadData *Data = (Argon2ThreadData *)ThrData;
	
	FillSegment(Data->Matrix, Data->slice, Data->lane);
	return(NULL);
}

void Argon2dFillAllBlocks(Argon2d_Block *Matrix)
{
	pthread_t ThrHandles[CONCURRENT_THREADS];
	Argon2ThreadData ThrData[CONCURRENT_THREADS];
	
	int s;
	for(s = 0; s < 4; ++s)
	{
		// WARNING: Assumes CONCURRENT_THREADS == lanes == 4
		int l;
		for(l = 0; l < 4; ++l)
		{
			FillSegment(Matrix, s, l);
		}		
	}
}

void Argon2dFinalizeHash(void *OutputHash, Argon2d_Block *Matrix)
{
	int l;
	for(l = 1; l < 4; ++l)
	{
		int i;
		for(i = 0; i < 32; ++i)
			Matrix[LANE_LENGTH - 1].qqwords[i] = _mm256_xor_si256(Matrix[LANE_LENGTH - 1].qqwords[i], Matrix[LANE_LENGTH * l + (LANE_LENGTH - 1)].qqwords[i]);
	}
	
	blake2b_long(OutputHash, 32, Matrix[LANE_LENGTH - 1].data, 1024);
}

void WolfArgon2dPoWHash(void *Output, void *Matrix, const void *BlkHdr)
{
	uint8_t tmp[72];
		
	Argon2dInitHash(tmp, (uint8_t *)BlkHdr);
		
	Argon2dFillFirstBlocks(Matrix, tmp);
	
	Argon2dFillAllBlocks(Matrix);
	
	Argon2dFinalizeHash((uint8_t *)Output, Matrix);
}

void WolfArgon2dAllocateCtx(void **Matrix)
{
	#ifdef _WIN32
	*((Argon2d_Block **)Matrix) = (Argon2d_Block *)_aligned_malloc(32, sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	#else
	*((Argon2d_Block **)Matrix) = (Argon2d_Block *)malloc(sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	posix_memalign(Matrix, 32, sizeof(Argon2d_Block) * (SEGMENT_LENGTH << 4));
	#endif
}

void WolfArgon2dFreeCtx(void *Matrix)
{
	free(Matrix);
}

#endif
