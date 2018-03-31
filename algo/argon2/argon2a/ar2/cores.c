/*
 * Argon2 source code package
 *
 * Written by Daniel Dinu and Dmitry Khovratovich, 2015
 *
 * This work is licensed under a Creative Commons CC0 1.0 License/Waiver.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along
 * with
 * this software. If not, see
 * <http://creativecommons.org/publicdomain/zero/1.0/>.
 */

/*For memory wiping*/
#ifdef _MSC_VER
#include <windows.h>
#include <winbase.h> /* For SecureZeroMemory */
#endif
#if defined __STDC_LIB_EXT1__
#define __STDC_WANT_LIB_EXT1__ 1
#endif
#define VC_GE_2005(version) (version >= 1400)

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "argon2.h"
#include "cores.h"
#include "blake2/blake2.h"
#include "blake2/blake2-impl.h"

#ifdef GENKAT
#include "genkat.h"
#endif

#if defined(__clang__)
#if __has_attribute(optnone)
#define NOT_OPTIMIZED __attribute__((optnone))
#endif
#elif defined(__GNUC__)
#define GCC_VERSION                                                            \
    (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + __GNUC_PATCHLEVEL__)
#if GCC_VERSION >= 40400
#define NOT_OPTIMIZED __attribute__((optimize("O0")))
#endif
#endif
#ifndef NOT_OPTIMIZED
#define NOT_OPTIMIZED
#endif

/***************Instance and Position constructors**********/
void ar2_init_block_value(block *b, uint8_t in) { memset(b->v, in, sizeof(b->v)); }
//inline void init_block_value(block *b, uint8_t in) { memset(b->v, in, sizeof(b->v)); }

void ar2_copy_block(block *dst, const block *src) {
//inline void copy_block(block *dst, const block *src) {
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_WORDS_IN_BLOCK);
}

void ar2_xor_block(block *dst, const block *src) {
//inline void xor_block(block *dst, const block *src) {
    int i;
    for (i = 0; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        dst->v[i] ^= src->v[i];
    }
}

static void ar2_load_block(block *dst, const void *input) {
//static inline void load_block(block *dst, const void *input) {
    unsigned i;
    for (i = 0; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static void ar2_store_block(void *output, const block *src) {
//static inline void store_block(void *output, const block *src) {
    unsigned i;
    for (i = 0; i < ARGON2_WORDS_IN_BLOCK; ++i) {
        store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

/***************Memory allocators*****************/
int ar2_allocate_memory(block **memory, uint32_t m_cost) {
    if (memory != NULL) {
        size_t memory_size = sizeof(block) * m_cost;
        if (m_cost != 0 &&
            memory_size / m_cost !=
                sizeof(block)) { /*1. Check for multiplication overflow*/
            return ARGON2_MEMORY_ALLOCATION_ERROR;
        }

        *memory = (block *)malloc(memory_size); /*2. Try to allocate*/

        if (!*memory) {
            return ARGON2_MEMORY_ALLOCATION_ERROR;
        }

        return ARGON2_OK;
    } else {
        return ARGON2_MEMORY_ALLOCATION_ERROR;
    }
}

void ar2_secure_wipe_memory(void *v, size_t n) { memset(v, 0, n); }
//inline void secure_wipe_memory(void *v, size_t n) { memset(v, 0, n); }

/*********Memory functions*/

void ar2_clear_memory(argon2_instance_t *instance, int clear) {
//inline void clear_memory(argon2_instance_t *instance, int clear) {
    if (instance->memory != NULL && clear) {
        ar2_secure_wipe_memory(instance->memory,
                           sizeof(block) * /*instance->memory_blocks*/16);
    }
}

void ar2_free_memory(block *memory) { free(memory); }
//inline void free_memory(block *memory) { free(memory); }

void ar2_finalize(const argon2_context *context, argon2_instance_t *instance) {
    if (context != NULL && instance != NULL) {
        block blockhash;
        ar2_copy_block(&blockhash, instance->memory + 15);

        /* Hash the result */
        {
            uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
            ar2_store_block(blockhash_bytes, &blockhash);
            ar2_blake2b_long(context->out, blockhash_bytes);
            ar2_secure_wipe_memory(blockhash.v, ARGON2_BLOCK_SIZE);
            ar2_secure_wipe_memory(blockhash_bytes, ARGON2_BLOCK_SIZE); /* clear blockhash_bytes */
        }

#ifdef GENKAT
        print_tag(context->out, context->outlen);
#endif

        /* Clear memory */
        // clear_memory(instance, 1);

        ar2_free_memory(instance->memory);
    }
}

uint32_t ar2_index_alpha(const argon2_instance_t *instance,
                     const argon2_position_t *position, uint32_t pseudo_rand,
                     int same_lane) {
    /*
     * Pass 0:
     *      This lane : all already finished segments plus already constructed
     * blocks in this segment
     *      Other lanes : all already finished segments
     * Pass 1+:
     *      This lane : (SYNC_POINTS - 1) last segments plus already constructed
     * blocks in this segment
     *      Other lanes : (SYNC_POINTS - 1) last segments
     */
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
        /* First pass */
        if (0 == position->slice) {
            /* First slice */
            reference_area_size =
                position->index - 1; /* all but the previous */
        } else {
            if (same_lane) {
                /* The same lane => add current segment */
                reference_area_size =
                    position->slice * 4 +
                    position->index - 1;
            } else {
                reference_area_size =
                    position->slice * 4 +
                    ((position->index == 0) ? (-1) : 0);
            }
        }
    } else {
        /* Second pass */
        if (same_lane) {reference_area_size = 11 + position->index;}
        else {reference_area_size = 12 - (position->index == 0);}
    }

    /* 1.2.4. Mapping pseudo_rand to 0..<reference_area_size-1> and produce
     * relative position */
    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 -
                        (reference_area_size * relative_position >> 32);

    /* 1.2.5 Computing starting position */
    start_position = 0;

    if (0 != position->pass) {
        start_position = (position->slice == ARGON2_SYNC_POINTS - 1)
                             ? 0 : (position->slice + 1) * 4;
    }

    /* 1.2.6. Computing absolute position */
    absolute_position = (start_position + relative_position) % 16;
    return absolute_position;
}

void ar2_fill_memory_blocks(argon2_instance_t *instance) {
    uint32_t r, s;

    for (r = 0; r < 2; ++r) {
        for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {

            argon2_position_t position;
            position.pass = r;
            position.lane = 0;
            position.slice = (uint8_t)s;
            position.index = 0;
            ar2_fill_segment(instance, position);
        }

#ifdef GENKAT
        internal_kat(instance, r); /* Print all memory blocks */
#endif
    }
}

void ar2_fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance) {
    /* Make the first and second block in each lane as G(H0||i||0) or
       G(H0||i||1) */
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, 0);
    ar2_blake2b_too(blockhash_bytes, blockhash);
    ar2_load_block(&instance->memory[0], blockhash_bytes);

    store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
    ar2_blake2b_too(blockhash_bytes, blockhash);
    ar2_load_block(&instance->memory[1], blockhash_bytes);
    ar2_secure_wipe_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}


static const blake2b_state base_hash = {
 .h = {
  UINT64_C(7640891576939301192), UINT64_C(13503953896175478587),
  UINT64_C(4354685564936845355), UINT64_C(11912009170470909681),
  UINT64_C(5840696475078001361), UINT64_C(11170449401992604703),
  UINT64_C(2270897969802886507), UINT64_C(6620516959819538809)
 },
 .t = {UINT64_C(0),UINT64_C(0)},
 .f = {UINT64_C(0),UINT64_C(0)},
 .buf = {
  1, 0, 0, 0, 32, 0, 0, 0, 16, 0, 0, 0, 2, 0, 0, 0, 16, 0, 0, 0, 1, 0,
  0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
 .buflen = 28,
 .outlen = 64,
 .last_node = 0
};

#define PWDLEN 32
#define SALTLEN 32
#define SECRETLEN 0
#define ADLEN 0
void ar2_initial_hash(uint8_t *blockhash, argon2_context *context,
                  argon2_type type) {

    uint8_t value[sizeof(uint32_t)];

    /* Is it generating cache invalidation between cores ? */
    blake2b_state BlakeHash = base_hash;
    BlakeHash.buf[20] = (uint8_t) type;
    my_blake2b_update(&BlakeHash, (const uint8_t *)context->pwd,
                   PWDLEN);


    ar2_secure_wipe_memory(context->pwd, PWDLEN);
    context->pwdlen = 0;

    store32(&value, SALTLEN);
    my_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    my_blake2b_update(&BlakeHash, (const uint8_t *)context->salt,
                   SALTLEN);

    store32(&value, SECRETLEN);
    my_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, ADLEN);
    my_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    ar2_blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

int ar2_initialize(argon2_instance_t *instance, argon2_context *context) {
    /* 1. Memory allocation */


    ar2_allocate_memory(&(instance->memory), 16);

    /* 2. Initial hashing */
    /* H_0 + 8 extra bytes to produce the first blocks */
    /* Hashing all inputs */
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    ar2_initial_hash(blockhash, context, instance->type);
    /* Zeroing 8 extra bytes */
    ar2_secure_wipe_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH,
                       ARGON2_PREHASH_SEED_LENGTH -
                           ARGON2_PREHASH_DIGEST_LENGTH);

#ifdef GENKAT
    initial_kat(blockhash, context, instance->type);
#endif

    /* 3. Creating first blocks, we always have at least two blocks in a slice
     */
    ar2_fill_first_blocks(blockhash, instance);
    /* Clearing the hash */
    ar2_secure_wipe_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return ARGON2_OK;
}

int ar2_argon2_core(argon2_context *context, argon2_type type) {
    argon2_instance_t instance;
    instance.memory = NULL;
    instance.type = type;

    /* 3. Initialization: Hashing inputs, allocating memory, filling first
     * blocks
     */

    int result = ar2_initialize(&instance, context);
    if (ARGON2_OK != result) return result;

    /* 4. Filling memory */
    ar2_fill_memory_blocks(&instance);

    /* 5. Finalization */
    ar2_finalize(context, &instance);

    return ARGON2_OK;
}
