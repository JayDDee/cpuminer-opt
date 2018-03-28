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

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

#include <immintrin.h>

#include "argon2.h"
#include "cores.h"
#include "opt.h"

#include "blake2/blake2.h"
#include "blake2/blamka-round-opt.h"

void ar2_fill_block(__m128i *state, __m128i const *ref_block, __m128i *next_block)
{
    __m128i ALIGN(16) block_XY[ARGON2_QWORDS_IN_BLOCK];
    uint32_t i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        block_XY[i] = state[i] = _mm_xor_si128(
            state[i], _mm_load_si128(&ref_block[i]));
    }

    BLAKE2_ROUND(state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7]);
    BLAKE2_ROUND(state[8], state[9], state[10], state[11], state[12], state[13], state[14], state[15]);
    BLAKE2_ROUND(state[16], state[17], state[18], state[19], state[20], state[21], state[22], state[23]);
    BLAKE2_ROUND(state[24], state[25], state[26], state[27], state[28], state[29], state[30], state[31]);
    BLAKE2_ROUND(state[32], state[33], state[34], state[35], state[36], state[37], state[38], state[39]);
    BLAKE2_ROUND(state[40], state[41], state[42], state[43], state[44], state[45], state[46], state[47]);
    BLAKE2_ROUND(state[48], state[49], state[50], state[51], state[52], state[53], state[54], state[55]);
    BLAKE2_ROUND(state[56], state[57], state[58], state[59], state[60], state[61], state[62], state[63]);
    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * i + 0], state[8 * i + 1], state[8 * i + 2],
                     state[8 * i + 3], state[8 * i + 4], state[8 * i + 5],
                     state[8 * i + 6], state[8 * i + 7]);
    }*/

    BLAKE2_ROUND(state[0], state[8], state[16], state[24], state[32], state[40], state[48], state[56]);
    BLAKE2_ROUND(state[1], state[9], state[17], state[25], state[33], state[41], state[49], state[57]);
    BLAKE2_ROUND(state[2], state[10], state[18], state[26], state[34], state[42], state[50], state[58]);
    BLAKE2_ROUND(state[3], state[11], state[19], state[27], state[35], state[43], state[51], state[59]);
    BLAKE2_ROUND(state[4], state[12], state[20], state[28], state[36], state[44], state[52], state[60]);
    BLAKE2_ROUND(state[5], state[13], state[21], state[29], state[37], state[45], state[53], state[61]);
    BLAKE2_ROUND(state[6], state[14], state[22], state[30], state[38], state[46], state[54], state[62]);
    BLAKE2_ROUND(state[7], state[15], state[23], state[31], state[39], state[47], state[55], state[63]);
    /*for (i = 0; i < 8; ++i) {
        BLAKE2_ROUND(state[8 * 0 + i], state[8 * 1 + i], state[8 * 2 + i],
                     state[8 * 3 + i], state[8 * 4 + i], state[8 * 5 + i],
                     state[8 * 6 + i], state[8 * 7 + i]);
    }*/

    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; i++) {
        state[i] = _mm_xor_si128(state[i], block_XY[i]);
        _mm_storeu_si128(&next_block[i], state[i]);
    }
}

static const uint64_t bad_rands[32] = {
    UINT64_C(17023632018251376180), UINT64_C(4911461131397773491),
    UINT64_C(15927076453364631751), UINT64_C(7860239898779391109),

    UINT64_C(11820267568857244377), UINT64_C(12188179869468676617),
    UINT64_C(3732913385414474778),  UINT64_C(7651458777762572084),

    UINT64_C(3062274162574341415),  UINT64_C(17922653540258786897),
    UINT64_C(17393848266100524980), UINT64_C(8539695715554563839),

    UINT64_C(13824538050656654359), UINT64_C(12078939433126460936),
    UINT64_C(15331979418564540430), UINT64_C(12058346794217174273),

    UINT64_C(13593922096015221049), UINT64_C(18356682276374416500),
    UINT64_C(4968040514092703824),  UINT64_C(11202790346130235567),

    UINT64_C(2276229735041314644), UINT64_C(220837743321691382),
    UINT64_C(4861211596230784273), UINT64_C(6330592584132590331),

    UINT64_C(3515580430960296763), UINT64_C(9869356316971855173),
    UINT64_C(485533243489193056),  UINT64_C(14596447761048148032),

    UINT64_C(16531790085730132900), UINT64_C(17328824500878824371),
    UINT64_C(8548260058287621283),  UINT64_C(8641748798041936364)
};

void ar2_generate_addresses(const argon2_instance_t *instance,
                        const argon2_position_t *position,
                        uint64_t *pseudo_rands)
{
    uint8_t offset = position->pass * 16 + position->slice * 4;
    pseudo_rands[0] = bad_rands[offset++];
    pseudo_rands[1] = bad_rands[offset++];
    pseudo_rands[2] = bad_rands[offset++];
    pseudo_rands[3] = bad_rands[offset++];

    /*if ((position->pass == 1 && position->slice == 3))
      print64("pseudo_rands", pseudo_rands, 4);*/
}

#define SEGMENT_LENGTH 4
#define LANE_LENGTH 16
#define POS_LANE 0

void ar2_fill_segment(const argon2_instance_t *instance,
                  argon2_position_t position)
{
    block *ref_block = NULL, *curr_block = NULL;
    uint64_t pseudo_rand, ref_index;
    uint32_t prev_offset, curr_offset;
    uint8_t i;
    __m128i state[64];
    int data_independent_addressing = (instance->type == Argon2_i);

    /* Pseudo-random values that determine the reference block position */
    uint64_t *pseudo_rands = NULL;

    pseudo_rands = (uint64_t *)malloc(/*sizeof(uint64_t) * 4*/32);

    if (data_independent_addressing) {
        ar2_generate_addresses(instance, &position, pseudo_rands);
    }

    i = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
        i = 2; /* we have already generated the first two blocks */
    }

    /*printf("Position.lane = %d\nPosition.slice = %d\nStarting index : %d\n", position.lane, position.slice, starting_index);*/
    /* Offset of the current block */
    curr_offset = position.slice * 4 + i;

    if (0 == curr_offset % 16) {
        /* Last block in this lane */
        prev_offset = curr_offset + /*instance->lane_length - 1*/15;
    } else {
        /* Previous block */
        prev_offset = curr_offset - 1;
    }

    memcpy(state, ((instance->memory + prev_offset)->v), ARGON2_BLOCK_SIZE);

    for (; i < SEGMENT_LENGTH;
         ++i, ++curr_offset, ++prev_offset) {
        /*1.1 Rotating prev_offset if needed */
        if (curr_offset % LANE_LENGTH == 1) {
            prev_offset = curr_offset - 1;
        }

        /* 1.2 Computing the index of the reference block */
        /* 1.2.1 Taking pseudo-random value from the previous block */
        if (data_independent_addressing) {
            pseudo_rand = pseudo_rands[i];
        } else {
            pseudo_rand = instance->memory[prev_offset].v[0];
        }

        /* 1.2.2 Computing the lane of the reference block */

        /* 1.2.3 Computing the number of possible reference block within the
         * lane.
         */
        position.index = i;
        ref_index = ar2_index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF,1);

        /* 2 Creating a new block */
        ref_block = instance->memory + ref_index;
        curr_block = instance->memory + curr_offset;
        ar2_fill_block(state, (__m128i const *)ref_block->v, (__m128i *)curr_block->v);
    }

    free(pseudo_rands);
}
