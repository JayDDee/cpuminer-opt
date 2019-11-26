/*
 * Copyright (c) 2008 Sebastiaan Indesteege
 *                              <sebastiaan.indesteege@esat.kuleuven.be>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Optimised ANSI-C implementation of LANE
 */

#ifndef LANE_H
#define LANE_H

#include <string.h>
//#include "algo/sha/sha3-defs.h"
#include <stdint.h>

typedef unsigned char BitSequence;
typedef unsigned long long DataLength;

//typedef enum { SUCCESS = 0, FAIL = 1, BAD_HASHBITLEN = 2, BAD_DATABITLEN = 3 } HashReturn;

//typedef unsigned char u8;
//typedef unsigned int u32;
//typedef unsigned long long u64;

typedef struct {
  int hashbitlen;
  uint64_t ctr;
  uint32_t h[16];
  uint8_t buffer[128];
} hashState;

void laneInit (hashState *state, int hashbitlen);
void laneUpdate (hashState *state, const BitSequence *data, DataLength databitlen);
void laneFinal (hashState *state, BitSequence *hashval);
void laneHash (int hashbitlen, const BitSequence *data, DataLength databitlen, BitSequence *hashval);

#endif /* LANE_H */
