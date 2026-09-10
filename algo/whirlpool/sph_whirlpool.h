/* $Id: sph_whirlpool.h 216 2010-06-08 09:46:57Z tp $ */
/**
 * WHIRLPOOL interface.
 *
 * WHIRLPOOL knows three variants, dubbed "WHIRLPOOL-0" (original
 * version, published in 2000, studied by NESSIE), "WHIRLPOOL-1"
 * (first revision, 2001, with a new S-box) and "WHIRLPOOL" (current
 * version, 2003, with a new diffusion matrix, also described as "plain
 * WHIRLPOOL"). All three variants are implemented here.
 *
 * The original WHIRLPOOL (i.e. WHIRLPOOL-0) was published in: P. S. L.
 * M. Barreto, V. Rijmen, "The Whirlpool Hashing Function", First open
 * NESSIE Workshop, Leuven, Belgium, November 13--14, 2000.
 *
 * The current WHIRLPOOL specification and a reference implementation
 * can be found on the WHIRLPOOL web page:
 * http://paginas.terra.com.br/informatica/paulobarreto/WhirlpoolPage.html
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @file     sph_whirlpool.h
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifndef SPH_WHIRLPOOL_H__
#define SPH_WHIRLPOOL_H__

#include <stddef.h>
#include "compat/sph_types.h"

#if SPH_64

/**
 * Output size (in bits) for WHIRLPOOL.
 */
#define SPH_SIZE_whirlpool   512

/**
 * Output size (in bits) for WHIRLPOOL-0.
 */
#define SPH_SIZE_whirlpool0   512

/**
 * Output size (in bits) for WHIRLPOOL-1.
 */
#define SPH_SIZE_whirlpool1   512

/**
 * This structure is a context for WHIRLPOOL computations: it contains the
 * intermediate values and some data from the last entered block. Once
 * a WHIRLPOOL computation has been performed, the context can be reused for
 * another computation.
 *
 * The contents of this structure are private. A running WHIRLPOOL computation
 * can be cloned by copying the context (e.g. with a simple
 * <code>memcpy()</code>).
 */
typedef struct {
#ifndef DOXYGEN_IGNORE
	unsigned char buf[64];    /* first field, for alignment */
	sph_u64 state[8];
#if SPH_64
	sph_u64 count;
#else
	sph_u32 count_high, count_low;
#endif
#endif
} sph_whirlpool_context;

/**
 * Initialize a WHIRLPOOL context. This process performs no memory allocation.
 *
 * @param cc   the WHIRLPOOL context (pointer to a
 *             <code>sph_whirlpool_context</code>)
 */
void sph_whirlpool_init(void *cc);

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing). This function applies the
 * plain WHIRLPOOL algorithm.
 *
 * @param cc     the WHIRLPOOL context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_whirlpool(void *cc, const void *data, size_t len);

/**
 * Terminate the current WHIRLPOOL computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (64 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the WHIRLPOOL context
 * @param dst   the destination buffer
 */
void sph_whirlpool_close(void *cc, void *dst);

#define sph_whirlpool512_full( cc, dst, data, len ) \
do{ \
   sph_whirlpool_init( cc ); \
   sph_whirlpool( cc, data, len ); \
   sph_whirlpool_close( cc, dst ); \
}while(0)

/* ------------------------------------------------------------------------
 * Precomputed round keys (plain WHIRLPOOL only).
 *
 * WHIRLPOOL's compression is a block cipher keyed by the chaining state, so a
 * caller that hashes many messages sharing a chaining state -- a mining nonce
 * loop, where only the last block varies -- expands the same ten round keys
 * every time. That key schedule is half the work of a compression.
 *
 * Expand once with sph_whirlpool_expand_keys(), then call
 * sph_whirlpool_compress_keyed() per message block. Bit-identical to
 * sph_whirlpool() over the same input; the plain API is unchanged and remains
 * the reference.
 *
 * Additive: no existing behaviour depends on these.
 */
typedef struct {
   sph_u64 K[11][8];       /* K[0] = the chaining state, K[r+1] = round r key */
} sph_whirlpool_keys;

/**
 * One-time setup for the two functions below. Idempotent, not thread-safe --
 * call it once at algorithm registration, before any mining thread starts.
 */
void sph_whirlpool_keyed_init( void );

/**
 * Which table layout the keyed path compiled to, reported from inside its own
 * translation unit. The choice is architecture-dependent and measured, so a
 * build wanting to state its configuration must ask rather than re-derive it.
 */
const char *sph_whirlpool_keyed_config( void );

/**
 * Expand the ten round keys for a fixed chaining state.
 *
 * @param wk      destination
 * @param state   the eight chaining-state words, i.e. the `state` field of an
 *                sph_whirlpool_context after the constant prefix was hashed
 */
void sph_whirlpool_expand_keys( sph_whirlpool_keys *wk, const sph_u64 *state );

/**
 * Compress one 64-byte block against precomputed round keys.
 *
 * @param wk      round keys from sph_whirlpool_expand_keys()
 * @param blk     the 64-byte block, padded by the caller
 * @param state   the same chaining state the keys were expanded from
 * @param out     the eight resulting state words (may alias `state`)
 */
void sph_whirlpool_compress_keyed( const sph_whirlpool_keys *wk,
                                   const void *blk, const sph_u64 *state,
                                   sph_u64 *out );

/**
 * Most significant 64-bit word of the offset-32 fold of one keyed compression,
 * i.e. word 3 XOR word 7 of what sph_whirlpool_compress_keyed() would produce.
 *
 * For a caller that folds a 512-bit digest to 256 by XORing the two halves and
 * then compares the result as a little-endian integer, this one word decides
 * almost every comparison -- and only two of the final round's eight state
 * words are needed to compute it, so the last round costs a quarter.
 *
 * Returns exactly `out[3] ^ out[7]`, message and chaining terms included, so a
 * caller cannot omit them. That matters: for an 80-byte message the message
 * contribution is the padding length word, which is easy to forget because it
 * is zero for a fold at other offsets.
 *
 * @param wk      round keys from sph_whirlpool_expand_keys()
 * @param blk     the 64-byte block, padded by the caller
 * @param state   the chaining state the keys were expanded from
 */
sph_u64 sph_whirlpool_keyed_fold32_msw( const sph_whirlpool_keys *wk,
                                        const void *blk,
                                        const sph_u64 *state );

/**
 * WHIRLPOOL-0 uses the same structure than plain WHIRLPOOL.
 */
typedef sph_whirlpool_context sph_whirlpool0_context;

#ifdef DOXYGEN_IGNORE
/**
 * Initialize a WHIRLPOOL-0 context. This function is identical to
 * <code>sph_whirlpool_init()</code>.
 *
 * @param cc   the WHIRLPOOL context (pointer to a
 *             <code>sph_whirlpool0_context</code>)
 */
void sph_whirlpool0_init(void *cc);
#endif

#ifndef DOXYGEN_IGNORE
#define sph_whirlpool0_init   sph_whirlpool_init
#endif

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing). This function applies the
 * WHIRLPOOL-0 algorithm.
 *
 * @param cc     the WHIRLPOOL context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_whirlpool0(void *cc, const void *data, size_t len);

/**
 * Terminate the current WHIRLPOOL-0 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (64 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the WHIRLPOOL-0 context
 * @param dst   the destination buffer
 */
void sph_whirlpool0_close(void *cc, void *dst);

/**
 * WHIRLPOOL-1 uses the same structure than plain WHIRLPOOL.
 */
typedef sph_whirlpool_context sph_whirlpool1_context;

#ifdef DOXYGEN_IGNORE
/**
 * Initialize a WHIRLPOOL-1 context. This function is identical to
 * <code>sph_whirlpool_init()</code>.
 *
 * @param cc   the WHIRLPOOL context (pointer to a
 *             <code>sph_whirlpool1_context</code>)
 */
void sph_whirlpool1_init(void *cc);
#endif

#ifndef DOXYGEN_IGNORE
#define sph_whirlpool1_init   sph_whirlpool_init
#endif

/**
 * Process some data bytes. It is acceptable that <code>len</code> is zero
 * (in which case this function does nothing). This function applies the
 * WHIRLPOOL-1 algorithm.
 *
 * @param cc     the WHIRLPOOL context
 * @param data   the input data
 * @param len    the input data length (in bytes)
 */
void sph_whirlpool1(void *cc, const void *data, size_t len);

/**
 * Terminate the current WHIRLPOOL-1 computation and output the result into the
 * provided buffer. The destination buffer must be wide enough to
 * accomodate the result (64 bytes). The context is automatically
 * reinitialized.
 *
 * @param cc    the WHIRLPOOL-1 context
 * @param dst   the destination buffer
 */
void sph_whirlpool1_close(void *cc, void *dst);

#endif

#endif
