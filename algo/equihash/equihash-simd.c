/*
 * Equihash optimized backend.
 *
 * Validated against the frozen scalar reference (equihash-ref.c) via the
 * differential oracle eh_backend_selftest() — if a kernel here ever diverges,
 * eh_active_backend() falls back to the reference automatically.
 *
 * ── Item 1: Blake2b midstate ──────────────────────────────────────────────
 * The Blake2b input is header[140] || LE32(blk) = one full 128-byte block
 * (header[0..127]) + a 16-byte tail (header[128..139] || LE32(blk)). Within one
 * solve the header is fixed; only blk varies, so block 0 compresses to the SAME
 * state for every blk. Compute that midstate ONCE (scalar), then per blk process
 * only the final 16-byte block.
 *
 * ── Item 2: SIMD Blake2b (4-way AVX2 / 8-way AVX-512) ─────────────────────
 * The final block is identical across blk except its last 4 bytes (LE32(blk)),
 * so W block indices are hashed in parallel. We reuse the proven interleaved
 * compress in algo/blake/blake2b-hash.c: seed the W-way ctx with the broadcast
 * midstate (h) and t=128, feed the 16-byte interleaved final block, then read
 * ctx->h[0..7] (the compress writes all 8 words in place) for the full digest.
 *
 *   final block words (little-endian):
 *     m0 = header[128..135]                         (shared across lanes)
 *     m1 = header[136..139] | (LE32(blk) << 32)     (per lane: low32 shared,
 *                                                    high32 = blk)
 *     m2..m15 = 0                                    (zero-padded by *_final)
 *
 * The output is bit-identical to the reference (same byte stream, same block
 * boundaries, same standard Blake2b IV/sigma/G as sph_blake2b).
 */

#include "equihash-impl.h"
#include "../blake/blake2b-hash.h"

/* Build one lane's digest (LE of h[0..7]) and expand its iph hashes into hbuf0. */
static inline void eh_emit_lane(eh_workspace_t *ws, const eh_params_t *p,
                                int iph, int raw_hlen, uint32_t blk,
                                const uint64_t hword[8])
{
    uint8_t digest[64];
    for (int w = 0; w < 8; w++) {
        uint64_t x = hword[w];
        for (int b = 0; b < 8; b++) digest[w*8 + b] = (uint8_t)(x >> (8*b));
    }
    for (int h = 0; h < iph; h++) {
        uint32_t idx  = blk * iph + h;
        uint8_t *slot = ws->hbuf0 + (size_t)idx * p->slot_bytes;
        memset(slot, 0, p->slot_bytes);
        expand_hash(digest + h * raw_hlen, raw_hlen,
                    slot, p->hash_length, p->collision_bits);
        slot_set_min(slot, p->hash_length, idx);
    }
}

/* ── Hash generation (midstate + SIMD final block) ───────────────────────── */

static void simd_gen_hashes(const uint8_t *header, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int iph      = eh_indices_per_hash(p->wn);
    int hash_out = eh_hash_output(p->wn);    /* bytes per Blake2b call (<= 64) */
    int raw_hlen = (p->wn + 7) / 8;
    uint32_t nblk = (uint32_t)(p->nhashes_init / iph);

    /* Block-0 midstate (item 1): absorbing 129 bytes compresses header[0..127]
     * and buffers header[128]; base.h is then the post-block-0 chained state. */
    sph_blake2b_ctx base;
    blake2b_init_pers(&base, hash_out, p->personalization);
    sph_blake2b_update(&base, header, 129);

    uint32_t blk = 0;

#if defined(__AVX2__) || defined(SIMD512)
    uint64_t mid_h[8];
    for (int i = 0; i < 8; i++) mid_h[i] = base.h[i];
    uint64_t m0 = eh_load64le(header + 128);                 /* header[128..135] */
    uint64_t m1lo = (uint64_t)( (uint32_t)header[136]        /* header[136..139] */
                  | ((uint32_t)header[137] <<  8)
                  | ((uint32_t)header[138] << 16)
                  | ((uint32_t)header[139] << 24) );
#endif

#if defined(SIMD512)
    /* 8-way AVX-512 */
    for (; blk + 8 <= nblk; blk += 8) {
        blake2b_8x64_ctx ctx;
        for (int i = 0; i < 8; i++) ctx.h[i] = _mm512_set1_epi64((long long)mid_h[i]);
        ctx.t[0] = 128; ctx.t[1] = 0; ctx.c = 0; ctx.outlen = hash_out;

        __m512i in[2];
        in[0] = _mm512_set1_epi64((long long)m0);
        in[1] = _mm512_set_epi64(
            (long long)(m1lo | ((uint64_t)(blk+7) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+6) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+5) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+4) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+3) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+2) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+1) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+0) << 32)) );

        __m512i sink[4];
        blake2b_8x64_update(&ctx, in, 16);
        blake2b_8x64_final(&ctx, sink);     /* compresses last block; fills h[0..7] */

        uint64_t hw[8][8];
        for (int w = 0; w < 8; w++)
            _mm512_storeu_si512((void *)hw[w], ctx.h[w]);
        for (int k = 0; k < 8; k++) {
            uint64_t hword[8];
            for (int w = 0; w < 8; w++) hword[w] = hw[w][k];
            eh_emit_lane(ws, p, iph, raw_hlen, blk + k, hword);
        }
    }
#endif

#if defined(__AVX2__)
    /* 4-way AVX2 (also mops up the 0..7 remainder after the 8-way loop) */
    for (; blk + 4 <= nblk; blk += 4) {
        blake2b_4x64_ctx ctx;
        for (int i = 0; i < 8; i++) ctx.h[i] = _mm256_set1_epi64x((long long)mid_h[i]);
        ctx.t[0] = 128; ctx.t[1] = 0; ctx.c = 0; ctx.outlen = hash_out;

        __m256i in[2];
        in[0] = _mm256_set1_epi64x((long long)m0);
        in[1] = _mm256_set_epi64x(
            (long long)(m1lo | ((uint64_t)(blk+3) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+2) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+1) << 32)),
            (long long)(m1lo | ((uint64_t)(blk+0) << 32)) );

        __m256i sink[4];
        blake2b_4x64_update(&ctx, in, 16);
        blake2b_4x64_final(&ctx, sink);     /* compresses last block; fills h[0..7] */

        uint64_t hw[8][4];
        for (int w = 0; w < 8; w++)
            _mm256_storeu_si256((__m256i *)hw[w], ctx.h[w]);
        for (int k = 0; k < 4; k++) {
            uint64_t hword[8];
            for (int w = 0; w < 8; w++) hword[w] = hw[w][k];
            eh_emit_lane(ws, p, iph, raw_hlen, blk + k, hword);
        }
    }
#endif

    /* Scalar tail (remaining < W block indices). Also the full path when no
     * AVX2/AVX-512 is available — item 1 midstate, one block index at a time. */
    {
        uint8_t tail[15];
        memcpy(tail, header + 129, 11);     /* header[129..139] */
        uint8_t digest[64];
        for (; blk < nblk; blk++) {
            sph_blake2b_ctx ctx = base;
            tail[11] = (uint8_t) blk;
            tail[12] = (uint8_t)(blk >>  8);
            tail[13] = (uint8_t)(blk >> 16);
            tail[14] = (uint8_t)(blk >> 24);
            sph_blake2b_update(&ctx, tail, 15);
            sph_blake2b_final(&ctx, digest);
            for (int h = 0; h < iph; h++) {
                uint32_t idx  = blk * iph + h;
                uint8_t *slot = ws->hbuf0 + (size_t)idx * p->slot_bytes;
                memset(slot, 0, p->slot_bytes);
                expand_hash(digest + h * raw_hlen, raw_hlen,
                            slot, p->hash_length, p->collision_bits);
                slot_set_min(slot, p->hash_length, idx);
            }
        }
    }
}

/* ── Bucket sort (software prefetch, item 4a) ───────────────────────────────
 * Same counting-sort as eh_ref_bucket_sort (byte-identical sort_orig /
 * bucket_start / bucket_size / hbuf1 layout), with look-ahead software prefetch
 * on the two random-access cache-miss generators:
 *   - counting scan: the histogram update bsz[bucket] (nbuckets*4 = 4 MB on the
 *     large variants, so random increments miss L2);
 *   - scatter scan : the write to hbuf1[dst] (scattered by bucket).
 * Source reads of hbuf0 are sequential (hardware-prefetched), so we recompute
 * the look-ahead item's bucket cheaply rather than materialize a bucket array.
 * Prefetch hints never change results; the differential oracle gates this.
 *
 * GATING: prefetch only pays when the random-access targets miss cache. When
 * the whole working set is cache-resident (small variants, e.g. 96/5: 256 KB
 * histogram + 2 MB hbuf1) the look-ahead recompute is pure overhead and slows
 * the sort (~10% regression measured). So we enable it only above a working-set
 * threshold (~L3). Measured: ~1.0x below the gate (no regression), ~1.03-1.04x
 * on 200/9 / 144/5. The sort is bandwidth/TLB-bound — prefetch is a minor win;
 * the larger levers are huge-page backing (item 3) and slimmer slots (4b).    */
#define EH_SORT_PF        8                 /* look-ahead distance (iterations) */
#define EH_SORT_PF_MIN    ((size_t)16 << 20) /* enable prefetch above ~L3 working set */

static void simd_bucket_sort(uint32_t n_src, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    uint32_t *bsz = ws->bucket_size;
    uint32_t *bst = ws->bucket_start;
    int   cbl = p->cbl, cb = p->collision_bits;
    size_t sb = p->slot_bytes;
    int   pf  = (size_t)n_src * sb > EH_SORT_PF_MIN;   /* loop-invariant gate */

    memset(bsz, 0, (size_t)p->nbuckets * 4);

    /* Counting scan: prefetch the future histogram slot for write. */
    for (uint32_t i = 0; i < n_src; i++) {
        if (pf && i + EH_SORT_PF < n_src) {
            const uint8_t *sf = ws->hbuf0 + (size_t)(i + EH_SORT_PF) * sb;
            __builtin_prefetch(&bsz[bucket_key_be(sf, cbl, cb)], 1, 1);
        }
        const uint8_t *s = ws->hbuf0 + (size_t)i * sb;
        bsz[bucket_key_be(s, cbl, cb)]++;
    }

    bst[0] = 0;
    for (int b = 0; b < p->nbuckets; b++)
        bst[b+1] = bst[b] + bsz[b];
    memset(bsz, 0, (size_t)p->nbuckets * 4);

    /* Scatter scan: prefetch the future scatter target (write, non-temporal).
     * dst is approximate for the look-ahead (its bsz[] may still grow before we
     * reach it) but prefetch only needs the right cache line, not the exact slot. */
    for (uint32_t i = 0; i < n_src; i++) {
        if (pf && i + EH_SORT_PF < n_src) {
            const uint8_t *sf = ws->hbuf0 + (size_t)(i + EH_SORT_PF) * sb;
            uint32_t bf   = bucket_key_be(sf, cbl, cb);
            uint32_t dstf = bst[bf] + bsz[bf];
            __builtin_prefetch(ws->hbuf1 + (size_t)dstf * sb, 1, 0);
        }
        const uint8_t *s = ws->hbuf0 + (size_t)i * sb;
        uint32_t b   = bucket_key_be(s, cbl, cb);
        uint32_t dst = bst[b] + bsz[b];
        memcpy(ws->hbuf1 + (size_t)dst * sb, s, sb);
        ws->sort_orig[dst] = i;
        bsz[b]++;
    }
}

/* ── Wagner round (fused merge) ────────────────────────────────────────────
 * Profiling shows wagner_round is 58-73% of every solve once hash-gen is
 * optimized (96/5 58.9%, 200/9 73.2%, 144/5 58.4% on an i7-11700F). The
 * reference merge does four passes over a slot per emitted pair:
 *     memcpy(dst, si, slot_bytes); xor_hash(dst, sj); shift_hash(dst); set_min
 * But the two parents collided, so their leading cbl bytes are equal and XOR to
 * zero — exactly the bytes shift_hash then drops. So the whole sequence collapses
 * to a SINGLE fused pass: dst[k] = si[cbl+k] ^ sj[cbl+k] for k in [0, hl-cbl),
 * zero the trailing cbl bytes, write min. Byte-identical to the reference
 * (same result, same emission order); the differential oracle gates it.        */
static inline void eh_merge_pair(uint8_t *dst, const uint8_t *si,
                                 const uint8_t *sj, int hash_length, int cbl,
                                 uint32_t min_val)
{
    int body = hash_length - cbl;       /* surviving bytes after the dropped group */
    const uint8_t *a = si + cbl, *b = sj + cbl;
    int k = 0;
    for (; k + 8 <= body; k += 8) {
        uint64_t x, y;
        memcpy(&x, a + k, 8); memcpy(&y, b + k, 8);
        x ^= y; memcpy(dst + k, &x, 8);
    }
    for (; k < body; k++) dst[k] = a[k] ^ b[k];
    memset(dst + body, 0, cbl);
    slot_set_min(dst, hash_length, min_val);
}

/* Same bucket / i / j traversal and emission order as eh_ref_wagner_round (so
 * output is byte-identical), with the fused merge above replacing the
 * memcpy+xor+shift+set_min sequence. bucket_sort stays the reference for now.  */
static uint32_t simd_wagner_round(int round, uint32_t n_in, uint32_t max_out,
                                  eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int cbl = p->cbl;
    int hl  = p->hash_length;
    uint32_t n_out = 0;
    (void)n_in;

    for (int b = 0; b < p->nbuckets && n_out < max_out; b++) {
        uint32_t start = ws->bucket_start[b];
        uint32_t cnt   = ws->bucket_size[b];

        for (uint32_t i = start; i < start+cnt && n_out < max_out; i++) {
            const uint8_t *si = ws->hbuf1 + (size_t)i * p->slot_bytes;
            uint32_t min_i = slot_get_min(si, hl);

            for (uint32_t j = i+1; j < start+cnt && n_out < max_out; j++) {
                const uint8_t *sj = ws->hbuf1 + (size_t)j * p->slot_bytes;

                if (!coll_match(si, sj, cbl)) continue;
                uint32_t min_j = slot_get_min(sj, hl);
                if (min_i == min_j) continue;

                uint8_t *dst = ws->hbuf0 + (size_t)n_out * p->slot_bytes;
                eh_merge_pair(dst, si, sj, hl, cbl,
                              min_i < min_j ? min_i : min_j);

                uint32_t *pr = ws->pairs +
                    ((size_t)round * p->max_rows + n_out) * 2;
                pr[0] = ws->sort_orig[i];
                pr[1] = ws->sort_orig[j];
                n_out++;
            }
        }
    }
    return n_out;
}

/* ── Backend vtable ──────────────────────────────────────────────── */
/* bucket_sort reuses the reference until specialized (item 4).        */

const eh_backend_t eh_backend_simd = {
    "optimized",
    simd_gen_hashes,
    simd_bucket_sort,
    simd_wagner_round,
};
