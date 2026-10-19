/*
 * Equihash reference backend — scalar Wagner kernels.
 *
 * FROZEN: this is the correctness oracle and the living documentation of the
 * algorithm. Do NOT optimize in place — add optimized kernels in
 * equihash-simd.c behind the eh_backend_t vtable and validate them against this
 * backend.
 *
 * Provides the three hot kernels dispatched by equihash_solve() in equihash.c:
 *   - gen_hashes   : Blake2b hash generation + ExpandArray into hbuf0
 *   - bucket_sort  : counting-sort hbuf0 -> hbuf1 by collision group
 *   - wagner_round : one round of pairwise collision + XOR merge
 *
 * All byte-layout primitives are shared via equihash-impl.h so this backend and
 * the verifier in equihash.c stay bit-identical.
 */

#include "equihash-impl.h"

/* ── Hash generation ─────────────────────────────────────────────── */

void eh_ref_gen_hashes(const uint8_t *header, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int iph       = eh_indices_per_hash(p->wn);
    int hash_out  = eh_hash_output(p->wn);   /* bytes per Blake2b call */
    int raw_hlen  = (p->wn + 7) / 8;         /* raw bytes per hash value */

    uint8_t digest[64];

    for (uint32_t blk = 0; blk < (uint32_t)(p->nhashes_init / iph); blk++) {
        sph_blake2b_ctx ctx;
        blake2b_init_pers(&ctx, hash_out, p->personalization);
        sph_blake2b_update(&ctx, header, 140);
        uint32_t blk_le = blk;
        sph_blake2b_update(&ctx, &blk_le, 4);
        sph_blake2b_final(&ctx, digest);

        for (int h = 0; h < iph; h++) {
            uint32_t idx = blk * iph + h;
            uint8_t *slot = ws->hbuf0 + (size_t)idx * p->slot_bytes;
            memset(slot, 0, p->slot_bytes);

            /* Expand the raw hash into (K+1)*cbl aligned byte groups.
             * expand_hash implements ExpandArray from the reference.    */
            expand_hash(digest + h * raw_hlen, raw_hlen,
                        slot, p->hash_length, p->collision_bits);

            /* Store initial min_idx = the hash index itself */
            slot_set_min(slot, p->hash_length, idx);
        }
    }
}

/* ── Bucket sort ─────────────────────────────────────────────────── */

void eh_ref_bucket_sort(uint32_t n_src, eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    uint32_t *bsz = ws->bucket_size;
    uint32_t *bst = ws->bucket_start;

    memset(bsz, 0, (size_t)p->nbuckets * 4);
    for (uint32_t i = 0; i < n_src; i++) {
        const uint8_t *s = ws->hbuf0 + (size_t)i * p->slot_bytes;
        bsz[bucket_key_be(s, p->cbl, p->collision_bits)]++;
    }
    bst[0] = 0;
    for (int b = 0; b < p->nbuckets; b++)
        bst[b+1] = bst[b] + bsz[b];
    memset(bsz, 0, (size_t)p->nbuckets * 4);

    for (uint32_t i = 0; i < n_src; i++) {
        const uint8_t *s = ws->hbuf0 + (size_t)i * p->slot_bytes;
        uint32_t b = bucket_key_be(s, p->cbl, p->collision_bits);
        uint32_t dst = bst[b] + bsz[b];
        memcpy(ws->hbuf1 + (size_t)dst * p->slot_bytes, s, p->slot_bytes);
        ws->sort_orig[dst] = i;
        bsz[b]++;
    }
}

/* ── One Wagner round ────────────────────────────────────────────── */
/*
 * For each bucket in hbuf1 (sorted), find all pairs (i, j) where the first
 * cbl bytes match exactly (HasCollision).  Before creating a pair:
 *   - Check coll_match(i, j, cbl) for FULL collision_bits (bkt_bits may be
 *     fewer than collision_bits when bkt_bits < collision_bits)
 *   - Check min_idx(i) != min_idx(j): if equal, these two items share at
 *     least one common ancestor leaf -> they cannot form a valid distinct pair
 *
 * On a valid pair: XOR the hashes, shift away the matched group, compute
 * new min_idx = min(min_i, min_j), record parent refs in pairs[round][].
 */
uint32_t eh_ref_wagner_round(int round, uint32_t n_in, uint32_t max_out,
                             eh_workspace_t *ws)
{
    const eh_params_t *p = &ws->params;
    int cbl = p->cbl;
    uint32_t n_out = 0;
    (void)n_in;

    for (int b = 0; b < p->nbuckets && n_out < max_out; b++) {
        uint32_t start = ws->bucket_start[b];
        uint32_t cnt   = ws->bucket_size[b];

        for (uint32_t i = start; i < start+cnt && n_out < max_out; i++) {
            const uint8_t *si = ws->hbuf1 + (size_t)i * p->slot_bytes;
            uint32_t min_i = slot_get_min(si, p->hash_length);

            for (uint32_t j = i+1; j < start+cnt && n_out < max_out; j++) {
                const uint8_t *sj = ws->hbuf1 + (size_t)j * p->slot_bytes;

                /* Full collision check (needed when bkt_bits < collision_bits) */
                if (!coll_match(si, sj, cbl)) continue;

                uint32_t min_j = slot_get_min(sj, p->hash_length);

                /* Approximate DistinctIndices: reject if same min leaf index.
                 * Two rows sharing their minimum leaf index definitely share
                 * that index -> merging them produces a duplicate-index solution.
                 * This eliminates the most common cause of invalid solutions.  */
                if (min_i == min_j) continue;

                /* Merge: XOR hashes, shift away the matched cbl-byte group */
                uint8_t *dst = ws->hbuf0 + (size_t)n_out * p->slot_bytes;
                memcpy(dst, si, p->slot_bytes);
                xor_hash(dst, sj, p->hash_length);
                shift_hash(dst, p->hash_length, cbl);

                /* Propagate min_idx = min(min_i, min_j) */
                slot_set_min(dst, p->hash_length,
                             min_i < min_j ? min_i : min_j);

                /* Record source positions for tree reconstruction */
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

const eh_backend_t eh_backend_ref = {
    "reference",
    eh_ref_gen_hashes,
    eh_ref_bucket_sort,
    eh_ref_wagner_round,
};
