/*
 * Equihash solver core — arch-neutral orchestration, workspace, tree
 * reconstruction, solution packing and verification.
 *
 * The three hot kernels (hash generation, bucket sort, Wagner round) are
 * dispatched through the eh_backend_t vtable so an optimized SIMD backend can
 * replace them without touching this file. The scalar reference backend lives
 * in equihash-ref.c (the correctness oracle); shared byte-layout primitives are
 * in equihash-impl.h.
 *
 * Algorithm: Wagner's Generalised Birthday Problem.
 * Reference:  Zcash src/crypto/equihash.cpp (BasicSolve / IsValidSolution).
 *
 * EXPANDED HASH FORMAT: hashes are stored as (K+1) groups of CollisionByteLength
 * bytes (ExpandArray), so collision detection is a plain memcmp. For variants
 * where CollisionBitLength is divisible by 8 (96/5:16, 144/5:24, 192/7:24) the
 * expanded format equals the raw bytes; for 200/9 (20) and 125/4 (25) it differs.
 *
 * SLOT LAYOUT
 *   slot[0 .. hash_length-1]          : expanded hash (shrinks by CBL each round)
 *   slot[hash_length .. hash_length+3]: min leaf index (LE uint32)
 *   slot_bytes = hash_length + 4
 *
 * WORKSPACE LAYOUT   (max_rows = nhashes_init + EH_ROW_SLACK_PCT%, see equihash.h)
 *   hbuf0/hbuf1[max_rows][slot_bytes]     : two alternating hash buffers
 *   pairs[wk][max_rows][2]                : parent-index pairs (reconstruction)
 *   sort_orig[max_rows]                   : bucket-sort position -> source map
 *   bucket_start[nbuckets+1] / bucket_size[nbuckets]
 */

#include "equihash-impl.h"
#include <stdlib.h>
#include <stdio.h>

/* Platform headers for the huge-page workspace allocator (item 3). */
#if defined(_WIN32)
  #include <windows.h>
#elif defined(__linux__)
  #include <sys/mman.h>
  #ifndef MAP_ANONYMOUS
    #ifdef MAP_ANON
      #define MAP_ANONYMOUS MAP_ANON
    #endif
  #endif
#endif

/* ── Variant table ───────────────────────────────────────────────── */

eh_params_t EH_PARAMS_200_9;
eh_params_t EH_PARAMS_144_5;
eh_params_t EH_PARAMS_192_7;
eh_params_t EH_PARAMS_96_5;
eh_params_t EH_PARAMS_125_4;

static int g_variants_init = 0;

static eh_params_t build_params(int wn, int wk, const char *prefix)
{
    eh_params_t p;
    p.wn              = wn;
    p.wk              = wk;
    p.collision_bits  = wn / (wk + 1);
    p.proofsize       = 1 << wk;
    p.nhashes_init    = 1 << (p.collision_bits + 1);
    /* Row capacity, not the initial list size: a round may legitimately produce
     * more rows than it consumed, and clipping that costs solutions. */
    p.max_rows        = p.nhashes_init
                      + (int)((int64_t)p.nhashes_init * EH_ROW_SLACK_PCT / 100);
    /* CollisionByteLength = ceil(CollisionBitLength / 8) */
    p.cbl             = (p.collision_bits + 7) / 8;
    /* HashLength = (K+1) * CollisionByteLength  (expanded format) */
    p.hash_length     = (wk + 1) * p.cbl;
    /* slot_bytes: hash + 4-byte min_leaf_index */
    p.slot_bytes      = p.hash_length + 4;
    /* Bucket count: use all CollisionBits as bucket key, cap at 2^20 */
    int bkt_bits      = p.collision_bits < 20 ? p.collision_bits : 20;
    p.nbuckets        = 1 << bkt_bits;
    p.index_bits      = p.collision_bits + 1;
    p.solution_size   = (p.proofsize * p.index_bits + 7) / 8;
    /* hashlen: raw bytes per hash value = ceil(wn/8) (for Blake2b output) */
    p.hashlen         = (wn + 7) / 8;

    /* Personalization: 8-char prefix + LE32(wn) + LE32(wk) */
    memset(p.personalization, 0, 16);
    memcpy(p.personalization, prefix, 8);
    p.personalization[ 8] = (uint8_t)wn;
    p.personalization[ 9] = (uint8_t)(wn >> 8);
    p.personalization[10] = (uint8_t)(wn >> 16);
    p.personalization[11] = (uint8_t)(wn >> 24);
    p.personalization[12] = (uint8_t)wk;
    p.personalization[13] = (uint8_t)(wk >> 8);
    p.personalization[14] = (uint8_t)(wk >> 16);
    p.personalization[15] = (uint8_t)(wk >> 24);
    return p;
}

static void ensure_variants(void)
{
    if (g_variants_init) return;
    EH_PARAMS_200_9 = build_params(200, 9, "ZcashPoW");
    EH_PARAMS_144_5 = build_params(144, 5, "BgoldPoW");
    EH_PARAMS_192_7 = build_params(192, 7, "ZERO    ");
    EH_PARAMS_96_5  = build_params( 96, 5, "ZcashPoW");
    EH_PARAMS_125_4 = build_params(125, 4, "ZelProoW");
    g_variants_init = 1;
}

void eh_ensure_variants(void) { ensure_variants(); }

/* ── Pool-sent params parsing ────────────────────────────────────── */

bool eh_params_from_stratum(eh_params_t *out, const char *wn_wk_str,
                             const char *personal8)
{
    if (!wn_wk_str || !personal8) return false;
    int wn = 0, wk = 0;
    if (sscanf(wn_wk_str, "%d_%d", &wn, &wk) != 2) return false;
    if (wn <= 0 || wk <= 0 || (wn % (wk + 1)) != 0) return false;
    *out = build_params(wn, wk, personal8);
    return true;
}

/* ── Workspace ───────────────────────────────────────────────────── */

/* ── Huge-page-backed flat buffer (item 3) ─────────────────────────────────
 * The workspace is one flat buffer of 11 MB – 6.4 GB. With 4 KB pages the big
 * variants need ~1M page entries, so bucket_sort's scatter thrashes the dTLB.
 * Back the buffer with 2 MB pages where the OS allows it, recording the
 * allocator so the free path matches. Fallback chain:
 *   Linux:   mmap(MAP_HUGETLB) -> mmap+madvise(MADV_HUGEPAGE, THP) -> malloc
 *   Windows: VirtualAlloc(MEM_LARGE_PAGES) -> malloc
 * Allocation-only change: no effect on solver output.                        */

#define EH_HUGE_2M         ((size_t)2 * 1024 * 1024)
#define EH_HUGE_MIN_ALLOC  ((size_t)6 * 1024 * 1024)   /* below this huge pages don't pay */

#if defined(_WIN32)
/* Enable SeLockMemoryPrivilege (needed for MEM_LARGE_PAGES), then try a
 * large-page reservation. Returns NULL if the privilege is not held.         */
static void *eh_win_large_alloc(size_t size)
{
    HANDLE tok = NULL;
    if (OpenProcessToken(GetCurrentProcess(),
                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME,
                                 &tp.Privileges[0].Luid))
            AdjustTokenPrivileges(tok, FALSE, &tp, 0, NULL, NULL);
        CloseHandle(tok);
    }
    return VirtualAlloc(NULL, size, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES,
                        PAGE_READWRITE);   /* NULL if privilege not granted */
}
#endif

/* Allocate `want` bytes, preferring 2 MB pages. On success sets *got to the
 * (possibly rounded-up) allocation size and *kind to the matching deallocator,
 * and *how to a human-readable label for logging. Never returns rounded-down. */
static uint8_t *eh_huge_alloc(size_t want, size_t *got, int *kind,
                              const char **how)
{
#if defined(_WIN32)
    if (want >= EH_HUGE_MIN_ALLOC) {
        SIZE_T lp = GetLargePageMinimum();   /* 0 if large pages unsupported */
        if (lp) {
            size_t rounded = (want + lp - 1) & ~((size_t)lp - 1);
            void *p = eh_win_large_alloc(rounded);
            if (p) { *got = rounded; *kind = EH_MEM_VALLOC;
                     *how = "VirtualAlloc(MEM_LARGE_PAGES)"; return p; }
        }
    }
#elif defined(__linux__) && defined(MAP_ANONYMOUS)
    if (want >= EH_HUGE_MIN_ALLOC) {
        size_t rounded = (want + EH_HUGE_2M - 1) & ~(EH_HUGE_2M - 1);
  #if defined(MAP_HUGETLB)
        void *p = mmap(NULL, rounded, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
        if (p != MAP_FAILED) { *got = rounded; *kind = EH_MEM_MMAP;
                               *how = "mmap(MAP_HUGETLB)"; return p; }
  #endif
        /* THP fallback: ordinary anonymous mapping + madvise hint. */
        void *q = mmap(NULL, rounded, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (q != MAP_FAILED) {
  #if defined(MADV_HUGEPAGE)
            madvise(q, rounded, MADV_HUGEPAGE);
  #endif
            *got = rounded; *kind = EH_MEM_MMAP;
            *how = "mmap+madvise(THP)"; return q;
        }
    }
#endif

    /* Plain malloc fallback (always available). */
    void *p = malloc(want);
    if (p) { *got = want; *kind = EH_MEM_MALLOC; *how = "malloc"; }
    return (uint8_t *)p;
}

static void eh_huge_free(void *base, int kind, size_t size)
{
    (void)size;   /* used only by munmap (Linux) */
    if (!base) return;
    switch (kind) {
#if defined(__linux__)
    case EH_MEM_MMAP:   munmap(base, size);               return;
#endif
#if defined(_WIN32)
    case EH_MEM_VALLOC: VirtualFree(base, 0, MEM_RELEASE); return;
#endif
    default:            free(base);                        return;
    }
}

size_t eh_workspace_bytes(const eh_params_t *p)
{
    size_t h  = (size_t)p->max_rows * p->slot_bytes;
    size_t pr = (size_t)p->wk * p->max_rows * 8;
    size_t so = (size_t)p->max_rows * 4;
    size_t bs = (size_t)(p->nbuckets + 1) * 4;
    size_t bz = (size_t)p->nbuckets * 4;
    return 2*h + pr + so + bs + bz + 256;
}

bool eh_workspace_alloc(eh_workspace_t **ws_ptr, const eh_params_t *p)
{
    size_t total = eh_workspace_bytes(p);
    if (total > 512UL * 1024 * 1024)
        fprintf(stderr, "equihash: allocating %.0f MB for %d/%d "
                "(significant RAM required)\n",
                total / (1024.0*1024.0), p->wn, p->wk);

    if (*ws_ptr) {
        eh_huge_free((*ws_ptr)->_base, (*ws_ptr)->_mem_kind, (*ws_ptr)->_size);
        free(*ws_ptr); *ws_ptr = NULL;
    }

    eh_workspace_t *ws = (eh_workspace_t *)calloc(1, sizeof(eh_workspace_t));
    if (!ws) return false;

    size_t      got  = 0;
    int         kind = EH_MEM_MALLOC;
    const char *how  = "malloc";
    uint8_t *base = eh_huge_alloc(total, &got, &kind, &how);
    if (!base) { free(ws); return false; }
    ws->_base = base;  ws->_size = got;  ws->_mem_kind = kind;
    ws->params = *p;

    /* Log the chosen backing once for the variants where it matters (≥64 MB;
     * skips the tiny 96/5 self-test allocs so the flag isn't burned before the
     * large mining workspace, and avoids one line per mining thread).         */
    static int logged = 0;
    if (!logged && got >= (size_t)64 * 1024 * 1024) {
        logged = 1;
        fprintf(stderr, "equihash: workspace %.0f MB via %s\n",
                got / (1024.0*1024.0), how);
    }

    uint8_t *cur = base;
    size_t sh = (size_t)p->max_rows * p->slot_bytes;
    ws->hbuf0         = cur;  cur += sh;
    ws->hbuf1         = cur;  cur += sh;
    ws->pairs         = (uint32_t *)cur;
    cur += (size_t)p->wk * p->max_rows * 8;
    ws->sort_orig     = (uint32_t *)cur;
    cur += (size_t)p->max_rows * 4;
    ws->bucket_start  = (uint32_t *)cur;
    cur += (size_t)(p->nbuckets + 1) * 4;
    ws->bucket_size   = (uint32_t *)cur;
    *ws_ptr = ws;
    return true;
}

void eh_workspace_free(eh_workspace_t *ws)
{
    if (!ws) return;
    eh_huge_free(ws->_base, ws->_mem_kind, ws->_size);
    free(ws);
}

/* ── Backend selection ───────────────────────────────────────────── */

/* Run hash-gen + all k (bucket_sort, wagner_round) rounds with the given
 * backend, leaving the final merged rows in hbuf0[0 .. round_cnt[wk]) and the
 * reconstruction pairs in pairs[]. Returns the final row count. Shared by the
 * public solver and the differential oracle so both drive the backend the same
 * way.                                                                          */
static uint32_t eh_run_rounds(const uint8_t *header, eh_workspace_t *ws,
                              const eh_backend_t *be)
{
    const eh_params_t *p = &ws->params;
    be->gen_hashes(header, ws);
    /* gen_hashes fills exactly (nhashes_init / iph) * iph slots; bound round 0
     * to the populated slots so uninitialized tail never enters as collisions. */
    int iph = eh_indices_per_hash(p->wn);
    ws->round_cnt[0] = (p->nhashes_init / iph) * iph;
    for (int r = 0; r < p->wk; r++) {
        be->bucket_sort(ws->round_cnt[r], ws);
        ws->round_cnt[r + 1] =
            be->wagner_round(r, ws->round_cnt[r], p->max_rows, ws);
    }
    return ws->round_cnt[p->wk];
}

/* Differential oracle: run the reference and optimized backends on the same
 * fixed input (smallest variant, 96/5) and confirm byte-identical output. Two
 * stages: (1) gen_hashes hbuf0 over the populated range; (2) the full round
 * sequence — final row counts, the populated reconstruction pairs[] of every
 * round, and the final merged hbuf0. Stage 2 is what validates wagner_round
 * (and bucket_sort): any reordering or off-by-one would diverge here. Cheap
 * (~one 96/5 solve each). Returns true on agreement.                           */
bool eh_backend_selftest(void)
{
    ensure_variants();
    const eh_params_t *p = &EH_PARAMS_96_5;

    eh_workspace_t *wa = NULL, *wb = NULL;
    if (!eh_workspace_alloc(&wa, p) || !eh_workspace_alloc(&wb, p)) {
        eh_workspace_free(wa); eh_workspace_free(wb);
        return false;
    }

    uint8_t hdr[140];
    for (int i = 0; i < 140; i++) hdr[i] = (uint8_t)(i * 7 + 1);   /* arbitrary fixed */

    int iph = eh_indices_per_hash(p->wn);

    /* Stage 1: gen_hashes byte-identical over the populated range (the tail
     * beyond (nhashes/iph)*iph is untouched and differs between workspaces).   */
    eh_backend_ref.gen_hashes (hdr, wa);
    eh_backend_simd.gen_hashes(hdr, wb);
    size_t gn = (size_t)(p->nhashes_init / iph) * iph * p->slot_bytes;
    bool ok = (memcmp(wa->hbuf0, wb->hbuf0, gn) == 0);

    /* Stage 2: full bucket_sort + wagner_round sequence byte-identical. */
    if (ok) {
        uint32_t fa = eh_run_rounds(hdr, wa, &eh_backend_ref);
        uint32_t fb = eh_run_rounds(hdr, wb, &eh_backend_simd);
        ok = (fa == fb);
        for (int r = 0; r <= p->wk && ok; r++)
            ok = (wa->round_cnt[r] == wb->round_cnt[r]);
        for (int r = 0; r < p->wk && ok; r++) {
            size_t cnt = (size_t)wa->round_cnt[r + 1] * 2;     /* uint32 pair entries */
            const uint32_t *pa = wa->pairs + (size_t)r * p->max_rows * 2;
            const uint32_t *pb = wb->pairs + (size_t)r * p->max_rows * 2;
            ok = (memcmp(pa, pb, cnt * 4) == 0);
        }
        if (ok && fa)
            ok = (memcmp(wa->hbuf0, wb->hbuf0,
                         (size_t)fa * p->slot_bytes) == 0);
    }

    eh_workspace_free(wa);
    eh_workspace_free(wb);
    return ok;
}

/* Returns the active solver backend: the optimized backend iff it matches the
 * reference (differential self-test), otherwise the reference as a safe
 * fallback. Cached after first call. Trigger once single-threaded (at algo
 * registration) so concurrent miner threads never race the check.
 *
 * Full CPU-feature selection (AVX-512 -> AVX2 -> SSE2 -> NEON) lands when the
 * optimized backend gains ISA-specific kernels; for now the optimized backend
 * is portable scalar (Blake2b midstate).                                      */
const eh_backend_t *eh_active_backend(void)
{
    static int   resolved = 0;
    static const eh_backend_t *active = NULL;
    if (!resolved) {
        active   = eh_backend_selftest() ? &eh_backend_simd : &eh_backend_ref;
        resolved = 1;
    }
    return active;
}

/* ── Tree reconstruction ─────────────────────────────────────────── */

static void collect_indices(int round, uint32_t slot,
                             const eh_workspace_t *ws,
                             uint32_t *out, uint32_t *pos)
{
    if (round < 0) { out[(*pos)++] = slot; return; }
    const uint32_t *pr = ws->pairs +
        ((size_t)round * ws->params.max_rows + slot) * 2;
    collect_indices(round - 1, pr[0], ws, out, pos);
    collect_indices(round - 1, pr[1], ws, out, pos);
}

/* ── Tree-order fix (IndicesBefore) ──────────────────────────────── */

static void fix_tree_order(uint32_t *idx, int n)
{
    if (n <= 1) return;
    int half = n / 2;
    fix_tree_order(idx,        half);
    fix_tree_order(idx + half, half);
    if (idx[0] > idx[half]) {
        uint32_t tmp[512];  /* max proofsize */
        memcpy(tmp,        idx,        (size_t)half * 4);
        memmove(idx,       idx + half, (size_t)half * 4);
        memcpy(idx + half, tmp,        (size_t)half * 4);
    }
}

/* ── Index validation ────────────────────────────────────────────── */

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t*)a, y = *(const uint32_t*)b;
    return (x > y) - (x < y);
}

/* Sort a copy and check adjacent elements — catches ALL duplicates,
 * not just adjacent ones after tree-ordering.                         */
static int indices_distinct(const uint32_t *idx, int n)
{
    uint32_t *tmp = (uint32_t *)malloc((size_t)n * 4);
    if (!tmp) return 0;
    memcpy(tmp, idx, (size_t)n * 4);
    qsort(tmp, n, 4, cmp_u32);
    int ok = 1;
    for (int i = 1; i < n; i++) {
        if (tmp[i] == tmp[i-1]) { ok = 0; break; }
    }
    free(tmp);
    return ok;
}

/* ── Solution packing (big-endian, CompressArray convention) ─────── */

static void pack_indices(const uint32_t *idx, int proofsize,
                         int index_bits, uint8_t *out)
{
    int sol_bytes = (proofsize * index_bits + 7) / 8;
    memset(out, 0, sol_bytes);
    uint64_t acc  = 0;
    int acc_bits  = 0, out_pos = 0;
    uint32_t mask = (index_bits < 32) ? ((1u << index_bits) - 1u) : ~0u;
    for (int i = 0; i < proofsize; i++) {
        acc = (acc << index_bits) | (idx[i] & mask);
        acc_bits += index_bits;
        while (acc_bits >= 8) {
            acc_bits -= 8;
            out[out_pos++] = (uint8_t)((acc >> acc_bits) & 0xFF);
        }
    }
    if (acc_bits > 0)
        out[out_pos] = (uint8_t)((acc << (8 - acc_bits)) & 0xFF);
}

/* ── TLS workspace ───────────────────────────────────────────────── */

/* Thread-local workspace (kept for API compat; gate allocates via
 * eh_workspace_alloc which sizes correctly per variant).              */
static __thread void *tl_ws_unused = NULL;

bool equihash_thread_init(int thr_id)
{
    (void)thr_id;
    (void)tl_ws_unused;
    return true;   /* actual workspace allocated in equihash-gate.c */
}

/* ── Public solver ───────────────────────────────────────────────── */

int equihash_solve(const uint8_t *header, eh_workspace_t *ws,
                   uint8_t solutions[][EH_MAX_SOLUTION_BYTES], int max_sols)
{
    ensure_variants();
    int nsols = 0;

    uint32_t n_final = eh_run_rounds(header, ws, eh_active_backend());
    const eh_params_t *p = &ws->params;

    for (uint32_t s = 0; s < n_final && nsols < max_sols; s++) {
        const uint8_t *slot = ws->hbuf0 + (size_t)s * p->slot_bytes;
        /* Final solution: remaining cbl bytes must be zero */
        if (!slot_zero(slot, p->cbl)) continue;

        uint32_t *indices = (uint32_t *)malloc((size_t)p->proofsize * 4);
        if (!indices) break;
        uint32_t pos = 0;
        collect_indices(p->wk - 1, s, ws, indices, &pos);
        if ((int)pos != p->proofsize) { free(indices); continue; }

        fix_tree_order(indices, p->proofsize);
        if (!indices_distinct(indices, p->proofsize)) { free(indices); continue; }

        pack_indices(indices, p->proofsize, p->index_bits, solutions[nsols++]);
        free(indices);
    }
    return nsols;
}

/* ── Verifier ────────────────────────────────────────────────────── */

/* Unpack one index from big-endian CompressArray-packed solution. */
static uint32_t unpack_index(const uint8_t *sol, int i, int index_bits)
{
    int bit_start = i * index_bits;
    int byte_off  = bit_start / 8;
    int bit_off   = bit_start % 8;
    uint32_t v = 0;
    int bytes_needed = (index_bits + bit_off + 7) / 8;
    for (int b = 0; b < bytes_needed && b < 4; b++)
        v = (v << 8) | sol[byte_off + b];
    int total_bits = bytes_needed * 8;
    v >>= (total_bits - bit_off - index_bits);
    return v & ((1u << index_bits) - 1);
}

bool equihash_verify(const uint8_t *header, const eh_params_t *p,
                     const uint8_t *solution, size_t sol_len)
{
    ensure_variants();
    if ((int)sol_len != p->solution_size) return false;

    uint32_t *indices = (uint32_t *)malloc((size_t)p->proofsize * 4);
    if (!indices) return false;

    for (int i = 0; i < p->proofsize; i++)
        indices[i] = unpack_index(solution, i, p->index_bits);

    /* Check tree-level ordering (IndicesBefore at every tree depth).
     * After fix_tree_order, left subtree always has smaller first index. */
    for (int step = 1; step < p->proofsize; step *= 2) {
        for (int i = 0; i + step < p->proofsize; i += 2*step) {
            if (indices[i] >= indices[i + step]) {
                free(indices); return false;
            }
        }
    }

    /* Allocate per-hash slots on heap */
    uint8_t *hashes = (uint8_t *)malloc((size_t)p->proofsize * p->slot_bytes);
    if (!hashes) { free(indices); return false; }

    int iph      = eh_indices_per_hash(p->wn);
    int hash_out = eh_hash_output(p->wn);
    int raw_hlen = p->hashlen;
    uint8_t digest[64];

    for (int i = 0; i < p->proofsize; i++) {
        uint32_t blk = indices[i] / iph;
        int      pos = indices[i] % iph;
        sph_blake2b_ctx ctx;
        blake2b_init_pers(&ctx, hash_out, p->personalization);
        sph_blake2b_update(&ctx, header, 140);
        sph_blake2b_update(&ctx, &blk, 4);
        sph_blake2b_final(&ctx, digest);
        uint8_t *slot = hashes + (size_t)i * p->slot_bytes;
        memset(slot, 0, p->slot_bytes);
        expand_hash(digest + pos * raw_hlen, raw_hlen,
                    slot, p->hash_length, p->collision_bits);
    }
    free(indices);

    /* Verify K rounds of pairwise XOR cancellation.
     * Pairs: (0,1), (2,3), ..., writing merged result to positions 0, 1, ...
     * After all n/2 merges, array [0..n/2-1] holds the next round's hashes. */
    int n = p->proofsize;
    for (int r = 0; r < p->wk; r++) {
        int n2 = n / 2;
        for (int i = 0; i < n2; i++) {
            uint8_t *a   = hashes + (size_t)(2*i)   * p->slot_bytes;
            uint8_t *b   = hashes + (size_t)(2*i+1) * p->slot_bytes;
            uint8_t *dst = hashes + (size_t)i       * p->slot_bytes;
            if (!coll_match(a, b, p->cbl)) { free(hashes); return false; }
            /* Merge into a temporary then copy to dst */
            uint8_t merged[40] = {0};   /* max hash_length = 30 (200/9) + margin */
            memcpy(merged, a, p->hash_length);
            xor_hash(merged, b, p->hash_length);
            shift_hash(merged, p->hash_length, p->cbl);
            memcpy(dst, merged, p->hash_length);
        }
        n = n2;
    }

    bool ok = slot_zero(hashes, p->cbl);
    free(hashes);
    return ok;
}
