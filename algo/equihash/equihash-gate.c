#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "equihash.h"
#include "equihash-gate.h"
#include "miner.h"
#include "algo-gate-api.h"
#include "algo/sha/sha256d.h"

/* ── Thread-local workspace (one per miner thread) ───────────────────── */

static __thread eh_workspace_t *tl_ws = NULL;

/* ── Global variant params (shared by all threads) ───────────────────── */
/*
 * NOTE: these MUST be global (not __thread) because:
 *   - set_default_params() is called from register_*_algo() in the main thread
 *   - equihash_build_extraheader() updates them in the stratum thread
 *   - scanhash_equihash() reads them in each miner thread
 *
 * build_extraheader() is called inside g_work_lock (write-locked) in
 * stratum_gen_work(), BEFORE restart_threads().  The restart provides a
 * pthread synchronisation barrier, so all miner threads see the updated
 * params by the time they fetch the new work.
 */
static eh_params_t  g_eq_params;
static int          g_eq_params_set = 0;

static void set_default_params(const eh_params_t *p)
{
    g_eq_params     = *p;
    g_eq_params_set = 1;
}

static const eh_params_t *active_params(void)
{
    return g_eq_params_set ? &g_eq_params : &EH_PARAMS_200_9;
}

/* Ensure the per-thread workspace matches the current global params.      */
static bool ensure_workspace(const eh_params_t *p)
{
    if (tl_ws && memcmp(&tl_ws->params, p, sizeof(eh_params_t)) == 0)
        return true;

    return eh_workspace_alloc(&tl_ws, p);
}

/* ── Work data size ──────────────────────────────────────────────────── */

int    equihash_get_work_data_size(void) { return EQH_WORK_DATA_SIZE; }
size_t equihash_get_workspace_size(void) { return eh_workspace_bytes(active_params()); }

/* ── Build block header from stratum job ─────────────────────────────── */
/*
 * Equihash 140-byte header:
 *   [0..3]    version
 *   [4..35]   prevhash
 *   [36..67]  merkleroot
 *   [68..99]  reserved (finalsaplingroot)
 *   [100..103] ntime
 *   [104..107] nbits
 *   [108..139] nonce = xnonce1 || xnonce2 || [iter_counter]
 */
void equihash_build_extraheader(struct work *g_work, struct stratum_ctx *sctx)
{
    uint8_t *hdr = (uint8_t *)g_work->data;
    memset(hdr, 0, EQH_WORK_DATA_SIZE);

    memcpy(hdr + 0,   sctx->job.version,   4);
    memcpy(hdr + 4,   sctx->job.prevhash,  32);
    memcpy(hdr + 36,  sctx->job.merkleroot, 32);
    memcpy(hdr + 68,  sctx->job.reserved,  32);
    memcpy(hdr + 100, sctx->job.ntime,     4);
    memcpy(hdr + 104, sctx->job.nbits,     4);

    if (sctx->xnonce1 && sctx->xnonce1_size)
        memcpy(hdr + 108, sctx->xnonce1, sctx->xnonce1_size);
    if (g_work->xnonce2 && g_work->xnonce2_len)
        memcpy(hdr + 108 + sctx->xnonce1_size,
               g_work->xnonce2, g_work->xnonce2_len);

    /* If pool sent variant params in the notify, update the global now.
     * This runs inside g_work_lock (write-held) in stratum_gen_work, and
     * restart_threads() runs immediately after — giving all miner threads
     * a visibility guarantee before they next call scanhash.              */
    if (sctx->job.eq_params[0] && sctx->job.eq_personal[0]) {
        eh_params_t newp;
        if (eh_params_from_stratum(&newp, sctx->job.eq_params,
                                    sctx->job.eq_personal)) {
            g_eq_params     = newp;
            g_eq_params_set = 1;
        }
    }
}

/* ── Compact-size encoding helper ────────────────────────────────────── */

/* Write Bitcoin compact-size for value v into buf, return bytes written. */
static int write_compact_size(uint8_t *buf, uint64_t v)
{
    if (v < 0xfd) { buf[0] = (uint8_t)v; return 1; }
    if (v <= 0xffff) {
        buf[0] = 0xfd;
        buf[1] = (uint8_t)(v); buf[2] = (uint8_t)(v >> 8);
        return 3;
    }
    buf[0] = 0xfe;
    for (int i = 0; i < 4; i++) buf[i+1] = (uint8_t)(v >> (8*i));
    return 5;
}

/* ── Build stratum submit request ────────────────────────────────────── */
/*
 * Equihash submit params: [user, job_id, ntime(8), nonce(56), solution]
 *
 * YAAMP_EQUIHASH_NONCE_SIZE = 28 bytes (56 hex chars).
 * The FULL 32-byte nonce = extranonce1 (pool, 4 B) + miner_nonce (28 B).
 * The miner submits only the 28-byte miner portion; the pool prepends its
 * own extranonce1 when rebuilding the header for verification.
 * Sending all 32 bytes causes an "Invalid nonce size" rejection.
 *
 * solution = compact_size_prefix + raw_solution_bytes, all hex-encoded.
 */
void equihash_build_stratum_request(char *req, struct work *work,
                                    struct stratum_ctx *sctx)
{
    const uint8_t *hdr = (const uint8_t *)work->data;

    char ntimestr[9];
    for (int i = 0; i < 4; i++) snprintf(ntimestr + i*2, 3, "%02x", hdr[100+i]);

    /* Skip the pool's extranonce1 prefix; submit only the 28-byte miner nonce */
    int xn1_size = sctx ? (int)sctx->xnonce1_size : 4;  /* default 4 if no sctx */
    int miner_nonce_len = 32 - xn1_size;                  /* = 28 typically     */
    char noncestr[57];  /* 28 bytes × 2 hex chars + NUL */
    memset(noncestr, '0', sizeof(noncestr) - 1);
    noncestr[sizeof(noncestr) - 1] = '\0';
    for (int i = 0; i < miner_nonce_len; i++)
        snprintf(noncestr + i*2, 3, "%02x", hdr[108 + xn1_size + i]);

    if (!work->equihash_solution || !work->equihash_solution_len) {
        applog(LOG_ERR, "equihash_build_stratum_request: no solution");
        snprintf(req, JSON_BUF_LEN_EQH, "{}");
        return;
    }

    uint8_t cs[5];
    int cs_len = write_compact_size(cs, work->equihash_solution_len);
    size_t wire_len = cs_len + work->equihash_solution_len;

    /* solstr: 2 × wire_len hex chars + NUL */
    char *solstr = (char *)malloc(wire_len * 2 + 1);
    if (!solstr) { snprintf(req, JSON_BUF_LEN_EQH, "{}"); return; }

    for (int i = 0; i < cs_len; i++)
        snprintf(solstr + i*2, 3, "%02x", cs[i]);
    for (int i = 0; i < (int)work->equihash_solution_len; i++)
        snprintf(solstr + (cs_len + i)*2, 3, "%02x", work->equihash_solution[i]);

    snprintf(req, JSON_BUF_LEN_EQH,
        "{\"method\": \"mining.submit\","
        " \"params\": [\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"],"
        " \"id\":4}",
        rpc_user, work->job_id, ntimestr, noncestr, solstr);

    free(solstr);
}

/* ── Share hash ──────────────────────────────────────────────────────── */

/* Compute SHA256d over the full Equihash block: header (140 B) +
 * compact_size_prefix + raw_solution.
 *
 * This matches the Yiimp/ccminer pool server's share-difficulty check
 * (build_submit_values_equihash:160):
 *   g_current_algo->hash_function(header_bin + equihash_solution_hex_as_bin)
 *
 * The difficulty is then read from bytes [24..31] of the 32-byte result as a
 * little-endian uint64 (get_equihash_difficulty), which is what valid_hash
 * also compares (it checks hash[3], the most-significant uint64 in LE storage,
 * which spans bytes 24-31 of the SHA256d output).                          */
static void sha256d_full_block(const uint8_t *hdr,
                                const uint8_t *solution, int sol_size,
                                uint32_t *out)
{
    uint8_t buf[2048];  /* 140 + 3 + 1344 = 1487 max for 200/9 */
    memcpy(buf, hdr, 140);

    uint8_t cs[5];
    int cs_len = write_compact_size(cs, (uint64_t)sol_size);
    memcpy(buf + 140, cs, cs_len);
    memcpy(buf + 140 + cs_len, solution, sol_size);

    sha256d((void *)out, buf, 140 + cs_len + sol_size);
}

/* ── Scanhash ────────────────────────────────────────────────────────── */

int scanhash_equihash(struct work *work, uint32_t max_nonce,
                      uint64_t *hashes_done, struct thr_info *mythr)
{
    int thr_id = mythr->id;
    const eh_params_t *p = active_params();

    if (!ensure_workspace(p)) {
        applog(LOG_ERR, "equihash thr%d: workspace alloc failed for %d/%d "
               "(need %.0f MB)", thr_id, p->wn, p->wk,
               eh_workspace_bytes(p) / (1024.0 * 1024.0));
        return -1;
    }

    /* Log active variant + personalization whenever it changes, so the user
     * can confirm the SOLVER is actually using the pool-sent personalization
     * (e.g. "BitcoinZ") and not the algo's registered default ("BgoldPoW").
     * The stratum "Equihash variant:" line only proves the notify was parsed,
     * not that the override reached the solver. A mismatch here is the #1
     * cause of pool "Invalid share" rejects that still pass local verify.    */
    static __thread uint8_t logged_pers[16] = { 0 };
    if (memcmp(logged_pers, p->personalization, 16) != 0) {
        char pershex[33];
        for (int i = 0; i < 16; i++)
            snprintf(pershex + i*2, 3, "%02x", p->personalization[i]);
        applog(LOG_BLUE,
               "equihash thr%d: solver %d/%d  nhashes=%d  proofsize=%d  "
               "solsize=%d  workspace=%.0f MB  pers=\"%.8s\" [%s]",
               thr_id, p->wn, p->wk, p->nhashes_init, p->proofsize,
               p->solution_size,
               eh_workspace_bytes(p) / (1024.0 * 1024.0),
               (const char *)p->personalization, pershex);
        memcpy(logged_pers, p->personalization, 16);
    }

    uint8_t  *hdr    = (uint8_t *)work->data;
    uint64_t *iter   = (uint64_t *)(hdr + 132);   /* miner iteration counter */
    uint32_t *target = work->target;

    /* Equihash: max_nonce is meaningless here — each solve takes seconds,
     * so the outer framework's initial seed of 20 H/s gives max_nonce≈100
     * which would mean hours per scanhash call.  Always do exactly 1 solve
     * per scanhash call; the outer loop measures elapsed time and adapts.
     * work_restart is still honoured between calls via the outer loop.      */
    (void)max_nonce;

    uint8_t solutions[EH_MAX_SOLS][EH_MAX_SOLUTION_BYTES];
    uint32_t share_hash[8];

    *hashes_done = 0;

    /* Check work_restart before starting — avoids solving stale work */
    if (work_restart[thr_id].restart)
        return 0;

    /* Each scanhash call must try a DIFFERENT nonce (different iter value).
     * The outer loop keeps calling scanhash for the same job; if we always
     * use iter=0 we'd hash the same nonce every time and never explore the
     * nonce space.  Reset the counter on each new job.
     *
     * Work with no job_id (benchmark, getwork) is one continuous job, not a
     * new job every call: testing `!work->job_id` reset the counter on every
     * call, so --benchmark re-solved a single header forever and reported the
     * solution count of that one header rather than a nonce-space average.  */
    static __thread uint64_t iter_counter = 0;
    static __thread char     last_job_id[64] = {0};
    static __thread bool     iter_started = false;
    const char *job_id = work->job_id ? work->job_id : "";
    if (!iter_started || strcmp(job_id, last_job_id) != 0) {
        iter_counter = (uint64_t)thr_id;   /* thread-stagger: each thread
                                            * starts at a unique offset      */
        strncpy(last_job_id, job_id, 63);
        last_job_id[63] = '\0';
        iter_started = true;
    }
    *iter = iter_counter;
    iter_counter += opt_n_threads;   /* step by thread count so threads
                                      * cover disjoint nonce ranges          */

    int nsols = equihash_solve(hdr, tl_ws, solutions, EH_MAX_SOLS);

    /* Stale-work guard. A solve can take seconds (tens of seconds for large
     * variants like 192/7), during which one or more new stratum jobs may
     * arrive and set work_restart. Any solution we found belongs to the now
     * superseded job and the pool would reject it as "Invalid job id", so
     * submit nothing and let the outer miner loop pick up the latest g_work
     * on its next iteration. The batch is still verified and counted below:
     * hashes_done measures work done, not shares sent, and verification costs
     * microseconds against a multi-second solve. Benchmark mode never sets
     * restart, so this is a no-op there.                                    */
    const bool stale = work_restart[thr_id].restart;

    int verified = 0;   /* solutions that pass full verification */
    for (int s = 0; s < nsols; s++) {
        /* Always verify the solution before submitting.
         * Invalid solutions arise when two items in the same bucket share
         * a common ancestor (duplicate leaf indices); the verifier's
         * DistinctIndices check would reject them at the pool.             */
        if (!equihash_verify(hdr, p, solutions[s], p->solution_size)) {
            if (opt_debug)
                applog(LOG_DEBUG,
                       "equihash thr%d: discarding invalid solution "
                       "(duplicate indices or wrong params)", thr_id);
            continue;
        }
        verified++;

        /* Hash = SHA256d(header_140 + compact_prefix + solution).
         * This matches the pool's share-difficulty computation exactly.     */
        sha256d_full_block(hdr, solutions[s], p->solution_size, share_hash);

        bool meets_target = valid_hash(share_hash, target);

        /* In benchmark mode there is no pool to submit to, so report the
         * solver result directly — this is the only way to confirm the
         * solver is actually producing valid solutions.                    */
        if (opt_benchmark)
            applog(LOG_NOTICE,
                   "equihash thr%d: valid solution found%s",
                   thr_id, meets_target ? " (meets target)" : "");

        if (meets_target && !opt_benchmark && !stale) {
            int sol_size = p->solution_size;

            /* Dump the full (personalization, header, solution) tuple so a
             * share the pool rejects as "Invalid share" can be checked against
             * an independent equihash verifier. If that external check says
             * VALID, the pool is reconstructing a different header (nonce/ntime);
             * if INVALID, our solver/encoding/personalization diverges from the
             * canonical definition.                                            */
            if (opt_debug) {
                char hdrhex[2 * EQH_WORK_DATA_SIZE + 1];
                for (int i = 0; i < EQH_WORK_DATA_SIZE; i++)
                    snprintf(hdrhex + i*2, 3, "%02x", hdr[i]);
                char *solhex = (char *)malloc((size_t)sol_size * 2 + 1);
                if (solhex) {
                    for (int i = 0; i < sol_size; i++)
                        snprintf(solhex + i*2, 3, "%02x", solutions[s][i]);
                    applog(LOG_DEBUG, "equihash thr%d submit header(%d): %s",
                           thr_id, EQH_WORK_DATA_SIZE, hdrhex);
                    applog(LOG_DEBUG, "equihash thr%d submit solution(%d): %s",
                           thr_id, sol_size, solhex);
                    free(solhex);
                }
            }

            if (!work->equihash_solution)
                work->equihash_solution = (unsigned char *)malloc(sol_size);
            if (work->equihash_solution) {
                memcpy(work->equihash_solution, solutions[s], sol_size);
                work->equihash_solution_len = (uint16_t)sol_size;
            }
            submit_solution(work, share_hash, mythr);
        }
    }

    /* Every verified solution is hashed and tested against the target, so it
     * is one independent draw with probability target/2**256. The difficulty
     * math elsewhere (expected work = diff * 2**32, see diff_to_hash) counts
     * those draws, not solve attempts, and so does the pool when it derives a
     * rate from submitted shares. Reporting 1 per solve made TTF and the
     * displayed rate wrong by the solutions-per-solve ratio (~1.9 for 200/9).
     * This is the conventional Sol/s unit for equihash.
     *
     * The framework recomputes thr_hashrates from a single call, so the rate
     * shown now varies with the solution count of the last solve instead of
     * sitting at a constant (biased) value; the average, and total_hashes,
     * are right. A solve that yields none reports 0, which with -t 1 can
     * briefly suppress the hr-gated TTF line.                               */
    *hashes_done = (uint64_t)verified;

    if (opt_debug)
        applog(LOG_DEBUG, "equihash thr%d: 1 solve → %d raw, %d verified%s",
               thr_id, nsols, verified, stale ? " (stale, not submitted)" : "");

    return 0;
}

/* ── Thread init (called once per miner thread) ──────────────────────── */

static bool equihash_thread_init_gate(int thr_id)
{
    (void)thr_id;
    /* Workspace is lazily allocated on first scanhash call. */
    return true;
}

/* The largest per-thread allocation in the tree: 7 MB for 96/5 up to ~3.6 GB
 * for 192/7, so releasing it on an algo switch is not a nicety. The next scan
 * reallocates through ensure_workspace(). */
static void equihash_thread_free_gate(int thr_id)
{
    (void)thr_id;
    eh_workspace_free(tl_ws);
    tl_ws = NULL;
}

/* ── Self-test: known-answer validation against real blockchain data ─────────
 *
 * Validates equihash_verify() against real (block header, solution) pairs taken
 * from the chain. A passing verify INDEPENDENTLY proves the Blake2b
 * personalization, hash generation, ExpandArray and 25/21-bit index packing are
 * all canonical — something the solver<->verifier round trip cannot prove,
 * because they share code (a self-consistent bug passes locally but the pool
 * rejects it, exactly the "Invalid share" symptom).
 *
 * Vectors are read from "equihash-vectors.txt" in the working directory, so you
 * can add data without recompiling. Each non-comment, non-blank line is:
 *
 *     <wn> <wk> <personal8> <rawblock_hex>
 *     <wn> <wk> <personal8> <header140_hex> <solution_hex>
 *
 * rawblock_hex is the serialized block — only the leading header(140) +
 * compactSize + solution bytes are read, trailing tx data is ignored, so a
 * truncated prefix (~first 3000 hex chars) is enough. Get it with e.g.:
 *
 *     zcash-cli    getblock <hash> 0     # 200/9, personal "ZcashPoW"
 *     bitcoinz-cli getblock <hash> 0     # 144/5, personal "BitcoinZ"
 *
 * Slicing from the raw block avoids any per-field byte-order mistakes.
 * ------------------------------------------------------------------------- */

static int eh_hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Decode up to max_bytes from a hex string; returns bytes decoded, -1 on a bad
 * character. Stops cleanly at end-of-string (so a longer raw block is fine).   */
static int eh_hex2bin_n(const char *hex, uint8_t *out, int max_bytes)
{
    int n = 0;
    while (n < max_bytes) {
        int c0 = hex[2*n], c1 = c0 ? hex[2*n + 1] : 0;
        if (!c0 || !c1) break;
        int hi = eh_hexval(c0), lo = eh_hexval(c1);
        if (hi < 0 || lo < 0) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return n;
}

/* Run one vector. solution_hex == NULL means header_hex is a raw block to slice.
 * Returns true on PASS (valid accepted AND a 1-bit-corrupted copy rejected).    */
static bool eh_selftest_vector(const char *src, int wn, int wk, const char *pers,
                               const char *header_hex, const char *solution_hex)
{
    char wnwk[16];
    snprintf(wnwk, sizeof wnwk, "%d_%d", wn, wk);

    eh_params_t p;
    if (!eh_params_from_stratum(&p, wnwk, pers)) {
        applog(LOG_ERR, "EH selftest [%s]: invalid params %d/%d", src, wn, wk);
        return false;
    }

    uint8_t  header[EQH_WORK_DATA_SIZE];
    uint8_t *sol  = (uint8_t *)malloc(p.solution_size);
    if (!sol) return false;
    bool pass = false;

    if (solution_hex) {
        if (eh_hex2bin_n(header_hex, header, EQH_WORK_DATA_SIZE) != EQH_WORK_DATA_SIZE) {
            applog(LOG_ERR, "EH selftest [%s]: header must be %d bytes (%d hex chars)",
                   src, EQH_WORK_DATA_SIZE, 2 * EQH_WORK_DATA_SIZE);
            goto done;
        }
        if (eh_hex2bin_n(solution_hex, sol, p.solution_size) != p.solution_size) {
            applog(LOG_ERR, "EH selftest [%s]: solution must be %d bytes",
                   src, p.solution_size);
            goto done;
        }
    } else {
        /* raw block: header(140) || compactSize || solution || tx... */
        int need = EQH_WORK_DATA_SIZE + 5 + p.solution_size;
        uint8_t *raw = (uint8_t *)malloc(need);
        if (!raw) goto done;
        int got = eh_hex2bin_n(header_hex, raw, need);
        if (got < EQH_WORK_DATA_SIZE + 1) {
            applog(LOG_ERR, "EH selftest [%s]: raw block too short", src);
            free(raw); goto done;
        }
        memcpy(header, raw, EQH_WORK_DATA_SIZE);
        int off = EQH_WORK_DATA_SIZE, cs;
        uint64_t slen;
        uint8_t b = raw[off];
        if      (b <  0xfd) { slen = b;                                              cs = 1; }
        else if (b == 0xfd) { slen = (uint64_t)raw[off+1] | ((uint64_t)raw[off+2]<<8); cs = 3; }
        else                { slen = 0;                                              cs = 5; }
        if ((int)slen != p.solution_size) {
            applog(LOG_ERR, "EH selftest [%s]: solution size %llu != %d expected for "
                   "%d/%d (wrong variant in this line?)", src,
                   (unsigned long long)slen, p.solution_size, wn, wk);
            free(raw); goto done;
        }
        if (got < off + cs + p.solution_size) {
            applog(LOG_ERR, "EH selftest [%s]: raw block truncated before end of solution "
                   "(need >= %d hex chars)", src, 2 * (off + cs + p.solution_size));
            free(raw); goto done;
        }
        memcpy(sol, raw + off + cs, p.solution_size);
        free(raw);
    }

    bool ok = equihash_verify(header, &p, sol, p.solution_size);
    sol[0] ^= 0x01;   /* negative control: a corrupted solution MUST be rejected */
    bool neg = equihash_verify(header, &p, sol, p.solution_size);
    sol[0] ^= 0x01;

    if (ok && !neg) {
        applog(LOG_NOTICE, "EH selftest [%s] %d/%d pers=\"%s\": PASS", src, wn, wk, pers);
        pass = true;
    } else {
        applog(LOG_ERR, "EH selftest [%s] %d/%d pers=\"%s\": FAIL "
               "(valid->%s, corrupted->%s)", src, wn, wk, pers,
               ok ? "accept" : "reject", neg ? "accept" : "reject");
    }
done:
    free(sol);
    return pass;
}

#define EH_VECTORS_FILE "equihash-vectors.txt"

static void eh_load_vectors_file(const char *path, int *nrun, int *npass)
{
    FILE *f = fopen(path, "r");
    if (!f) return;
    applog(LOG_BLUE, "EH selftest: loading vectors from %s", path);

    size_t cap = 1u << 20;            /* 1 MB line buffer (paste a prefix, not whole big blocks) */
    char  *line = (char *)malloc(cap);
    if (!line) { fclose(f); return; }

    while (fgets(line, (int)cap, f)) {
        char *s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '#' || *s == '\n' || *s == '\r' || *s == '\0') continue;

        char *t_wn   = strtok(s,    " \t\r\n");
        char *t_wk   = strtok(NULL, " \t\r\n");
        char *t_pers = strtok(NULL, " \t\r\n");
        char *t_h1   = strtok(NULL, " \t\r\n");
        char *t_h2   = strtok(NULL, " \t\r\n");   /* optional */
        if (!t_wn || !t_wk || !t_pers || !t_h1) continue;

        (*nrun)++;
        if (eh_selftest_vector(EH_VECTORS_FILE, atoi(t_wn), atoi(t_wk),
                               t_pers, t_h1, t_h2))
            (*npass)++;
    }
    free(line);
    fclose(f);
}

/* Runs once at registration. Cheap (a few hundred Blake2b calls per vector). */
static void eh_run_selftests_once(void)
{
    static bool done = false;
    if (done) return;
    done = true;

    /* Resolve and report the solver backend. This triggers the differential
     * oracle (optimized vs reference gen_hashes) once, single-threaded, before
     * any miner thread runs — if the optimized backend diverges it falls back
     * to the reference automatically.                                         */
    const eh_backend_t *be = eh_active_backend();
    applog(LOG_BLUE, "EH backend: %s%s", be->name,
           be == &eh_backend_ref ? " (optimized backend failed self-test, "
                                    "using reference)" : "");

    int nrun = 0, npass = 0;
    /* Embedded vectors could be added here once a verified pair is available;
     * for now everything comes from the user-supplied file.                   */
    eh_load_vectors_file(EH_VECTORS_FILE, &nrun, &npass);

    if (nrun == 0)
        applog(LOG_BLUE, "EH selftest: no vectors found (optional: create %s, one "
               "vector per line as \"<wn> <wk> <personalization> <header_hex> "
               "[<solution_hex>]\", to validate the verifier against a known block)",
               EH_VECTORS_FILE);
    else
        applog(npass == nrun ? LOG_NOTICE : LOG_ERR,
               "EH selftest: %d/%d vectors PASSED", npass, nrun);
}

/* ── Gate registration ───────────────────────────────────────────────── */

static void fill_gate(algo_gate_t *gate)
{
    gate->scanhash              = (void *)&scanhash_equihash;
    gate->miner_thread_init     = (void *)&equihash_thread_init_gate;
    gate->miner_thread_free     = (void *)&equihash_thread_free_gate;
    gate->build_extraheader     = (void *)&equihash_build_extraheader;
    gate->build_stratum_request = (void *)&equihash_build_stratum_request;
    gate->get_work_data_size    = (void *)&equihash_get_work_data_size;
    gate->get_workspace_size    = (void *)&equihash_get_workspace_size;
    gate->ntime_index           = EQH_NTIME_INDEX;
    gate->nbits_index           = EQH_NBITS_INDEX;
    gate->nonce_index           = EQH_NONCE_INDEX;
    gate->work_cmp_size         = EQH_WORK_CMP_SIZE;

    /* Validate the verifier against any known-answer vectors the user supplied
     * (equihash-vectors.txt). Runs once at startup, before mining. */
    eh_run_selftests_once();
}

/* Trigger eh_params initialisation (ensure_variants is called inside
 * equihash_solve, but we also call it at registration time so the param
 * pointers are valid immediately).  Declare as extern to avoid a header
 * dependency cycle — ensure_variants is defined in equihash.c.           */
extern void eh_ensure_variants(void);

/* opt_target_factor = EQH_DIFF_SCALE tells stratum_gen_work:
 *
 *   g_work->targetdiff = sctx->job.diff / opt_target_factor
 *                      = diff_pool / EQH_DIFF_SCALE
 *                      = diff_internal          ← correct for diff_to_hash
 *
 * sctx->job.diff (= next_diff set by stratum_set_target) holds diff_pool.
 * All log lines that print sctx->job.diff or stratum_diff therefore show
 * the pool-compatible difficulty number — matching what the pool operator
 * sees (e.g. "Stratum 4.0" instead of "Stratum 2.384e-7").
 *
 * EQH_DIFF_SCALE is defined in equihash.h (shared with util.c).           */

bool register_equihash_algo(algo_gate_t *gate)
{
    eh_ensure_variants();
    fill_gate(gate);
    set_default_params(&EH_PARAMS_200_9);
    opt_target_factor = EQH_DIFF_SCALE;
    return true;
}

bool register_equihash96_algo(algo_gate_t *gate)
{
    eh_ensure_variants();
    fill_gate(gate);
    set_default_params(&EH_PARAMS_96_5);
    opt_target_factor = EQH_DIFF_SCALE;
    return true;
}

bool register_equihash144_algo(algo_gate_t *gate)
{
    eh_ensure_variants();
    fill_gate(gate);
    set_default_params(&EH_PARAMS_144_5);
    opt_target_factor = EQH_DIFF_SCALE;
    return true;
}

bool register_equihash192_algo(algo_gate_t *gate)
{
    eh_ensure_variants();
    fill_gate(gate);
    set_default_params(&EH_PARAMS_192_7);
    opt_target_factor = EQH_DIFF_SCALE;
    return true;
}

bool register_equihash125_algo(algo_gate_t *gate)
{
    eh_ensure_variants();
    fill_gate(gate);
    set_default_params(&EH_PARAMS_125_4);
    opt_target_factor = EQH_DIFF_SCALE;
    return true;
}
