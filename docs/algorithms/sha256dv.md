# SHA256Dv (Veil)

**Coin:** Veil (VEIL)
**Algorithm name:** `sha256dv`
**Family:** double SHA-256, with a coin-specific Stratum protocol

```
./cpuminer -a sha256dv -o stratum+tcp://<pool>:<port> -u <wallet> -p x
```

---

## Overview

SHA256Dv is Veil's variant of double SHA-256. The hashing itself is ordinary
SHA-256d, but the work arrives in a non-standard form: **the pool performs the
stage-1 hashing and hands the miner a midstate**, and the search space uses a
**64-bit nonce** instead of the usual 32-bit one. Because of this, SHA256Dv needs a
bespoke Stratum notify and submit — see [Stratum protocol](#stratum-protocol).

The 32-byte double-SHA-256 result is compared against the target.

## Hash structure

For each candidate nonce the miner builds an 80-byte "stage-2" buffer and runs
double SHA-256 over it:

| Offset | Size | Field |
|---|---|---|
| 0  | 4  | version (LE) |
| 4  | 32 | midstate (BE) — supplied by the pool |
| 36 | 32 | merkle (LE — the byte-reversed `merkle_be` from the pool) |
| 68 | 4  | ntime (LE) |
| 72 | 4  | nonce_lo (LE) |
| 76 | 4  | nonce_hi (LE) |

```
hash = SHA256( SHA256( stage2 ) )
```

The miner scans the 32-bit **nonce_lo** for a given **nonce_hi**; together they form
the 64-bit nonce. This layout matches Veil's reference `veil_sha256d_miner.py`.

## Stratum protocol

SHA256Dv does **not** use the standard sha256d Stratum flow. The differences:

### No client-side coinbase / extranonce

Standard sha256d builds the coinbase from `coinb1 + xnonce1 + xnonce2 + coinb2` and
computes the merkle root locally. SHA256Dv does none of this — the pool has already
done stage-1 and sends a finished **midstate** and **merkle root**. There is no
extranonce2 (`xnonce2_len = 0`) and nothing is assembled client-side.

### Bespoke `mining.notify`

Instead of the usual `version / prevhash / coinb1 / coinb2 / merkle_branch[] /
version / nbits / ntime / clean` fields, the SHA256Dv notify carries:

- **job_id**
- **midstate** (the pool's stage-1 SHA-256 midstate)
- **merkle** (big-endian)
- **ntime**
- **nbits** — carried for difficulty display; it is *not* part of the hashed stage-2
  pre-image (see the stage-2 layout above, which has no nbits field)
- **nonce_hi** — the base value for the high 32 bits of the 64-bit nonce

### 64-bit nonce, split across notify and submit

The nonce is 64-bit, handled as two 32-bit words:

- A **new job** seeds the `nonce_hi` base from the notify.
- A **re-notify of the same job** advances `nonce_hi` by the thread count
  (`opt_n_threads`), so each thread's range stays disjoint as it keeps working the
  same job.
- Each thread scans `nonce_lo` (32 bits) within its `nonce_hi`.

### Bespoke `mining.submit`

The submit reuses the standard five-slot request template but repurposes the slots:
where a normal sha256d submit sends `(xnonce2, ntime, nonce)`, SHA256Dv sends
**`(nonce_hi, ntime, nonce_lo)`**:

```
mining.submit ← [ user, job_id, nonce_hi, ntime, nonce_lo ]
```

Shares are sent directly over Stratum (not through the generic submit path) because
of this custom field mapping.

## Verification

A known-answer test runs at startup and refuses to mine on mismatch; the backend was
confirmed by accepted shares on a live Veil pool.

## Possible optimizations (preview)

SHA256Dv is plain double SHA-256 under the hood, so it inherits the project's fast
SHA-256 code; remaining candidates are incremental:

- **SHA extensions / parallel lanes** — use the CPU SHA-NI instructions where
  present, or wide multi-way SHA-256 (8/16-way) on AVX2/AVX-512 to scan many
  `nonce_lo` values per pass.
- **Stage-2 midstate caching** — the first SHA-256 block of stage-2 is fixed for a
  job (only the nonce words change), so its midstate can be precomputed once per job
  and reused across the `nonce_lo` scan.
