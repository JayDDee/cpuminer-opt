/* Known-answer tests for the vendored RandomX core (algo/randomx/randomx).
 *
 * Vectors transcribed from upstream tevador/RandomX @7c761cf, src/tests/tests.cpp:
 *   test_a..test_f     lines 972-1017   (v1 digest / v2 digest per vector)
 *   cache-init words   lines 1084-1086  ("Cache initialization: SSSE3"/"AVX2")
 *   batch              lines 1131-1133 (v1), 1146-1148 (v2)
 *   commitment         line  1186
 * Upstream's own suite passes 108/108 on this commit; these are the subset that
 * pins the *hash*, which is what a re-vendor or a new ISA tier can break.
 *
 * Scope: the hash core only, on every arch and ISA tier. It does not validate
 * the mining integration (stratum, dataset epoch lifecycle) -- an accepted
 * share is the only evidence for that.
 *
 * Default run is light mode (256 MiB cache, no dataset) so `make check` stays
 * cheap. --full adds the 2080 MiB fast-mode path, the only thing that
 * exercises randomx_init_dataset(); it needs ~2.4 GB free and about a minute.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

#include "randomx/randomx.h"
#include "randomx-buildinfo.h"

static int failures = 0;
static int ran = 0;
static int skipped = 0;

/* ---------------------------------------------------------------- helpers */

static void hex2bin(const char *hex, uint8_t *out, size_t outlen)
{
	size_t i;
	for (i = 0; i < outlen; i++) {
		unsigned v;
		sscanf(hex + 2 * i, "%2x", &v);
		out[i] = (uint8_t)v;
	}
}

static void bin2hex(const uint8_t *in, size_t inlen, char *out)
{
	size_t i;
	for (i = 0; i < inlen; i++)
		sprintf(out + 2 * i, "%02x", in[i]);
	out[2 * inlen] = '\0';
}

static void check_hash(const char *name, const uint8_t *got, const char *want_hex)
{
	char got_hex[2 * RANDOMX_HASH_SIZE + 1];
	ran++;
	bin2hex(got, RANDOMX_HASH_SIZE, got_hex);
	if (strcmp(got_hex, want_hex) == 0) {
		printf("  PASS  %s\n", name);
	} else {
		printf("  FAIL  %s\n        want %s\n        got  %s\n",
		       name, want_hex, got_hex);
		failures++;
	}
}

static void check_u64(const char *name, uint64_t got, uint64_t want)
{
	ran++;
	if (got == want) {
		printf("  PASS  %s\n", name);
	} else {
		printf("  FAIL  %s\n        want %016llx\n        got  %016llx\n",
		       name, (unsigned long long)want, (unsigned long long)got);
		failures++;
	}
}

/* ------------------------------------------------------------- the vectors */

#define KEY0 "test key 000"
#define KEY1 "test key 001"

#define IN_A "This is a test"
#define IN_B "Lorem ipsum dolor sit amet"
#define IN_C "sed do eiusmod tempor incididunt ut labore et dolore magna aliqua"

/* test_e / test_f take a hex blob rather than a string. */
#define IN_E_HEX \
  "0b0b98bea7e805e0010a2126d287a2a0cc833d312cb786385a7c2f9de69d2553" \
  "7f584a9bc9977b00000000666fd8753bf61a8631f12984e3fd44f4014eca6292" \
  "76817b56f32e9b68bd82f416"
#define IN_F_HEX \
  "1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e" \
  "1f6821fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6" \
  "514d90689721c4aac5a9bb0d"
/* test_f's key is a binary blob, not a string. Two traps, both of which cost a
 * KAT run here:
 *   - upstream spells it as a byte list, and transcribing it by hand got two
 *     bytes wrong. The hex below was diffed against that list programmatically;
 *     do the same after any re-vendor.
 *   - it is 32 bytes on the page but the *key size is 31*. Upstream's helper is
 *     `initCache(const char (&key)[N])` calling `randomx_init_cache(cache, key,
 *     N - 1)`, so the trailing 0x00 is the string terminator and is dropped.
 *     That is what upstream's "last byte is ignored by initCache" comment means;
 *     passing 32 gives a plausible-looking wrong digest.
 */
#define KEY_F_HEX \
  "7797373ea4633194640bf8d8c3b66724d6aa7bd2dc20e009df2f8f1710abe8"
#define KEY_F_LEN 31

struct hash_vec {
	const char *name;
	const char *key;      /* NUL-terminated string key */
	const char *key_hex;  /* or a hex key; exactly one of these is set */
	size_t      key_hex_len;
	const char *in;       /* NUL-terminated string input */
	const char *in_hex;   /* or a hex input */
	const char *want_v1;
	const char *want_v2;  /* NULL => upstream has no v2 vector for this one */
};

static const struct hash_vec vecs[] = {
	{ "1a", KEY0, NULL, 0, IN_A, NULL,
	  "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
	  "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f" },
	{ "1b", KEY0, NULL, 0, IN_B, NULL,
	  "300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
	  "9e2c772c12fd48f93c14c97fdc89d556264d9100597023f44d9163e279012ecf" },
	{ "1c", KEY0, NULL, 0, IN_C, NULL,
	  "c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8",
	  "4d6b063a1a603751d525f18a171336a4002f2f06df6c17e4b25fe17e17796e42" },
	{ "1d", KEY1, NULL, 0, IN_C, NULL,
	  "e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc",
	  "97024134686ce27d362ea8d86d8ef16483ac272abdabd46ef13359400777fe5e" },
	{ "1e", KEY1, NULL, 0, NULL, IN_E_HEX,
	  "c56414121acda1713c2f2a819d8ae38aed7c80c35c2a769298d34f03833cd5f1",
	  "c8e92c5f7c1946fecf06bc382b92e3111da38ee3e6a5ad90704e1a9d8aaf6e76" },
	/* ISUB_R edge case. Upstream runs this one in v1 mode only. */
	{ "1f (ISUB_R edge case)", NULL, KEY_F_HEX, KEY_F_LEN, NULL, IN_F_HEX,
	  "78af2a1864c42abce36d2e8983e13df99b2af0ce1362999af09fab004d4435a8",
	  NULL },
};
#define NVECS (sizeof(vecs) / sizeof(vecs[0]))

/* ------------------------------------------------------------------ driver */

/* Scratch big enough for the longest hex input above. */
static uint8_t inbuf[128];
static uint8_t keybuf[64];

static const void *vec_key(const struct hash_vec *v, size_t *len)
{
	if (v->key) {
		*len = strlen(v->key);
		return v->key;
	}
	*len = v->key_hex_len;
	hex2bin(v->key_hex, keybuf, *len);
	return keybuf;
}

static const void *vec_input(const struct hash_vec *v, size_t *len)
{
	if (v->in) {
		*len = strlen(v->in);
		return v->in;
	}
	*len = strlen(v->in_hex) / 2;
	hex2bin(v->in_hex, inbuf, *len);
	return inbuf;
}

/* Runs every vector through one (cache, vm) pair. `cache_key` tracks the key
 * the cache currently holds so we only re-init when the vector changes it --
 * cache init is the expensive part (argon2 over 256 MiB).
 */
static void run_vectors(const char *label, randomx_flags vmflags,
                        randomx_cache *cache, randomx_dataset *dataset,
                        int v2)
{
	randomx_vm *vm;
	const char *cur_key = NULL;
	size_t i;

	vm = randomx_create_vm(vmflags, cache, dataset);
	if (!vm) {
		printf("  SKIP  %s: randomx_create_vm returned NULL\n", label);
		skipped++;
		return;
	}

	for (i = 0; i < NVECS; i++) {
		const struct hash_vec *v = &vecs[i];
		const char *want = v2 ? v->want_v2 : v->want_v1;
		char name[128];
		uint8_t hash[RANDOMX_HASH_SIZE];
		const void *key, *in;
		size_t keylen, inlen;
		const char *key_id;

		if (!want)
			continue;   /* upstream has no vector for this mode */

		key_id = v->key ? v->key : v->key_hex;

		/* In fast mode the dataset was expanded from one cache key, and
		 * re-keying would mean rebuilding all of it. Restrict to the
		 * vectors using the key the dataset was built from. */
		if (dataset != NULL && strcmp(key_id, KEY0) != 0)
			continue;

		key = vec_key(v, &keylen);
		if (cur_key == NULL || strcmp(cur_key, key_id) != 0) {
			randomx_init_cache(cache, key, keylen);
			cur_key = key_id;
			/* The VM caches a pointer into the cache/dataset; re-point it
			 * so it picks up the new SuperscalarHash programs. */
			if (dataset == NULL)
				randomx_vm_set_cache(vm, cache);
		}

		in = vec_input(v, &inlen);
		randomx_calculate_hash(vm, in, inlen, hash);
		snprintf(name, sizeof(name), "%s hash %s", label, v->name);
		check_hash(name, hash, want);
	}

	randomx_destroy_vm(vm);
}

static void run_batch(const char *label, randomx_flags vmflags,
                      randomx_cache *cache, randomx_dataset *dataset,
                      int v2)
{
	/* The batched API overlaps hash N's finalisation with hash N+1's start;
	 * it is the path scanhash will use, so a wrong digest here and a right
	 * one in run_vectors() is exactly the bug worth catching. */
	static const char *want_v1[3] = {
		"639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f",
		"300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969",
		"c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"
	};
	static const char *want_v2[3] = {
		"22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f",
		"9e2c772c12fd48f93c14c97fdc89d556264d9100597023f44d9163e279012ecf",
		"4d6b063a1a603751d525f18a171336a4002f2f06df6c17e4b25fe17e17796e42"
	};
	const char **want = v2 ? want_v2 : want_v1;
	uint8_t h1[RANDOMX_HASH_SIZE], h2[RANDOMX_HASH_SIZE], h3[RANDOMX_HASH_SIZE];
	char name[128];
	randomx_vm *vm;

	randomx_init_cache(cache, KEY0, strlen(KEY0));

	vm = randomx_create_vm(vmflags, cache, dataset);
	if (!vm) {
		printf("  SKIP  %s batch: randomx_create_vm returned NULL\n", label);
		skipped++;
		return;
	}

	randomx_calculate_hash_first(vm, IN_A, strlen(IN_A));
	randomx_calculate_hash_next(vm, IN_B, strlen(IN_B), h1);
	randomx_calculate_hash_next(vm, IN_C, strlen(IN_C), h2);
	randomx_calculate_hash_last(vm, h3);

	snprintf(name, sizeof(name), "%s batch 1/3", label);
	check_hash(name, h1, want[0]);
	snprintf(name, sizeof(name), "%s batch 2/3", label);
	check_hash(name, h2, want[1]);
	snprintf(name, sizeof(name), "%s batch 3/3", label);
	check_hash(name, h3, want[2]);

	randomx_destroy_vm(vm);
}

static void run_commitment(randomx_cache *cache)
{
	/* rx/2 submits a commitment, not the raw hash. Not needed for rx/0, but
	 * free to pin now and it keeps the v2 path covered. */
	uint8_t hash[RANDOMX_HASH_SIZE], com[RANDOMX_HASH_SIZE];
	randomx_vm *vm;

	randomx_init_cache(cache, KEY0, strlen(KEY0));
	vm = randomx_create_vm(RANDOMX_FLAG_V2, cache, NULL);
	if (!vm) {
		printf("  SKIP  commitment: randomx_create_vm returned NULL\n");
		skipped++;
		return;
	}
	randomx_calculate_hash(vm, IN_A, strlen(IN_A), hash);
	randomx_calculate_commitment(IN_A, strlen(IN_A), hash, com);
	check_hash("commitment (v2, key 000, \"This is a test\")", com,
	           "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18");
	randomx_destroy_vm(vm);
}

/* ------------------------------------------------- rx/sfx real-share vector */

/* Reconstructed from a share a live Safex pool accepted. A Monero-dialect
 * submit carries the job blob, the nonce and the resulting digest, so an
 * accepted share is a complete vector: cache key is the job's seed_hash,
 * input is the blob with that nonce written at byte 39, expected output is
 * the digest the pool credited.
 *
 * Upstream publishes vectors for rx/0 and v2 only, so this is the only ground
 * truth that exists for a variant. rx/sfx is tier 1 and therefore runs on the
 * stock core, which is why its vector can live here; a tier-2 variant must be
 * hashed by its own core and its vectors live in randomx-variant.c.
 */
static const char SFX_SEED[] =
	"906f3490027d8cec7561c5683a6ea0ff2972661e7b5babcb3648a1ec49c0a62a";
static const char SFX_BLOB[] =
	"0707e289ead40678d3c7ca25309983e9b193477151797095a160130bcec824fc2"
	"0513364a94038e40300e0d84d0b0cca950a183398da4fa7526b5088eaa96c58f2"
	"5b19fadfe2b239d5247101";
static const char SFX_WANT[] =
	"b7c2975ebf2238b6c29737c82d0d4ef0da0d64e75a7b7903da2d931474180000";

/* Set in randomx/dataset.cpp. */
extern const unsigned char *randomx_argon_salt;
extern unsigned int         randomx_argon_salt_len;

bool rx_kat_sfx_vector(void)
{
	static const unsigned char salt[] = "RandomSFX\x01";
	const unsigned char *saved_salt = randomx_argon_salt;
	unsigned int         saved_len  = randomx_argon_salt_len;
	randomx_flags rt, cacheflags;
	randomx_cache *cache;
	randomx_vm *vm;
	uint8_t seed[32], blob[76], hash[RANDOMX_HASH_SIZE];
	int before = failures;

	/* Guard the vector literals themselves. SFX_BLOB is written as three
	 * concatenated string pieces, so a miscount there would silently shift
	 * the input; this file's local hex2bin() returns void and cannot report
	 * it. Note that helper takes (hex, out, len) -- the reverse of miner.h's
	 * hex2bin(), which is not linked into the standalone KAT binary. */
	if (strlen(SFX_SEED) != 64 || strlen(SFX_BLOB) != 152 ||
	    strlen(SFX_WANT) != 64) {
		printf("  FAIL  rx/sfx vector: literal is the wrong length "
		       "(seed %zu/64, blob %zu/152, want %zu/64)\n",
		       strlen(SFX_SEED), strlen(SFX_BLOB), strlen(SFX_WANT));
		failures++; ran++;
		return false;
	}
	hex2bin(SFX_SEED, seed, 32);
	hex2bin(SFX_BLOB, blob, 76);

	/* Self-contained: works whether or not the caller already selected the
	 * variant, and leaves the salt as it found it. */
	randomx_argon_salt     = salt;
	randomx_argon_salt_len = (unsigned)(sizeof salt - 1);

	rt = randomx_get_flags();
	cacheflags = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);
	cache = randomx_alloc_cache(cacheflags);
	if (!cache) {
		printf("  SKIP  rx/sfx vector: cache allocation failed\n");
		skipped++;
		goto restore;
	}
	randomx_init_cache(cache, seed, 32);

	/* Light mode: the pool credited this digest from a full-dataset miner, so
	 * matching it in light mode also proves the two modes agree here. */
	vm = randomx_create_vm(rt & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2),
	                       cache, NULL);
	if (!vm) {
		printf("  SKIP  rx/sfx vector: randomx_create_vm returned NULL\n");
		skipped++;
	} else {
		randomx_calculate_hash(vm, blob, sizeof blob, hash);
		check_hash("rx/sfx accepted-share vector (Safex, real block)",
		           hash, SFX_WANT);
		randomx_destroy_vm(vm);
	}
	randomx_release_cache(cache);

restore:
	randomx_argon_salt     = saved_salt;
	randomx_argon_salt_len = saved_len;
	return failures == before;
}

/* Nonce-sequence differential: one-shot vs batched over a run of nonces, in a
 * 76-byte blob with the nonce at byte 39 as scanhash writes it.
 *
 * The batch vectors above prove the batched primitive is correct. They cannot
 * catch what goes wrong in a driver: randomx_calculate_hash_next() emits the
 * digest of the PREVIOUS input, so a loop can pair digest N with nonce N+1 and
 * emit valid hashes against the wrong nonces -- invisible to any single-digest
 * test, and visible only as pool rejects.
 *
 * This pins that pairing rule. It is a separate expression of it rather than
 * the shipped loop (which needs a struct work and the miner's globals), so
 * scanhash also re-derives every winning nonce one-shot before submitting. */
static void run_nonce_sequence(randomx_cache *cache, randomx_flags vmflags,
                               const char *label)
{
	enum { NONCES = 6, BLOB = 76, NOFF = 39 };
	uint8_t blob[BLOB];
	uint8_t one[NONCES][RANDOMX_HASH_SIZE];
	uint8_t bat[NONCES][RANDOMX_HASH_SIZE];
	const uint32_t start = 0x7ffffffeu;   /* straddles a 32-bit carry */
	randomx_vm *vm;
	char name[128];
	int i, bad = 0;

	/* Any deterministic blob will do; not-all-zero so a dropped byte shows up.
	 * Bytes 39..42 are overwritten with the nonce. */
	for (i = 0; i < BLOB; i++)
		blob[i] = (uint8_t)(0x10 + i * 7);

	randomx_init_cache(cache, KEY0, strlen(KEY0));
	vm = randomx_create_vm(vmflags, cache, NULL);
	if (!vm) {
		printf("  SKIP  %s nonce-sequence: randomx_create_vm returned NULL\n",
		       label);
		skipped++;
		return;
	}

	/* one-shot */
	for (i = 0; i < NONCES; i++) {
		const uint32_t nn = start + (uint32_t)i;
		blob[NOFF+0] = (uint8_t)(nn      ); blob[NOFF+1] = (uint8_t)(nn >>  8);
		blob[NOFF+2] = (uint8_t)(nn >> 16); blob[NOFF+3] = (uint8_t)(nn >> 24);
		randomx_calculate_hash(vm, blob, BLOB, one[i]);
	}

	/* batched, attributing each digest to the nonce that is in flight */
	{
		uint32_t nn = start;
		int pending = 0;
		blob[NOFF+0] = (uint8_t)(nn      ); blob[NOFF+1] = (uint8_t)(nn >>  8);
		blob[NOFF+2] = (uint8_t)(nn >> 16); blob[NOFF+3] = (uint8_t)(nn >> 24);
		randomx_calculate_hash_first(vm, blob, BLOB);
		for (;;) {
			if (pending == NONCES - 1) {
				randomx_calculate_hash_last(vm, bat[pending]);
				break;
			}
			nn = start + (uint32_t)(pending + 1);
			blob[NOFF+0] = (uint8_t)(nn      ); blob[NOFF+1] = (uint8_t)(nn >>  8);
			blob[NOFF+2] = (uint8_t)(nn >> 16); blob[NOFF+3] = (uint8_t)(nn >> 24);
			randomx_calculate_hash_next(vm, blob, BLOB, bat[pending]);
			pending++;
		}
	}

	for (i = 0; i < NONCES; i++)
		if (memcmp(one[i], bat[i], RANDOMX_HASH_SIZE) != 0)
			bad++;

	ran++;
	snprintf(name, sizeof(name), "%s nonce-sequence one-shot == batched (%d nonces)",
	         label, NONCES);
	if (!bad) {
		printf("  PASS  %s\n", name);
	} else {
		printf("  FAIL  %s -- %d of %d digests differ\n", name, bad, NONCES);
		failures++;
	}

	/* Vacuity guard: the two paths must not agree merely because the nonce is
	 * not reaching the hash at all. */
	ran++;
	if (memcmp(one[0], one[1], RANDOMX_HASH_SIZE) != 0) {
		printf("  PASS  %s nonce-sequence is nonce-sensitive\n", label);
	} else {
		printf("  FAIL  %s nonce-sequence: nonce %08x and %08x hash the same "
		       "-- the differential above is vacuous\n",
		       label, start, start + 1);
		failures++;
	}

	randomx_destroy_vm(vm);
}

/* The argon2 cache fill on its own, pinned separately from any VM digest: a
 * wrong cache fails every hash vector identically and says nothing about where
 * the fault is. */
static void run_cache_init(randomx_cache *cache)
{
	const uint64_t *m;
	randomx_init_cache(cache, KEY0, strlen(KEY0));
	m = (const uint64_t *)randomx_get_cache_memory(cache);
	if (!m) {
		printf("  SKIP  cache init: randomx_get_cache_memory returned NULL\n");
		skipped++;
		return;
	}
	check_u64("cache init word 0",        m[0],        0x191e0e1d23c02186ULL);
	check_u64("cache init word 1568413",  m[1568413],  0xf1b62fe6210bf8b1ULL);
	check_u64("cache init word 33554431", m[33554431], 0x1f47f056d05cd99bULL);
}

/* ------------------------------------------------------------------- main */

static void print_build(randomx_flags rt)
{
	printf("librandomx build (reported from inside the library):\n");
	printf("  jit arch          : %s\n", randomx_build_jit_arch());
	printf("  simd tier         : %s\n", randomx_build_simd());
	printf("  compiled hard AES : %s\n", randomx_build_have_aes() ? "yes" : "no (soft AES only)");
	printf("  compiled JIT      : %s\n", randomx_build_have_compiler() ? "yes" : "no (interpreter only)");
	printf("  compiled argon2   : ref%s%s\n",
	       randomx_build_have_argon2_ssse3() ? " ssse3" : "",
	       randomx_build_have_argon2_avx2()  ? " avx2"  : "");
	printf("  randomx_get_flags : 0x%02x =", (unsigned)rt);
	if (rt & RANDOMX_FLAG_JIT)          printf(" JIT");
	if (rt & RANDOMX_FLAG_HARD_AES)     printf(" HARD_AES");
	if (rt & RANDOMX_FLAG_ARGON2_AVX2)  printf(" ARGON2_AVX2");
	if (rt & RANDOMX_FLAG_ARGON2_SSSE3) printf(" ARGON2_SSSE3");
	if (rt & RANDOMX_FLAG_SECURE)       printf(" SECURE");
	if (rt == RANDOMX_FLAG_DEFAULT)     printf(" DEFAULT");
	printf("\n\n");
}

/* The whole suite. Returns 0 on success, 1 on any failure (including a vacuous
 * run). `full` adds the 2336 MiB dataset path. Driven by randomx-kat-main.c
 * under `make check`. */
int rx_kat_full(int full)
{
	randomx_flags rt, cacheflags;
	randomx_cache *cache;

	failures = ran = skipped = 0;

	rt = randomx_get_flags();
	print_build(rt);

	/* Cache flags: JIT (for fast dataset init) plus whichever argon2 impl the
	 * CPU supports. Deliberately taken from randomx_get_flags() rather than
	 * hardcoded, so each ISA tier tests the path it will actually mine with. */
	cacheflags = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);
	cache = randomx_alloc_cache(cacheflags);
	if (!cache) {
		fprintf(stderr, "randomx_alloc_cache(0x%02x) failed\n", (unsigned)cacheflags);
		return 1;
	}

	printf("cache init (argon2 fill, 256 MiB):\n");
	run_cache_init(cache);

	printf("\nlight mode, interpreter:\n");
	run_vectors("interp v1", RANDOMX_FLAG_DEFAULT, cache, NULL, 0);
	run_vectors("interp v2", RANDOMX_FLAG_V2,      cache, NULL, 1);

	if (randomx_build_have_compiler()) {
		printf("\nlight mode, JIT:\n");
		run_vectors("jit v1", rt & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2),
		            cache, NULL, 0);
		run_vectors("jit v2", (rt & ~RANDOMX_FLAG_FULL_MEM) | RANDOMX_FLAG_V2,
		            cache, NULL, 1);
		printf("\nbatched API:\n");
		run_batch("jit v1", rt & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2),
		          cache, NULL, 0);
		run_batch("jit v2", (rt & ~RANDOMX_FLAG_FULL_MEM) | RANDOMX_FLAG_V2,
		          cache, NULL, 1);
	} else {
		printf("\nlight mode, JIT: SKIP (no JIT for %s)\n", randomx_build_jit_arch());
		skipped++;
	}

	printf("\nnonce-sequence differential (the batched driver's pairing rule):\n");
	run_nonce_sequence(cache, RANDOMX_FLAG_DEFAULT, "interp");
	if (randomx_build_have_compiler())
		run_nonce_sequence(cache, rt & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2),
		                   "jit");

	printf("\ncommitment:\n");
	run_commitment(cache);

	/* Variant coverage. Self-contained (sets and restores the salt), so it is
	 * safe here in the middle of the rx/0 run. */
	printf("\nvariants:\n");
	rx_kat_sfx_vector();

	if (full) {
		randomx_dataset *ds;
		unsigned long count;

		printf("\nfast mode (full 2080 MiB dataset):\n");
		ds = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
		if (!ds) {
			printf("  SKIP  dataset alloc failed (need ~2.4 GB free)\n");
			skipped++;
		} else {
			randomx_init_cache(cache, KEY0, strlen(KEY0));
			count = randomx_dataset_item_count();
			printf("  ...  initialising %lu dataset items single-threaded\n", count);
			randomx_init_dataset(ds, cache, 0, count);
			run_vectors("full v1", (rt | RANDOMX_FLAG_FULL_MEM) & ~RANDOMX_FLAG_V2,
			            cache, ds, 0);
			randomx_release_dataset(ds);
		}
	} else {
		printf("\nfast mode: not run (pass --full; needs ~2.4 GB and ~1 min)\n");
	}

	randomx_release_cache(cache);

	printf("\n%d checks, %d failed, %d skipped\n", ran, failures, skipped);
	if (failures)
		printf("RANDOMX KAT: FAIL\n");
	else if (!ran)
		printf("RANDOMX KAT: FAIL (nothing ran -- a vacuous pass is a fail)\n");
	else
		printf("RANDOMX KAT: PASS\n");
	return (failures || !ran) ? 1 : 0;
}

/* In-process A/B of the two scanhash drivers, fast mode.
 *
 * A live-pool hashrate swings ~20% run to run, which is far too noisy to
 * compare drivers. Timing both in one process against the same dataset removes
 * the pool, job churn, thread count and scheduler from the comparison.
 * Single-threaded on purpose: this measures the driver, not the box. */
int rx_kat_bench(int nonces)
{
	randomx_flags rt, cf;
	randomx_cache *cache;
	randomx_dataset *ds;
	randomx_vm *vm;
	uint8_t blob[76], hash[RANDOMX_HASH_SIZE];
	struct timespec t0, t1;
	double one_s, bat_s;
	unsigned long count;
	int i;

	if (nonces <= 0) nonces = 64;

	rt = randomx_get_flags();
	cf = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);

	cache = randomx_alloc_cache(cf | RANDOMX_FLAG_LARGE_PAGES);
	if (!cache) cache = randomx_alloc_cache(cf);
	if (!cache) { printf("bench: cache alloc failed\n"); return 1; }
	randomx_init_cache(cache, KEY0, strlen(KEY0));

	ds = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
	if (!ds) ds = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT);
	if (!ds) { printf("bench: dataset alloc failed (need ~2.1 GB)\n"); return 1; }

	count = randomx_dataset_item_count();
	printf("bench: building %lu dataset items...\n", count);
	randomx_init_dataset(ds, cache, 0, count);

	vm = randomx_create_vm((rt | RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_LARGE_PAGES)
	                       & ~RANDOMX_FLAG_V2, cache, ds);
	if (!vm)
		vm = randomx_create_vm((rt | RANDOMX_FLAG_FULL_MEM) & ~RANDOMX_FLAG_V2,
		                       cache, ds);
	if (!vm) { printf("bench: vm create failed\n"); return 1; }

	for (i = 0; i < 76; i++) blob[i] = (uint8_t)(0x10 + i * 7);

	/* warm up: first touches of a fresh 2 GB dataset are page faults */
	for (i = 0; i < 8; i++) {
		blob[39] = (uint8_t)i;
		randomx_calculate_hash(vm, blob, sizeof blob, hash);
	}

#define RX_NOW(t) clock_gettime(CLOCK_MONOTONIC, &(t))
#define RX_EL(a,b) ((double)((b).tv_sec-(a).tv_sec) + \
                    1e-9*(double)((b).tv_nsec-(a).tv_nsec))

	/* ABBA within the process, reporting the MINIMUM of each arm. Running one
	 * arm always first attributes whatever else the box is doing during the
	 * second half to that arm; order-swapping removes it. The minimum is the
	 * right statistic because interference only ever makes a run slower. */
	one_s = bat_s = 1e30;
	for (i = 0; i < 2; i++) {
		int rep;
		double t;

		for (rep = 0; rep < 2; rep++) {
			int j;
			const int one_first = (rep == i);   /* A B / B A */

			if (one_first) {
				/* one-shot: getFinalResult + initScratchpad = two passes
				 * over the 2 MiB scratchpad per hash */
				RX_NOW(t0);
				for (j = 0; j < nonces; j++) {
					blob[39] = (uint8_t)(j      ); blob[40] = (uint8_t)(j >> 8);
					blob[41] = (uint8_t)(j >> 16); blob[42] = (uint8_t)(j >> 24);
					randomx_calculate_hash(vm, blob, sizeof blob, hash);
				}
				RX_NOW(t1);
				t = RX_EL(t0, t1);
				if (t < one_s) one_s = t;
			} else {
				/* batched: hashAndFill finalises N while filling for N+1 */
				RX_NOW(t0);
				blob[39] = 0; blob[40] = 0; blob[41] = 0; blob[42] = 0;
				randomx_calculate_hash_first(vm, blob, sizeof blob);
				for (j = 1; j < nonces; j++) {
					blob[39] = (uint8_t)(j      ); blob[40] = (uint8_t)(j >> 8);
					blob[41] = (uint8_t)(j >> 16); blob[42] = (uint8_t)(j >> 24);
					randomx_calculate_hash_next(vm, blob, sizeof blob, hash);
				}
				randomx_calculate_hash_last(vm, hash);
				RX_NOW(t1);
				t = RX_EL(t0, t1);
				if (t < bat_s) bat_s = t;
			}
		}
	}

#undef RX_NOW
#undef RX_EL

	printf("\nbench (%d nonces x 2 each, ABBA, best of 2, 1 thread, fast mode, "
	       "%s):\n", nonces,
	       (rt & RANDOMX_FLAG_HARD_AES) ? "hard AES" : "soft AES");
	printf("  one-shot : %8.3f s  %8.2f h/s\n", one_s, (double)nonces / one_s);
	printf("  batched  : %8.3f s  %8.2f h/s\n", bat_s, (double)nonces / bat_s);
	printf("  batched / one-shot = %.4f  (>1 means batched is faster)\n",
	       one_s / bat_s);

	randomx_destroy_vm(vm);
	randomx_release_dataset(ds);
	randomx_release_cache(cache);
	return 0;
}

/* ------------------------------------------------- multi-threaded sweep */

/* Thread-count sweep against a real dataset, all in one process.
 *
 * `--benchmark` cannot work for randomx (no job, so scanhash returns early) and
 * a live-pool hashrate is far too noisy to compare thread counts. Here the
 * dataset is built once, every point runs the shipping batched driver against
 * it, and only the thread count varies.
 *
 * Each thread gets its own VM (hence its own scratchpad) and nonce range, as
 * the miner does. It does NOT model stratum, job churn, the reseed standoff or
 * cpuminer's affinity, so the winner is a hint to confirm on a pool. */
struct sweep_thr {
	pthread_t      tid;
	randomx_vm    *vm;
	uint32_t       base;
	int            nonces;
	volatile int  *go;
};

static void *sweep_worker(void *arg)
{
	struct sweep_thr *t = (struct sweep_thr *)arg;
	uint8_t blob[76], hash[RANDOMX_HASH_SIZE];
	uint32_t nn;
	int i;

	for (i = 0; i < 76; i++) blob[i] = (uint8_t)(0x10 + i * 7);

	/* spin until released, so the timed region is the parallel phase and not
	 * thread creation */
	while (!*t->go) { }

	nn = t->base;
	blob[39] = (uint8_t)(nn      ); blob[40] = (uint8_t)(nn >>  8);
	blob[41] = (uint8_t)(nn >> 16); blob[42] = (uint8_t)(nn >> 24);
	randomx_calculate_hash_first(t->vm, blob, sizeof blob);
	for (i = 1; i < t->nonces; i++) {
		nn = t->base + (uint32_t)i;
		blob[39] = (uint8_t)(nn      ); blob[40] = (uint8_t)(nn >>  8);
		blob[41] = (uint8_t)(nn >> 16); blob[42] = (uint8_t)(nn >> 24);
		randomx_calculate_hash_next(t->vm, blob, sizeof blob, hash);
	}
	randomx_calculate_hash_last(t->vm, hash);
	return NULL;
}

/* One timed point. Returns the elapsed seconds, or 0 on failure. `lp_vm`
 * receives how many scratchpads got large pages. */
static double sweep_one(randomx_flags vmf, randomx_cache *cache,
                        randomx_dataset *ds, int T, int nonces, int *lp_vm)
{
	struct sweep_thr *th = (struct sweep_thr *)calloc((size_t)T, sizeof *th);
	volatile int go = 0;
	struct timespec t0, t1;
	double el = 0.;
	int i, made = 0, lp = 0, ok = 1;

	if (!th) return 0.;

	for (i = 0; i < T; i++) {
		th[i].vm = randomx_create_vm(vmf | RANDOMX_FLAG_LARGE_PAGES, cache, ds);
		if (th[i].vm) lp++;
		else          th[i].vm = randomx_create_vm(vmf, cache, ds);
		if (!th[i].vm) { ok = 0; break; }
		th[i].base   = (uint32_t)i * 0x01000000u;  /* disjoint, as miner slices */
		th[i].nonces = nonces;
		th[i].go     = &go;
	}

	if (ok) {
		for (i = 0; i < T; i++)
			if (pthread_create(&th[i].tid, NULL, sweep_worker, &th[i]) == 0)
				made++;
		clock_gettime(CLOCK_MONOTONIC, &t0);
		go = 1;
		for (i = 0; i < made; i++) pthread_join(th[i].tid, NULL);
		clock_gettime(CLOCK_MONOTONIC, &t1);
		if (made == T)
			el = (double)(t1.tv_sec - t0.tv_sec)
			   + 1e-9 * (double)(t1.tv_nsec - t0.tv_nsec);
	}

	for (i = 0; i < T; i++) if (th[i].vm) randomx_destroy_vm(th[i].vm);
	free(th);
	if (lp_vm) *lp_vm = lp;
	return el;
}

int rx_kat_sweep(int nonces, int maxthreads)
{
	static const int ladder[] = { 1, 2, 3, 4, 6, 8, 10, 12, 14, 16, 20, 24, 32 };
	enum { NLAD = (int)(sizeof ladder / sizeof ladder[0]) };
	double bestsec[NLAD];
	randomx_flags rt, cf, vmf;
	randomx_cache *cache;
	randomx_dataset *ds;
	unsigned long count;
	double best1 = 0.;
	int npoints = 0, li, lp_ok = 1, lp_vm = 0;

	if (nonces <= 0)     nonces = 250;
	if (maxthreads <= 0) maxthreads = 8;

	rt = randomx_get_flags();
	cf = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);

	cache = randomx_alloc_cache(cf | RANDOMX_FLAG_LARGE_PAGES);
	if (!cache) { cache = randomx_alloc_cache(cf); lp_ok = 0; }
	if (!cache) { printf("sweep: cache alloc failed\n"); return 1; }
	randomx_init_cache(cache, KEY0, strlen(KEY0));

	ds = randomx_alloc_dataset(RANDOMX_FLAG_LARGE_PAGES);
	if (!ds) { ds = randomx_alloc_dataset(RANDOMX_FLAG_DEFAULT); lp_ok = 0; }
	if (!ds) { printf("sweep: dataset alloc failed (need ~2.1 GB)\n"); return 1; }

	count = randomx_dataset_item_count();
	printf("sweep: building %lu dataset items (once)...\n", count);
	randomx_init_dataset(ds, cache, 0, count);

	vmf = (rt | RANDOMX_FLAG_FULL_MEM) & ~RANDOMX_FLAG_V2;

	while (npoints < NLAD && ladder[npoints] <= maxthreads) npoints++;
	if (!npoints) { printf("sweep: no ladder points <= %d\n", maxthreads);
	                goto done; }
	for (li = 0; li < NLAD; li++) bestsec[li] = 0.;

	printf("\nthread sweep: %d nonces/thread, fast mode, %s, %s\n", nonces,
	       (rt & RANDOMX_FLAG_HARD_AES) ? "hard AES" : "soft AES",
	       lp_ok ? "large pages" : "NORMAL PAGES (results will understate)");

	/* Warm-up, then walk the ladder UP and back DOWN, keeping the best time per
	 * point.
	 *
	 * A single ascending pass is wrong on anything that scales frequency with
	 * load: the low-thread points run first on a cool, un-ramped CPU and the
	 * high-thread points last on a hot one, which can manufacture apparent
	 * superlinear scaling. On x86 the same bias runs the other way, as thermal
	 * throttling penalises the later, higher-thread points. */
	printf("  warming up at %d threads...\n", maxthreads);
	(void)sweep_one(vmf, cache, ds, maxthreads, nonces, &lp_vm);
	if (lp_vm != maxthreads)
		printf("  warning: only %d/%d scratchpads on large pages -- raise "
		       "vm.nr_hugepages\n", lp_vm, maxthreads);

	for (li = 0; li < 2 * npoints; li++) {
		const int idx = (li < npoints) ? li : (2 * npoints - 1 - li);
		const double el = sweep_one(vmf, cache, ds, ladder[idx], nonces, NULL);
		if (el > 0. && (bestsec[idx] == 0. || el < bestsec[idx]))
			bestsec[idx] = el;
	}

	printf("  thr    h/s     h/s/thr   vs 1thr   scaling\n");
	for (li = 0; li < npoints; li++) {
		const int T = ladder[li];
		double hs;
		if (bestsec[li] <= 0.) { printf("  %3d    (failed)\n", T); continue; }
		hs = (double)T * (double)nonces / bestsec[li];
		if (T == 1) best1 = hs;
		printf("  %3d  %8.2f  %8.2f   %6.2fx   %5.0f%%\n", T, hs, hs / T,
		       best1 > 0. ? hs / best1 : 0.,
		       best1 > 0. ? 100. * (hs / best1) / (double)T : 0.);
	}

done:
	randomx_release_dataset(ds);
	randomx_release_cache(cache);
	return 0;
}

/* The startup self-test the algo gate runs before it will mine.
 *
 * Deliberately a subset: one interpreter vector, one JIT vector and the three
 * argon2 cache words. That covers argon2, blake2b, superscalar and both VM
 * paths -- enough to catch a vendored core broken on this arch or toolchain --
 * for the cost of one cache init rather than the whole suite.
 *
 * Not a substitute for `make check`, and it validates only the hash: the
 * stratum wiring is proven by an accepted share and nothing else. */
bool rx_kat_selftest(void)
{
	randomx_flags rt, cacheflags;
	randomx_cache *cache;
	randomx_vm *vm;
	const uint64_t *m;
	uint8_t hash[RANDOMX_HASH_SIZE];
	int local_fail = 0;

	failures = ran = skipped = 0;

	rt = randomx_get_flags();
	cacheflags = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);
	cache = randomx_alloc_cache(cacheflags);
	if (!cache) {
		printf("RandomX self-test: cache allocation failed\n");
		return false;
	}

	randomx_init_cache(cache, KEY0, strlen(KEY0));

	/* argon2 cache fill */
	m = (const uint64_t *)randomx_get_cache_memory(cache);
	if (!m || m[0] != 0x191e0e1d23c02186ULL
	       || m[1568413] != 0xf1b62fe6210bf8b1ULL
	       || m[33554431] != 0x1f47f056d05cd99bULL) {
		printf("RandomX self-test: argon2 cache fill mismatch\n");
		local_fail++;
	}

	/* interpreter */
	vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, NULL);
	if (!vm) {
		printf("RandomX self-test: could not create an interpreter VM\n");
		local_fail++;
	} else {
		randomx_calculate_hash(vm, IN_A, strlen(IN_A), hash);
		check_hash("self-test interpreter", hash, vecs[0].want_v1);
		randomx_destroy_vm(vm);
	}

	/* JIT, if this build has one */
	if (randomx_build_have_compiler()) {
		vm = randomx_create_vm(rt & ~(RANDOMX_FLAG_FULL_MEM | RANDOMX_FLAG_V2),
		                       cache, NULL);
		if (!vm) {
			/* Not fatal: rx_vm_get falls back to the interpreter. */
			printf("RandomX self-test: JIT VM unavailable, "
			       "will fall back to the interpreter\n");
			skipped++;
		} else {
			randomx_calculate_hash(vm, IN_A, strlen(IN_A), hash);
			check_hash("self-test JIT", hash, vecs[0].want_v1);
			randomx_destroy_vm(vm);
		}
	}

	randomx_release_cache(cache);

	return (failures + local_fail) == 0 && ran > 0;
}

/* Proves the selected variant is not silently still hashing as rx/0.
 *
 * Hashes rx/0's own key and input under whatever argon salt is currently in
 * force and requires the digest to DIFFER from rx/0's published one. That is
 * a weak check in the sense that it cannot confirm the digest is *correct* --
 * no variant has a published vector -- but it is the strongest thing
 * available offline, and it catches the failure that matters: a variant whose
 * salt never reached the core. Correctness itself is closed by the pool.
 */
bool rx_kat_variant_differs(void)
{
	randomx_flags rt, cacheflags;
	randomx_cache *cache;
	randomx_vm *vm;
	uint8_t hash[RANDOMX_HASH_SIZE];
	bool differs;

	rt = randomx_get_flags();
	cacheflags = rt & (RANDOMX_FLAG_JIT | RANDOMX_FLAG_ARGON2);
	cache = randomx_alloc_cache(cacheflags);
	if (!cache) {
		printf("RandomX variant check: cache allocation failed\n");
		return false;
	}

	randomx_init_cache(cache, KEY0, strlen(KEY0));

	vm = randomx_create_vm(RANDOMX_FLAG_DEFAULT, cache, NULL);
	if (!vm) {
		printf("RandomX variant check: could not create a VM\n");
		randomx_release_cache(cache);
		return false;
	}

	randomx_calculate_hash(vm, IN_A, strlen(IN_A), hash);
	differs = memcmp(hash, vecs[0].want_v1, RANDOMX_HASH_SIZE) != 0;

	randomx_destroy_vm(vm);
	randomx_release_cache(cache);

	printf("  %s  variant salt changes the digest vs rx/0\n",
	       differs ? "PASS" : "FAIL");
	return differs;
}
