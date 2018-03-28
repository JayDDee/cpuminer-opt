#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

#include "blake2/blake2.h"
#include "blake2/blake2-impl.h"

#if defined(_MSC_VER)
// i know there is a trick but nvm :p
#define PRIu64 "%llu"
#define PRIx64 "%llx"
#endif

static const uint64_t blake2b_IV[8] = {
	UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
	UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
	UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
	UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)
};

static const unsigned int blake2b_sigma[12][16] = {
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static BLAKE2_INLINE void blake2b_set_lastnode(blake2b_state *S) {
	S->f[1] = (uint64_t)-1;
}

static BLAKE2_INLINE void blake2b_set_lastblock(blake2b_state *S) {
	if (S->last_node) {
		blake2b_set_lastnode(S);
	}
	S->f[0] = (uint64_t)-1;
}

static BLAKE2_INLINE void blake2b_increment_counter(blake2b_state *S, uint64_t inc) {
	S->t[0] += inc;
	S->t[1] += (S->t[0] < inc);
}

static BLAKE2_INLINE void blake2b_invalidate_state(blake2b_state *S) {
	burn(S, sizeof(*S));      /* wipe */
	blake2b_set_lastblock(S); /* invalidate for further use */
}

static BLAKE2_INLINE void blake2b_init0(blake2b_state *S) {
	memset(S, 0, sizeof(*S));
	memcpy(S->h, blake2b_IV, sizeof(S->h));
}

/*
void print_state(blake2b_state BlakeHash)
{
	printf(".h = {UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 "),\n"
				"UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 "),\n"
				"UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 "),\n"
				"UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 ")},\n"
		".t = {UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 ")},\n"
		".f = {UINT64_C(%" PRIu64 "), UINT64_C(%" PRIu64 ")}\n",
		BlakeHash.h[0], BlakeHash.h[1], BlakeHash.h[2], BlakeHash.h[3],
		BlakeHash.h[4], BlakeHash.h[5], BlakeHash.h[6], BlakeHash.h[7],
		BlakeHash.t[0], BlakeHash.t[1],
		BlakeHash.f[0], BlakeHash.f[1]);
	printf(".buf = {");
	for (register uint8_t i = 0; i < BLAKE2B_BLOCKBYTES; i++)
		printf("%" PRIu8 ", ", BlakeHash.buf[i]);
	puts("\n");
	printf("}\n.buflen = %d\n.outlen = %d\n",
		  BlakeHash.buflen, BlakeHash.outlen);
	printf(".last_node = %" PRIu8 "\n", BlakeHash.last_node);
	fflush(stdout);
}
*/

static const blake2b_state miou = {
	.h = {
		UINT64_C(7640891576939301128), UINT64_C(13503953896175478587),
		UINT64_C(4354685564936845355), UINT64_C(11912009170470909681),
		UINT64_C(5840696475078001361), UINT64_C(11170449401992604703),
		UINT64_C(2270897969802886507), UINT64_C(6620516959819538809)
	},
	.t = {UINT64_C(0), UINT64_C(0)},
	.f = {UINT64_C(0), UINT64_C(0)},
	.buf = {
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	},
	.buflen = 0,
	.outlen = 64,
	.last_node = 0
};


int ar2_blake2b_init_param(blake2b_state *S, const blake2b_param *P)
{
	const unsigned char *p = (const unsigned char *)P;
	unsigned int i;

	if (NULL == P || NULL == S) {
		return -1;
	}

	blake2b_init0(S);
	/* IV XOR Parameter Block */
	for (i = 0; i < 8; ++i) {
		S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
	}
	S->outlen = P->digest_length;
	return 0;
}

void compare_buffs(uint64_t *h, size_t outlen)
{
	// printf("CMP : %d", memcmp(h, miou.h, 8*(sizeof(uint64_t))));
	printf("miou : %" PRIu64 " - h : %" PRIu64 " - outlen : %ld\n", miou.h[0], h[0], outlen);
	fflush(stdout);
}

/* Sequential blake2b initialization */
int ar2_blake2b_init(blake2b_state *S, size_t outlen)
{
	memcpy(S, &miou, sizeof(*S));
	S->h[0] += outlen;
	return 0;
}

void print64(const char *name, const uint64_t *array, uint16_t size)
{
	printf("%s = {", name);
	for (uint8_t i = 0; i < size; i++) printf("UINT64_C(%" PRIu64 "), ", array[i]);
	printf("};\n");
}

int ar2_blake2b_init_key(blake2b_state *S, size_t outlen, const void *key, size_t keylen)
{
	return 0;
}

static void blake2b_compress(blake2b_state *S, const uint8_t *block)
{
	uint64_t m[16];
	uint64_t v[16];
	unsigned int i, r;

	for (i = 0; i < 16; ++i) {
		m[i] = load64(block + i * 8);
	}

	for (i = 0; i < 8; ++i) {
		v[i] = S->h[i];
	}

	v[8] = blake2b_IV[0];
	v[9] = blake2b_IV[1];
	v[10] = blake2b_IV[2];
	v[11] = blake2b_IV[3];
	v[12] = blake2b_IV[4] ^ S->t[0];
	v[13] = blake2b_IV[5]/* ^ S->t[1]*/;
	v[14] = blake2b_IV[6] ^ S->f[0];
	v[15] = blake2b_IV[7]/* ^ S->f[1]*/;

#define G(r, i, a, b, c, d)                                                    \
	do {                                                                       \
		a = a + b + m[blake2b_sigma[r][2 * i + 0]];                            \
		d = rotr64(d ^ a, 32);                                                 \
		c = c + d;                                                             \
		b = rotr64(b ^ c, 24);                                                 \
		a = a + b + m[blake2b_sigma[r][2 * i + 1]];                            \
		d = rotr64(d ^ a, 16);                                                 \
		c = c + d;                                                             \
		b = rotr64(b ^ c, 63);                                                 \
	} while ((void)0, 0)

#define ROUND(r)                                                               \
	do {                                                                       \
		G(r, 0, v[0], v[4], v[8], v[12]);                                      \
		G(r, 1, v[1], v[5], v[9], v[13]);                                      \
		G(r, 2, v[2], v[6], v[10], v[14]);                                     \
		G(r, 3, v[3], v[7], v[11], v[15]);                                     \
		G(r, 4, v[0], v[5], v[10], v[15]);                                     \
		G(r, 5, v[1], v[6], v[11], v[12]);                                     \
		G(r, 6, v[2], v[7], v[8], v[13]);                                      \
		G(r, 7, v[3], v[4], v[9], v[14]);                                      \
	} while ((void)0, 0)

	for (r = 0; r < 12; ++r) ROUND(r);

	for (i = 0; i < 8; ++i) S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];

#undef G
#undef ROUND
}

int ar2_blake2b_update(blake2b_state *S, const void *in, size_t inlen)
{
	const uint8_t *pin = (const uint8_t *)in;
	/* Complete current block */
	memcpy(&S->buf[4], pin, 124);
	blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
	blake2b_compress(S, S->buf);
	S->buflen = 0;
	pin += 124;

	register int8_t i = 7;
	/* Avoid buffer copies when possible */
	while (i--) {
	  blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
	  blake2b_compress(S, pin);
	  pin += BLAKE2B_BLOCKBYTES;
	}
	memcpy(&S->buf[S->buflen], pin, 4);
	S->buflen += 4;
	return 0;
}

void my_blake2b_update(blake2b_state *S, const void *in, size_t inlen)
{
	memcpy(&S->buf[S->buflen], in, inlen);
	S->buflen += (unsigned int)inlen;
}

int ar2_blake2b_final(blake2b_state *S, void *out, size_t outlen)
{
	uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
	unsigned int i;

	blake2b_increment_counter(S, S->buflen);
	blake2b_set_lastblock(S);
	memset(&S->buf[S->buflen], 0, BLAKE2B_BLOCKBYTES - S->buflen); /* Padding */
	blake2b_compress(S, S->buf);

	for (i = 0; i < 8; ++i) { /* Output full hash to temp buffer */
		store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
	}

	memcpy(out, buffer, S->outlen);

	burn(buffer, sizeof(buffer));
	burn(S->buf, sizeof(S->buf));
	burn(S->h, sizeof(S->h));
	return 0;
}

int ar2_blake2b(void *out, const void *in, const void *key, size_t keylen)
{
	blake2b_state S;

	ar2_blake2b_init(&S, 64);
	my_blake2b_update(&S, in, 64);
	ar2_blake2b_final(&S, out, 64);
	burn(&S, sizeof(S));
	return 0;
}

void ar2_blake2b_too(void *pout, const void *in)
{
	uint8_t *out = (uint8_t *)pout;
	uint8_t out_buffer[64];
	uint8_t in_buffer[64];

	blake2b_state blake_state;
	ar2_blake2b_init(&blake_state, 64);
	blake_state.buflen = blake_state.buf[1] = 4;
	my_blake2b_update(&blake_state, in, 72);
	ar2_blake2b_final(&blake_state, out_buffer, 64);
	memcpy(out, out_buffer, 32);
	out += 32;

	register uint8_t i = 29;
	while (i--) {
		memcpy(in_buffer, out_buffer, 64);
		ar2_blake2b(out_buffer, in_buffer, NULL, 0);
		memcpy(out, out_buffer, 32);
		out += 32;
	}

	memcpy(in_buffer, out_buffer, 64);
	ar2_blake2b(out_buffer, in_buffer, NULL, 0);
	memcpy(out, out_buffer, 64);

	burn(&blake_state, sizeof(blake_state));
}

/* Argon2 Team - Begin Code */
int ar2_blake2b_long(void *pout, const void *in)
{
	uint8_t *out = (uint8_t *)pout;
	blake2b_state blake_state;
	uint8_t outlen_bytes[sizeof(uint32_t)] = {0};

	store32(outlen_bytes, 32);

	ar2_blake2b_init(&blake_state, 32);
	my_blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes));
	ar2_blake2b_update(&blake_state, in, 1024);
	ar2_blake2b_final(&blake_state, out, 32);
	burn(&blake_state, sizeof(blake_state));
	return 0;
}
/* Argon2 Team - End Code */
