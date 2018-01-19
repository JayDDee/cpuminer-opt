#ifndef __NIST_H__
#define __NIST_H__

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGN(x) x __attribute__((aligned(16)))
#else
#define DATA_ALIGN(x) __declspec(align(16)) x
#endif

#include "simd-compat.h"
#include "algo/sha/sha3-defs.h"
/*
 * NIST API Specific types.
 */

typedef struct {
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;

#ifdef HAS_64
  u64 count;
#else
  u32 count_low;
  u32 count_high;
#endif

  DATA_ALIGN(u32 A[32]);
  u32 *B;
  u32 *C;
  u32 *D;
  DATA_ALIGN(unsigned char buffer[128]);
  
} hashState_sd;

/* 
 * NIST API
 */

static HashReturn init_sd(hashState_sd *state, int hashbitlen) {
  printf("use udefined init_sd\n");
}

static HashReturn update_sd(hashState_sd *state, const BitSequence *data, DataLength databitlen) {
  printf("use udefined upd_sd\n");
}

static HashReturn final_sd(hashState_sd *state, BitSequence *hashval) {
  printf("use udefined final_sd\n");
}

static HashReturn update_final_sd( hashState_sd *state, BitSequence *hashval,
                            const BitSequence *data, DataLength databitlen ) {
  printf("use udefined upd_final_sd\n");
}

//HashReturn Hash(int hashbitlen, const BitSequence *data, DataLength databitlen,
//                BitSequence *hashval);

/* 
 * Internal API
 */

int SupportedLength(int hashbitlen);
int RequiredAlignment(void);
void SIMD_Compress(hashState_sd * state, const unsigned char *M, int final);

void fft128_natural(fft_t *a, unsigned char *x);
void fft256_natural(fft_t *a, unsigned char *x);

#endif
