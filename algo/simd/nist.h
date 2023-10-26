#ifndef __NIST_H__
#define __NIST_H__

/*define data alignment for different C compilers*/
#if defined(__GNUC__)
#define DATA_ALIGN(x) x __attribute__((aligned(16)))
#else
#define DATA_ALIGN(x) __declspec(align(16)) x
#endif

#include "simd-compat.h"
#include "compat/sha3-defs.h"
/*
 * NIST API Specific types.
 */

typedef struct {
  unsigned int hashbitlen;
  unsigned int blocksize;
  unsigned int n_feistels;

#ifdef HAS_64
  uint64_t count;
#else
  uint32_t count_low;
  uint32_t count_high;
#endif

  DATA_ALIGN(uint32_t A[32]);
  uint32_t *B;
  uint32_t *C;
  uint32_t *D;
  DATA_ALIGN(unsigned char buffer[128]);
  
} hashState_sd;

/* 
 * NIST API
 */

int init_sd(hashState_sd *state, int hashbitlen);

int update_sd(hashState_sd *state, const BitSequence *data, DataLength databitlen);

int final_sd(hashState_sd *state, BitSequence *hashval);

int update_final_sd( hashState_sd *state, BitSequence *hashval,
                            const BitSequence *data, DataLength databitlen );

int simd_full( hashState_sd *state, BitSequence *hashval,
               const BitSequence *data, DataLength databitlen );

/* 
 * Internal API
 */

//int SupportedLength(int hashbitlen);
int RequiredAlignment(void);
void SIMD_Compress(hashState_sd * state, const unsigned char *M, int final);

void fft128_natural(fft_t *a, unsigned char *x);
void fft256_natural(fft_t *a, unsigned char *x);

#endif
