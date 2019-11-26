///////////////////////////////////////////////////////////////////////////////////////////////
//
//  SWIFFTX ANSI C OPTIMIZED 32BIT IMPLEMENTATION FOR NIST SHA-3 COMPETITION
//
//  SWIFFTX.h
//
//  October 2008
//
//	This file is the exact copy from the reference implementation.
//
///////////////////////////////////////////////////////////////////////////////////////////////
#ifndef __SWIFFTX__
#define __SWIFFTX__

#ifdef __cplusplus
extern "C"{
#endif

// See the remarks concerning compatibility issues inside stdint.h.
//#include <stdint.h>
#include <stdbool.h>
#include "stdint.h"
//#include "stdbool.h"
//#include "SHA3swift.h"

// The size of SWIFFTX input in bytes.
#define SWIFFTX_INPUT_BLOCK_SIZE 256

// The size of output block in bytes. The compression function of SWIFFT outputs a block of
// this size (i.e., this is the size of the resulting hash value).
#define SWIFFTX_OUTPUT_BLOCK_SIZE 65

// Computes the result of a single SWIFFT operation.
// This is the simple implementation, where our main concern is to show our design principles.
// It is made more efficient in the optimized version, by using FFT instead of DFT, and
// through other speed-up techniques.
//
// Parameters:
// - input: the input string. Consists of 8*m input bytes, where each octet passes the DFT
//   processing.
// - m: the length of the input in bytes.
// - output: the resulting hash value of SWIFFT, of size 65 bytes (520 bit). This is the
//	 result of summing the dot products of the DFTS with the A's after applying the base
//	 change transformation
// - A: the A's coefficients to work with (since every SWIFFT in SWIFFTX uses different As).
//   A single application of SWIFFT uses 64*m A's.
void ComputeSingleSWIFFT(unsigned char *input, unsigned short m,
					  	 unsigned char output[SWIFFTX_OUTPUT_BLOCK_SIZE],
						 const swift_int16_t *a);

// Computes the result of a single SWIFFTX operation.
// NOTE: for simplicity we use 'ComputeSingleSWIFFT()' as a subroutine. This is only to show
// the design idea. In the optimized versions we don't do this for efficiency concerns, since
// there we compute the first part (which doesn't involve the A coefficients) only once for all
// of the 3 invocations of SWIFFT. This enables us to introduce a significant speedup.
//
// Parameters:
// - input: the input input of 256 bytes (2048 bit).
// - output: the resulting hash value of SWIFFT, of size 64 bytes (512 bit).
// - doSMooth: if true, a final smoothing stage is performed and the output is of size 512 bits.
//
// Returns:
// - Success value.
void ComputeSingleSWIFFTX( unsigned char input[SWIFFTX_INPUT_BLOCK_SIZE],
                           unsigned char output[SWIFFTX_OUTPUT_BLOCK_SIZE] );

void ComputeSingleSWIFFTX_smooth( unsigned char input[SWIFFTX_INPUT_BLOCK_SIZE],
	            unsigned char output[SWIFFTX_OUTPUT_BLOCK_SIZE], bool doSmooth);

// Calculates the powers of OMEGA and generates the bit reversal permutation.
// You must call this function before doing SWIFFT/X, otherwise you will get zeroes everywhere.
void InitializeSWIFFTX();

#ifdef __cplusplus
}
#endif

#endif // __SWIFFTX__
