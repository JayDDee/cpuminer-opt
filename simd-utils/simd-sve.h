// Placeholder for now.
//
// This file will hold AArch64 SVE code, a replecement for NEON that uses vector length
// agnostic instructions. This means the same code can be used on CPUs with different
// SVE vector register lengths. This is not good for vectorized hashing.
// Optimum hash is sensitive to the vector register length with different code
// used for different register sizes. On X86_64 the vector length is tied to the CPU
// feature making it simple and efficient to handle different lengths although it
// results in multiple executables. Theoretically SVE could use a single executable for
// any vector length.
//
// With the SVE vector length only known at run time it resultis in run time overhead
// to test the vector length. Theoretically it could be tested at program loading and
// appropriate libraries loaded. However I don't know if this can be done and if so
// how to do it.
//
// SVE is not expected to be used for 128 bit vectors as it does not provide any
// advantages over NEON. However, it may be implemented for testing purposes
// because CPU with registers larger than 128 bits are currently very rare and very
// expensive server class CPUs.
//
// N-way parallel hashing could be the best use of SVE, usimg the same code for all 
// vector lengths with the only variable being the number of lanes. This will still
// require run time checking but should be lighter than substituting functions.

