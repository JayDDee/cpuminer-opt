// Placeholder for now.
//
// This file will hold AArch64 SVE code, a replecement for NEON that uses
// vector length agnostic instructions. This means the same code can be used
// on CPUs with different SVE vector register lengths. This is not good for
// vectorized hashing.
// Optimum hash is sensitive to the vector register length with different code
// used for different register sizes. On X86_64 the vector length is tied to
// the CPU feature making it simple and efficient to handle different lengths
// although it results in multiple executables. Theoretically SVE could use a
// single executable for any vector length.
//
// With the SVE vector length only known at run time it results in run time
// overhead to test the vector length. Theoretically it could be tested at
// program loading and appropriate libraries loaded. However I don't know if
// this can be done and if specified how to do it.
//
// SVE is not expected to be used for 128 bit vectors as it does not provide any
// advantages over NEON. However, it may be implemented for testing purposes
// because CPU with registers larger than 128 bits are currently very rare and
// very expensive server class CPUs.
//
// However, 128 bit vectors also need to be supported with 256 bit registers.
// This could be a challenge for un-predicated functions.
//
// N-way parallel hashing could be the best use of SVE, usimg the same code
// for all vector lengths with the only variable being the number of lanes.
// This will still require run time checking but should be lighter than
// substituting functions.

// Current approach is to hard code the length in these intrinsics and called
// by existing length specific code.
// define with sv_ prefix for generic use predicate provided by caller,
// use sv<size>_ with hard coded predicate.
// v<size>_ only if and when it's compatible with SSE & NEON

// Many instructions have no predicate operand, how is VVL handled?
// How does the CPU know how long the vector is and whether it spans
// multiple registers without the predicate?

// Also how does the predicate define the vector size? How to tell if inactive
// high lanes are part of the vector or beyond its range.
//
// Some intructions may have an implied predicate by other arguments. 
// TBL for example will only have shuffle indexes for active lanes.
// However this is dependant on software being aware of register size.


 
#if 0
// #if defined USE_SV128
// NEON needs to be disabled

#define PRED128 0xffff
#define PRED256 0xffffffff

// Types should be transparent


#define sv128u32_t  svuint32_t
#define sv256u32_t  svuint32_t


// load1


// arithmetic

// _z zero inactive elements, _x undefined inactive elements, _m inactive
// elements from first arg. arg order only matters when _m used. Use _x.

#define sv_add32( p, v1, v0 )         svadd_u32_x( p, v1, v0 )

#define sv128_add32( v1, v0 )         svadd_u32_x( PRED128, v1, v0 )
#define sv256_add32( v1, v0 )         svadd_u32_x( PRED256, v1, v0 )

// Add integer to each element
#define sv_addi32( p, v, i )           svadd_n_u32_x( p, v, i )



// compare

#define sv_cmpeq32( p, v1, v0 )       svcmpeq_u32( p, v1, v0 )

#define sv128_cmpeq32( v1, v0 )       svcmpeq_u32( PRED128, v1, v0 )
#define sv256_cmpeq32( v1, v0 )       svcmpeq_u32( PRED256, v1, v0 )


// bit shift

#define sv_sl32( v, c )              svlsl_n_u32_x( p, v, c )

#define sv128_sl32( v, c )           svlsl_n_u32_x( PRED128, v, c )
#define sv256_sl32( v, c )           svlsl_n_u32_x( PRED256, v, c )


// logic

#define sv_or( p, v1, v0 )           svorr_u32_x( p, v1, v0 )

#define sv128_or( v1, v0 )           svorr_u32_x( PRED128, v1, v0 )
#define sv256_or( v1, v0 )           svorr_u32_x( PRED256, v1, v0 )

// ext used for alignr, and zip used for unpack have no predicate arg.
// How is vector length determined? How are register sizes handled?
// How are part registers handled?

// alignr (ext)

// unpack


// AES

// AES uses fixed 128 bit vectors, how does this work with larger registers?
 
// set1

#define sv128_32( n )      svdup_n_u32_x( PRED128, n )
#define sv256_32( n )      svdup_n_u32_x( PRED256, n )

// broadcast

// svdup_lane has no predicate

// constants


// pointer cast


// Bit rotation

// No predication for shift instructions

// Cross lane shuffles

// Very limited shuffling, mostly svtbl which has no predicate and  uses
// vector for the index.


// endian byte swap


#define sv128_bswap32(v)        svrevb_u32_x( p, v )


// blend

#enfif

