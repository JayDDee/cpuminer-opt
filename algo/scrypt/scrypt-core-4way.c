#include "scrypt-core-4way.h"

//////////////////////////////////////////////////////////////////////////
//
//  Optimized Salsa implementation inspired by Pooler.
//  Any similarities are not a coincidence.
//
//  Implementations include reference X64, SSE2, AVX2 & AVX512
//  using both serial and parallel vectoring using SIMD instruction.
//
//  Generic macros are providedi and invoked with different targets depending
//  on level of parallelism and data organization. Targets for any macros
//  needed must be defined by the calling function. XOR, ROL32 and ADD32
//  are needed in all cases. Additionally ROL_1X32, SWAP_64 and ROR_1X32
//  shuffles are needed for serial SIMD.
//
//  SALSA_8ROUNDS_SIMD uses vectors on serial data rather than traditional
//  n-way parallel hashing.
//  The SIMD version has different implied arguments {X0:X3}, representing
//  an array of 4 vectors of 4 32 bit words, while the version used for
//  regular parallel hashing has {x0:xf} representing array of 16 by 32 bit
//  words.
//  These arguments must be defined by the calling function.
//  The calling function must also define targets for all macros used for
//  arithmetic, logic and shuffling: XOR, ROL32, ADD32 for all targets and
//  ROL_1X32, SWAP_64, ROR_1X32 for serial SIMD targets.
//
//  Serial and parallel SIMD will be combined with AVX2 doing 2 way 
//  parallel over 4 way linear for 8 way throughput, and AVX512 doing
//  4 way parallel over 4 way linear for 16 way thoughput.
//
//  The term SIMD128 here refers to vectors that contain multiple contiguous
//  data from a single stream (lane) as opposed to parallel vectors that
//  contain interleaved words of data from multiple streams.
//
//  The sequencing of techniques in the naming convention is a little
//  mixed up. The logical hierarchy top down is to put Nbuffs at the top
//  where each buffer then performs another technique.
//
//  Although, Nway and SIMS128 are listed in top down order Nbuffs is
//  always listed last:
//
//  scrypt_core_simd128_2way means a linear simd operation on 2 parallel
//  streams of data while
//   scrypt_core_2way_simd128 is 2 parallel streams linear SIMD vectors.
//
///////////////////////////////////////////////////////////////////////////


// Used by all targets, needs XOR, ROL32 & ADD32 macros defined
// Function, return typically overwrites in1
//
#define ARX( in1, in2, in3, n ) \
   XOR( in1, ROL32( ADD32( in2, in3 ), n ) )

// Multi buffering has 2 main benefits and one drawback. 
// Traditionally double buffering has been used to empty one bucket
// while another is filling. This requires a second (or 3rd, etc)
// bucket. The computing analogy is to use 2 registers, 1 to read
// and 1 to write, and switch back and forth.
//
// The second benefit in computing is using multiple registers to 
// provide data independence that improves multiple instruction issue and
// pipelining in the CPU. The number of buffers is limited by the number
// of registers available. Three seems to be a swet spot as a 4 variable
// data set uses 12 registers triple buffered, leaving 4 of 16 as temps.
// Many pipelined instructions require 3 clocks to complete and triple
// bufferin keeps the pipeline full. Many execution units are also 3 wide
// allowing up to 3 similar instructions to be issued per clock.
// However, execution units are shared by hyperthreading which reduces
// the effect on a single thread.
//  
// The drawback is the increased size of the data. Although multi buffering
// also improves memory throughput this is offset by the amount of
// memory required and it's effect on cache performance and will eventually
// hit memory bus saturation.
//
// For example scryptn2 struggles with more than 4 buffers, multi
// buffered and parallel SIMD combined, and performance drops. This can
// be mitigated somewhat by reducing the number of CPU threads but
// ultimately excessive multi buffering has a negative impact.
//
// Unlike paralle SIMD, increasing multi buffering does not require a
// CPU technology increase, ie SSE2 to AVX2 or AVX2 TO AVX512.
// SSE2 is limited to 4 way SIMD but no theoretical limit to multibuffering.
// Multi buffering  also does not suffer the clock penalty of increasing
// parallism.
//
// Multi buffering implementations here focus on powers of 2,
// to match sha256 without re-interleaving the data.
//
// A decision will have to be made at run time, based of the N factor,
// whether to use multi buffering or serial execution.

// Need TYPE macro defined.
#define ARX_2BUF( a1, a2, a3, b1, b2, b3, n ) \
do{ \
   TYPE ta = ADD32( a2, a3 ); \
   TYPE tb = ADD32( b2, b3 ); \
   ta = ROL32( ta, n ); \
   tb = ROL32( tb, n ); \
   a1 = XOR( a1, ta ); \
   b1 = XOR( b1, tb ); \
} while (0);

#define ARX_3BUF( a1, a2, a3, b1, b2, b3, c1, c2, c3, n ) \
do{ \
   TYPE ta = ADD32( a2, a3 ); \
   TYPE tb = ADD32( b2, b3 ); \
   TYPE tc = ADD32( c2, c3 ); \
   ta = ROL32( ta, n ); \
   tb = ROL32( tb, n ); \
   tc = ROL32( tc, n ); \
   a1 = XOR( a1, ta ); \
   b1 = XOR( b1, tb ); \
   c1 = XOR( c1, tc ); \
} while (0);


// Used by SIMD128 and hybrid targets, needs also ROL_1X32, SWAP_64 &
// ROR_1X32 defined.
//
// Implied arguments ( X0 = { x3, x2, x1, x0 },
//                     X1 = { x7, x6, x5, x4 },
//                     X3 = { xb, xa, x9, x8 },
//                     X3 = { xf, xe, xd, xc } )
//
#define SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ) \
   /* Operate on columns */ \
   X1 = ARX( X1, X0, X3,  7 );  /* ( x4, x0, xc,  7 )  */ \
   X2 = ARX( X2, X1, X0,  9 );  /* ( x8, x4, x0,  9 )  */ \
   X3 = ARX( X3, X2, X1, 13 );  /* ( xc, x8, x4, 13 )  */ \
   X0 = ARX( X0, X3, X2, 18 );  /* ( x0, xc, x8, 18 )  */ \
   /* Rearrange data */ \
   X1 = ROL_1X32( X1 ); \
   X3 = ROR_1X32( X3 ); \
   X2 = SWAP_64( X2 ); \
   /* Operate on rows */ \
   X3 = ARX( X3, X0, X1,  7 ); \
   X2 = ARX( X2, X3, X0,  9 ); \
   X1 = ARX( X1, X2, X3, 13 ); \
   X0 = ARX( X0, X1, X2, 18 ); \
   /* Rearrange data */ \
   X3 = ROL_1X32( X3 ); \
   X1 = ROR_1X32( X1 ); \
   X2 = SWAP_64( X2 ); \

// Final round optimization, don't rearange data back to original order on exit
// Used only on pre-AVX2 CPUs where blend instruction is not avaiable.
// It saves a few redundant shuffles.
#define SALSA_2ROUNDS_FINAL_SIMD128( X0, X1, X2, X3 ) \
   /* Operate on columns */ \
   X1 = ARX( X1, X0, X3,  7 );  /* ( x4, x0, xc,  7 )  */ \
   X2 = ARX( X2, X1, X0,  9 );  /* ( x8, x4, x0,  9 )  */ \
   X3 = ARX( X3, X2, X1, 13 );  /* ( xc, x8, x4, 13 )  */ \
   X0 = ARX( X0, X3, X2, 18 );  /* ( x0, xc, x8, 18 )  */ \
   /* Rearrange data */ \
   X1 = ROL_1X32( X1 ); \
   X3 = ROR_1X32( X3 ); \
   X2 = SWAP_64( X2 ); \
   /* Operate on rows */ \
   X3 = ARX( X3, X0, X1,  7 ); \
   X2 = ARX( X2, X3, X0,  9 ); \
   X1 = ARX( X1, X2, X3, 13 ); \
   X0 = ARX( X0, X1, X2, 18 ); \
   /* Final round, don't rearrange data
   X1 = ROR_1X32( X1 ); \
   X2 = SWAP_64( X2 ); \
   X3 = ROL_1X32( X3 ); */

// Implied args ( XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3 )
#define SALSA_2ROUNDS_SIMD128_2BUF \
   ARX_2BUF( XA1, XA0, XA3, XB1, XB0, XB3,  7 ); \
   ARX_2BUF( XA2, XA1, XA0, XB2, XB1, XB0,  9 ); \
   ARX_2BUF( XA3, XA2, XA1, XB3, XB2, XB1, 13 ); \
   ARX_2BUF( XA0, XA3, XA2, XB0, XB3, XB2, 18 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XA3 = ROR_1X32( XA3 ); \
   XB3 = ROR_1X32( XB3 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   ARX_2BUF( XA3, XA0, XA1, XB3, XB0, XB1,  7 ); \
   ARX_2BUF( XA2, XA3, XA0, XB2, XB3, XB0,  9 ); \
   ARX_2BUF( XA1, XA2, XA3, XB1, XB2, XB3, 13 ); \
   ARX_2BUF( XA0, XA1, XA2, XB0, XB1, XB2, 18 ); \
   XA3 = ROL_1X32( XA3 ); \
   XB3 = ROL_1X32( XB3 ); \
   XA1 = ROR_1X32( XA1 ); \
   XB1 = ROR_1X32( XB1 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 );

// For use when fast bit rotate is not available.
// contains target specif instructions, only use with 128 bit vectrors.
#define SALSA_2ROUNDS_SIMD128_2BUF_SLOROT \
do{ \
   TYPE TA = ADD32( XA0, XA3 ); \
   TYPE TB = ADD32( XB0, XB3 ); \
   TYPE T  = v128_sl32( TA, 7 ); \
   TA = v128_sr32( TA, 25 ); \
   XA1 = XOR( XA1, T  ); \
   XA1 = XOR( XA1, TA  ); \
   T = v128_sl32( TB, 7 );\
   TB = v128_sr32( TB, 25 ); \
   XB1 = XOR( XB1, T ); \
   XB1 = XOR( XB1, TB ); \
\
   TA = ADD32( XA1, XA0 ); \
   TB = ADD32( XB1, XB0 ); \
   T  = v128_sl32( TA, 9 ); \
   TA = v128_sr32( TA, 23 ); \
   XA2 = XOR( XA2, T ); \
   XA2 = XOR( XA2, TA ); \
   T = v128_sl32( TB, 9 );\
   TB = v128_sr32( TB, 23 );\
   XB2 = XOR( XB2, T ); \
   XB2 = XOR( XB2, TB ); \
\
   TA = ADD32( XA2, XA1 ); \
   TB = ADD32( XB2, XB1 ); \
   T  = v128_sl32( TA, 13); \
   TA = v128_sr32( TA, 19 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XA3 = XOR( XA3, T ); \
   XA3 = XOR( XA3, TA ); \
   T  = v128_sl32( TB, 13); \
   TB = v128_sr32( TB, 19 ); \
   XB3 = XOR( XB3, T ); \
   XB3 = XOR( XB3, TB ); \
\
   TA = ADD32( XA3, XA2 ); \
   TB = ADD32( XB3, XB2 ); \
   T  = v128_sl32( TA, 18 ); \
   TA = v128_sr32( TA, 14 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XA0 = XOR( XA0, T ); \
   XA0 = XOR( XA0, TA ); \
   T  = v128_sl32( TB, 18 ); \
   TB = v128_sr32( TB, 14 ); \
   XB0 = XOR( XB0, T ); \
   XB0 = XOR( XB0, TB ); \
\
   TA = ADD32( XA0, XA1 ); \
   TB = ADD32( XB0, XB1 ); \
   T = v128_sl32( TA, 7 ); \
   TA = v128_sr32( TA, 25 ); \
   XA3 = ROR_1X32( XA3 ); \
   XA3 = XOR( XA3, T ); \
   XA3 = XOR( XA3, TA ); \
   T = v128_sl32( TB, 7 ); \
   TB = v128_sr32( TB, 25 ); \
   XB3 = ROR_1X32( XB3 ); \
   XB3 = XOR( XB3, T ); \
   XB3 = XOR( XB3, TB ); \
\
   TA = ADD32( XA3, XA0 ); \
   TB = ADD32( XB3, XB0 ); \
   T = v128_sl32( TA, 9 ); \
   TA = v128_sr32( TA, 23 ); \
   XA2 = XOR( XA2, T ); \
   XA2 = XOR( XA2, TA ); \
   T = v128_sl32( TB, 9 ); \
   TB = v128_sr32( TB, 23 ); \
   XB2 = XOR( XB2, T ); \
   XB2 = XOR( XB2, TB ); \
\
   TA = ADD32( XA2, XA3 ); \
   TB = ADD32( XB2, XB3 ); \
   T = v128_sl32( TA, 13 ); \
   TA = v128_sr32( TA, 19 ); \
   XA3 = ROL_1X32( XA3 ); \
   XB3 = ROL_1X32( XB3 ); \
   XA1 = XOR( XA1, T ); \
   XA1 = XOR( XA1, TA ); \
   T = v128_sl32( TB, 13 ); \
   TB = v128_sr32( TB, 19 ); \
   XB1 = XOR( XB1, T ); \
   XB1 = XOR( XB1, TB ); \
\
   TA = ADD32( XA1, XA2 ); \
   TB = ADD32( XB1, XB2 ); \
   T = v128_sl32( TA, 18 ); \
   TA = v128_sr32( TA, 14 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XA0 = XOR( XA0, T ); \
   XA0 = XOR( XA0, TA ); \
   T = v128_sl32( TB, 18 ); \
   TB = v128_sr32( TB, 14 ); \
   XA1 = ROR_1X32( XA1 ); \
   XB0 = XOR( XB0, T ); \
   XB0 = XOR( XB0, TB ); \
   XB1 = ROR_1X32( XB1 ); \
} while (0);

#define SALSA_2ROUNDS_FINAL_SIMD128_2BUF \
   ARX_2BUF( XA1, XA0, XA3, XB1, XB0, XB3,  7 ); \
   ARX_2BUF( XA2, XA1, XA0, XB2, XB1, XB0,  9 ); \
   ARX_2BUF( XA3, XA2, XA1, XB3, XB2, XB1, 13 ); \
   ARX_2BUF( XA0, XA3, XA2, XB0, XB3, XB2, 18 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XA3 = ROR_1X32( XA3 ); \
   XB3 = ROR_1X32( XB3 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   ARX_2BUF( XA3, XA0, XA1, XB3, XB0, XB1,  7 ); \
   ARX_2BUF( XA2, XA3, XA0, XB2, XB3, XB0,  9 ); \
   ARX_2BUF( XA1, XA2, XA3, XB1, XB2, XB3, 13 ); \
   ARX_2BUF( XA0, XA1, XA2, XB0, XB1, XB2, 18 );


// Inlined ARX
#define SALSA_2ROUNDS_SIMD128_3BUF \
do{ \
   TYPE TA = ADD32( XA0, XA3 ); \
   TYPE TB = ADD32( XB0, XB3 ); \
   TYPE TC = ADD32( XC0, XC3 ); \
   TA = ROL32( TA, 7 ); \
   TB = ROL32( TB, 7 ); \
   TC = ROL32( TC, 7 ); \
   XA1 = XOR( XA1, TA ); \
   XB1 = XOR( XB1, TB ); \
   XC1 = XOR( XC1, TC ); \
\
   TA = ADD32( XA1, XA0 ); \
   TB = ADD32( XB1, XB0 ); \
   TC = ADD32( XC1, XC0 ); \
   TA = ROL32( TA, 9 ); \
   TB = ROL32( TB, 9 ); \
   TC = ROL32( TC, 9 ); \
   XA2 = XOR( XA2, TA ); \
   XB2 = XOR( XB2, TB ); \
   XC2 = XOR( XC2, TC ); \
\
   TA = ADD32( XA2, XA1 ); \
   XA1 = ROL_1X32( XA1 ); \
   TB = ADD32( XB2, XB1 ); \
   TC = ADD32( XC2, XC1 ); \
   XB1 = ROL_1X32( XB1 ); \
   TA = ROL32( TA, 13 ); \
   XA3 = XOR( XA3, TA ); \
   XC1 = ROL_1X32( XC1 ); \
   TB = ROL32( TB, 13 ); \
   XB3 = XOR( XB3, TB ); \
   TC = ROL32( TC, 13 ); \
   XC3 = XOR( XC3, TC ); \
\
   TA = ADD32( XA3, XA2 ); \
   XA2 = SWAP_64( XA2 ); \
   TB = ADD32( XB3, XB2 ); \
   TC = ADD32( XC3, XC2 ); \
   TA = ROL32( TA, 18 ); \
   XB2 = SWAP_64( XB2 ); \
   XA0 = XOR( XA0, TA ); \
   TB = ROL32( TB, 18 ); \
   XB0 = XOR( XB0, TB ); \
   XC2 = SWAP_64( XC2 ); \
   TC = ROL32( TC, 18 ); \
   XC0 = XOR( XC0, TC ); \
\
   TA = ADD32( XA0, XA1 ); \
   XA3 = ROR_1X32( XA3 ); \
   TB = ADD32( XB0, XB1 ); \
   TC = ADD32( XC0, XC1 ); \
   TA = ROL32( TA, 7 ); \
   XB3 = ROR_1X32( XB3 ); \
   XA3 = XOR( XA3, TA ); \
   TB = ROL32( TB, 7 ); \
   XC3 = ROR_1X32( XC3 ); \
   XB3 = XOR( XB3, TB ); \
   TC = ROL32( TC, 7 ); \
   XC3 = XOR( XC3, TC ); \
\
   TA = ADD32( XA3, XA0 ); \
   TB = ADD32( XB3, XB0 ); \
   TC = ADD32( XC3, XC0 ); \
   TA = ROL32( TA, 9 ); \
   TB = ROL32( TB, 9 ); \
   TC = ROL32( TC, 9 ); \
   XA2 = XOR( XA2, TA ); \
   XB2 = XOR( XB2, TB ); \
   XC2 = XOR( XC2, TC ); \
\
   TA = ADD32( XA2, XA3 ); \
   TB = ADD32( XB2, XB3 ); \
   TA = ROL32( TA, 13 ); \
   TC = ADD32( XC2, XC3 ); \
   XA3 = ROL_1X32( XA3 ); \
   TB = ROL32( TB, 13 ); \
   XB3 = ROL_1X32( XB3 ); \
   XA1 = XOR( XA1, TA ); \
   TC = ROL32( TC, 13 ); \
   XC3 = ROL_1X32( XC3 ); \
   XB1 = XOR( XB1, TB ); \
   XC1 = XOR( XC1, TC ); \
\
   TA = ADD32( XA1, XA2 ); \
   XA2 = SWAP_64( XA2 ); \
   TB = ADD32( XB1, XB2 ); \
   XB2 = SWAP_64( XB2 ); \
   TA = ROL32( TA, 18); \
   TC = ADD32( XC1, XC2 ); \
   XC2 = SWAP_64( XC2 ); \
   TB = ROL32( TB, 18); \
   XA0 = XOR( XA0, TA ); \
   XA1 = ROR_1X32( XA1 ); \
   TC = ROL32( TC, 18); \
   XB0 = XOR( XB0, TB ); \
   XB1 = ROR_1X32( XB1 ); \
   XC0 = XOR( XC0, TC ); \
   XC1 = ROR_1X32( XC1 ); \
} while (0);
   

// slow rot, an attempt to optimze non-avx512 bit rotations
// Contains target specific instructions, only for use with 128 bit vectors
#define SALSA_2ROUNDS_SIMD128_3BUF_SLOROT \
do{ \
   TYPE TA = ADD32( XA0, XA3 ); \
   TYPE TB = ADD32( XB0, XB3 ); \
   TYPE TC = ADD32( XC0, XC3 ); \
   TYPE T  = v128_sl32( TA, 7 ); \
   TA = v128_sr32( TA, 25 ); \
   XA1 = XOR( XA1, T  ); \
   XA1 = XOR( XA1, TA  ); \
   T = v128_sl32( TB, 7 );\
   TB = v128_sr32( TB, 25 ); \
   XB1 = XOR( XB1, T ); \
   XB1 = XOR( XB1, TB ); \
   T = v128_sl32( TC, 7 );\
   TC = v128_sr32( TC, 25 );\
   XC1 = XOR( XC1, T ); \
   XC1 = XOR( XC1, TC ); \
\
   TA = ADD32( XA1, XA0 ); \
   TB = ADD32( XB1, XB0 ); \
   TC = ADD32( XC1, XC0 ); \
   T  = v128_sl32( TA, 9 ); \
   TA = v128_sr32( TA, 23 ); \
   XA2 = XOR( XA2, T ); \
   XA2 = XOR( XA2, TA ); \
   T = v128_sl32( TB, 9 );\
   TB = v128_sr32( TB, 23 );\
   XB2 = XOR( XB2, T ); \
   XB2 = XOR( XB2, TB ); \
   T = v128_sl32( TC, 9 );\
   TC = v128_sr32( TC, 23 );\
   XC2 = XOR( XC2, T ); \
   XC2 = XOR( XC2, TC ); \
\
   TA = ADD32( XA2, XA1 ); \
   TB = ADD32( XB2, XB1 ); \
   TC = ADD32( XC2, XC1 ); \
   T  = v128_sl32( TA, 13); \
   TA = v128_sr32( TA, 19 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XC1 = ROL_1X32( XC1 ); \
   XA3 = XOR( XA3, T ); \
   XA3 = XOR( XA3, TA ); \
   T  = v128_sl32( TB, 13); \
   TB = v128_sr32( TB, 19 ); \
   XB3 = XOR( XB3, T ); \
   XB3 = XOR( XB3, TB ); \
   T  = v128_sl32( TC, 13); \
   TC = v128_sr32( TC, 19 ); \
   XC3 = XOR( XC3, T ); \
   XC3 = XOR( XC3, TC ); \
\
   TA = ADD32( XA3, XA2 ); \
   TB = ADD32( XB3, XB2 ); \
   TC = ADD32( XC3, XC2 ); \
   T  = v128_sl32( TA, 18 ); \
   TA = v128_sr32( TA, 14 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XC2 = SWAP_64( XC2 ); \
   XA0 = XOR( XA0, T ); \
   XA0 = XOR( XA0, TA ); \
   T  = v128_sl32( TB, 18 ); \
   TB = v128_sr32( TB, 14 ); \
   XB0 = XOR( XB0, T ); \
   XB0 = XOR( XB0, TB ); \
   T = v128_sl32( TC, 18 ); \
   TC = v128_sr32( TC, 14 ); \
   XC0 = XOR( XC0, T ); \
   XC0 = XOR( XC0, TC ); \
\
   TA = ADD32( XA0, XA1 ); \
   TB = ADD32( XB0, XB1 ); \
   TC = ADD32( XC0, XC1 ); \
   T = v128_sl32( TA, 7 ); \
   TA = v128_sr32( TA, 25 ); \
   XA3 = ROR_1X32( XA3 ); \
   XA3 = XOR( XA3, T ); \
   XA3 = XOR( XA3, TA ); \
   T = v128_sl32( TB, 7 ); \
   TB = v128_sr32( TB, 25 ); \
   XB3 = ROR_1X32( XB3 ); \
   XB3 = XOR( XB3, T ); \
   XB3 = XOR( XB3, TB ); \
   T = v128_sl32( TC, 7 ); \
   TC = v128_sr32( TC, 25 ); \
   XC3 = ROR_1X32( XC3 ); \
   XC3 = XOR( XC3, T ); \
   XC3 = XOR( XC3, TC ); \
\
   TA = ADD32( XA3, XA0 ); \
   TB = ADD32( XB3, XB0 ); \
   TC = ADD32( XC3, XC0 ); \
   T = v128_sl32( TA, 9 ); \
   TA = v128_sr32( TA, 23 ); \
   XA2 = XOR( XA2, T ); \
   XA2 = XOR( XA2, TA ); \
   T = v128_sl32( TB, 9 ); \
   TB = v128_sr32( TB, 23 ); \
   XB2 = XOR( XB2, T ); \
   XB2 = XOR( XB2, TB ); \
   T = v128_sl32( TC, 9 ); \
   TC = v128_sr32( TC, 23 ); \
   XC2 = XOR( XC2, T ); \
   XC2 = XOR( XC2, TC ); \
\
   TA = ADD32( XA2, XA3 ); \
   TB = ADD32( XB2, XB3 ); \
   TC = ADD32( XC2, XC3 ); \
   T = v128_sl32( TA, 13 ); \
   TA = v128_sr32( TA, 19 ); \
   XA3 = ROL_1X32( XA3 ); \
   XB3 = ROL_1X32( XB3 ); \
   XC3 = ROL_1X32( XC3 ); \
   XA1 = XOR( XA1, T ); \
   XA1 = XOR( XA1, TA ); \
   T = v128_sl32( TB, 13 ); \
   TB = v128_sr32( TB, 19 ); \
   XB1 = XOR( XB1, T ); \
   XB1 = XOR( XB1, TB ); \
   T = v128_sl32( TC, 13 ); \
   TC = v128_sr32( TC, 19 ); \
   XC1 = XOR( XC1, T ); \
   XC1 = XOR( XC1, TC ); \
\
   TA = ADD32( XA1, XA2 ); \
   TB = ADD32( XB1, XB2 ); \
   TC = ADD32( XC1, XC2 ); \
   T = v128_sl32( TA, 18 ); \
   TA = v128_sr32( TA, 14 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XA0 = XOR( XA0, T ); \
   XA0 = XOR( XA0, TA ); \
   T = v128_sl32( TB, 18 ); \
   TB = v128_sr32( TB, 14 ); \
   XC2 = SWAP_64( XC2 ); \
   XA1 = ROR_1X32( XA1 ); \
   XB0 = XOR( XB0, T ); \
   XB0 = XOR( XB0, TB ); \
   T = v128_sl32( TC, 18 ); \
   TC = v128_sr32( TC, 14 ); \
   XB1 = ROR_1X32( XB1 ); \
   XC1 = ROR_1X32( XC1 ); \
   XC0 = XOR( XC0, T ); \
   XC0 = XOR( XC0, TC ); \
} while (0);


/*
// Standard version using ARX
#define SALSA_2ROUNDS_SIMD128_3BUF \
   ARX_3BUF( XA1, XA0, XA3, XB1, XB0, XB3, \
             XC1, XC0, XC3, 7 ); \
   ARX_3BUF( XA2, XA1, XA0, XB2, XB1, XB0, \
             XC2, XC1, XC0,  9 ); \
   ARX_3BUF( XA3, XA2, XA1, XB3, XB2, XB1, \
             XC3, XC2, XC1, 13 ); \
   ARX_3BUF( XA0, XA3, XA2, XB0, XB3, XB2, \
             XC0, XC3, XC2, 18 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XC1 = ROL_1X32( XC1 ); \
   XA3 = ROR_1X32( XA3 ); \
   XB3 = ROR_1X32( XB3 ); \
   XC3 = ROR_1X32( XC3 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XC2 = SWAP_64( XC2 ); \
   ARX_3BUF( XA3, XA0, XA1, XB3, XB0, XB1, \
             XC3, XC0, XC1,  7 ); \
   ARX_3BUF( XA2, XA3, XA0, XB2, XB3, XB0, \
             XC2, XC3, XC0,  9 ); \
   ARX_3BUF( XA1, XA2, XA3, XB1, XB2, XB3, \
             XC1, XC2, XC3, 13 ); \
   ARX_3BUF( XA0, XA1, XA2, XB0, XB1, XB2, \
             XC0, XC1, XC2, 18 ); \
   XA3 = ROL_1X32( XA3 ); \
   XB3 = ROL_1X32( XB3 ); \
   XC3 = ROL_1X32( XC3 ); \
   XA1 = ROR_1X32( XA1 ); \
   XB1 = ROR_1X32( XB1 ); \
   XC1 = ROR_1X32( XC1 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XC2 = SWAP_64( XC2 );
*/

#define SALSA_2ROUNDS_FINAL_SIMD128_3BUF \
   ARX_3BUF( XA1, XA0, XA3, XB1, XB0, XB3, \
             XC1, XC0, XC3, 7 ); \
   ARX_3BUF( XA2, XA1, XA0, XB2, XB1, XB0, \
             XC2, XC1, XC0,  9 ); \
   ARX_3BUF( XA3, XA2, XA1, XB3, XB2, XB1, \
             XC3, XC2, XC1, 13 ); \
   ARX_3BUF( XA0, XA3, XA2, XB0, XB3, XB2, \
             XC0, XC3, XC2, 18 ); \
   XA1 = ROL_1X32( XA1 ); \
   XB1 = ROL_1X32( XB1 ); \
   XC1 = ROL_1X32( XC1 ); \
   XA3 = ROR_1X32( XA3 ); \
   XB3 = ROR_1X32( XB3 ); \
   XC3 = ROR_1X32( XC3 ); \
   XA2 = SWAP_64( XA2 ); \
   XB2 = SWAP_64( XB2 ); \
   XC2 = SWAP_64( XC2 ); \
   ARX_3BUF( XA3, XA0, XA1, XB3, XB0, XB1, \
             XC3, XC0, XC1,  7 ); \
   ARX_3BUF( XA2, XA3, XA0, XB2, XB3, XB0, \
             XC2, XC3, XC0,  9 ); \
   ARX_3BUF( XA1, XA2, XA3, XB1, XB2, XB3, \
             XC1, XC2, XC3, 13 ); \
   ARX_3BUF( XA0, XA1, XA2, XB0, XB1, XB2, \
             XC0, XC1, XC2, 18 );


#define SALSA_8ROUNDS_SIMD128 \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 );

#define SALSA_8ROUNDS_FINAL_SIMD128 \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_SIMD128( X0, X1, X2, X3 ); \
   SALSA_2ROUNDS_FINAL_SIMD128( X0, X1, X2, X3 );

// Implied args ( XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3 )
#define SALSA_8ROUNDS_SIMD128_2BUF \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_SIMD128_2BUF;

#define SALSA_8ROUNDS_SIMD128_2BUF_SLOROT \
   SALSA_2ROUNDS_SIMD128_2BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_2BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_2BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_2BUF_SLOROT;

#define SALSA_8ROUNDS_FINAL_SIMD128_2BUF \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_SIMD128_2BUF; \
   SALSA_2ROUNDS_FINAL_SIMD128_2BUF;

#define SALSA_8ROUNDS_SIMD128_3BUF \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_SIMD128_3BUF;

#define SALSA_8ROUNDS_SIMD128_3BUF_SLOROT \
   SALSA_2ROUNDS_SIMD128_3BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_3BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_3BUF_SLOROT; \
   SALSA_2ROUNDS_SIMD128_3BUF_SLOROT;

#define SALSA_8ROUNDS_FINAL_SIMD128_3BUF \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_SIMD128_3BUF; \
   SALSA_2ROUNDS_FINAL_SIMD128_3BUF;

// Implied args ( XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3,
//                XC0, XC1, XC2, XC3, XD0, XD1, XD2, XD3, )
#define SALSA_8ROUNDS_SIMD128_4BUF \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_SIMD128_4BUF;

#define SALSA_8ROUNDS_FINAL_SIMD128_4BUF \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_SIMD128_4BUF; \
   SALSA_2ROUNDS_FINAL_SIMD128_4BUF;

// Used by reference code and pure parallel implementations
//
// Implied arguments ( x0, x1, x2, x3, x4, x5, x6, x7,
//                     x8, x9, xa, xb, xc, xd, xe, xf )
//
#define SALSA_COLUMN \
   x4 = ARX( x4, x0, xc,  7 ); \
   x9 = ARX( x9, x5, x1,  7 ); \
   xe = ARX( xe, xa, x6,  7 ); \
   x3 = ARX( x3, xf, xb,  7 ); \
   x8 = ARX( x8, x4, x0,  9 ); \
   xd = ARX( xd, x9, x5,  9 ); \
   x2 = ARX( x2, xe, xa,  9 ); \
   x7 = ARX( x7, x3, xf,  9 ); \
   xc = ARX( xc, x8, x4, 13 ); \
   x1 = ARX( x1, xd, x9, 13 ); \
   x6 = ARX( x6, x2, xe, 13 ); \
   xb = ARX( xb, x7, x3, 13 ); \
   x0 = ARX( x0, xc, x8, 18 ); \
   x5 = ARX( x5, x1, xd, 18 ); \
   xa = ARX( xa, x6, x2, 18 ); \
   xf = ARX( xf, xb, x7, 18 ) 
   
#define SALSA_ROW \
   x1 = ARX( x1, x0, x3,  7 ); \
   x6 = ARX( x6, x5, x4,  7 ); \
   xb = ARX( xb, xa, x9,  7 ); \
   xc = ARX( xc, xf, xe,  7 ); \
   x2 = ARX( x2, x1, x0,  9 ); \
   x7 = ARX( x7, x6, x5,  9 ); \
   x8 = ARX( x8, xb, xa,  9 ); \
   xd = ARX( xd, xc, xf,  9 ); \
   x3 = ARX( x3, x2, x1, 13 ); \
   x4 = ARX( x4, x7, x6, 13 ); \
   x9 = ARX( x9, x8, xb, 13 ); \
   xe = ARX( xe, xd, xc, 13 ); \
   x0 = ARX( x0, x3, x2, 18 ); \
   x5 = ARX( x5, x4, x7, 18 ); \
   xa = ARX( xa, x9, x8, 18 ); \
   xf = ARX( xf, xe, xd, 18 );

#define SALSA_2ROUNDS    SALSA_COLUMN; SALSA_ROW;

#define SALSA_8ROUNDS \
   SALSA_2ROUNDS; SALSA_2ROUNDS; SALSA_2ROUNDS; SALSA_2ROUNDS;


#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// Tested OK but very slow
// 16 way parallel, requires 16x32 interleaving
static void xor_salsa8_16way( __m512i * const B, const __m512i * const C)
{
   __m512i x0 = B[ 0] = _mm512_xor_si512( B[ 0], C[ 0] );
   __m512i x1 = B[ 1] = _mm512_xor_si512( B[ 1], C[ 1] );
   __m512i x2 = B[ 2] = _mm512_xor_si512( B[ 2], C[ 2] );
   __m512i x3 = B[ 3] = _mm512_xor_si512( B[ 3], C[ 3] );
   __m512i x4 = B[ 4] = _mm512_xor_si512( B[ 4], C[ 4] );
   __m512i x5 = B[ 5] = _mm512_xor_si512( B[ 5], C[ 5] );
   __m512i x6 = B[ 6] = _mm512_xor_si512( B[ 6], C[ 6] );
   __m512i x7 = B[ 7] = _mm512_xor_si512( B[ 7], C[ 7] );
   __m512i x8 = B[ 8] = _mm512_xor_si512( B[ 8], C[ 8] );
   __m512i x9 = B[ 9] = _mm512_xor_si512( B[ 9], C[ 9] );
   __m512i xa = B[10] = _mm512_xor_si512( B[10], C[10] );
   __m512i xb = B[11] = _mm512_xor_si512( B[11], C[11] );
   __m512i xc = B[12] = _mm512_xor_si512( B[12], C[12] );
   __m512i xd = B[13] = _mm512_xor_si512( B[13], C[13] );
   __m512i xe = B[14] = _mm512_xor_si512( B[14], C[14] );
   __m512i xf = B[15] = _mm512_xor_si512( B[15], C[15] );

   #define ROL32       _mm512_rol_epi32
   #define ADD32       _mm512_add_epi32
   #define XOR         _mm512_xor_si512

   SALSA_8ROUNDS;

   #undef ROL32
   #undef ADD32
   #undef XOR 
   
   B[ 0] = _mm512_add_epi32( B[ 0], x0 );
   B[ 1] = _mm512_add_epi32( B[ 1], x1 );
   B[ 2] = _mm512_add_epi32( B[ 2], x2 );
   B[ 3] = _mm512_add_epi32( B[ 3], x3 );
   B[ 4] = _mm512_add_epi32( B[ 4], x4 );
   B[ 5] = _mm512_add_epi32( B[ 5], x5 );
   B[ 6] = _mm512_add_epi32( B[ 6], x6 );
   B[ 7] = _mm512_add_epi32( B[ 7], x7 );
   B[ 8] = _mm512_add_epi32( B[ 8], x8 );
   B[ 9] = _mm512_add_epi32( B[ 9], x9 );
   B[10] = _mm512_add_epi32( B[10], xa );
   B[11] = _mm512_add_epi32( B[11], xb );
   B[12] = _mm512_add_epi32( B[12], xc );
   B[13] = _mm512_add_epi32( B[13], xd );
   B[14] = _mm512_add_epi32( B[14], xe );
   B[15] = _mm512_add_epi32( B[15], xf );
}

void scrypt_core_16way( __m512i *X, __m512i *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[n * 32], X, 128*16 );
      xor_salsa8_16way( &X[ 0], &X[16] );
      xor_salsa8_16way( &X[16], &X[ 0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      m512_ovly *vptr[16];   // pointer to V offset for each lane 
      m512_ovly *x16 = (m512_ovly*)(&X[16]);

      // create pointers to V for each lane using data from each lane of X[16]
      // as index.
      for ( int l = 0; l < 16; l++ )
      {
         uint32_t xl = (*x16).u32[l];
         vptr[l] = (m512_ovly*)( &V[ 32 * ( xl & ( N-1 ) ) ] );
      }

      for ( int i = 0; i < 32; i++ )
      {
         m512_ovly v;    // V value assembled from different indexes
         for ( int l = 0; l < 8; l++ )
            v.u32[l] = ( *(vptr[l] +i ) ) .u32[l];
         X[i] = _mm512_xor_si512( X[i], v.m512 );
      }

      xor_salsa8_16way( &X[ 0], &X[16] );
      xor_salsa8_16way( &X[16], &X[ 0] );
   }
}

// Working, not up to date, needs stream, shuffle optimizations.
// 4x32 interleaving
static void salsa8_simd128_4way( v128_t *b, const v128_t *c )
{
   __m512i X0, X1, X2, X3, Y0, Y1, Y2, Y3;
   __m512i *B = (__m512i*)b; 
   const __m512i *C = (const __m512i*)c;

   // mix C into B then shuffle B into X
   B[0] = _mm512_xor_si512( B[0], C[0] );
   B[1] = _mm512_xor_si512( B[1], C[1] );
   B[2] = _mm512_xor_si512( B[2], C[2] );
   B[3] = _mm512_xor_si512( B[3], C[3] );

   Y0 = _mm512_mask_blend_epi64( 0x03, B[1], B[0] );
   X0 = _mm512_mask_blend_epi64( 0x30, B[3], B[2] );
   X0 = _mm512_mask_blend_epi64( 0x0f, X0, Y0 );

   Y0 = _mm512_mask_blend_epi64( 0x03, B[2], B[1] );
   X1 = _mm512_mask_blend_epi64( 0x30, B[0], B[3] );
   X1 = _mm512_mask_blend_epi64( 0x0f, X1, Y0 );

   Y0 = _mm512_mask_blend_epi64( 0x03, B[3], B[2] );
   X2 = _mm512_mask_blend_epi64( 0x30, B[1], B[0] );
   X2 = _mm512_mask_blend_epi64( 0x0f, X2, Y0 );

   Y0 = _mm512_mask_blend_epi64( 0x03, B[0], B[3] );
   X3 = _mm512_mask_blend_epi64( 0x30, B[2], B[1] );
   X3 = _mm512_mask_blend_epi64( 0x0f, X3, Y0 );

   // define targets for macros used in round function template
   #define ROL_1X32    mm512_shufll_128 
   #define ROR_1X32    mm512_shuflr_128
   #define SWAP_64     mm512_swap_256
   #define ROL32       _mm512_rol_epi32
   #define ADD32       _mm512_add_epi32
   #define XOR         _mm512_xor_si512

   SALSA_8ROUNDS_SIMD128;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 

   Y0 = _mm512_mask_blend_epi64( 0xc0, X0, X1 );
   Y1 = _mm512_mask_blend_epi64( 0x03, X0, X1 );
   Y2 = _mm512_mask_blend_epi64( 0x0c, X0, X1 );
   Y3 = _mm512_mask_blend_epi64( 0x30, X0, X1 );

   Y0 = _mm512_mask_blend_epi64( 0x30, Y0, X2 );
   Y1 = _mm512_mask_blend_epi64( 0xc0, Y1, X2 );
   Y2 = _mm512_mask_blend_epi64( 0x03, Y2, X2 );
   Y3 = _mm512_mask_blend_epi64( 0x0c, Y3, X2 );

   Y0 = _mm512_mask_blend_epi64( 0x0c, Y0, X3 );
   Y1 = _mm512_mask_blend_epi64( 0x30, Y1, X3 );
   Y2 = _mm512_mask_blend_epi64( 0xc0, Y2, X3 );
   Y3 = _mm512_mask_blend_epi64( 0x03, Y3, X3 );

   B[0] = _mm512_add_epi32( B[0], Y0 );
   B[1] = _mm512_add_epi32( B[1], Y1 );
   B[2] = _mm512_add_epi32( B[2], Y2 );
   B[3] = _mm512_add_epi32( B[3], Y3 );
}

// data format for 512 bits: 4 * ( 4 way 32 )
// { l3d3, l2d3, l1d3, l0d3, l3d2, l2d2, l1d2, l0d2,
//   l3d1, l2d1, l1d1, l0d1, l3d0, l2d0, l1d0, l0d0 }

void scrypt_core_simd128_4way( v128_t *X, v128_t *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[n * 32], X, 4*128 );
      salsa8_simd128_4way( &X[ 0], &X[16] );
      salsa8_simd128_4way( &X[16], &X[ 0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      uint32_t x16[4];   // index into V for each lane
      memcpy( x16, &X[16], 16 );
      x16[0] = 32 * ( x16[0] & ( N-1) );
      x16[1] = 32 * ( x16[1] & ( N-1) );
      x16[2] = 32 * ( x16[2] & ( N-1) );
      x16[3] = 32 * ( x16[3] & ( N-1) );
      v128_ovly *v = (v128_ovly*)V;

      for( int i = 0; i < 32; i++ )
      {
         X[i] = v128_xor( X[i], v128_set32( v[ x16[3] + i ].u32[3],
                                            v[ x16[2] + i ].u32[2],
                                            v[ x16[1] + i ].u32[1],
                                            v[ x16[0] + i ].u32[0] ) );
      }

      salsa8_simd128_4way( &X[ 0], &X[16] );
      salsa8_simd128_4way( &X[16], &X[ 0] );
   }
}

// 4x memory usage
// Working
// 4x128 interleaving
static inline void salsa_shuffle_4way_simd128( __m512i *X )
{
  __m512i t0 = _mm512_mask_blend_epi32( 0xaaaa, X[0], X[1] );
  __m512i t1 = _mm512_mask_blend_epi32( 0x5555, X[0], X[1] );
  __m512i t2 = _mm512_mask_blend_epi32( 0xaaaa, X[2], X[3] );
  __m512i t3 = _mm512_mask_blend_epi32( 0x5555, X[2], X[3] );
  X[0] = _mm512_mask_blend_epi32( 0xcccc, t0, t2 );
  X[1] = _mm512_mask_blend_epi32( 0x6666, t1, t3 );
  X[2] = _mm512_mask_blend_epi32( 0x3333, t0, t2 );
  X[3] = _mm512_mask_blend_epi32( 0x9999, t1, t3 );
}

static inline void salsa_unshuffle_4way_simd128( __m512i *X )
{
  __m512i t0 = _mm512_mask_blend_epi32( 0xcccc, X[0], X[2] );
  __m512i t1 = _mm512_mask_blend_epi32( 0x3333, X[0], X[2] );
  __m512i t2 = _mm512_mask_blend_epi32( 0x6666, X[1], X[3] );
  __m512i t3 = _mm512_mask_blend_epi32( 0x9999, X[1], X[3] );
  X[0] = _mm512_mask_blend_epi32( 0xaaaa, t0, t2 );
  X[1] = _mm512_mask_blend_epi32( 0x5555, t0, t2 );
  X[2] = _mm512_mask_blend_epi32( 0xaaaa, t1, t3 );
  X[3] = _mm512_mask_blend_epi32( 0x5555, t1, t3 );
}

static void salsa8_4way_simd128( __m512i * const B, const __m512i * const C)
{
   __m512i X0, X1, X2, X3;

   X0 = B[0] = _mm512_xor_si512( B[0], C[0] );
   X1 = B[1] = _mm512_xor_si512( B[1], C[1] );
   X2 = B[2] = _mm512_xor_si512( B[2], C[2] );
   X3 = B[3] = _mm512_xor_si512( B[3], C[3] );

   #define ROL_1X32    mm512_shufll128_32  // shuffle within 128 bit lanes
   #define ROR_1X32    mm512_shuflr128_32
   #define SWAP_64     mm512_swap128_64
   #define ROL32       _mm512_rol_epi32
   #define ADD32       _mm512_add_epi32
   #define XOR         _mm512_xor_si512

   SALSA_8ROUNDS_SIMD128;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 

   B[0] = _mm512_add_epi32( B[0], X0 );
   B[1] = _mm512_add_epi32( B[1], X1 );
   B[2] = _mm512_add_epi32( B[2], X2 );
   B[3] = _mm512_add_epi32( B[3], X3 );
}

void scrypt_core_4way_simd128( __m512i *X, __m512i *V, const uint32_t N )
{
   salsa_shuffle_4way_simd128( X );
   salsa_shuffle_4way_simd128( X+4 );
   
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[n * 8], X, 128*4 );
      salsa8_4way_simd128( &X[0], &X[4] );
      salsa8_4way_simd128( &X[4], &X[0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      m512_ovly x16;
      x16 = ( (m512_ovly*)X )[4];
      uint32_t j0 = 8 * ( x16.u32[ 0] & ( N-1 ) );
      uint32_t j1 = 8 * ( x16.u32[ 4] & ( N-1 ) );
      uint32_t j2 = 8 * ( x16.u32[ 8] & ( N-1 ) );
      uint32_t j3 = 8 * ( x16.u32[12] & ( N-1 ) );

      for ( int i = 0; i < 8; i++ )
      { 
         __m512i v10 = _mm512_mask_blend_epi32( 0x000f, V[ j1+i ], V[ j0+i ] );
         __m512i v32 = _mm512_mask_blend_epi32( 0x0f00, V[ j3+i ], V[ j2+i ] );
         X[i] = _mm512_xor_si512( X[i], _mm512_mask_blend_epi32( 0x00ff,
                                                                 v32, v10 ) );
      }

      salsa8_4way_simd128( &X[0], &X[4] );
      salsa8_4way_simd128( &X[4], &X[0] );
   }

   salsa_unshuffle_4way_simd128( X );
   salsa_unshuffle_4way_simd128( X+4 );
}
   
#endif // AVX512

#if defined(__AVX2__)

// 8x memory usage
// Tested OK but slow scrypt, very slow scryptn2, 2x4way is faster
// Crashes with large N & many threads, OOM? Use only for scrypt
// 8x32 interleaving
static void salsa8_8way( __m256i * const B, const __m256i * const C )
{
   __m256i x0 = B[ 0] = _mm256_xor_si256( B[ 0], C[ 0] );
   __m256i x1 = B[ 1] = _mm256_xor_si256( B[ 1], C[ 1] );
   __m256i x2 = B[ 2] = _mm256_xor_si256( B[ 2], C[ 2] );
   __m256i x3 = B[ 3] = _mm256_xor_si256( B[ 3], C[ 3] );
   __m256i x4 = B[ 4] = _mm256_xor_si256( B[ 4], C[ 4] );
   __m256i x5 = B[ 5] = _mm256_xor_si256( B[ 5], C[ 5] );
   __m256i x6 = B[ 6] = _mm256_xor_si256( B[ 6], C[ 6] );
   __m256i x7 = B[ 7] = _mm256_xor_si256( B[ 7], C[ 7] );
   __m256i x8 = B[ 8] = _mm256_xor_si256( B[ 8], C[ 8] );
   __m256i x9 = B[ 9] = _mm256_xor_si256( B[ 9], C[ 9] );
   __m256i xa = B[10] = _mm256_xor_si256( B[10], C[10] );
   __m256i xb = B[11] = _mm256_xor_si256( B[11], C[11] );
   __m256i xc = B[12] = _mm256_xor_si256( B[12], C[12] );
   __m256i xd = B[13] = _mm256_xor_si256( B[13], C[13] );
   __m256i xe = B[14] = _mm256_xor_si256( B[14], C[14] );
   __m256i xf = B[15] = _mm256_xor_si256( B[15], C[15] );

   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256

   SALSA_8ROUNDS;

   #undef ROL32
   #undef ADD32
   #undef XOR 

   B[ 0] = _mm256_add_epi32( B[ 0], x0 );
   B[ 1] = _mm256_add_epi32( B[ 1], x1 );
   B[ 2] = _mm256_add_epi32( B[ 2], x2 );
   B[ 3] = _mm256_add_epi32( B[ 3], x3 );
   B[ 4] = _mm256_add_epi32( B[ 4], x4 );
   B[ 5] = _mm256_add_epi32( B[ 5], x5 );
   B[ 6] = _mm256_add_epi32( B[ 6], x6 );
   B[ 7] = _mm256_add_epi32( B[ 7], x7 );
   B[ 8] = _mm256_add_epi32( B[ 8], x8 );
   B[ 9] = _mm256_add_epi32( B[ 9], x9 );
   B[10] = _mm256_add_epi32( B[10], xa );
   B[11] = _mm256_add_epi32( B[11], xb );
   B[12] = _mm256_add_epi32( B[12], xc );
   B[13] = _mm256_add_epi32( B[13], xd );
   B[14] = _mm256_add_epi32( B[14], xe );
   B[15] = _mm256_add_epi32( B[15], xf );
}

void scrypt_core_8way( __m256i *X, __m256i *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[n * 32], X, 128*8 );
      salsa8_8way( &X[ 0], &X[16] );
      salsa8_8way( &X[16], &X[ 0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      m256_ovly *vptr[8];   // pointer to V offset for each lane 
      m256_ovly *x16 = (m256_ovly*)(&X[16]);

      // create pointers to V for each lane using data from each lane of X[16]
      // as index.
      for ( int l = 0; l < 8; l++ )
      {
         uint32_t xl = (*x16).u32[l];
         vptr[l] = (m256_ovly*)( &V[ 32 * ( xl & ( N-1 ) ) ] );
      }

      for ( int i = 0; i < 32; i++ )
      {
         m256_ovly v;    // V value assembled from different indexes
         for ( int l = 0; l < 8; l++ )
            v.u32[l] = ( *(vptr[l] +i ) ) .u32[l];
         X[i] = _mm256_xor_si256( X[i], v.m256 );
      }

      salsa8_8way( &X[ 0], &X[16] );
      salsa8_8way( &X[16], &X[ 0] );
   }
}

// 2x memory usage
// Working
// Essentially Pooler 6way
// 2x128 interleaved simd128
//   ------- lane 1 -------    ------- lane 0 -------
// { l1x3, l1x2, l1x1, l1x0,   l0x3, l0x2, l0x1, l0x0 }   b[3]  B[ 7: 0]
// { l1x7, l1x6, l1x5, l1x4,   l0x7, l0x6, l0x5, l0x4 }   b[2]  B[15: 8]
// { l1xb, l1xa, l1c9, l1x8,   l0xb, l0xa, l0x9, l0x8 }   b[1]  B[23:16]
// { l1xf, l1xe, l1xd, l1xc,   l0xf, l0xe, l0xd, l0xc }   b[0]  B[31:24]

static inline void salsa_shuffle_2way_simd128( __m256i *X )
{
  __m256i t0 = _mm256_blend_epi32( X[0], X[1], 0xaa );
  __m256i t1 = _mm256_blend_epi32( X[0], X[1], 0x55 );
  __m256i t2 = _mm256_blend_epi32( X[2], X[3], 0xaa );
  __m256i t3 = _mm256_blend_epi32( X[2], X[3], 0x55 );
  X[0] = _mm256_blend_epi32( t0, t2, 0xcc );
  X[1] = _mm256_blend_epi32( t1, t3, 0x66 );
  X[2] = _mm256_blend_epi32( t0, t2, 0x33 );
  X[3] = _mm256_blend_epi32( t1, t3, 0x99 );
}

static inline void salsa_unshuffle_2way_simd128( __m256i *X )
{
  __m256i t0 = _mm256_blend_epi32( X[0], X[2], 0xcc );
  __m256i t1 = _mm256_blend_epi32( X[0], X[2], 0x33 );
  __m256i t2 = _mm256_blend_epi32( X[1], X[3], 0x66 );
  __m256i t3 = _mm256_blend_epi32( X[1], X[3], 0x99 );
  X[0] = _mm256_blend_epi32( t0, t2, 0xaa );
  X[1] = _mm256_blend_epi32( t0, t2, 0x55 );
  X[2] = _mm256_blend_epi32( t1, t3, 0xaa );
  X[3] = _mm256_blend_epi32( t1, t3, 0x55 );
}

static void salsa8_2way_simd128( __m256i * const B, const __m256i * const C)
{
   __m256i X0, X1, X2, X3;

   X0 = B[0] = _mm256_xor_si256( B[0], C[0] );
   X1 = B[1] = _mm256_xor_si256( B[1], C[1] );
   X2 = B[2] = _mm256_xor_si256( B[2], C[2] );
   X3 = B[3] = _mm256_xor_si256( B[3], C[3] );

   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll128_32  // shuffle within 128 bit lanes
   #define ROR_1X32    mm256_shuflr128_32
   #define SWAP_64     mm256_swap128_64
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256

   SALSA_8ROUNDS_SIMD128;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 

   B[0] = _mm256_add_epi32( B[0], X0 );
   B[1] = _mm256_add_epi32( B[1], X1 );
   B[2] = _mm256_add_epi32( B[2], X2 );
   B[3] = _mm256_add_epi32( B[3], X3 );
}

void scrypt_core_2way_simd128( __m256i *X, __m256i *V, const uint32_t N )
{
   salsa_shuffle_2way_simd128( X );
   salsa_shuffle_2way_simd128( X+4 );

   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[n * 8], X, 128*2 );
      salsa8_2way_simd128( &X[0], &X[4] );
      salsa8_2way_simd128( &X[4], &X[0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      m256_ovly x16;
      x16 = ( (m256_ovly*)X )[4];
      uint32_t j0 = 8 * ( x16.u32[0] & ( N-1 ) );
      uint32_t j1 = 8 * ( x16.u32[4] & ( N-1 ) );

      for ( int i = 0; i < 8; i++ )
         X[i] = _mm256_xor_si256( X[i], _mm256_blend_epi32( V[ j1+i ],
                                                            V[ j0+i ], 0x0f ) );

      salsa8_2way_simd128( &X[0], &X[4] );
      salsa8_2way_simd128( &X[4], &X[0] );
   }

   salsa_unshuffle_2way_simd128( X );
   salsa_unshuffle_2way_simd128( X+4 );
}

// Working
// 2x128 interleaving
static void salsa8_2way_simd128_2buf( __m256i * const BA, __m256i * const BB,
      const __m256i * const CA, const __m256i * const CB )
{
   __m256i XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3;
   __m256i YA0, YA1, YA2, YA3, YB0, YB1, YB2, YB3;

   // mix C into B then shuffle B into X
   BA[0] = _mm256_xor_si256( BA[0], CA[0] );
   BB[0] = _mm256_xor_si256( BB[0], CB[0] );
   BA[1] = _mm256_xor_si256( BA[1], CA[1] );
   BB[1] = _mm256_xor_si256( BB[1], CB[1] );
   BA[2] = _mm256_xor_si256( BA[2], CA[2] );
   BB[2] = _mm256_xor_si256( BB[2], CB[2] );
   BA[3] = _mm256_xor_si256( BA[3], CA[3] );
   BB[3] = _mm256_xor_si256( BB[3], CB[3] );

   YA0 = _mm256_blend_epi32( BA[1], BA[0], 0x11 );
   YB0 = _mm256_blend_epi32( BB[1], BB[0], 0x11 );
   XA0 = _mm256_blend_epi32( BA[3], BA[2], 0x44 );
   XB0 = _mm256_blend_epi32( BB[3], BB[2], 0x44 );
   XA0 = _mm256_blend_epi32( XA0, YA0, 0x33);
   XB0 = _mm256_blend_epi32( XB0, YB0, 0x33);

   YA0 = _mm256_blend_epi32( BA[2], BA[1], 0x11 );
   YB0 = _mm256_blend_epi32( BB[2], BB[1], 0x11 );
   XA1 = _mm256_blend_epi32( BA[0], BA[3], 0x44 );
   XB1 = _mm256_blend_epi32( BB[0], BB[3], 0x44 );
   XA1 = _mm256_blend_epi32( XA1, YA0, 0x33 );
   XB1 = _mm256_blend_epi32( XB1, YB0, 0x33 );

   YA0 = _mm256_blend_epi32( BA[3], BA[2], 0x11 );
   YB0 = _mm256_blend_epi32( BB[3], BB[2], 0x11 );
   XA2 = _mm256_blend_epi32( BA[1], BA[0], 0x44 );
   XB2 = _mm256_blend_epi32( BB[1], BB[0], 0x44 );
   XA2 = _mm256_blend_epi32( XA2, YA0, 0x33 );
   XB2 = _mm256_blend_epi32( XB2, YB0, 0x33 );

   YA0 = _mm256_blend_epi32( BA[0], BA[3], 0x11 );
   YB0 = _mm256_blend_epi32( BB[0], BB[3], 0x11 );
   XA3 = _mm256_blend_epi32( BA[2], BA[1], 0x44 );
   XB3 = _mm256_blend_epi32( BB[2], BB[1], 0x44 );
   XA3 = _mm256_blend_epi32( XA3, YA0, 0x33 );
   XB3 = _mm256_blend_epi32( XB3, YB0, 0x33 );
   
   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll128_32  // shuffle within 128 bit lanes
   #define ROR_1X32    mm256_shuflr128_32
   #define SWAP_64     mm256_swap128_64
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256
   #define TYPE        __m256i

   SALSA_8ROUNDS_SIMD128_2BUF;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR
   #undef TYPE

   YA0 = _mm256_blend_epi32( XA0, XA1, 0x88 );
   YB0 = _mm256_blend_epi32( XB0, XB1, 0x88 );
   YA1 = _mm256_blend_epi32( XA0, XA1, 0x11 );
   YB1 = _mm256_blend_epi32( XB0, XB1, 0x11 );
   YA2 = _mm256_blend_epi32( XA0, XA1, 0x22 );
   YB2 = _mm256_blend_epi32( XB0, XB1, 0x22 );
   YA3 = _mm256_blend_epi32( XA0, XA1, 0x44 );
   YB3 = _mm256_blend_epi32( XB0, XB1, 0x44 );

   YA0 = _mm256_blend_epi32( YA0, XA2, 0x44 );
   YB0 = _mm256_blend_epi32( YB0, XB2, 0x44 );
   YA1 = _mm256_blend_epi32( YA1, XA2, 0x88 );
   YB1 = _mm256_blend_epi32( YB1, XB2, 0x88 );
   YA2 = _mm256_blend_epi32( YA2, XA2, 0x11 );
   YB2 = _mm256_blend_epi32( YB2, XB2, 0x11 );
   YA3 = _mm256_blend_epi32( YA3, XA2, 0x22 );
   YB3 = _mm256_blend_epi32( YB3, XB2, 0x22 );

   YA0 = _mm256_blend_epi32( YA0, XA3, 0x22 );
   YB0 = _mm256_blend_epi32( YB0, XB3, 0x22 );
   YA1 = _mm256_blend_epi32( YA1, XA3, 0x44 );
   YB1 = _mm256_blend_epi32( YB1, XB3, 0x44 );
   YA2 = _mm256_blend_epi32( YA2, XA3, 0x88 );
   YB2 = _mm256_blend_epi32( YB2, XB3, 0x88 );
   YA3 = _mm256_blend_epi32( YA3, XA3, 0x11 );
   YB3 = _mm256_blend_epi32( YB3, XB3, 0x11 );

   BA[0] = _mm256_add_epi32( BA[0], YA0 );
   BB[0] = _mm256_add_epi32( BB[0], YB0 );
   BA[1] = _mm256_add_epi32( BA[1], YA1 );
   BB[1] = _mm256_add_epi32( BB[1], YB1 );
   BA[2] = _mm256_add_epi32( BA[2], YA2 );
   BB[2] = _mm256_add_epi32( BB[2], YB2 );
   BA[3] = _mm256_add_epi32( BA[3], YA3 );
   BB[3] = _mm256_add_epi32( BB[3], YB3 );

}

void scrypt_core_2way_simd128_2buf( __m256i *X, __m256i *V, const uint32_t N )
{
   __m256i *X0 = X;
   __m256i *X1 = X + 8;
   __m256i *V0 = V;
   __m256i *V1 = V + 8*N;

   for ( int n = 0; n < N; n++ )
   {
      for ( int i = 0; i < 8; i++ )
      {
         _mm256_stream_si256( V0 + n*8 + i, X0[i] );   
         _mm256_stream_si256( V1 + n*8 + i, X1[i] );      
      }
      salsa8_2way_simd128_2buf( &X0[0], &X1[0], &X0[4], &X1[4] );
      salsa8_2way_simd128_2buf( &X0[4], &X1[4], &X0[0], &X1[0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      const m256_ovly x16a = ( (m256_ovly*)X0 )[4];
      const m256_ovly x16b = ( (m256_ovly*)X1 )[4];
      
      const uint32_t j0a = 8 * ( x16a.u32[0] & ( N-1 ) );
      const uint32_t j0b = 8 * ( x16b.u32[0] & ( N-1 ) );
      const uint32_t j1a = 8 * ( x16a.u32[4] & ( N-1 ) );
      const uint32_t j1b = 8 * ( x16b.u32[4] & ( N-1 ) );

      for ( int i = 0; i < 8; i++ )
      {
         const __m256i V0j0a = _mm256_stream_load_si256( V0 + j0a + i );
         const __m256i V0j1a = _mm256_stream_load_si256( V0 + j1a + i );
         const __m256i V1j0b = _mm256_stream_load_si256( V1 + j0b + i );
         const __m256i V1j1b = _mm256_stream_load_si256( V1 + j1b + i );
         X0[i] = _mm256_xor_si256( X0[i],
                       _mm256_blend_epi32( V0j1a, V0j0a, 0x0f ) );
         X1[i] = _mm256_xor_si256( X1[i],
                       _mm256_blend_epi32( V1j1b, V1j0b, 0x0f ) );
      }

      salsa8_2way_simd128_2buf( &X0[0], &X1[0], &X0[4], &X1[4] );
      salsa8_2way_simd128_2buf( &X0[4], &X1[4], &X0[0], &X1[0] );
   }
}

// Triple buffered, not up to date, needs stream optimization
// 2x128 interleaving
static void salsa8_2way_simd128_3buf( __m256i * const BA, __m256i * const BB,
      __m256i * const BC, const __m256i * const CA, const __m256i * const CB,
      const __m256i * const CC )
{
   __m256i XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3, XC0, XC1, XC2, XC3;
   __m256i YA0, YA1, YA2, YA3, YB0, YB1, YB2, YB3, YC0, YC1, YC2, YC3;

   // mix C into B then shuffle B into X
   BA[0] = _mm256_xor_si256( BA[0], CA[0] );
   BB[0] = _mm256_xor_si256( BB[0], CB[0] );
   BC[0] = _mm256_xor_si256( BC[0], CC[0] );
   BA[1] = _mm256_xor_si256( BA[1], CA[1] );
   BB[1] = _mm256_xor_si256( BB[1], CB[1] );
   BC[1] = _mm256_xor_si256( BC[1], CC[1] );
   BA[2] = _mm256_xor_si256( BA[2], CA[2] );
   BB[2] = _mm256_xor_si256( BB[2], CB[2] );
   BC[2] = _mm256_xor_si256( BC[2], CC[2] );
   BA[3] = _mm256_xor_si256( BA[3], CA[3] );
   BB[3] = _mm256_xor_si256( BB[3], CB[3] );
   BC[3] = _mm256_xor_si256( BC[3], CC[3] );

   YA0 = _mm256_blend_epi32( BA[1], BA[0], 0x11 );
   YB0 = _mm256_blend_epi32( BB[1], BB[0], 0x11 );
   YC0 = _mm256_blend_epi32( BC[1], BC[0], 0x11 );
   XA0 = _mm256_blend_epi32( BA[3], BA[2], 0x44 );
   XB0 = _mm256_blend_epi32( BB[3], BB[2], 0x44 );
   XC0 = _mm256_blend_epi32( BC[3], BC[2], 0x44 );
   XA0 = _mm256_blend_epi32( XA0, YA0, 0x33);
   XB0 = _mm256_blend_epi32( XB0, YB0, 0x33);
   XC0 = _mm256_blend_epi32( XC0, YC0, 0x33);

   YA0 = _mm256_blend_epi32( BA[2], BA[1], 0x11 );
   YB0 = _mm256_blend_epi32( BB[2], BB[1], 0x11 );
   YC0 = _mm256_blend_epi32( BC[2], BC[1], 0x11 );
   XA1 = _mm256_blend_epi32( BA[0], BA[3], 0x44 );
   XB1 = _mm256_blend_epi32( BB[0], BB[3], 0x44 );
   XC1 = _mm256_blend_epi32( BC[0], BC[3], 0x44 );
   XA1 = _mm256_blend_epi32( XA1, YA0, 0x33 );
   XB1 = _mm256_blend_epi32( XB1, YB0, 0x33 );
   XC1 = _mm256_blend_epi32( XC1, YC0, 0x33 );

   YA0 = _mm256_blend_epi32( BA[3], BA[2], 0x11 );
   YB0 = _mm256_blend_epi32( BB[3], BB[2], 0x11 );
   YC0 = _mm256_blend_epi32( BC[3], BC[2], 0x11 );
   XA2 = _mm256_blend_epi32( BA[1], BA[0], 0x44 );
   XB2 = _mm256_blend_epi32( BB[1], BB[0], 0x44 );
   XC2 = _mm256_blend_epi32( BC[1], BC[0], 0x44 );
   XA2 = _mm256_blend_epi32( XA2, YA0, 0x33 );
   XB2 = _mm256_blend_epi32( XB2, YB0, 0x33 );
   XC2 = _mm256_blend_epi32( XC2, YC0, 0x33 );

   YA0 = _mm256_blend_epi32( BA[0], BA[3], 0x11 );
   YB0 = _mm256_blend_epi32( BB[0], BB[3], 0x11 );
   YC0 = _mm256_blend_epi32( BC[0], BC[3], 0x11 );
   XA3 = _mm256_blend_epi32( BA[2], BA[1], 0x44 );
   XB3 = _mm256_blend_epi32( BB[2], BB[1], 0x44 );
   XC3 = _mm256_blend_epi32( BC[2], BC[1], 0x44 );
   XA3 = _mm256_blend_epi32( XA3, YA0, 0x33 );
   XB3 = _mm256_blend_epi32( XB3, YB0, 0x33 );
   XC3 = _mm256_blend_epi32( XC3, YC0, 0x33 );

   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll128_32  // shuffle within 128 bit lanes
   #define ROR_1X32    mm256_shuflr128_32
   #define SWAP_64     mm256_swap128_64
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256
   #define TYPE        __m256i

   SALSA_8ROUNDS_SIMD128_3BUF;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR
   #undef TYPE

   YA0 = _mm256_blend_epi32( XA0, XA1, 0x88 );
   YB0 = _mm256_blend_epi32( XB0, XB1, 0x88 );
   YC0 = _mm256_blend_epi32( XC0, XC1, 0x88 );
   YA1 = _mm256_blend_epi32( XA0, XA1, 0x11 );
   YB1 = _mm256_blend_epi32( XB0, XB1, 0x11 );
   YC1 = _mm256_blend_epi32( XC0, XC1, 0x11 );
   YA2 = _mm256_blend_epi32( XA0, XA1, 0x22 );
   YB2 = _mm256_blend_epi32( XB0, XB1, 0x22 );
   YC2 = _mm256_blend_epi32( XC0, XC1, 0x22 );
   YA3 = _mm256_blend_epi32( XA0, XA1, 0x44 );
   YB3 = _mm256_blend_epi32( XB0, XB1, 0x44 );
   YC3 = _mm256_blend_epi32( XC0, XC1, 0x44 );

   YA0 = _mm256_blend_epi32( YA0, XA2, 0x44 );
   YB0 = _mm256_blend_epi32( YB0, XB2, 0x44 );
   YC0 = _mm256_blend_epi32( YC0, XC2, 0x44 );
   YA1 = _mm256_blend_epi32( YA1, XA2, 0x88 );
   YB1 = _mm256_blend_epi32( YB1, XB2, 0x88 );
   YC1 = _mm256_blend_epi32( YC1, XC2, 0x88 );
   YA2 = _mm256_blend_epi32( YA2, XA2, 0x11 );
   YB2 = _mm256_blend_epi32( YB2, XB2, 0x11 );
   YC2 = _mm256_blend_epi32( YC2, XC2, 0x11 );
   YA3 = _mm256_blend_epi32( YA3, XA2, 0x22 );
   YB3 = _mm256_blend_epi32( YB3, XB2, 0x22 );
   YC3 = _mm256_blend_epi32( YC3, XC2, 0x22 );

   YA0 = _mm256_blend_epi32( YA0, XA3, 0x22 );
   YB0 = _mm256_blend_epi32( YB0, XB3, 0x22 );
   YC0 = _mm256_blend_epi32( YC0, XC3, 0x22 );
   YA1 = _mm256_blend_epi32( YA1, XA3, 0x44 );
   YB1 = _mm256_blend_epi32( YB1, XB3, 0x44 );
   YC1 = _mm256_blend_epi32( YC1, XC3, 0x44 );
   YA2 = _mm256_blend_epi32( YA2, XA3, 0x88 );
   YB2 = _mm256_blend_epi32( YB2, XB3, 0x88 );
   YC2 = _mm256_blend_epi32( YC2, XC3, 0x88 );
   YA3 = _mm256_blend_epi32( YA3, XA3, 0x11 );
   YB3 = _mm256_blend_epi32( YB3, XB3, 0x11 );
   YC3 = _mm256_blend_epi32( YC3, XC3, 0x11 );

   BA[0] = _mm256_add_epi32( BA[0], YA0 );
   BB[0] = _mm256_add_epi32( BB[0], YB0 );
   BC[0] = _mm256_add_epi32( BC[0], YC0 );
   BA[1] = _mm256_add_epi32( BA[1], YA1 );
   BB[1] = _mm256_add_epi32( BB[1], YB1 );
   BC[1] = _mm256_add_epi32( BC[1], YC1 );
   BA[2] = _mm256_add_epi32( BA[2], YA2 );
   BB[2] = _mm256_add_epi32( BB[2], YB2 );
   BC[2] = _mm256_add_epi32( BC[2], YC2 );
   BA[3] = _mm256_add_epi32( BA[3], YA3 );
   BB[3] = _mm256_add_epi32( BB[3], YB3 );
   BC[3] = _mm256_add_epi32( BC[3], YC3 );

}

void scrypt_core_2way_simd128_3buf( __m256i *X, __m256i *V, const uint32_t N )
{
   __m256i *X0 = X;
   __m256i *X1 = X+8;
   __m256i *X2 = X+16;
   __m256i *V0 = V;
   __m256i *V1 = V + 8*N;
   __m256i *V2 = V + 16*N;

   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V0[n * 8], X0, 128*2 );
      memcpy( &V1[n * 8], X1, 128*2 );
      memcpy( &V2[n * 8], X2, 128*2 );
      salsa8_2way_simd128_3buf( &X0[0], &X1[0], &X2[0],
                                &X0[4], &X1[4], &X2[4] );
      salsa8_2way_simd128_3buf( &X0[4], &X1[4], &X2[4],
                                &X0[0], &X1[0], &X2[0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      m256_ovly x16a, x16b, x16c;
      x16a = ( (m256_ovly*)X0 )[4];
      x16b = ( (m256_ovly*)X1 )[4];
      x16c = ( (m256_ovly*)X2 )[4];

      uint32_t j0a = 8 * ( x16a.u32[0] & ( N-1 ) );
      uint32_t j0b = 8 * ( x16b.u32[0] & ( N-1 ) );
      uint32_t j0c = 8 * ( x16c.u32[0] & ( N-1 ) );
      uint32_t j1a = 8 * ( x16a.u32[4] & ( N-1 ) );
      uint32_t j1b = 8 * ( x16b.u32[4] & ( N-1 ) );
      uint32_t j1c = 8 * ( x16c.u32[4] & ( N-1 ) );

      for ( int i = 0; i < 8; i++ )
      {
         X0[i] = _mm256_xor_si256( X0[i],
                       _mm256_blend_epi32( V0[ j1a+i ], V0[ j0a+i ], 0x0f ) );
         X1[i] = _mm256_xor_si256( X1[i],
                       _mm256_blend_epi32( V1[ j1b+i ], V1[ j0b+i ], 0x0f ) );
         X2[i] = _mm256_xor_si256( X2[i],
                       _mm256_blend_epi32( V2[ j1c+i ], V2[ j0c+i ], 0x0f ) );
      }

      salsa8_2way_simd128_3buf( &X0[0], &X1[0], &X2[0], 
                                &X0[4], &X1[4], &X2[4] );
      salsa8_2way_simd128_3buf( &X0[4], &X1[4], &X2[4],  
                                &X0[0], &X1[0], &X2[0] );
   }
}


// 2x memory usage

// Tested OK, good speed
//
// Serial SIMD over 2 way parallel

// Uses uint64_t as a poorman's vector then applying linear SIMD to the
// pairs of data.
//
// Interleaving is standard 2 way.
// Use 64 bit shuffles but 32 bit arithmetic.

//  B = { lane1, lane0 }
//  b[i] = { B[4*i+3], B[4*i+2], B[4*i+1], B[4*i] }

// 2x32 interleaving
static void salsa8_simd128_2way( uint64_t *b, const uint64_t *c )
{
   __m256i X0, X1, X2, X3, Y0, Y1, Y2, Y3;
   __m256i *B = (__m256i*)b; 
   const __m256i *C = (const __m256i*)c;

   // mix C into B then shuffle B into X
   B[0] = _mm256_xor_si256( B[0], C[0] );
   B[1] = _mm256_xor_si256( B[1], C[1] );
   B[2] = _mm256_xor_si256( B[2], C[2] );
   B[3] = _mm256_xor_si256( B[3], C[3] );

   Y0 = _mm256_blend_epi32( B[1], B[0], 0x03 );
   X0 = _mm256_blend_epi32( B[3], B[2], 0x30 );
   X0 = _mm256_blend_epi32( X0, Y0, 0x0f);

   Y0 = _mm256_blend_epi32( B[2], B[1], 0x03 );
   X1 = _mm256_blend_epi32( B[0], B[3], 0x30 );
   X1 = _mm256_blend_epi32( X1, Y0, 0x0f );

   Y0 = _mm256_blend_epi32( B[3], B[2], 0x03 );
   X2 = _mm256_blend_epi32( B[1], B[0], 0x30 );
   X2 = _mm256_blend_epi32( X2, Y0, 0x0f );

   Y0 = _mm256_blend_epi32( B[0], B[3], 0x03 );
   X3 = _mm256_blend_epi32( B[2], B[1], 0x30 );
   X3 = _mm256_blend_epi32( X3, Y0, 0x0f );
   
   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll_64
   #define ROR_1X32    mm256_shuflr_64
   #define SWAP_64     mm256_swap_128
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256

   SALSA_8ROUNDS_SIMD128;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 

   Y0 = _mm256_blend_epi32( X0, X1, 0xc0 );
   Y1 = _mm256_blend_epi32( X0, X1, 0x03 );
   Y2 = _mm256_blend_epi32( X0, X1, 0x0c );
   Y3 = _mm256_blend_epi32( X0, X1, 0x30 );

   Y0 = _mm256_blend_epi32( Y0, X2, 0x30 );
   Y1 = _mm256_blend_epi32( Y1, X2, 0xc0 );
   Y2 = _mm256_blend_epi32( Y2, X2, 0x03 );
   Y3 = _mm256_blend_epi32( Y3, X2, 0x0c );

   Y0 = _mm256_blend_epi32( Y0, X3, 0x0c );
   Y1 = _mm256_blend_epi32( Y1, X3, 0x30 );
   Y2 = _mm256_blend_epi32( Y2, X3, 0xc0 );
   Y3 = _mm256_blend_epi32( Y3, X3, 0x03 );

   B[0] = _mm256_add_epi32( B[0], Y0 );
   B[1] = _mm256_add_epi32( B[1], Y1 );
   B[2] = _mm256_add_epi32( B[2], Y2 );
   B[3] = _mm256_add_epi32( B[3], Y3 );

}

// data format for 256 bits: 4 * ( 2 way 32 )
// { l1d3, l0d3, l1d2, l0d2, l1d1, l0d1, l1d0, l0d0 }

void scrypt_core_simd128_2way( uint64_t *X, uint64_t *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      for ( int i = 0; i < 8; i++ )
         _mm256_stream_si256( (__m256i*)V + n*8 + i, casti_m256i( X, i ) );
      salsa8_simd128_2way( &X[ 0], &X[16] );
      salsa8_simd128_2way( &X[16], &X[ 0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      // need 2 J's
      const uint32_t j0 = 32 * ( (uint32_t)( X[16]       ) & ( N-1 ) );
      const uint32_t j1 = 32 * ( (uint32_t)( X[16] >> 32 ) & ( N-1 ) );

      for ( int i = 0; i < 32; i++ )
         X[i] ^= ( ( V[ j1 + i ] & 0xffffffff00000000 )
                 | ( V[ j0 + i ] & 0x00000000ffffffff ) );  

      salsa8_simd128_2way( &X[ 0], &X[16] );
      salsa8_simd128_2way( &X[16], &X[ 0] );
   }
}

// Double buffered, 4x memory usage
// 2x32 interleaving
static void salsa8_simd128_2way_2buf( uint64_t *ba, uint64_t *bb, 
                                      const uint64_t *ca, const uint64_t *cb )
{
   __m256i XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3;
   __m256i YA0, YA1, YA2, YA3, YB0, YB1, YB2, YB3;
   __m256i *BA = (__m256i*)ba; 
   __m256i *BB = (__m256i*)bb; 
   const __m256i *CA = (const __m256i*)ca;
   const __m256i *CB = (const __m256i*)cb;

   // mix C into B then shuffle B into X
   BA[0] = _mm256_xor_si256( BA[0], CA[0] );
   BB[0] = _mm256_xor_si256( BB[0], CB[0] );
   BA[1] = _mm256_xor_si256( BA[1], CA[1] );
   BB[1] = _mm256_xor_si256( BB[1], CB[1] );
   BA[2] = _mm256_xor_si256( BA[2], CA[2] );
   BB[2] = _mm256_xor_si256( BB[2], CB[2] );
   BA[3] = _mm256_xor_si256( BA[3], CA[3] );
   BB[3] = _mm256_xor_si256( BB[3], CB[3] );

   YA0 = _mm256_blend_epi32( BA[1], BA[0], 0x03 );
   YB0 = _mm256_blend_epi32( BB[1], BB[0], 0x03 );
   XA0 = _mm256_blend_epi32( BA[3], BA[2], 0x30 );
   XB0 = _mm256_blend_epi32( BB[3], BB[2], 0x30 );
   XA0 = _mm256_blend_epi32( XA0, YA0, 0x0f);
   XB0 = _mm256_blend_epi32( XB0, YB0, 0x0f);

   YA0 = _mm256_blend_epi32( BA[2], BA[1], 0x03 );
   YB0 = _mm256_blend_epi32( BB[2], BB[1], 0x03 );
   XA1 = _mm256_blend_epi32( BA[0], BA[3], 0x30 );
   XB1 = _mm256_blend_epi32( BB[0], BB[3], 0x30 );
   XA1 = _mm256_blend_epi32( XA1, YA0, 0x0f );
   XB1 = _mm256_blend_epi32( XB1, YB0, 0x0f );

   YA0 = _mm256_blend_epi32( BA[3], BA[2], 0x03 );
   YB0 = _mm256_blend_epi32( BB[3], BB[2], 0x03 );
   XA2 = _mm256_blend_epi32( BA[1], BA[0], 0x30 );
   XB2 = _mm256_blend_epi32( BB[1], BB[0], 0x30 );
   XA2 = _mm256_blend_epi32( XA2, YA0, 0x0f );
   XB2 = _mm256_blend_epi32( XB2, YB0, 0x0f );

   YA0 = _mm256_blend_epi32( BA[0], BA[3], 0x03 );
   YB0 = _mm256_blend_epi32( BB[0], BB[3], 0x03 );
   XA3 = _mm256_blend_epi32( BA[2], BA[1], 0x30 );
   XB3 = _mm256_blend_epi32( BB[2], BB[1], 0x30 );
   XA3 = _mm256_blend_epi32( XA3, YA0, 0x0f );
   XB3 = _mm256_blend_epi32( XB3, YB0, 0x0f );

   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll_64
   #define ROR_1X32    mm256_shuflr_64
   #define SWAP_64     mm256_swap_128
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256
   #define TYPE        __m256i

   SALSA_8ROUNDS_SIMD128_2BUF;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 
   #undef TYPE

   YA0 = _mm256_blend_epi32( XA0, XA1, 0xc0 );
   YB0 = _mm256_blend_epi32( XB0, XB1, 0xc0 );
   YA1 = _mm256_blend_epi32( XA0, XA1, 0x03 );
   YB1 = _mm256_blend_epi32( XB0, XB1, 0x03 );
   YA2 = _mm256_blend_epi32( XA0, XA1, 0x0c );
   YB2 = _mm256_blend_epi32( XB0, XB1, 0x0c );
   YA3 = _mm256_blend_epi32( XA0, XA1, 0x30 );
   YB3 = _mm256_blend_epi32( XB0, XB1, 0x30 );

   YA0 = _mm256_blend_epi32( YA0, XA2, 0x30 );
   YB0 = _mm256_blend_epi32( YB0, XB2, 0x30 );
   YA1 = _mm256_blend_epi32( YA1, XA2, 0xc0 );
   YB1 = _mm256_blend_epi32( YB1, XB2, 0xc0 );
   YA2 = _mm256_blend_epi32( YA2, XA2, 0x03 );
   YB2 = _mm256_blend_epi32( YB2, XB2, 0x03 );
   YA3 = _mm256_blend_epi32( YA3, XA2, 0x0c );
   YB3 = _mm256_blend_epi32( YB3, XB2, 0x0c );

   YA0 = _mm256_blend_epi32( YA0, XA3, 0x0c );
   YB0 = _mm256_blend_epi32( YB0, XB3, 0x0c );
   YA1 = _mm256_blend_epi32( YA1, XA3, 0x30 );
   YB1 = _mm256_blend_epi32( YB1, XB3, 0x30 );
   YA2 = _mm256_blend_epi32( YA2, XA3, 0xc0 );
   YB2 = _mm256_blend_epi32( YB2, XB3, 0xc0 );
   YA3 = _mm256_blend_epi32( YA3, XA3, 0x03 );
   YB3 = _mm256_blend_epi32( YB3, XB3, 0x03 );

   BA[0] = _mm256_add_epi32( BA[0], YA0 );
   BB[0] = _mm256_add_epi32( BB[0], YB0 );
   BA[1] = _mm256_add_epi32( BA[1], YA1 );
   BB[1] = _mm256_add_epi32( BB[1], YB1 );
   BA[2] = _mm256_add_epi32( BA[2], YA2 );
   BB[2] = _mm256_add_epi32( BB[2], YB2 );
   BA[3] = _mm256_add_epi32( BA[3], YA3 );
   BB[3] = _mm256_add_epi32( BB[3], YB3 );

}

void scrypt_core_simd128_2way_2buf( uint64_t *X, uint64_t *V, const uint32_t N )

{
   uint64_t *X0 = X;
   uint64_t *X1 = X+32;
   uint64_t *V0 = V;
   uint64_t *V1 = V + 32*N;

   for ( int n = 0; n < N; n++ )
   {
      for ( int i = 0; i < 8; i++ )
      {
         _mm256_stream_si256( (__m256i*)V0 + n*8 + i, casti_m256i( X0, i ) );
         _mm256_stream_si256( (__m256i*)V1 + n*8 + i, casti_m256i( X1, i ) );
      }
      salsa8_simd128_2way_2buf( &X0[ 0], &X1[ 0], &X0[16], &X1[16] );
      salsa8_simd128_2way_2buf( &X0[16], &X1[16], &X0[ 0], &X1[ 0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      // need 4 J's
      const uint32_t j0l = 32 * ( (const uint32_t)( X0[16]       ) & ( N-1 ) );
      const uint32_t j0h = 32 * ( (const uint32_t)( X0[16] >> 32 ) & ( N-1 ) );
      const uint32_t j1l = 32 * ( (const uint32_t)( X1[16]       ) & ( N-1 ) );
      const uint32_t j1h = 32 * ( (const uint32_t)( X1[16] >> 32 ) & ( N-1 ) );
         
      for ( int i = 0; i < 32; i++ )
      {
         X0[i] ^= ( ( V0[ j0h + i ] & 0xffffffff00000000 )
                  | ( V0[ j0l + i ] & 0x00000000ffffffff ) );
         X1[i] ^= ( ( V1[ j1h + i ] & 0xffffffff00000000 )
                  | ( V1[ j1l + i ] & 0x00000000ffffffff ) );
      }
      salsa8_simd128_2way_2buf( &X0[ 0], &X1[ 0], &X0[16], &X1[16] );
      salsa8_simd128_2way_2buf( &X0[16], &X1[16], &X0[ 0], &X1[ 0] );
   }
}

// Working, deprecated, not up to date
// Triple buffered 2 way, 6x memory usage
// 2x32 interleaving
static void salsa8_simd128_2way_3buf( uint64_t *BA, uint64_t *BB,
          uint64_t *BC, const uint64_t *CA, const uint64_t *CB,
          const uint64_t *CC )
{
   __m256i XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3,
           XC0, XC1, XC2, XC3;
   __m256i *ba = (__m256i*)BA;
   __m256i *bb = (__m256i*)BB;
   __m256i *bc = (__m256i*)BC;
   const __m256i *ca = (const __m256i*)CA;
   const __m256i *cb = (const __m256i*)CB;
   const __m256i *cc = (const __m256i*)CC;
   m256_ovly ya[4], yb[4], yc[4],
             za[4], zb[4], zc[4];

   // mix C into B then shuffle B into X
   ba[0] = _mm256_xor_si256( ba[0], ca[0] );
   bb[0] = _mm256_xor_si256( bb[0], cb[0] );
   bc[0] = _mm256_xor_si256( bc[0], cc[0] );
   ba[1] = _mm256_xor_si256( ba[1], ca[1] );
   bb[1] = _mm256_xor_si256( bb[1], cb[1] );
   bc[1] = _mm256_xor_si256( bc[1], cc[1] );
   ba[2] = _mm256_xor_si256( ba[2], ca[2] );
   bb[2] = _mm256_xor_si256( bb[2], cb[2] );
   bc[2] = _mm256_xor_si256( bc[2], cc[2] );
   ba[3] = _mm256_xor_si256( ba[3], ca[3] );
   bb[3] = _mm256_xor_si256( bb[3], cb[3] );
   bc[3] = _mm256_xor_si256( bc[3], cc[3] );

   XA0 = _mm256_set_epi64x( BA[15], BA[10], BA[ 5], BA[ 0] );
   XB0 = _mm256_set_epi64x( BB[15], BB[10], BB[ 5], BB[ 0] );
   XC0 = _mm256_set_epi64x( BC[15], BC[10], BC[ 5], BC[ 0] );
   XA1 = _mm256_set_epi64x( BA[ 3], BA[14], BA[ 9], BA[ 4] );
   XB1 = _mm256_set_epi64x( BB[ 3], BB[14], BB[ 9], BB[ 4] );
   XC1 = _mm256_set_epi64x( BC[ 3], BC[14], BC[ 9], BC[ 4] );
   XA2 = _mm256_set_epi64x( BA[ 7], BA[ 2], BA[13], BA[ 8] );
   XB2 = _mm256_set_epi64x( BB[ 7], BB[ 2], BB[13], BB[ 8] );
   XC2 = _mm256_set_epi64x( BC[ 7], BC[ 2], BC[13], BC[ 8] );
   XA3 = _mm256_set_epi64x( BA[11], BA[ 6], BA[ 1], BA[12] );
   XB3 = _mm256_set_epi64x( BB[11], BB[ 6], BB[ 1], BB[12] );
   XC3 = _mm256_set_epi64x( BC[11], BC[ 6], BC[ 1], BC[12] );

   // define targets for macros used in round function template
   #define ROL_1X32    mm256_shufll_64
   #define ROR_1X32    mm256_shuflr_64
   #define SWAP_64     mm256_swap_128
   #define ROL32       mm256_rol_32
   #define ADD32       _mm256_add_epi32
   #define XOR         _mm256_xor_si256
   #define TYPE        __m256i

   SALSA_8ROUNDS_FINAL_SIMD128_3BUF;

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 
   #undef TYPE

   ya[0].m256 = XA0;    yb[0].m256 = XB0;
   yc[0].m256 = XC0;
   ya[1].m256 = XA1;    yb[1].m256 = XB1;
   yc[1].m256 = XC1;
   ya[2].m256 = XA2;    yb[2].m256 = XB2;
   yc[2].m256 = XC2;
   ya[3].m256 = XA3;    yb[3].m256 = XB3;
   yc[3].m256 = XC3;

   za[0].u64[0] = ya[0].u64[0];
   zb[0].u64[0] = yb[0].u64[0];
   zc[0].u64[0] = yc[0].u64[0];
   za[0].u64[3] = ya[1].u64[0];
   zb[0].u64[3] = yb[1].u64[0];
   zc[0].u64[3] = yc[1].u64[0];
   za[0].u64[2] = ya[2].u64[0];
   zb[0].u64[2] = yb[2].u64[0];
   zc[0].u64[2] = yc[2].u64[0];
   za[0].u64[1] = ya[3].u64[0];
   zb[0].u64[1] = yb[3].u64[0];
   zc[0].u64[1] = yc[3].u64[0];

   za[1].u64[1] = ya[0].u64[1];
   zb[1].u64[1] = yb[0].u64[1];
   zc[1].u64[1] = yc[0].u64[1];
   za[1].u64[0] = ya[1].u64[1];
   zb[1].u64[0] = yb[1].u64[1];
   zc[1].u64[0] = yc[1].u64[1];
   za[1].u64[3] = ya[2].u64[1];
   zb[1].u64[3] = yb[2].u64[1];
   zc[1].u64[3] = yc[2].u64[1];
   za[1].u64[2] = ya[3].u64[1];
   zb[1].u64[2] = yb[3].u64[1];
   zc[1].u64[2] = yc[3].u64[1];

   za[2].u64[2] = ya[0].u64[2];
   zb[2].u64[2] = yb[0].u64[2];
   zc[2].u64[2] = yc[0].u64[2];
   za[2].u64[1] = ya[1].u64[2];
   zb[2].u64[1] = yb[1].u64[2];
   zc[2].u64[1] = yc[1].u64[2];
   za[2].u64[0] = ya[2].u64[2];
   zb[2].u64[0] = yb[2].u64[2];
   zc[2].u64[0] = yc[2].u64[2];
   za[2].u64[3] = ya[3].u64[2];
   zb[2].u64[3] = yb[3].u64[2];
   zc[2].u64[3] = yc[3].u64[2];

   za[3].u64[3] = ya[0].u64[3];
   zb[3].u64[3] = yb[0].u64[3];
   zc[3].u64[3] = yc[0].u64[3];
   za[3].u64[2] = ya[1].u64[3];
   zb[3].u64[2] = yb[1].u64[3];
   zc[3].u64[2] = yc[1].u64[3];
   za[3].u64[1] = ya[2].u64[3];
   zb[3].u64[1] = yb[2].u64[3];
   zc[3].u64[1] = yc[2].u64[3];
   za[3].u64[0] = ya[3].u64[3];
   zb[3].u64[0] = yb[3].u64[3];
   zc[3].u64[0] = yc[3].u64[3];

   ba[0] = _mm256_add_epi32( ba[0], za[0].m256 );
   bb[0] = _mm256_add_epi32( bb[0], zb[0].m256 );
   bc[0] = _mm256_add_epi32( bc[0], zc[0].m256 );
   ba[1] = _mm256_add_epi32( ba[1], za[1].m256 );
   bb[1] = _mm256_add_epi32( bb[1], zb[1].m256 );
   bc[1] = _mm256_add_epi32( bc[1], zc[1].m256 );
   ba[2] = _mm256_add_epi32( ba[2], za[2].m256 );
   bb[2] = _mm256_add_epi32( bb[2], zb[2].m256 );
   bc[2] = _mm256_add_epi32( bc[2], zc[2].m256 );
   ba[3] = _mm256_add_epi32( ba[3], za[3].m256 );
   bb[3] = _mm256_add_epi32( bb[3], zb[3].m256 );
   bc[3] = _mm256_add_epi32( bc[3], zc[3].m256 );
}

void scrypt_core_simd128_2way_3buf( uint64_t *X, uint64_t *V,
                                    const uint32_t N )
{
   uint64_t *X0 = X;
   uint64_t *X1 = X+32;
   uint64_t *X2 = X+64;
   uint64_t *V0 = V;
   uint64_t *V1 = V + 32*N;
   uint64_t *V2 = V + 64*N;

   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V0[ n*32 ], X0, 2*128 );
      memcpy( &V1[ n*32 ], X1, 2*128 );
      memcpy( &V2[ n*32 ], X2, 2*128 );
      salsa8_simd128_2way_3buf( &X0[ 0], &X1[ 0], &X2[ 0],
                                &X0[16], &X1[16], &X2[16] );
      salsa8_simd128_2way_3buf( &X0[16], &X1[16], &X2[16],
                                &X0[ 0], &X1[ 0], &X2[ 0] );
   }

   for ( int n = 0; n < N; n++ )
   {
      uint32_t j0l = 32 * ( (uint32_t)( X0[16]       ) & ( N-1 ) );
      uint32_t j0h = 32 * ( (uint32_t)( X0[16] >> 32 ) & ( N-1 ) );
      uint32_t j1l = 32 * ( (uint32_t)( X1[16]       ) & ( N-1 ) );
      uint32_t j1h = 32 * ( (uint32_t)( X1[16] >> 32 ) & ( N-1 ) );
      uint32_t j2l = 32 * ( (uint32_t)( X2[16]       ) & ( N-1 ) );
      uint32_t j2h = 32 * ( (uint32_t)( X2[16] >> 32 ) & ( N-1 ) );

      for ( int i = 0; i < 32; i++ )
      {
         X0[i] ^= ( ( V0[ j0h + i ] & 0xffffffff00000000 )
                  | ( V0[ j0l + i ] & 0x00000000ffffffff ) );
         X1[i] ^= ( ( V1[ j1h + i ] & 0xffffffff00000000 )
                  | ( V1[ j1l + i ] & 0x00000000ffffffff ) );
         X2[i] ^= ( ( V2[ j2h + i ] & 0xffffffff00000000 )
                  | ( V2[ j2l + i ] & 0x00000000ffffffff ) );
      }
      salsa8_simd128_2way_3buf( &X0[ 0], &X1[ 0], &X2[ 0],
                                &X0[16], &X1[16], &X2[16] );
      salsa8_simd128_2way_3buf( &X0[16], &X1[16], &X2[16],
                                &X0[ 0], &X1[ 0], &X2[ 0] );
   }
}


#endif  // AVX2

#if defined(__SSE2__) || defined(__ARM_NEON)

// Simple 4 way parallel.
// Tested OK
// Scyptn2 a little slower than pooler
// Scrypt 2x faster than pooler
// 4x memory usage
// 4x32 interleaving
static void xor_salsa8_4way( v128_t * const B, const v128_t * const C )
{
   v128_t x0 = B[ 0] = v128_xor( B[ 0], C[ 0] );
   v128_t x1 = B[ 1] = v128_xor( B[ 1], C[ 1] );
   v128_t x2 = B[ 2] = v128_xor( B[ 2], C[ 2] );
   v128_t x3 = B[ 3] = v128_xor( B[ 3], C[ 3] );
   v128_t x4 = B[ 4] = v128_xor( B[ 4], C[ 4] );
   v128_t x5 = B[ 5] = v128_xor( B[ 5], C[ 5] );
   v128_t x6 = B[ 6] = v128_xor( B[ 6], C[ 6] );
   v128_t x7 = B[ 7] = v128_xor( B[ 7], C[ 7] );
   v128_t x8 = B[ 8] = v128_xor( B[ 8], C[ 8] );
   v128_t x9 = B[ 9] = v128_xor( B[ 9], C[ 9] );
   v128_t xa = B[10] = v128_xor( B[10], C[10] );
   v128_t xb = B[11] = v128_xor( B[11], C[11] );
   v128_t xc = B[12] = v128_xor( B[12], C[12] );
   v128_t xd = B[13] = v128_xor( B[13], C[13] );
   v128_t xe = B[14] = v128_xor( B[14], C[14] );
   v128_t xf = B[15] = v128_xor( B[15], C[15] );

   #define ROL32       v128_rol32
   #define ADD32       v128_add32
   #define XOR         v128_xor

   SALSA_8ROUNDS;

   #undef ROL32
   #undef ADD32
   #undef XOR 

   B[ 0] = v128_add32( B[ 0], x0 );
   B[ 1] = v128_add32( B[ 1], x1 );
   B[ 2] = v128_add32( B[ 2], x2 );
   B[ 3] = v128_add32( B[ 3], x3 );
   B[ 4] = v128_add32( B[ 4], x4 );
   B[ 5] = v128_add32( B[ 5], x5 );
   B[ 6] = v128_add32( B[ 6], x6 );
   B[ 7] = v128_add32( B[ 7], x7 );
   B[ 8] = v128_add32( B[ 8], x8 );
   B[ 9] = v128_add32( B[ 9], x9 );
   B[10] = v128_add32( B[10], xa );
   B[11] = v128_add32( B[11], xb );
   B[12] = v128_add32( B[12], xc );
   B[13] = v128_add32( B[13], xd );
   B[14] = v128_add32( B[14], xe );
   B[15] = v128_add32( B[15], xf );
}

void scrypt_core_4way( v128_t *X, v128_t *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[ n*32 ], X, 128*4 );
      xor_salsa8_4way( &X[ 0], &X[16] );
      xor_salsa8_4way( &X[16], &X[ 0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      v128_ovly *vptr[4]; 
      v128_ovly *x16 = (v128_ovly*)(&X[16]);

      for ( int l = 0; l < 4; l++ )
      {
         uint32_t xl = (*x16).u32[l];
         vptr[l] = (v128_ovly*)( &V[ 32 * ( xl & ( N-1 ) ) ] ); 
      }

      for ( int i = 0; i < 32; i++ )
      {
         v128_ovly v;    
         for ( int l = 0; l < 4; l++ )
            v.u32[l] = ( *(vptr[l] +i ) ) .u32[l];
         X[i] = v128_xor( X[i], v.m128 );
      }

      xor_salsa8_4way( &X[ 0], &X[16] );
      xor_salsa8_4way( &X[16], &X[ 0] );
   }
}


// Linear SIMD single thread. No memory increase but some shuffling overhead
// required.

// 4 way 32 bit interleaved single 32 bit thread, interleave while loading,
// deinterleave while storing, do 2 way 128 & 4 way 128 parallel on top.
//
//   SALSA_2ROUNDS( {x0,x5,xa,xf}, {x4,x9,xe,x3}, {x8,xd,x2,x7}, {xc,x1,x6,xb})

// Tested OK.
// No interleaving
static void salsa8_simd128( uint32_t *b, const uint32_t * const c)
{
   v128_t X0, X1, X2, X3;
   v128_t *B = (v128_t*)b;
   const v128_t *C = (const v128_t*)c;

   // define targets for macros used in round function template
   #define ROL_1X32    v128_shufll32
   #define ROR_1X32    v128_shuflr32
   #define SWAP_64     v128_swap64
   #define ROL32       v128_rol32
   #define ADD32       v128_add32
   #define XOR         v128_xor
   
   // mix C into B then shuffle B into X
   B[0] = v128_xor( B[0], C[0] );
   B[1] = v128_xor( B[1], C[1] );
   B[2] = v128_xor( B[2], C[2] );
   B[3] = v128_xor( B[3], C[3] );

#if defined(__SSE4_1__)

   v128_t Y0, Y1, Y2, Y3;

#if defined(__AVX2__)
   
   Y0 = _mm_blend_epi32( B[1], B[0], 0x1 );
   X0 = _mm_blend_epi32( B[3], B[2], 0x4 );
   Y1 = _mm_blend_epi32( B[2], B[1], 0x1 );
   X1 = _mm_blend_epi32( B[0], B[3], 0x4 );
   Y2 = _mm_blend_epi32( B[3], B[2], 0x1 );
   X2 = _mm_blend_epi32( B[1], B[0], 0x4 );
   Y3 = _mm_blend_epi32( B[0], B[3], 0x1 );
   X3 = _mm_blend_epi32( B[2], B[1], 0x4 );
   X0 = _mm_blend_epi32( X0, Y0, 0x3 );
   X1 = _mm_blend_epi32( X1, Y1, 0x3 );
   X2 = _mm_blend_epi32( X2, Y2, 0x3 );
   X3 = _mm_blend_epi32( X3, Y3, 0x3 );

#else // SSE4_1

   Y0 = _mm_blend_epi16( B[1], B[0], 0x03 );
   X0 = _mm_blend_epi16( B[3], B[2], 0x30 );
   Y1 = _mm_blend_epi16( B[2], B[1], 0x03 );
   X1 = _mm_blend_epi16( B[0], B[3], 0x30 );
   Y2 = _mm_blend_epi16( B[3], B[2], 0x03 );
   X2 = _mm_blend_epi16( B[1], B[0], 0x30 );
   Y3 = _mm_blend_epi16( B[0], B[3], 0x03 );
   X3 = _mm_blend_epi16( B[2], B[1], 0x30 );

   X0 = _mm_blend_epi16( X0, Y0, 0x0f );
   X1 = _mm_blend_epi16( X1, Y1, 0x0f );
   X2 = _mm_blend_epi16( X2, Y2, 0x0f );
   X3 = _mm_blend_epi16( X3, Y3, 0x0f );

#endif // AVX2 else SSE4_1

   SALSA_8ROUNDS_SIMD128;

#if defined(__AVX2__)
   
   Y0 = _mm_blend_epi32( X0, X1, 0x8 );
   Y1 = _mm_blend_epi32( X0, X1, 0x1 );
   Y2 = _mm_blend_epi32( X0, X1, 0x2 );
   Y3 = _mm_blend_epi32( X0, X1, 0x4 );

   Y0 = _mm_blend_epi32( Y0, X2, 0x4 );
   Y1 = _mm_blend_epi32( Y1, X2, 0x8 );
   Y2 = _mm_blend_epi32( Y2, X2, 0x1 );
   Y3 = _mm_blend_epi32( Y3, X2, 0x2 );

   Y0 = _mm_blend_epi32( Y0, X3, 0x2 );
   Y1 = _mm_blend_epi32( Y1, X3, 0x4 );
   Y2 = _mm_blend_epi32( Y2, X3, 0x8 );
   Y3 = _mm_blend_epi32( Y3, X3, 0x1 );

#else  // SSE4_1

   Y0 = _mm_blend_epi16( X0, X1, 0xc0 );
   Y1 = _mm_blend_epi16( X0, X1, 0x03 );
   Y2 = _mm_blend_epi16( X0, X1, 0x0c );
   Y3 = _mm_blend_epi16( X0, X1, 0x30 );

   Y0 = _mm_blend_epi16( Y0, X2, 0x30 );
   Y1 = _mm_blend_epi16( Y1, X2, 0xc0 );
   Y2 = _mm_blend_epi16( Y2, X2, 0x03 );
   Y3 = _mm_blend_epi16( Y3, X2, 0x0c );

   Y0 = _mm_blend_epi16( Y0, X3, 0x0c );
   Y1 = _mm_blend_epi16( Y1, X3, 0x30 );
   Y2 = _mm_blend_epi16( Y2, X3, 0xc0 );
   Y3 = _mm_blend_epi16( Y3, X3, 0x03 );

#endif   // AVX2 else SSE4_1

   B[0] = v128_add32( B[0], Y0 );
   B[1] = v128_add32( B[1], Y1 );
   B[2] = v128_add32( B[2], Y2 );
   B[3] = v128_add32( B[3], Y3 );

#else  // SSE2

   v128_ovly y[4], z[4];

   X0 = v128_set32( b[15], b[10], b[ 5], b[ 0] );
   X1 = v128_set32( b[ 3], b[14], b[ 9], b[ 4] );
   X2 = v128_set32( b[ 7], b[ 2], b[13], b[ 8] );
   X3 = v128_set32( b[11], b[ 6], b[ 1], b[12] );
   
   SALSA_8ROUNDS_FINAL_SIMD128;

   // Final round doesn't shuffle data back to original input order,
   // process it as is.
   // X0 is unchanged                    { xf, xa, x5, x0 }
   // X1 is shuffled left 1 (rol_1x32)   { xe, x9, x4, x3 }
   // X2 is shuffled left 2 (swap_64)    { xd, x8, x7, x2 }
   // X3 is shuffled left 3 (ror_1x32)   { xc, xb, x6, x1 }

   y[0].m128 = X0;
   y[1].m128 = X1;
   y[2].m128 = X2;
   y[3].m128 = X3;

   z[0].u32[0] = y[0].u32[0];
   z[0].u32[3] = y[1].u32[0];
   z[0].u32[2] = y[2].u32[0];
   z[0].u32[1] = y[3].u32[0];

   z[1].u32[1] = y[0].u32[1];
   z[1].u32[0] = y[1].u32[1];
   z[1].u32[3] = y[2].u32[1];
   z[1].u32[2] = y[3].u32[1];

   z[2].u32[2] = y[0].u32[2];
   z[2].u32[1] = y[1].u32[2];
   z[2].u32[0] = y[2].u32[2];
   z[2].u32[3] = y[3].u32[2];

   z[3].u32[3] = y[0].u32[3];
   z[3].u32[2] = y[1].u32[3];
   z[3].u32[1] = y[2].u32[3];
   z[3].u32[0] = y[3].u32[3];

   B[0] = v128_add32( B[0], z[0].m128 );
   B[1] = v128_add32( B[1], z[1].m128 );
   B[2] = v128_add32( B[2], z[2].m128 );
   B[3] = v128_add32( B[3], z[3].m128 );

#endif

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR 

}

void scrypt_core_simd128( uint32_t *X, uint32_t *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      for ( int i = 0; i < 8; i++ )
   #if defined(__SSE4_1__)
         _mm_stream_si128( (v128_t*)V + n*8 + i, casti_v128( X, i ) );
   #else
         v128_store( (v128_t*)V + n*8 + i, casti_v128( X, i ) );
   #endif

      salsa8_simd128( &X[ 0], &X[16] );
      salsa8_simd128( &X[16], &X[ 0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      const int j = 32 * ( X[16] & ( N - 1 ) );
      for ( int i = 0; i < 32; i++ )
         X[i] ^= V[ j+i ];
      salsa8_simd128( &X[ 0], &X[16] );
      salsa8_simd128( &X[16], &X[ 0] );
   }
}

// Double buffered, 2x memory usage
// No interleaving

static inline void salsa_simd128_shuffle_2buf( uint32_t *xa, uint32_t *xb )
{
   v128_t *XA = (v128_t*)xa;
   v128_t *XB = (v128_t*)xb;

#if defined(__SSE4_1__)

  v128_t t0 = _mm_blend_epi16( XA[0], XA[1], 0xcc );
  v128_t t1 = _mm_blend_epi16( XA[0], XA[1], 0x33 );
  v128_t t2 = _mm_blend_epi16( XA[2], XA[3], 0xcc );
  v128_t t3 = _mm_blend_epi16( XA[2], XA[3], 0x33 );
  XA[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  XA[1] = _mm_blend_epi16( t1, t3, 0x3c );
  XA[2] = _mm_blend_epi16( t0, t2, 0x0f );
  XA[3] = _mm_blend_epi16( t1, t3, 0xc3 );
  t0 = _mm_blend_epi16( XB[0], XB[1], 0xcc );
  t1 = _mm_blend_epi16( XB[0], XB[1], 0x33 );
  t2 = _mm_blend_epi16( XB[2], XB[3], 0xcc );
  t3 = _mm_blend_epi16( XB[2], XB[3], 0x33 );
  XB[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  XB[1] = _mm_blend_epi16( t1, t3, 0x3c );
  XB[2] = _mm_blend_epi16( t0, t2, 0x0f );
  XB[3] = _mm_blend_epi16( t1, t3, 0xc3 );

#else    // SSE2 or NEON  

  const v128u64_t mask_cc = v128_set64(0xffffffff00000000, 0xffffffff00000000);
  const v128u64_t mask_f0 = v128_set64(0xffffffffffffffff,                  0);
  const v128u64_t mask_3c = v128_set64(0x00000000ffffffff, 0xffffffff00000000);

  v128_t t0 = v128_blendv( XA[0], XA[1], mask_cc );
  v128_t t1 = v128_blendv( XA[1], XA[0], mask_cc );
  v128_t t2 = v128_blendv( XA[2], XA[3], mask_cc );
  v128_t t3 = v128_blendv( XA[3], XA[2], mask_cc );
  XA[0] = v128_blendv( t0, t2, mask_f0 );
  XA[1] = v128_blendv( t1, t3, mask_3c );
  XA[2] = v128_blendv( t2, t0, mask_f0 );
  XA[3] = v128_blendv( t3, t1, mask_3c );
  t0 = v128_blendv( XB[0], XB[1], mask_cc );
  t1 = v128_blendv( XB[1], XB[0], mask_cc );
  t2 = v128_blendv( XB[2], XB[3], mask_cc );
  t3 = v128_blendv( XB[3], XB[2], mask_cc );
  XB[0] = v128_blendv( t0, t2, mask_f0 );
  XB[1] = v128_blendv( t1, t3, mask_3c );
  XB[2] = v128_blendv( t2, t0, mask_f0 );
  XB[3] = v128_blendv( t3, t1, mask_3c );

#endif

/*  
   v128_t YA0, YA1, YA2, YA3, YB0, YB1, YB2, YB3;
   
   YA0 = v128_set32( xa[15], xa[10], xa[ 5], xa[ 0] );
   YB0 = v128_set32( xb[15], xb[10], xb[ 5], xb[ 0] );
   YA1 = v128_set32( xa[ 3], xa[14], xa[ 9], xa[ 4] );
   YB1 = v128_set32( xb[ 3], xb[14], xb[ 9], xb[ 4] );
   YA2 = v128_set32( xa[ 7], xa[ 2], xa[13], xa[ 8] );
   YB2 = v128_set32( xb[ 7], xb[ 2], xb[13], xb[ 8] );
   YA3 = v128_set32( xa[11], xa[ 6], xa[ 1], xa[12] );
   YB3 = v128_set32( xb[11], xb[ 6], xb[ 1], xb[12] );

   XA[0] = YA0;
   XB[0] = YB0;
   XA[1] = YA1;
   XB[1] = YB1;
   XA[2] = YA2;
   XB[2] = YB2;
   XA[3] = YA3;
   XB[3] = YB3;
*/
}

static inline void salsa_simd128_unshuffle_2buf( uint32_t* xa, uint32_t* xb )
{

   v128_t *XA = (v128_t*)xa;
   v128_t *XB = (v128_t*)xb;
   
#if defined(__SSE4_1__) 

  v128_t t0 = _mm_blend_epi16( XA[0], XA[2], 0xf0 );
  v128_t t1 = _mm_blend_epi16( XA[0], XA[2], 0x0f );
  v128_t t2 = _mm_blend_epi16( XA[1], XA[3], 0x3c );
  v128_t t3 = _mm_blend_epi16( XA[1], XA[3], 0xc3 );
  XA[0] = _mm_blend_epi16( t0, t2, 0xcc );
  XA[1] = _mm_blend_epi16( t0, t2, 0x33 );
  XA[2] = _mm_blend_epi16( t1, t3, 0xcc );
  XA[3] = _mm_blend_epi16( t1, t3, 0x33 );
  t0 = _mm_blend_epi16( XB[0], XB[2], 0xf0 );
  t1 = _mm_blend_epi16( XB[0], XB[2], 0x0f );
  t2 = _mm_blend_epi16( XB[1], XB[3], 0x3c );
  t3 = _mm_blend_epi16( XB[1], XB[3], 0xc3 );
  XB[0] = _mm_blend_epi16( t0, t2, 0xcc );
  XB[1] = _mm_blend_epi16( t0, t2, 0x33 );
  XB[2] = _mm_blend_epi16( t1, t3, 0xcc );
  XB[3] = _mm_blend_epi16( t1, t3, 0x33 );

#else   //  SSE2 or NEON

  const v128u64_t mask_cc = v128_set64(0xffffffff00000000, 0xffffffff00000000);
  const v128u64_t mask_f0 = v128_set64(0xffffffffffffffff,                  0);
  const v128u64_t mask_3c = v128_set64(0x00000000ffffffff, 0xffffffff00000000);

  v128_t t0 = v128_blendv( XA[0], XA[2], mask_f0 );
  v128_t t1 = v128_blendv( XA[2], XA[0], mask_f0 );
  v128_t t2 = v128_blendv( XA[1], XA[3], mask_3c );
  v128_t t3 = v128_blendv( XA[3], XA[1], mask_3c );
  XA[0] = v128_blendv( t0, t2, mask_cc );
  XA[1] = v128_blendv( t2, t0, mask_cc );
  XA[2] = v128_blendv( t1, t3, mask_cc );
  XA[3] = v128_blendv( t3, t1, mask_cc );
  t0 = v128_blendv( XB[0], XB[2], mask_f0 );
  t1 = v128_blendv( XB[2], XB[0], mask_f0 );
  t2 = v128_blendv( XB[1], XB[3], mask_3c );
  t3 = v128_blendv( XB[3], XB[1], mask_3c );
  XB[0] = v128_blendv( t0, t2, mask_cc );
  XB[1] = v128_blendv( t2, t0, mask_cc );
  XB[2] = v128_blendv( t1, t3, mask_cc );
  XB[3] = v128_blendv( t3, t1, mask_cc );

#endif

/*
   v128_ovly ya[4], za[4], yb[4], zb[4];

   ya[0].m128 = XA[0];
   yb[0].m128 = XB[0];
   ya[1].m128 = XA[1];
   yb[1].m128 = XB[1];
   ya[2].m128 = XA[2];
   yb[2].m128 = XB[2];
   ya[3].m128 = XA[3];
   yb[3].m128 = XB[3];

   za[0].u32[0] = ya[0].u32[0];
   zb[0].u32[0] = yb[0].u32[0];
   za[0].u32[1] = ya[3].u32[1];
   zb[0].u32[1] = yb[3].u32[1];
   za[0].u32[2] = ya[2].u32[2];
   zb[0].u32[2] = yb[2].u32[2];
   za[0].u32[3] = ya[1].u32[3];
   zb[0].u32[3] = yb[1].u32[3];

   za[1].u32[0] = ya[1].u32[0];
   zb[1].u32[0] = yb[1].u32[0];
   za[1].u32[1] = ya[0].u32[1];
   zb[1].u32[1] = yb[0].u32[1];
   za[1].u32[2] = ya[3].u32[2];
   zb[1].u32[2] = yb[3].u32[2];
   za[1].u32[3] = ya[2].u32[3];
   zb[1].u32[3] = yb[2].u32[3];

   za[2].u32[0] = ya[2].u32[0];
   zb[2].u32[0] = yb[2].u32[0];
   za[2].u32[1] = ya[1].u32[1];
   zb[2].u32[1] = yb[1].u32[1];
   za[2].u32[2] = ya[0].u32[2];
   zb[2].u32[2] = yb[0].u32[2];
   za[2].u32[3] = ya[3].u32[3];
   zb[2].u32[3] = yb[3].u32[3];

   za[3].u32[0] = ya[3].u32[0];
   zb[3].u32[0] = yb[3].u32[0];
   za[3].u32[1] = ya[2].u32[1];
   zb[3].u32[1] = yb[2].u32[1];
   za[3].u32[2] = ya[1].u32[2];
   zb[3].u32[2] = yb[1].u32[2];
   za[3].u32[3] = ya[0].u32[3];
   zb[3].u32[3] = yb[0].u32[3];

   XA[0] = za[0].m128;
   XB[0] = zb[0].m128;
   XA[1] = za[1].m128;
   XB[1] = zb[1].m128;
   XA[2] = za[2].m128;
   XB[2] = zb[2].m128;
   XA[3] = za[3].m128;
   XB[3] = zb[3].m128;
*/
}

static void salsa8_simd128_2buf( uint32_t * const ba, uint32_t * const bb,
                       const uint32_t * const ca, const uint32_t * const cb )
{
   v128_t XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3;
   v128_t *BA = (v128_t*)ba;
   v128_t *BB = (v128_t*)bb;
   const v128_t *CA = (const v128_t*)ca;
   const v128_t *CB = (const v128_t*)cb;

   // define targets for macros used in round function template
   #define ROL_1X32    v128_shufll32
   #define ROR_1X32    v128_shuflr32
   #define SWAP_64     v128_swap64
   #define ROL32       v128_rol32
   #define ADD32       v128_add32
   #define XOR         v128_xor
   #define TYPE        v128_t

   XA0 = BA[0] = v128_xor( BA[0], CA[0] );
   XB0 = BB[0] = v128_xor( BB[0], CB[0] );
   XA1 = BA[1] = v128_xor( BA[1], CA[1] );
   XB1 = BB[1] = v128_xor( BB[1], CB[1] );
   XA2 = BA[2] = v128_xor( BA[2], CA[2] );
   XB2 = BB[2] = v128_xor( BB[2], CB[2] );
   XA3 = BA[3] = v128_xor( BA[3], CA[3] );
   XB3 = BB[3] = v128_xor( BB[3], CB[3] );

#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
             
   SALSA_8ROUNDS_SIMD128_2BUF;

#else

   SALSA_8ROUNDS_SIMD128_2BUF_SLOROT;
   
#endif

   BA[0] = v128_add32( BA[0], XA0 );
   BB[0] = v128_add32( BB[0], XB0 );
   BA[1] = v128_add32( BA[1], XA1 );
   BB[1] = v128_add32( BB[1], XB1 );
   BA[2] = v128_add32( BA[2], XA2 );
   BB[2] = v128_add32( BB[2], XB2 );
   BA[3] = v128_add32( BA[3], XA3 );
   BB[3] = v128_add32( BB[3], XB3 );

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR
   #undef TYPE
}

void scrypt_core_simd128_2buf( uint32_t *X, uint32_t *V, const uint32_t N )
{
   uint32_t *X0 = X;
   uint32_t *X1 = X+32;
   uint32_t *V0 = V;
   uint32_t *V1 = V + 32*N;

   salsa_simd128_shuffle_2buf( X0,    X1    );
   salsa_simd128_shuffle_2buf( X0+16, X1+16 );

   for ( int n = 0; n < N; n++ )
   {
   #if defined(__AVX__)

      for ( int i = 0; i < 4; i++ )
      {
         _mm256_stream_si256( (__m256i*)V0 + n*4 + i, casti_m256i( X0, i ) );
         _mm256_stream_si256( (__m256i*)V1 + n*4 + i, casti_m256i( X1, i ) );
      }

   #elif defined(__SSE4_1__)

      for ( int i = 0; i < 8; i++ )
      {
         _mm_stream_si128( (v128_t*)V0 + n*8 + i, casti_v128( X0, i ) );
         _mm_stream_si128( (v128_t*)V1 + n*8 + i, casti_v128( X1, i ) );
      }

   #else

      memcpy( &V0[ n*32 ], X0, 128 );
      memcpy( &V1[ n*32 ], X1, 128 );

   #endif

      salsa8_simd128_2buf( X0,    X1,    X0+16, X1+16 );
      salsa8_simd128_2buf( X0+16, X1+16, X0   , X1    );
   }

   for ( int n = 0; n < N; n++ )
   {
   #if defined(__AVX2__)

      const int j0 = 4 * ( X0[16] & ( N-1 ) );
      const int j1 = 4 * ( X1[16] & ( N-1 ) );

      const __m256i v00 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0   );
      const __m256i v10 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1   );
      const __m256i v01 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+1 );
      const __m256i v11 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+1 );
      const __m256i v02 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+2 );
      const __m256i v12 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+2 );
      const __m256i v03 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+3 );
      const __m256i v13 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+3 );

      casti_m256i( X0, 0 ) = _mm256_xor_si256( casti_m256i( X0, 0 ), v00 );
      casti_m256i( X1, 0 ) = _mm256_xor_si256( casti_m256i( X1, 0 ), v10 );
      casti_m256i( X0, 1 ) = _mm256_xor_si256( casti_m256i( X0, 1 ), v01 );
      casti_m256i( X1, 1 ) = _mm256_xor_si256( casti_m256i( X1, 1 ), v11 );
      casti_m256i( X0, 2 ) = _mm256_xor_si256( casti_m256i( X0, 2 ), v02 );
      casti_m256i( X1, 2 ) = _mm256_xor_si256( casti_m256i( X1, 2 ), v12 );
      casti_m256i( X0, 3 ) = _mm256_xor_si256( casti_m256i( X0, 3 ), v03 );
      casti_m256i( X1, 3 ) = _mm256_xor_si256( casti_m256i( X1, 3 ), v13 );

   #else

      const int j0 = 8 * ( X0[16] & ( N-1 ) );
      const int j1 = 8 * ( X1[16] & ( N-1 ) );
      for ( int i = 0; i < 8; i++ )
      {
         const v128_t v0 = v128_load( ( (v128_t*)V0 ) +j0+i );
         const v128_t v1 = v128_load( ( (v128_t*)V1 ) +j1+i );
         casti_v128( X0, i ) = v128_xor( casti_v128( X0, i ), v0 );
         casti_v128( X1, i ) = v128_xor( casti_v128( X1, i ), v1 );
      }

   #endif

      salsa8_simd128_2buf( X0,    X1,    X0+16, X1+16 );
      salsa8_simd128_2buf( X0+16, X1+16, X0   , X1    );
   }

   salsa_simd128_unshuffle_2buf( X0,    X1    );
   salsa_simd128_unshuffle_2buf( X0+16, X1+16 );
}


static inline void salsa_simd128_shuffle_3buf( uint32_t *xa, uint32_t *xb,
                                        uint32_t *xc )
{
   v128_t *XA = (v128_t*)xa;
   v128_t *XB = (v128_t*)xb;
   v128_t *XC = (v128_t*)xc;

#if defined(__SSE4_1__) 

  v128_t t0 = _mm_blend_epi16( XA[0], XA[1], 0xcc );
  v128_t t1 = _mm_blend_epi16( XA[0], XA[1], 0x33 );
  v128_t t2 = _mm_blend_epi16( XA[2], XA[3], 0xcc );
  v128_t t3 = _mm_blend_epi16( XA[2], XA[3], 0x33 );
  XA[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  XA[1] = _mm_blend_epi16( t1, t3, 0x3c );
  XA[2] = _mm_blend_epi16( t0, t2, 0x0f );
  XA[3] = _mm_blend_epi16( t1, t3, 0xc3 );
  t0 = _mm_blend_epi16( XB[0], XB[1], 0xcc );
  t1 = _mm_blend_epi16( XB[0], XB[1], 0x33 );
  t2 = _mm_blend_epi16( XB[2], XB[3], 0xcc );
  t3 = _mm_blend_epi16( XB[2], XB[3], 0x33 );
  XB[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  XB[1] = _mm_blend_epi16( t1, t3, 0x3c );
  XB[2] = _mm_blend_epi16( t0, t2, 0x0f );
  XB[3] = _mm_blend_epi16( t1, t3, 0xc3 );
  t0 = _mm_blend_epi16( XC[0], XC[1], 0xcc );
  t1 = _mm_blend_epi16( XC[0], XC[1], 0x33 );
  t2 = _mm_blend_epi16( XC[2], XC[3], 0xcc );
  t3 = _mm_blend_epi16( XC[2], XC[3], 0x33 );
  XC[0] = _mm_blend_epi16( t0, t2, 0xf0 );
  XC[1] = _mm_blend_epi16( t1, t3, 0x3c );
  XC[2] = _mm_blend_epi16( t0, t2, 0x0f );
  XC[3] = _mm_blend_epi16( t1, t3, 0xc3 );

#else    // SSE2 or NEON   

  const v128u64_t mask_cc = v128_set64(0xffffffff00000000, 0xffffffff00000000);
  const v128u64_t mask_f0 = v128_set64(0xffffffffffffffff,                  0);
  const v128u64_t mask_3c = v128_set64(0x00000000ffffffff, 0xffffffff00000000);

  v128_t t0 = v128_blendv( XA[0], XA[1], mask_cc );
  v128_t t1 = v128_blendv( XA[1], XA[0], mask_cc );
  v128_t t2 = v128_blendv( XA[2], XA[3], mask_cc );
  v128_t t3 = v128_blendv( XA[3], XA[2], mask_cc );
  XA[0] = v128_blendv( t0, t2, mask_f0 );
  XA[1] = v128_blendv( t2, t0, mask_f0 );
  XA[2] = v128_blendv( t1, t3, mask_3c );
  XA[3] = v128_blendv( t3, t1, mask_3c );
  t0 = v128_blendv( XB[0], XB[1], mask_cc );
  t1 = v128_blendv( XB[1], XB[0], mask_cc );
  t2 = v128_blendv( XB[2], XB[3], mask_cc );
  t3 = v128_blendv( XB[3], XB[2], mask_cc );
  XB[0] = v128_blendv( t0, t2, mask_f0 );
  XB[1] = v128_blendv( t2, t0, mask_f0 );
  XB[2] = v128_blendv( t1, t3, mask_3c );
  XB[3] = v128_blendv( t3, t1, mask_3c );
  t0 = v128_blendv( XC[0], XC[1], mask_cc );
  t1 = v128_blendv( XC[1], XC[0], mask_cc );
  t2 = v128_blendv( XC[2], XC[3], mask_cc );
  t3 = v128_blendv( XC[3], XC[2], mask_cc );
  XC[0] = v128_blendv( t0, t2, mask_f0 );
  XC[1] = v128_blendv( t2, t0, mask_f0 );
  XC[2] = v128_blendv( t1, t3, mask_3c );
  XC[3] = v128_blendv( t3, t1, mask_3c );

#endif

/*
   v128_t YA0, YA1, YA2, YA3, YB0, YB1, YB2, YB3, YC0, YC1, YC2, YC3;

   YA0 = v128_set32( xa[15], xa[10], xa[ 5], xa[ 0] );
   YB0 = v128_set32( xb[15], xb[10], xb[ 5], xb[ 0] );
   YC0 = v128_set32( xc[15], xc[10], xc[ 5], xc[ 0] );
   YA1 = v128_set32( xa[ 3], xa[14], xa[ 9], xa[ 4] );
   YB1 = v128_set32( xb[ 3], xb[14], xb[ 9], xb[ 4] );
   YC1 = v128_set32( xc[ 3], xc[14], xc[ 9], xc[ 4] );
   YA2 = v128_set32( xa[ 7], xa[ 2], xa[13], xa[ 8] );
   YB2 = v128_set32( xb[ 7], xb[ 2], xb[13], xb[ 8] );
   YC2 = v128_set32( xc[ 7], xc[ 2], xc[13], xc[ 8] );
   YA3 = v128_set32( xa[11], xa[ 6], xa[ 1], xa[12] );
   YB3 = v128_set32( xb[11], xb[ 6], xb[ 1], xb[12] );
   YC3 = v128_set32( xc[11], xc[ 6], xc[ 1], xc[12] );

   XA[0] = YA0;
   XB[0] = YB0;
   XC[0] = YC0;
   XA[1] = YA1;
   XB[1] = YB1;
   XC[1] = YC1;
   XA[2] = YA2;
   XB[2] = YB2;
   XC[2] = YC2;
   XA[3] = YA3;
   XB[3] = YB3;
   XC[3] = YC3;
*/
}

static inline void salsa_simd128_unshuffle_3buf( uint32_t* xa, uint32_t* xb,
                                          uint32_t* xc )
{
   v128_t *XA = (v128_t*)xa;
   v128_t *XB = (v128_t*)xb;
   v128_t *XC = (v128_t*)xc;

#if defined(__SSE4_1__)

  v128_t t0 = _mm_blend_epi16( XA[0], XA[2], 0xf0 );
  v128_t t1 = _mm_blend_epi16( XA[0], XA[2], 0x0f );
  v128_t t2 = _mm_blend_epi16( XA[1], XA[3], 0x3c );
  v128_t t3 = _mm_blend_epi16( XA[1], XA[3], 0xc3 );
  XA[0] = _mm_blend_epi16( t0, t2, 0xcc );
  XA[1] = _mm_blend_epi16( t0, t2, 0x33 );
  XA[2] = _mm_blend_epi16( t1, t3, 0xcc );
  XA[3] = _mm_blend_epi16( t1, t3, 0x33 );
  t0 = _mm_blend_epi16( XB[0], XB[2], 0xf0 );
  t1 = _mm_blend_epi16( XB[0], XB[2], 0x0f );
  t2 = _mm_blend_epi16( XB[1], XB[3], 0x3c );
  t3 = _mm_blend_epi16( XB[1], XB[3], 0xc3 );
  XB[0] = _mm_blend_epi16( t0, t2, 0xcc );
  XB[1] = _mm_blend_epi16( t0, t2, 0x33 );
  XB[2] = _mm_blend_epi16( t1, t3, 0xcc );
  XB[3] = _mm_blend_epi16( t1, t3, 0x33 );
  t0 = _mm_blend_epi16( XC[0], XC[2], 0xf0 );
  t1 = _mm_blend_epi16( XC[0], XC[2], 0x0f );
  t2 = _mm_blend_epi16( XC[1], XC[3], 0x3c );
  t3 = _mm_blend_epi16( XC[1], XC[3], 0xc3 );
  XC[0] = _mm_blend_epi16( t0, t2, 0xcc );
  XC[1] = _mm_blend_epi16( t0, t2, 0x33 );
  XC[2] = _mm_blend_epi16( t1, t3, 0xcc );
  XC[3] = _mm_blend_epi16( t1, t3, 0x33 );

#else   //  SSE2 or NEON

  const v128u64_t mask_cc = v128_set64(0xffffffff00000000, 0xffffffff00000000);
  const v128u64_t mask_f0 = v128_set64(0xffffffffffffffff,                  0);
  const v128u64_t mask_3c = v128_set64(0x00000000ffffffff, 0xffffffff00000000);

  v128_t t0 = v128_blendv( XA[0], XA[2], mask_f0 );
  v128_t t1 = v128_blendv( XA[2], XA[0], mask_f0 );
  v128_t t2 = v128_blendv( XA[1], XA[3], mask_3c );
  v128_t t3 = v128_blendv( XA[3], XA[1], mask_3c );
  XA[0] = v128_blendv( t0, t2, mask_cc );
  XA[1] = v128_blendv( t2, t0, mask_cc );
  XA[2] = v128_blendv( t1, t3, mask_cc );
  XA[3] = v128_blendv( t3, t1, mask_cc );
  t0 = v128_blendv( XB[0], XB[2], mask_f0 );
  t1 = v128_blendv( XB[2], XB[0], mask_f0 );
  t2 = v128_blendv( XB[1], XB[3], mask_3c );
  t3 = v128_blendv( XB[3], XB[1], mask_3c );
  XB[0] = v128_blendv( t0, t2, mask_cc );
  XB[1] = v128_blendv( t2, t0, mask_cc );
  XB[2] = v128_blendv( t1, t3, mask_cc );
  XB[3] = v128_blendv( t3, t1, mask_cc );
  t0 = v128_blendv( XC[0], XC[2], mask_f0 );
  t1 = v128_blendv( XC[2], XC[0], mask_f0 );
  t2 = v128_blendv( XC[1], XC[3], mask_3c );
  t3 = v128_blendv( XC[3], XC[1], mask_3c );
  XC[0] = v128_blendv( t0, t2, mask_cc );
  XC[1] = v128_blendv( t2, t0, mask_cc );
  XC[2] = v128_blendv( t1, t3, mask_cc );
  XC[3] = v128_blendv( t3, t1, mask_cc );

#endif

/*  
   v128_ovly ya[4], za[4], yb[4], zb[4], yc[4], zc[4];

   ya[0].m128 = XA[0];
   yb[0].m128 = XB[0];
   yc[0].m128 = XC[0];
   ya[1].m128 = XA[1];
   yb[1].m128 = XB[1];
   yc[1].m128 = XC[1];
   ya[2].m128 = XA[2];
   yb[2].m128 = XB[2];
   yc[2].m128 = XC[2];
   ya[3].m128 = XA[3];
   yb[3].m128 = XB[3];
   yc[3].m128 = XC[3];

   za[0].u32[0] = ya[0].u32[0];
   zb[0].u32[0] = yb[0].u32[0];
   zc[0].u32[0] = yc[0].u32[0];
   za[0].u32[1] = ya[3].u32[1];
   zb[0].u32[1] = yb[3].u32[1];
   zc[0].u32[1] = yc[3].u32[1];
   za[0].u32[2] = ya[2].u32[2];
   zb[0].u32[2] = yb[2].u32[2];
   zc[0].u32[2] = yc[2].u32[2];
   za[0].u32[3] = ya[1].u32[3];
   zb[0].u32[3] = yb[1].u32[3];
   zc[0].u32[3] = yc[1].u32[3];

   za[1].u32[0] = ya[1].u32[0];
   zb[1].u32[0] = yb[1].u32[0];
   zc[1].u32[0] = yc[1].u32[0];
   za[1].u32[1] = ya[0].u32[1];
   zb[1].u32[1] = yb[0].u32[1];
   zc[1].u32[1] = yc[0].u32[1];
   za[1].u32[2] = ya[3].u32[2];
   zb[1].u32[2] = yb[3].u32[2];
   zc[1].u32[2] = yc[3].u32[2];
   za[1].u32[3] = ya[2].u32[3];
   zb[1].u32[3] = yb[2].u32[3];
   zc[1].u32[3] = yc[2].u32[3];

   za[2].u32[0] = ya[2].u32[0];
   zb[2].u32[0] = yb[2].u32[0];
   zc[2].u32[0] = yc[2].u32[0];
   za[2].u32[1] = ya[1].u32[1];
   zb[2].u32[1] = yb[1].u32[1];
   zc[2].u32[1] = yc[1].u32[1];
   za[2].u32[2] = ya[0].u32[2];
   zb[2].u32[2] = yb[0].u32[2];
   zc[2].u32[2] = yc[0].u32[2];
   za[2].u32[3] = ya[3].u32[3];
   zb[2].u32[3] = yb[3].u32[3];
   zc[2].u32[3] = yc[3].u32[3];

   za[3].u32[0] = ya[3].u32[0];
   zb[3].u32[0] = yb[3].u32[0];
   zc[3].u32[0] = yc[3].u32[0];
   za[3].u32[1] = ya[2].u32[1];
   zb[3].u32[1] = yb[2].u32[1];
   zc[3].u32[1] = yc[2].u32[1];
   za[3].u32[2] = ya[1].u32[2];
   zb[3].u32[2] = yb[1].u32[2];
   zc[3].u32[2] = yc[1].u32[2];
   za[3].u32[3] = ya[0].u32[3];
   zb[3].u32[3] = yb[0].u32[3];
   zc[3].u32[3] = yc[0].u32[3];

   XA[0] = za[0].m128;
   XB[0] = zb[0].m128;
   XC[0] = zc[0].m128;
   XA[1] = za[1].m128;
   XB[1] = zb[1].m128;
   XC[1] = zc[1].m128;
   XA[2] = za[2].m128;
   XB[2] = zb[2].m128;
   XC[2] = zc[2].m128;
   XA[3] = za[3].m128;
   XB[3] = zb[3].m128;
   XC[3] = zc[3].m128;
*/
}   

// Triple buffered, 3x memory usage
// No interleaving
static void salsa8_simd128_3buf( uint32_t *ba, uint32_t *bb, uint32_t *bc,
               const uint32_t *ca, const uint32_t *cb, const uint32_t *cc )
{
   v128_t XA0, XA1, XA2, XA3, XB0, XB1, XB2, XB3,
           XC0, XC1, XC2, XC3;
   v128_t *BA = (v128_t*)ba;
   v128_t *BB = (v128_t*)bb;
   v128_t *BC = (v128_t*)bc;
   const v128_t *CA = (const v128_t*)ca;
   const v128_t *CB = (const v128_t*)cb;
   const v128_t *CC = (const v128_t*)cc;

   // define targets for macros used in round function template
   #define ROL_1X32    v128_shufll32
   #define ROR_1X32    v128_shuflr32
   #define SWAP_64     v128_swap64
   #define ROL32       v128_rol32
   #define ADD32       v128_add32
   #define XOR         v128_xor
   #define TYPE        v128_t

   XA0 = BA[0] = v128_xor( BA[0], CA[0] );
   XB0 = BB[0] = v128_xor( BB[0], CB[0] );
   XC0 = BC[0] = v128_xor( BC[0], CC[0] );
   XA1 = BA[1] = v128_xor( BA[1], CA[1] );
   XB1 = BB[1] = v128_xor( BB[1], CB[1] );
   XC1 = BC[1] = v128_xor( BC[1], CC[1] );
   XA2 = BA[2] = v128_xor( BA[2], CA[2] );
   XB2 = BB[2] = v128_xor( BB[2], CB[2] );
   XC2 = BC[2] = v128_xor( BC[2], CC[2] );
   XA3 = BA[3] = v128_xor( BA[3], CA[3] );
   XB3 = BB[3] = v128_xor( BB[3], CB[3] );
   XC3 = BC[3] = v128_xor( BC[3], CC[3] );
      
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)
   
   SALSA_8ROUNDS_SIMD128_3BUF;

#else

   SALSA_8ROUNDS_SIMD128_3BUF_SLOROT;

#endif

   BA[0] = v128_add32( BA[0], XA0 );
   BB[0] = v128_add32( BB[0], XB0 );
   BC[0] = v128_add32( BC[0], XC0 );
   BA[1] = v128_add32( BA[1], XA1 );
   BB[1] = v128_add32( BB[1], XB1 );
   BC[1] = v128_add32( BC[1], XC1 );
   BA[2] = v128_add32( BA[2], XA2 );
   BB[2] = v128_add32( BB[2], XB2 );
   BC[2] = v128_add32( BC[2], XC2 );
   BA[3] = v128_add32( BA[3], XA3 );
   BB[3] = v128_add32( BB[3], XB3 );
   BC[3] = v128_add32( BC[3], XC3 );

   #undef ROL_1X32
   #undef ROR_1X32
   #undef SWAP_64
   #undef ROL32
   #undef ADD32
   #undef XOR
   #undef TYPE
}

void scrypt_core_simd128_3buf( uint32_t *X, uint32_t *V, const uint32_t N )
{
   uint32_t *X0 = X;
   uint32_t *X1 = X+32;
   uint32_t *X2 = X+64;
   uint32_t *V0 = V;
   uint32_t *V1 = V + 32*N;
   uint32_t *V2 = V + 64*N;

   salsa_simd128_shuffle_3buf( X0,    X1,    X2    );
   salsa_simd128_shuffle_3buf( X0+16, X1+16, X2+16 );
  
   for ( int n = 0; n < N; n++ )
   {
   #if defined(__AVX__) 

      for ( int i = 0; i < 4; i++ )
      {
         _mm256_stream_si256( (__m256i*)V0 + n*4 + i, casti_m256i( X0, i ) );
         _mm256_stream_si256( (__m256i*)V1 + n*4 + i, casti_m256i( X1, i ) );
         _mm256_stream_si256( (__m256i*)V2 + n*4 + i, casti_m256i( X2, i ) );
      }

   #elif defined(__SSE4_1__)

      for ( int i = 0; i < 8; i++ )
      {
         _mm_stream_si128( (v128_t*)V0 + n*8 + i, casti_v128( X0, i ) );
         _mm_stream_si128( (v128_t*)V1 + n*8 + i, casti_v128( X1, i ) );
         _mm_stream_si128( (v128_t*)V2 + n*8 + i, casti_v128( X2, i ) );
      }

   #else

      memcpy( &V0[ n*32 ], X0, 128 );
      memcpy( &V1[ n*32 ], X1, 128 );
      memcpy( &V2[ n*32 ], X2, 128 );

   #endif

      salsa8_simd128_3buf( X0,    X1,    X2   , X0+16, X1+16, X2+16 );
      salsa8_simd128_3buf( X0+16, X1+16, X2+16, X0,    X1,    X2    );
   }

   for ( int n = 0; n < N; n++ )
   {
   #if defined(__AVX2__)

      const int j0 = 4 * ( X0[16] & ( N-1 ) );
      const int j1 = 4 * ( X1[16] & ( N-1 ) );
      const int j2 = 4 * ( X2[16] & ( N-1 ) );

      const __m256i v00 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0   );
      const __m256i v10 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1   );
      const __m256i v20 = _mm256_stream_load_si256( ( (__m256i*)V2 ) +j2   );
      const __m256i v01 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+1 );
      const __m256i v11 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+1 );
      const __m256i v21 = _mm256_stream_load_si256( ( (__m256i*)V2 ) +j2+1 );
      const __m256i v02 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+2 );
      const __m256i v12 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+2 );
      const __m256i v22 = _mm256_stream_load_si256( ( (__m256i*)V2 ) +j2+2 );
      const __m256i v03 = _mm256_stream_load_si256( ( (__m256i*)V0 ) +j0+3 );
      const __m256i v13 = _mm256_stream_load_si256( ( (__m256i*)V1 ) +j1+3 );
      const __m256i v23 = _mm256_stream_load_si256( ( (__m256i*)V2 ) +j2+3 );

      casti_m256i( X0, 0 ) = _mm256_xor_si256( casti_m256i( X0, 0 ), v00 );
      casti_m256i( X1, 0 ) = _mm256_xor_si256( casti_m256i( X1, 0 ), v10 );
      casti_m256i( X2, 0 ) = _mm256_xor_si256( casti_m256i( X2, 0 ), v20 );
      casti_m256i( X0, 1 ) = _mm256_xor_si256( casti_m256i( X0, 1 ), v01 );
      casti_m256i( X1, 1 ) = _mm256_xor_si256( casti_m256i( X1, 1 ), v11 );
      casti_m256i( X2, 1 ) = _mm256_xor_si256( casti_m256i( X2, 1 ), v21 );
      casti_m256i( X0, 2 ) = _mm256_xor_si256( casti_m256i( X0, 2 ), v02 );
      casti_m256i( X1, 2 ) = _mm256_xor_si256( casti_m256i( X1, 2 ), v12 );
      casti_m256i( X2, 2 ) = _mm256_xor_si256( casti_m256i( X2, 2 ), v22 );
      casti_m256i( X0, 3 ) = _mm256_xor_si256( casti_m256i( X0, 3 ), v03 );
      casti_m256i( X1, 3 ) = _mm256_xor_si256( casti_m256i( X1, 3 ), v13 );
      casti_m256i( X2, 3 ) = _mm256_xor_si256( casti_m256i( X2, 3 ), v23 );

   #else

      const int j0 = 8 * ( X0[16] & ( N-1 ) );
      const int j1 = 8 * ( X1[16] & ( N-1 ) );
      const int j2 = 8 * ( X2[16] & ( N-1 ) );
      for ( int i = 0; i < 8; i++ )
      {
         const v128_t v0 = v128_load( ( (v128_t*)V0 ) +j0+i );
         const v128_t v1 = v128_load( ( (v128_t*)V1 ) +j1+i );
         const v128_t v2 = v128_load( ( (v128_t*)V2 ) +j2+i );
         casti_v128( X0, i ) = v128_xor( casti_v128( X0, i ), v0 );
         casti_v128( X1, i ) = v128_xor( casti_v128( X1, i ), v1 );
         casti_v128( X2, i ) = v128_xor( casti_v128( X2, i ), v2 );
      }

   #endif

      salsa8_simd128_3buf( X0,    X1,    X2   , X0+16, X1+16, X2+16 );
      salsa8_simd128_3buf( X0+16, X1+16, X2+16, X0,    X1,    X2    );
   }

   salsa_simd128_unshuffle_3buf( X0,    X1,    X2    );
   salsa_simd128_unshuffle_3buf( X0+16, X1+16, X2+16 );

}


#endif // SSE2


// Reference, used only for testing.
// Tested OK.

static void xor_salsa8(uint32_t * const B, const uint32_t * const C)
{
   uint32_t x0 = (B[ 0] ^= C[ 0]),
            x1 = (B[ 1] ^= C[ 1]),
            x2 = (B[ 2] ^= C[ 2]),
            x3 = (B[ 3] ^= C[ 3]);
   uint32_t x4 = (B[ 4] ^= C[ 4]),
            x5 = (B[ 5] ^= C[ 5]),
            x6 = (B[ 6] ^= C[ 6]),
            x7 = (B[ 7] ^= C[ 7]);
   uint32_t x8 = (B[ 8] ^= C[ 8]),
            x9 = (B[ 9] ^= C[ 9]),
            xa = (B[10] ^= C[10]),
            xb = (B[11] ^= C[11]);
   uint32_t xc = (B[12] ^= C[12]),
            xd = (B[13] ^= C[13]),
            xe = (B[14] ^= C[14]),
            xf = (B[15] ^= C[15]);

   
   #define ROL32( a, c )    ror32( a, c )
   #define ADD32( a, b )    ( (a)+(b) )
   #define XOR( a, b )      ( (a)^(b) )

   SALSA_8ROUNDS;

   #undef ROL32
   #undef ADD32
   #undef XOR

   B[ 0] += x0;
   B[ 1] += x1;
   B[ 2] += x2;
   B[ 3] += x3;
   B[ 4] += x4;
   B[ 5] += x5;
   B[ 6] += x6;
   B[ 7] += x7;
   B[ 8] += x8;
   B[ 9] += x9;
   B[10] += xa;
   B[11] += xb;
   B[12] += xc;
   B[13] += xd;
   B[14] += xe;
   B[15] += xf;
}

/**
 * @param X input/ouput
 * @param V scratch buffer
 * @param N factor (def. 1024)
 */


void scrypt_core_1way( uint32_t *X, uint32_t *V, const uint32_t N )
{
   for ( int n = 0; n < N; n++ )
   {
      memcpy( &V[ n*32 ], X, 128 );
      xor_salsa8( &X[ 0], &X[16] );
      xor_salsa8( &X[16], &X[ 0] );
   }
   for ( int n = 0; n < N; n++ )
   {
      int j = 32 * ( X[16] & ( N - 1 ) );
      for ( int i = 0; i < 32; i++ )
         X[i] ^= V[ j+i ];
      xor_salsa8( &X[ 0], &X[16] );
      xor_salsa8( &X[16], &X[ 0] );
   }
}



