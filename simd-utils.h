#if !defined(SIMD_UTILS_H__)
#define SIMD_UTILS_H__ 1

//////////////////////////////////////////////////////////////////////
//
//             SIMD utilities
//
//    Not to be confused with the hashing function of the same name. This
//    is about Single Instruction Multiple Data programming using CPU
//    features such as SSE and AVX.
//
//    This header is the entry point to a suite of macros and functions
//    to perform basic operations on vectors that are useful in crypto
//    mining. Some of these functions have native CPU support for scalar
//    data but not for vectors. The main categories are bit rotation
//    and endian byte swapping
//
//    An attempt was made to make the names as similar as possible to
//    Intel's intrinsic function format. Most variations are to avoid
//    confusion with actual Intel intrinsics, brevity, and clarity.
//
//    This suite supports some operations on regular 64 bit integers
//    as well as 128 bit integers available on recent versions of Linux
//    and GCC.
//
//    It also supports various vector sizes on CPUs that meet the minimum
//    requirements.
//
//    The minimum for any real work is a 64 bit CPU with SSE2,
//    ie an the Intel Core 2.
//
//    Following are the minimum requirements for each vector size. There
//    is no significant 64 bit vectorization therefore SSE2 is the practical
//    minimum for using this code.
//
//    MMX:     64 bit vectors  
//    SSE2:   128 bit vectors  (64 bit CPUs only, such as Intel Core2.
//    AVX2:   256 bit vectors  (Starting with Intel Haswell and AMD Ryzen)
//    AVX512: 512 bit vectors  (Starting with SkylakeX)
//
//    Most functions are avalaible at the stated levels but in rare cases
//    a higher level feature may be required with no compatible alternative.
//    Some SSE2 functions have versions optimized for higher feature levels
//    such as SSSE3 or SSE4.1 that will be used automatically on capable
//    CPUs.
//
//    The vector size boundaries are respected to maintain compatibility.
//    For example, an instruction introduced with AVX2 may improve 128 bit
//    vector performance but will not be implemented. A CPU with AVX2 will
//    tend to use 256 bit vectors. On a practical level AVX512 does introduce
//    bit rotation instructions for 128 and 256 bit vectors in addition to
//    its own 5a12 bit vectors. These will not be back ported to replace the
//    SW implementations for the smaller vectors. This policy may be reviewed
//    in the future once AVX512 is established. 
//
//    Strict alignment of data is required: 16 bytes for 128 bit vectors,
//    32 bytes for 256 bit vectors and 64 bytes for 512 bit vectors. 64 byte
//    alignment is recommended in all cases for best cache alignment.
//
//    Windows has problems with function vector arguments larger than
//    128 bits. Stack alignment is only guaranteed to 16 bytes. Always use
//    pointers for larger vectors in function arguments. Macros can be
//    used for larger value arguments.
//
//    An attempt was made to make the names as similar as possible to
//    Intel's intrinsic function format. Most variations are to avoid
//    confusion with actual Intel intrinsics, brevity, and clarity
//
//    The main differences are:
//
//   - the leading underscore(s) "_" and the "i" are dropped from the
//     prefix of vector instructions.
//   - "mm64" and "mm128" used for 64 and 128 bit prefix respectively
//     to avoid the ambiguity of "mm".
//   - the element size does not include additional type specifiers
//      like "epi".
//   - some macros contain value args that are updated.
//   - specialized shift and rotate functions that move elements around
//     use the notation "1x32" to indicate the distance moved as units of
//     the element size.
//   - there is a subset of some functions for scalar data. They may have
//     no prefix nor vec-size, just one size, the size of the data.
//   - Some integer functions are also defined which use a similar notation.
//   
//    Function names follow this pattern:
//
//         prefix_op[esize]_[vsize]
//
//    Prefix: usually the size of the largest vectors used. Following
//            are some examples:
//
//    u64:  unsigned 64 bit integer function
//    i128: signed 128 bit integer function (rarely used)
//    m128: 128 bit vector identifier
//    mm128: 128 bit vector function
//
//    op: describes the operation of the function or names the data
//        identifier.
//
//    esize: optional, element size of operation
//
//    vsize: optional, lane size used when a function operates on elements
//           of vectors within lanes of a vector.
//
//    Ex: mm256_ror1x64_128 rotates each 128 bit lane of a 256 bit vector
//        right by 64 bits.
//
// Vector constants
//
// Vector constants are a big problem because they technically don't exist.
// All vectors used as constants either reside in memory or must be genererated
// at run time at significant cost. The cost of generating a constant
// increases non-linearly with the number of vector elements. A 4 element
// vector costs between 7 and 11 clocks to generate, an 8 element vector
// is 15-25 clocks. There are also additional clock due to data dependency
// stalls.
//
// Vector constants are often used as control indexes for permute, blend, etc,
// where generating the index can be over 90% of the operation. This is
// where the problem occurs. An instruction that only requires one to 3
// clocks needs may times more just to build the index argument.
//
// There is very little a programmer can do to avoid the worst case scenarios.
// Smaller integers can be merged to form 64 bit integers, and vectors with
// repeated elements can be generated more efficiently but they have limited
// benefit and limited application.
//
// If a vector constant is to be used repeatedly it is better to define a local
// variable to generate the constant only once.
//
// If a sequence of constants is to be used it can be more efficient to
// use arithmetic with already existing constants to generate new ones.
//
// ex: const __m512i one = m512_one_64;
//     const __m512i two = _mm512_add_epi64( one, one );
//     
//////////////////////////////////////////////////////////////////////////

#include <inttypes.h>
#include <x86intrin.h>
#include <memory.h>
#include <stdlib.h>
#include <stdbool.h>

// 64 and 128 bit integers.
#include "simd-utils/simd-int.h"

#if defined(__MMX__)

// 64 bit vectors
#include "simd-utils/simd-64.h"

#if defined(__SSE2__)

// 128 bit vectors
#include "simd-utils/simd-128.h"

#if defined(__AVX__)

// 256 bit vector basics
#include "simd-utils/simd-256.h"

#if defined(__AVX2__)

// Utilities that require AVX2 are defined in simd-256.h.

// Skylake-X has all these
#if defined(__AVX512F__) && defined(__AVX512VL__) && defined(__AVX512DQ__) && defined(__AVX512BW__)

// 512 bit vectors
#include "simd-utils/simd-512.h"

#endif  // AVX512
#endif  // AVX2
#endif  // AVX
#endif  // SSE2
#endif  // MMX

#include "simd-utils/intrlv.h"

#endif  // SIMD_UTILS_H__
