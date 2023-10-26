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
//    MMX:     64 bit vectors  (Not used in cpuminer-opt) 
//    SSE2:   128 bit vectors  (64 bit CPUs only, such as Intel Core2.
//    AVX2:   256 bit vectors  (Starting with Intel Haswell and AMD Ryzen)
//    AVX512: 512 bit vectors  (Starting with SkylakeX)
//    AVX10:  when available will supersede AVX512 and will bring AVX512
//        features, except 512 bit vectors, to Intel's Ecores. It needs to be
//        enabled manually when the relevant GCC macros are known.
//
//    Most functions are avalaible at the stated levels but in rare cases
//    a higher level feature may be required with no compatible alternative.
//    Some SSE2 functions have versions optimized for higher feature levels
//    such as SSSE3 or SSE4.1 that will be used automatically on capable
//    CPUs.
//
//    Strict alignment of data is required: 16 bytes for 128 bit vectors,
//    32 bytes for 256 bit vectors and 64 bytes for 512 bit vectors. 64 byte
//    alignment is recommended in all cases for best cache alignment.
//
//    All functions are defined with type agnostic pointers (void*) arguments
//    and are cast or aliased as the appropriate type. This adds convenience
//    for the applications but also adds responsibility to ensure adequate data
//    alignment.
//
//    An attempt was made to make the names as similar as possible to
//    Intel's intrinsic function format. Most variations are to avoid
//    confusion with actual Intel intrinsics, brevity, and clarity.
//
//    The main differences are:
//
//   - the leading underscore "_" is dropped from the prefix of vector function
//     macros.
//   - "mm128" is used 128 bit prefix to be consistent with mm256 & mm512 and
//     to avoid the ambiguity of "mm" which is also used for 64 bit MMX
//     intrinsics.
//   - the element size does not include additional type specifiers
//      like "epi".
//   - there is a subset of some functions for scalar data. They may have
//     no prefix nor vec-size, just one size, the size of the data.
//   - Some integer functions are also defined which use a similar notation.
//   
//    Function names follow this pattern:
//
//         [prefix]_[op][vsize]_[esize]
//
//    Prefix: usually the size of the returned vector.
//    Following are some examples:
//
//    u64:  unsigned 64 bit integer function
//    i128: signed 128 bit integer function (rarely used)
//    m128: 128 bit vector identifier (deprecated)
//    mm128: 128 bit vector function
//
//    op: describes the operation of the function or names the data
//        identifier.
//
//    esize: optional, element size of operation
//
//    vsize: optional, lane size used when a function operates on elements
//           within lanes of a larger vector.
//
//    Ex: mm256_shuflr128_32 rotates each 128 bit lane of a 256 bit vector
//        right by 32 bits.
// 
//  New architecture agnostic syntax to support multiple architectures.
//  currently only used for 128 bit vectors.
//
//         [prefix]_[op]esize]
//
//  Abbreviated when no vsize, space is removed between op & esize.
//
//  Ex:  v128_add32 gets remapped to the appropriate architecture intrinsic.
//
//  New type specification includes element size because it's significant on
//  AArch64. For x86_64 they'r all maped to v128_t. On arm the default is
//  v128u32_t.
//
//   v128_t, v1q28u64_t, v128u32_t.
//
//  [prefix] is changed to "v128" or size specific for typedef.
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
//////////////////////////////////////////////////////////////////////////

#include <inttypes.h>
#include <memory.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>

#if defined(__x86_64__)

#include <x86intrin.h>

#elif defined(__aarch64__)

#include <arm_neon.h>

#endif

#include "simd-utils/simd-int.h"

// x86_64 MMX 64 bit vectors
#include "simd-utils/simd-64.h"

// x86_64 SSE2 128 bit vectors
#include "simd-utils/simd-128.h"

// x86_64 AVX2 256 bit vectors
#include "simd-utils/simd-256.h"

// x86_64 AVX512 512 bit vectors
#include "simd-utils/simd-512.h"

// move up after cleaning
// CPU architectire abstraction
//#include "simd-utils/simd-portable.h"

// aarch64 neon 128 bit vectors
#include "simd-utils/simd-neon.h"

#include "simd-utils/intrlv.h"

#endif  // SIMD_UTILS_H__
