#ifndef _SWIFFT_STDINT_H
#define _SWIFFT_STDINT_H

///////////////////////////////////////////////////////////////////////////////////////////////
//
// A note from SWIFFTX implementers:
//
// Although the submission was targeted for Microsoft Visual Studio 2005 compiler, we strived
// to make the code as portable as possible. This is why we preferred to use the types defined
// here, instead of Microsoft-specific types. We compiled the code with gcc to make this sure.
// However, we couldn't use this header as is, due to VS2005 compiler objections. This is why
// we commented out certain defines and clearly marked it.
// To compile our code on gcc you may define SYS_STDINT.
//
///////////////////////////////////////////////////////////////////////////////////////////////

#ifdef SYS_STDINT

#include <stdint.h>

#else

#include "inttypes.h"
// The following was commented out by SWIFFTX implementers:
// __BEGIN_DECLS

typedef swift_int8_t swifftx_int_least8_t;
typedef swift_int16_t swifftx_int_least16_t;
typedef swift_int32_t swifftx_int_least32_t;
typedef swift_uint8_t swifftx_uint_least8_t;
typedef swift_uint16_t swifftx_uint_least16_t;
typedef swift_uint32_t swifftx_uint_least32_t;

#ifndef __STRICT_ANSI__
typedef swift_int64_t swifftx_int_least64_t;
typedef swift_uint64_t swifftx_uint_least64_t;
#endif

/*typedef signed char int_fast8_t;
typedef signed long int int_fast16_t;
typedef signed long int int_fast32_t;
typedef signed long long int int_fast64_t;

typedef unsigned char uint_fast8_t;
typedef unsigned long int uint_fast16_t;
typedef unsigned long int uint_fast32_t;
typedef unsigned long long int uint_fast64_t;*/

// The following was commented out by SWIFFTX implementers:
// #include <endian.h>
// __END_DECLS
#endif

#endif
