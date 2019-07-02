#if !defined(INTRLV_SELECTOR_H__)
#define INTRLV_SELECTOR_H__

//////////////////////////////////////////////////////////////
//
//  Generic interface for interleaving data for parallel processing.
//
//  Best tech is chosen atomatically.

/*
#if defined(__AVX512F__)

#define intrlv_4x128      mm512_intrlv_4x128
#define intrlv_4x128      mm512_intrlv_4x128

#define intrlv_8x64       mm512_intrlv_8x64
#define dintrlv_8x64      mm512_dintrlv_8x64
#define extr_lane_8x64    mm512_extr_lane_8x64

#define intrlv_16x32      mm512_intrlv_16x32
#define dintrlv_16x32     mm512_dintrlv_16x32
#define extr_lane_16x32    mm512_extr_lane_16x32

#define intrlv_2x128      mm512_intrlv_2x128
#define dintrlv_2x128     mm512_dintrlv_2x128

#define intrlv_4x64       mm512_intrlv_4x64
#define dintrlv_4x64      mm512_dintrlv_4x64
#define extr_lane_4x64    mm512_extr_lane_4x64

#define intrlv_8x32       mm512_intrlv_8x32
#define dintrlv_8x32      mm512_dintrlv_8x32
#define extr_lane_8x32    mm512_extr_lane_8x32

#elif defined(__AVX__)
*/
#if defined(__AVX__)

#define intrlv_2x128      mm256_intrlv_2x128
#define dintrlv_2x128     mm256_dintrlv_2x128

#define intrlv_4x64       mm256_intrlv_4x64
#define dintrlv_4x64      mm256_dintrlv_4x64
#define extr_lane_4x64    mm256_extr_lane_4x64

#define intrlv_8x32       mm256_intrlv_8x32
#define dintrlv_8x32      mm256_dintrlv_8x32
#define extr_lane_8x32    mm256_extr_lane_8x32

#define intrlv_4x32       mm256_intrlv_4x32
#define dintrlv_4x32      mm256_dintrlv_4x32
#define extr_lane_4x32    mm256_extr_lane_4x32

#else

#define intrlv_2x128      mm128_intrlv_2x128
#define dintrlv_2x128     mm128_dintrlv_2x128

#define intrlv_4x64       mm128_intrlv_4x64
#define dintrlv_4x64      mm128_dintrlv_4x64
#define extr_lane_4x64    mm128_extr_lane_4x64

#define intrlv_8x32       mm128_intrlv_8x32
#define dintrlv_8x32      mm128_dintrlv_8x32
#define extr_lane_8x32    mm128_extr_lane_8x32

#define intrlv_2x64       mm128_intrlv_2x64
#define dintrlv_2x64      mm128_dintrlv_2x64
#define extr_lane_2x64    mm128_extr_lane_2x64

#define intrlv_4x32       mm128_intrlv_4x32
#define dintrlv_4x32      mm128_dintrlv_4x32
#define extr_lane_4x32    mm128_extr_lane_4x32

#endif

#endif  // INTRLV_SELECTOR_H__
