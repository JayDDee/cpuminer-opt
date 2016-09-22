//   Some tools to help using AVX and AVX2

#include <inttypes.h>
//#include <immintrin.h>

// Use these overlays to access the same data in memory as different types
//
// Can they be used to access data in ymm/xmm regs?
// Can they be used in expressions?
// uint64 a;
// area256 v;
// _mm256_load_si256( v.v256, p );
//  a = v.v64[0];
//  a = v.64[0] + v.v64[1];

typedef union
{
#if defined __AVX__
__m256i   v256;
#endif
__m128i   v128[ 2];
uint64_t  v64 [ 4];
uint32_t  v32 [ 8];
uint16_t  v16 [16];
uint8_t   v8  [32];
} area256;

typedef union
{
__m128i   v128;
uint64_t  v64[ 2];
uint32_t  v32[ 4];
uint16_t  v16[ 8];
uint8_t   v8 [16];
} area128;


// useful instrinsics to move data between regs

// move 128 from ymm to xmm
// dst = a[127:0]   ; imm8 == 0
// dst = a[255:0]   ; imm8 == 1
//__m128i _mm256_extracti128_si256(__m256i a, int imm8)

//move 128 from xmm to ymm
// dst = a( a[255:128], b )  ; mask == 0
// dst = a( b, a[127:0] )    ; mask == 1
//__m256i _mm256_inserti128_si256(__m256i a, __m128i b, const int mask);

#if defined __AVX2__

// Rotate bits in 4 uint64
// __m256i mm256_rotr_64( __256i, int )
#define  mm256_rotr_64(w,c) _mm256_or_si256(_mm256_srli_epi64(w, c), \
                                            _mm256_slli_epi64(w, 64 - c))
//static inline __m256i mm256_rotr_64 ( __m256i w, int c)
//{
//   return _mm256_or_si256( _mm256_srli_epi64( w, c ),
//                           _mm256_slli_epi64( w, 64 - c ) );
//}
// Rotate uint64 by one uint64
//__m256i mm256_rotl256_1x64( _mm256i, int )
#define mm256_rotl256_1x64(s) _mm256_permute4x64_epi64( s, 0x39 )
#define mm256_rotr256_1x64(s) _mm256_permute4x64_epi64( s, 0x93 )
//static inline __m256i mm256_rotl256_1x64( __m256i s ) 
//{ 
//   return _mm256_permute4x64_epi64( s, 0x39 );
//}
//static inline __m256i mm256_rotr256_1x64( __m256i s )
//{
//   return _mm256_permute4x64_epi64( s, 0x93 );
//}

// swap hi and lo 128 bits in 256 bit vector
//  __m256i mm256_swap128( __m256i )
#define mm256_swap128(s) _mm256_permute2f128_si256( s, s, 1 )
//static inline __m256i mm256_swap128( __m256i s )
//{
//    return _mm256_permute2f128_si256( s, s, 1 );
//}

#endif

// rotate bits in 2 uint64
// _m128i mm_rotr_64( __m128i, int )
#define  mm_rotr_64(w,c) _mm_or_si128(_mm_srli_epi64(w, c), \
                                      _mm_slli_epi64(w, 64 - c))
//static inline __m128i  mm_rotr_64( __m128i w, int c )
//{
//      _mm_or_si128( _mm_srli_epi64( w, c ), 
//                    _mm_slli_epi64( w, 64 - c ) );
//}

// swap 128 bit source vectors
// void mm128_swap128( __m128i, __m128i )
// macro is better to update two args
#define mm128_swap128(s0, s1) s0 = _mm_xor_si128(s0, s1); \
                              s1 = _mm_xor_si128(s0, s1); \
                              s0 = _mm_xor_si128(s0, s1);


// swap upper and lower 64 bits of 128 bit source vector
// __m128i mm128_swap64( __m128 )
#define mm128_swap64(s) _mm_or_si128( _mm_slli_si128( s, 8 ), \
                                      _mm_srli_si128( s, 8 ) )

// rotate 2 128 bit vectors as one 256 vector by 1 uint64, use as equivalent of
// mm256_rotl256_1x64 when avx2 is not available or data is alreeady in __m128i
// format. uses one local
//void mm128_rotl256_1x64( __m128i, __m128i )
#define mm128_rotl256_1x64(s0, s1) do { \
   __m128i t; \
   s0 = mm128_swap64( s0); \
   s1 = mm128_swap64( s1); \
   t = _mm_or_si128( _mm_and_si128( s0, _mm_set_epi64x(0ull,0xffffffffffffffffull) ), \
                     _mm_and_si128( s1, _mm_set_epi64x(0xffffffffffffffffull,0ull) ) ); \
   s1 = _mm_or_si128( _mm_and_si128( s0, _mm_set_epi64x(0xffffffffffffffffull,0ull) ), \
                      _mm_and_si128( s1, _mm_set_epi64x(0ull,0xffffffffffffffffull) ) ); \
   s0 = t; \
} while(0)

#define mm128_rotr256_1x64(s0, s1) do { \
   __m128i t; \
   s0 = mm128_swap64( s0); \
   s1 = mm128_swap64( s1); \
   t = _mm_or_si128( _mm_and_si128( s0, _mm_set_epi64x(0xffffffffffffffffull,0ull) ), \
                        _mm_and_si128( s1, _mm_set_epi64x(0ull,0xffffffffffffffffull) ) ); \
   s1 = _mm_or_si128( _mm_and_si128( s0, _mm_set_epi64x(0ull,0xffffffffffffffffull) ), \
                      _mm_and_si128( s1, _mm_set_epi64x(0xffffffffffffffffull,0ull) ) ); \
   s0 = t; \
} while(0)

