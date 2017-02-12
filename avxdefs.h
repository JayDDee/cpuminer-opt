//   Some tools to help using AVX and AVX2

#include <inttypes.h>
#include <immintrin.h>

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
#if defined __AVX2__
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

#if defined (__AVX2__)

// Replacements for vectorized data
// n = number of __m256i (32 bytes)
inline void memset_zero_m256i( __m256i *dst, int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = _mm256_setzero_si256();
}

inline void memset_m256i( __m256i *dst, const __m256i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}


// optimized copying, first fit is usually best. If none of these works there
// are __m128i versions or plain memcpy.
 
// Fixed size

// multi  buffered copy for 64 bytes, the size of a cache line.
// minimum alignment is 32 bytes, optimum for cache is 64.
// src & dst are __m256i*
inline void mcpy64_m256i( __m256i* dst, const __m256i* src )
{
  const __m256i* dest = dst;
  const __m256i* srce = src;
  __m256i a = _mm256_load_si256( srce   );
  __m256i b = _mm256_load_si256( srce + 1 );
             _mm256_store_si256( dest,   a );
             _mm256_store_si256( dest + 1, b );
}  

inline void mcpy96_m256i( __m256i* dst, const __m256i* src )
{
  const __m256i* dest = dst;
  const __m256i* srce = src;
  __m256i a = _mm256_load_si256( srce   );
  __m256i b = _mm256_load_si256( srce + 1 );
             _mm256_store_si256( dest,     a );
  __m256i c = _mm256_load_si256( srce + 2 );
             _mm256_store_si256( dest + 1, b );
             _mm256_store_si256( dest + 2, c );
}           

inline void mcpy128_m256i( __m256i* dst, const __m256i* src )
{
   const __m256i* dest = dst;
   const __m256i* srce = src;
   __m256i a = _mm256_load_si256( srce     );
   __m256i b = _mm256_load_si256( srce + 1 );
   __m256i c = _mm256_load_si256( srce + 2 );
              _mm256_store_si256( dest    , a );
   __m256i d = _mm256_load_si256( srce + 3 );
              _mm256_store_si256( dest + 1, b );
           a = _mm256_load_si256( srce + 4 );
              _mm256_store_si256( dest + 2, c );
           b = _mm256_load_si256( srce + 5 );
              _mm256_store_si256( dest + 3, d );
           c = _mm256_load_si256( srce + 6 );
              _mm256_store_si256( dest + 4, a );
           d = _mm256_load_si256( srce + 7 );
              _mm256_store_si256( dest + 5, b );
              _mm256_store_si256( dest + 6, c );
              _mm256_store_si256( dest + 7, d );
}

// Variable size

// copy multiples of 64 bytes using quad buffering with interleave
// of first read of next line with last write of current line.
// n is a multiple of  32 bytes (_m256i size)
// minimum alignment:  32 bytes
// optimum alignment:  64 bytes (cache line size)
// minimum size.....: 128 bytes (4*n)
// recommended size.: 256+ bytes
// minimum increment: 128 bytes
// Only the first load or store in a cache line triggers a memory access.
// the subsequent actions are trivial because they benefit from data
// cached by the first.
// Priming the second cache line is done before dumping the first to
// give read priority to ensure there are no gaps in data available to
// the cpu caused by waiting for data to be written back.

inline void mcpy_m256i_x4( __m256i *dst, const __m256i *src, const int n )
{
   const __m256i* dest = dst;
   const __m256i* srce = src;

   // preload 1 cache line to absorb startup latency
   __m256i a = _mm256_load_si256( srce     );
   __m256i b = _mm256_load_si256( srce + 1 );
   // start loading second line, queue while waiting
   __m256i c = _mm256_load_si256( srce + 2 );
   // start writing first line, as soon as data available,
   // second line read will have priority on the bus
              _mm256_store_si256( dest, a );
   __m256i d;

   int i;
   const int loops = n/4 - 1;

   for ( i = 0; i < loops; i++ )
   {
      const int i4 = i*4;
      const __m256i* si4 = (__m256i*)(srce + i4);
      const __m256i* di4 = (__m256i*)(dest + i4);

      d = _mm256_load_si256( si4 + 3 );
         _mm256_store_si256( di4 + 1, b );
      // start loading next line
      a = _mm256_load_si256( si4 + 4 );
         _mm256_store_si256( di4 + 2, c );
      b = _mm256_load_si256( si4 + 5 );
         _mm256_store_si256( di4 + 3, d );
      c = _mm256_load_si256( si4 + 6 );
      // start writing next line
          _mm256_store_si256( di4 + 4, a );
   }
   // finish last line
   d = _mm256_load_si256( srce + n - 4 );
      _mm256_store_si256( dest + n - 3, b );
      _mm256_store_si256( dest + n - 2, c );
      _mm256_store_si256( dest + n - 1, d );
}

// basic __m256i memcpy

inline void memcpy_m256i( __m256i *dst, const __m256i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}


// For cheating with pointer types

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m256i(p) ((__m256i*)(p))
#define castp_m128i(p) ((__m128i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m256i(p) (*((__m256i*)(p)))
#define cast_m128i(p) (*((__m128i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns p[i]
#define casti_m256i(p,i) (((__m256i*)(p))[(i)])
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

// useful instrinsics to move data between regs

// move 128 from ymm to xmm
// dst = a[127:0]   ; imm8 == 0
// dst = a[255:0]   ; imm8 == 1
//__m128i _mm256_extracti128_si256(__m256i a, int imm8)

//move 128 from xmm to ymm
// dst = a( a[255:128], b )  ; mask == 0
// dst = a( b, a[127:0] )    ; mask == 1
//__m256i _mm256_inserti128_si256(__m256i a, __m128i b, const int mask);

// Rotate bits in 4 uint64  (3 instructions)
// __m256i mm256_rotr_64( __256i, int )
#define  mm256_rotr_64( w, c ) \
    _mm256_or_si256( _mm256_srli_epi64(w, c), _mm256_slli_epi64(w, 64 - c) )

#define  mm256_rotl_64( w, c ) \
    _mm256_or_si256( _mm256_slli_epi64(w, c), _mm256_srli_epi64(w, 64 - c) )

// swap hi and lo 128 bits in 256 bit vector
//  __m256i mm256_swap128( __m256i )
#define mm256_swap128( w ) \
    _mm256_permute2f128_si256( w, w, 1 )

// Rotate 256 bits by 64 bits (4 uint64 by one uint64)
//__m256i mm256_rotl256_1x64( _mm256i, int )
#define mm256_rotl256_1x64( w ) \
     _mm256_permute4x64_epi64( w, 0x39 )

#define mm256_rotr256_1x64( w ) \
     _mm256_permute4x64_epi64( w, 0x93 )

// shift 256 bits by n*64 bits (4 uint64 by n uint64)
#define mm256_slli256_1x64( w ) \
    _mm256_and_si256( mm256_rotl256_1x64( w ), \
                      _mm256_set_epi64x( 0, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull ) )
/*                      _mm256_set_epi64x( 0xffffffffffffffffull, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull, \
                                         0 ) )
*/

#define mm256_slli256_2x64( w ) \
    _mm256_and_si256( mm256_swap128( w ), \
                      _mm256_set_epi64x( 0xffffffffffffffffull, \
                                         0xffffffffffffffffull, \
                                         0, \
                                         0 ) )

#define mm256_slli256_3x64( w ) \
    _mm256_and_si256( mm256_rotr256_1x64( w ), \
                      _mm256_set_epi64x( 0xffffffffffffffffull, \
                                         0, \
                                         0, \
                                         0 ) )

#define mm256_srli256_1x64( w ) \
    _mm256_and_si256( mm256_rotr256_1x64( w ), \
                      _mm256_set_epi64x( 0, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull ) )

#define mm256_srli256_2x64( w ) \
    _mm256_and_si256( mm256_swap128( w ), \
                      _mm256_set_epi64x( 0, \
                                         0, \
                                         0xffffffffffffffffull, \
                                         0xffffffffffffffffull ))

#define mm256_srli256_3x64( w ) \
    _mm256_and_si256( mm256_rotl256_1x64( w ), \
                      _mm256_set_epi64x( 0xffffffffffffffffull, \
                                         0, \
                                         0, \
                                         0 ) )
/*                      _mm256_set_epi64x( 0, \
                                         0, \
                                         0, \
                                         0xffffffffffffffffull ) )
*/

#endif  // AVX2

// Replacements for vectorized data

inline void memset_zero_m128i( __m128i *dst,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = _mm_setzero_si128();
}

inline void memset_m128i( __m128i *dst, const __m128i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}

// __m128i versions of optimized copying

inline void mcpy32_m128i( __m128i* dst, const __m128i* src )
{
   const __m128i* dest = dst;
   const __m128i* srce = src;
   // 4 loads fills cache line
   __m128i a = _mm_load_si128( srce     );
   __m128i b = _mm_load_si128( srce + 1 );
              _mm_store_si128( dest,     a );
              _mm_store_si128( dest + 1, b );
}

inline void mcpy64_m128i( __m128i* dst, const __m128i* src )
{
   const __m128i* dest = dst;
   const __m128i* srce = src;
   // 4 loads fills cache line
   __m128i a = _mm_load_si128( srce     );
   __m128i b = _mm_load_si128( srce + 1 );
   __m128i c = _mm_load_si128( srce + 2 );
   __m128i d = _mm_load_si128( srce + 3 );
   // need to store a before overwriting it
              _mm_store_si128( dest,     a );
           a = _mm_load_si128( srce + 4 );
              _mm_store_si128( dest + 1, b );
           b = _mm_load_si128( srce + 5 );
              _mm_store_si128( dest + 2, c );
           c = _mm_load_si128( srce + 6 );
              _mm_store_si128( dest + 3, d );
           d = _mm_load_si128( srce + 7 );
              _mm_store_si128( dest + 4, a );
           d = _mm_load_si128( srce + 7 );
              _mm_store_si128( dest + 5, b );
              _mm_store_si128( dest + 6, c );
              _mm_store_si128( dest + 7, d );
}

// Variable length

// copy multiples of 16 bytes using quad buffering.
// n is a multiple of 16 bytes (__m128i size)
// minimum alignment: 16 bytes
// optimum alignment: 64 bytes (cache line size)
// minimum size.....: 32 bytes (4*n)
// recommended size.: 96+ bytes
// minimum increment: 32 bytes
inline void memcpy_m128i_x4( __m128i *dst, const __m128i *src, const int n )
{
   // preload 1 cache line to absorb startup latency
   __m128i a = _mm_load_si128( src     );
   __m128i b = _mm_load_si128( src + 1 );
   __m128i c = _mm_load_si128( src + 2 );
   __m128i d = _mm_load_si128( src + 3 );

   int i;
   const int loops = n/4 - 1;
   const __m128i* dst_n = (__m128i*)(dst + n);
 
   for ( i = 0; i < loops; i++ )
   {
      const int i4 = i*4;
      const __m128i* si4 = (__m128i*)(src + i4);
      const __m128i* di4 = (__m128i*)(dst + i4);

      // need to free a before overwriting it
         _mm_store_si128( di4,     a );
      a = _mm_load_si128( di4 + 4 );
         _mm_store_si128( di4 + 1, b );
      b = _mm_load_si128( di4 + 5 );
         _mm_store_si128( di4 + 2, c );
      c = _mm_load_si128( di4 + 6 );
         _mm_store_si128( di4 + 3, d );
      d = _mm_load_si128( di4 + 7 );
   }
   _mm_store_si128( dst_n - 4, a );
   _mm_store_si128( dst_n - 3, b );
   _mm_store_si128( dst_n - 2, c );
   _mm_store_si128( dst_n - 1, d );
}

// basic __m128i copy
inline void memcpy_m128i( __m128i *dst, const __m128i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}

// For cheating with pointer types

// p = any aligned pointer
// returns p as pointer to vector type
#define castp_m128i(p) ((__m128i*)(p))

// p = any aligned pointer
// returns *p, watch your pointer arithmetic
#define cast_m128i(p) (*((__m128i*)(p)))

// p = any aligned pointer, i = scaled array index
// returns p[i]
#define casti_m128i(p,i) (((__m128i*)(p))[(i)])

// rotate bits in 2 uint64
// _m128i mm_rotr_64( __m128i, int )
#define  mm_rotr_64(w,c) _mm_or_si128(_mm_srli_epi64(w, c), \
                                      _mm_slli_epi64(w, 64 - c))

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

