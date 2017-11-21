// Some tools to help using AVX and AVX2
// AVX support is required to include this header file, AVX2 optional.

#include <inttypes.h>
#include <immintrin.h>
#include <memory.h>

// Use these overlays to access the same data in memory as different types
//
// Can they be used to access data in ymm/xmm regs?
// Can they be used in expressions?
// uint64 a;
// area256 v;
// _mm256_load_si256( v.v256, p );
//  a = v.v64[0];
//  a = v.64[0] + v.v64[1];
// how does endian affect overlay?

typedef union
{
#if defined (__AVX2__)
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

// AVX2 replacements for vectorized data

// n = number of __m256i (32 bytes)
inline void memset_zero_m256i( __m256i *dst, int n )
{
   __m256i zero = _mm256_setzero_si256();
   for ( int i = 0; i < n; i++ ) dst[i] = zero;
}

inline void memset_m256i( __m256i *dst, const __m256i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}

// Optimized copying using vectors. For misaligned data or more ganuularity
// use __m128i versions or plain memcpy as appropriate.
 
// Copying fixed size

// Multi buffered copy using __m256i.
// minimum alignment is 32 bytes (_m1256i), optimum 64 (cache line).
// src & dst are __m256i*

// Copy 64 bytes (2x__m256i, one cache line), double buffered
inline void mcpy64_m256i( __m256i* dest, const __m256i* srce )
{
  __m256i a = _mm256_load_si256( srce     );
  __m256i b = _mm256_load_si256( srce + 1 );
  _mm256_store_si256( dest,     a );
  _mm256_store_si256( dest + 1, b );
}  

// Copy 96 bytes (3x__m256i), triple buffered
inline void mcpy96_m256i( __m256i* dest, const __m256i* srce )
{
  __m256i a = _mm256_load_si256( srce     );
  __m256i b = _mm256_load_si256( srce + 1 );
  __m256i c = _mm256_load_si256( srce + 2 );
  _mm256_store_si256( dest,     a );
  _mm256_store_si256( dest + 1, b );
  _mm256_store_si256( dest + 2, c );
}           

// Copy 128 bytes (4x__m256i), quad buffered
inline void mcpy128_m256i( __m256i* dest, const __m256i* srce )
{
   __m256i a = _mm256_load_si256( srce     );
   __m256i b = _mm256_load_si256( srce + 1 );
   __m256i c = _mm256_load_si256( srce + 2 );
   __m256i d = _mm256_load_si256( srce + 3 );
   _mm256_store_si256( dest    , a );
   a = _mm256_load_si256( srce + 4 );
   _mm256_store_si256( dest + 1, b );
   b = _mm256_load_si256( srce + 5 );
   _mm256_store_si256( dest + 2, c );
   c = _mm256_load_si256( srce + 6 );
   _mm256_store_si256( dest + 3, d );
   d = _mm256_load_si256( srce + 7 );
   _mm256_store_si256( dest + 4, a );
   _mm256_store_si256( dest + 5, b );
   _mm256_store_si256( dest + 6, c );
   _mm256_store_si256( dest + 7, d );
}

// Copy variable size
//
// copy multiples of 64 bytes using quad buffering with interleave
// of first read of next line with last write of current line.
// n is a multiple of  32 bytes (_m256i size)
// minimum alignment:  32 bytes
// optimum alignment:  64 bytes (cache line size)
// minimum size.....: 128 bytes (4*n)
// recommended size.: 256+ bytes (8*n)
// minimum increment: 128 bytes
// Only the first load or store in a cache line triggers a memory access.
// the subsequent actions are trivial because they benefit from data
// cached by the first.
// Priming the second cache line is done before dumping the first to
// give read priority to ensure there are no gaps in data available to
// the cpu caused by waiting for data to be written back.

inline void mcpy_m256i_x4( __m256i *dst, const __m256i *src, const int n )
{
   __m256i* end  = dst + n;

   // preload 1 cache line to absorb startup latency
   __m256i a = _mm256_load_si256( src     );
   __m256i b = _mm256_load_si256( src + 1 );
   // start loading second line, queued while waiting for 1st line.
   __m256i c = _mm256_load_si256( src + 2 );
   // start writing first line, as soon as data available,
   // second line read will have priority on the bus
              _mm256_store_si256( dst, a );
   __m256i d;

   int i;
   const int loops = n/4 - 1;

   for ( i = 0; i < loops; i++ )
   {
      const int i4 = i*4;
      const __m256i* si4 = src + i4;
            __m256i* di4 = dst + i4;

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
   d = _mm256_load_si256( end - 4 );
   _mm256_store_si256( end - 3, b );
   _mm256_store_si256( end - 2, c );
   _mm256_store_si256( end - 1, d );
}

// basic aligned __m256i memcpy
inline void memcpy_m256i( __m256i *dst, const __m256i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}

// For cheating with pointer types

// p = any aligned pointer
// returns p as pointer to vector type, not very useful
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
// w = packed 64 bit data, n= number of bits to rotate
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
// mm256_slli256_nx64( w )
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

// these ones probably are backward
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

// vectored version of BYTES_SWAP32
inline __m256i  mm256_byteswap_epi32( __m256i x )
{
  __m256i x1 = _mm256_and_si256( x,
          _mm256_set_epi32( 0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00,
                            0x0000ff00, 0x0000ff00, 0x0000ff00, 0x0000ff00 ) );
  __m256i x2 = _mm256_and_si256( x,
          _mm256_set_epi32( 0x00ff0000, 0x00ff0000, 0x00ff0000, 0x00ff0000,
                            0x00ff0000, 0x00ff0000, 0x00ff0000, 0x00ff0000 ) );
  __m256i x0 = _mm256_slli_epi32( x, 24 );   // x0 = x << 24
          x1 = _mm256_slli_epi32( x1, 8 );   // x1 = mask(x) << 8
          x2 = _mm256_srli_epi32( x2, 8 );   // x2 = mask(x) >> 8
  __m256i x3 = _mm256_srli_epi32( x, 24 );   // x3 = x >> 24
  return _mm256_or_si256( _mm256_or_si256( x0, x1 ),
                          _mm256_or_si256( x2, x3 ) );
}

inline __m256i mm256_byteswap_epi64( __m256i x )
{
// x = (x >> 32) | (x << 32)
  x = _mm256_or_si256( _mm256_srli_epi64( x, 32 ), _mm256_slli_epi64( x, 32 ) );

// x = ( (x & 0xFFFF0000FFFF0000) >> 16 ) | ( (x & 0x0000FFFF0000FFFF) << 16 )
  x = _mm256_or_si256(
        _mm256_srli_epi64(
          _mm256_and_si256( x,
           _mm256_set_epi64x( 0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000,
                              0xFFFF0000FFFF0000, 0xFFFF0000FFFF0000 ) ), 16 ),
        _mm256_slli_epi64(
          _mm256_and_si256( x,
           _mm256_set_epi64x( 0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF,
                              0x0000FFFF0000FFFF, 0x0000FFFF0000FFFF ) ), 16 ));

// x = ( (x & 0xFF00FF00FF00FF00) >> 8 ) | ( (x & 0x00FF00FF00FF00FF) << 16 )
   x = _mm256_or_si256(
        _mm256_srli_epi64(
          _mm256_and_si256( x,
            _mm256_set_epi64x( 0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00,
                               0xFF00FF00FF00FF00, 0xFF00FF00FF00FF00 ) ), 8 ),
        _mm256_slli_epi64(
          _mm256_and_si256( x,
            _mm256_set_epi64x( 0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF,
                               0x00FF00FF00FF00FF, 0x00FF00FF00FF00FF ) ), 8 ));
  return x;
}

#endif  // AVX2

// AVX replacements for vectorized data

inline void memset_zero_m128i( __m128i *dst,  int n )
{
   __m128i zero = _mm_setzero_si128();
   for ( int i = 0; i < n; i++ ) dst[i] = zero;
//   for ( int i = 0; i < n; i++ ) dst[i] = _mm_xor_si128( dst[i], dst[i] );
}

inline void memset_m128i( __m128i *dst, const __m128i a,  int n )
{
   for ( int i = 0; i < n; i++ ) dst[i] = a;
}

// __m128i versions of optimized copying

// Copy 32 bytes (2x__m128i), double buffered
inline void mcpy32_m128i( __m128i* dest, const __m128i* srce )
{
   // 4 loads fills cache line
   __m128i a = _mm_load_si128( srce     );
   __m128i b = _mm_load_si128( srce + 1 );
   _mm_store_si128( dest,     a );
   _mm_store_si128( dest + 1, b );
}

// Copy 64 Bytes (4x__m128i), quad buffered
inline void mcpy64_m128i( __m128i* dest, const __m128i* srce )
{
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
   _mm_store_si128( dest + 5, b );
   _mm_store_si128( dest + 6, c );
   _mm_store_si128( dest + 7, d );
}

// Copy 96 Bytes (6x__m128i), quad buffered
inline void mcpy96_m128i( __m128i* dest, const __m128i* srce )
{
   // 4 loads fills cache line
   __m128i a = _mm_load_si128( srce     );
   __m128i b = _mm_load_si128( srce +  1 );
   __m128i c = _mm_load_si128( srce +  2 );
   __m128i d = _mm_load_si128( srce +  3 );
   // need to store a before overwriting it
   _mm_store_si128( dest,      a );
   a = _mm_load_si128( srce +  4 );
   _mm_store_si128( dest +  1, b );
   b = _mm_load_si128( srce +  5 );
   _mm_store_si128( dest +  2, c );
   c = _mm_load_si128( srce +  6 );
   _mm_store_si128( dest +  3, d );
   d = _mm_load_si128( srce +  7 );
   _mm_store_si128( dest +  4, a );
   a = _mm_load_si128( srce +  8 );
   _mm_store_si128( dest +  5, b );
   b = _mm_load_si128( srce +  9 );
   _mm_store_si128( dest +  6, c );
   c = _mm_load_si128( srce + 10 );
   _mm_store_si128( dest +  7, d );
   d = _mm_load_si128( srce + 11 );
   _mm_store_si128( dest +  8,  a );
   _mm_store_si128( dest +  9, b );
   _mm_store_si128( dest + 10, c );
   _mm_store_si128( dest + 11, d );
}

// Variable length
//
// Copy multiples of 16 bytes (__m128i) using quad buffering.
// n is a multiple of 16 bytes (__m128i size)
// minimum alignment: 16 bytes
// optimum alignment: 64 bytes (cache line size)
// minimum size.....: 64 bytes (4*n)
// recommended size.: 128+ bytes (8*n)
// minimum increment: 64 bytes
inline void mcpy_m128i_x4( __m128i *dst, const __m128i *src, const int n )
{
   // preload 1 cache line to absorb startup latency
   __m128i a = _mm_load_si128( src     );
   __m128i b = _mm_load_si128( src + 1 );
   __m128i c = _mm_load_si128( src + 2 );
   __m128i d = _mm_load_si128( src + 3 );

   int i;
   const int loops = n/4 - 1;
   __m128i* end = dst + n;
 
   for ( i = 0; i < loops; i++ )
   {
      const int i4 = i*4;
      const __m128i* si4 = src + i4;
            __m128i* di4 = dst + i4;

      // need to free a before overwriting it
      _mm_store_si128( di4,     a );
      a = _mm_load_si128( si4 + 4 );
      _mm_store_si128( di4 + 1, b );
      b = _mm_load_si128( si4 + 5 );
      _mm_store_si128( di4 + 2, c );
      c = _mm_load_si128( si4 + 6 );
      _mm_store_si128( di4 + 3, d );
      d = _mm_load_si128( si4 + 7 );
   }
   _mm_store_si128( end - 4, a );
   _mm_store_si128( end - 3, b );
   _mm_store_si128( end - 2, c );
   _mm_store_si128( end - 1, d );
}

// basic aligned __m128i copy
inline void memcpy_m128i( __m128i *dst, const __m128i *src, int n )
{
   for ( int i = 0; i < n; i ++ ) dst[i] = src[i];
}

inline void memcpy_64( uint64_t* dst, const uint64_t* src, int n )
{
   for ( int i = 0; i < n; i++ )
       dst[i] = src[i];
}

// Smart generic mem copy optimized for copying large data, n = bytes.
// Most efficient with 256 bit aligned data and size a multiple of 4*256,
// but fkexible enough to handle any any alignment, any size with performance
// considerations. For common fixed sizes use the approppriate functions above.
inline void mcpy( void* dst, const void* src, int n )
{
// enforce alignment and minimum size for quad buffered vector copy
#if defined (__AVX2__)
  // Try 256 bit copy
  if ( ( (uint64_t)dst % 32 == 0 ) && ( (const uint64_t)src % 32 == 0 ) )
  {
     if ( n % 128 == 0 )
     {
        mcpy_m256i_x4( (__m256i*)dst, (const __m256i*)src, n/32 );
        return;
     }
     else
     {
        memcpy_m256i( (__m256i*)dst, (const __m256i*)src, n/32 );
        return;
     }
  }
  else
#endif
  // Try 128 bit copy
  if ( ( (uint64_t)dst % 16 == 0 ) && ( (const uint64_t)src % 16 == 0 ) )
  {
     if ( n % 64 == 0 )
     {
        mcpy_m128i_x4( (__m128i*)dst, (const __m128i*)src, n/16 );
        return;
     }
     else
     {   
        memcpy_m128i( (__m128i*)dst, (const __m128i*)src, n/16 );
        return;
      }
  }
  // Try 64 bit copy
  else if ( ( (uint64_t)dst % 8 == 0 ) && ( (const uint64_t)src % 8 == 0 )
           && ( n/8 == 0 ) )
  {
      memcpy_64( (uint64_t*)dst, (const uint64_t*)src, n/8 );
      return;
  }
  // slow copy
  memcpy( dst, src, n );
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
#define mm_rotr_64( w, c ) _mm_or_si128( _mm_srli_epi64( w, c ), \
                                         _mm_slli_epi64( w, 64-c ) )

#define mm_rotr_32( w, c ) _mm_or_si128( _mm_srli_epi32( w, c ), \
                                         _mm_slli_epi32( w, 32-c ) )

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
#define mm128_rotl256_1x64(s0,s1) do { \
   __m128i t; \
   s0 = mm128_swap64(s0); \
   s1 = mm128_swap64(s1); \
   t = _mm_or_si128( \
           _mm_and_si128( s0, _mm_set_epi64x(0ull,0xffffffffffffffffull) ), \
           _mm_and_si128( s1, _mm_set_epi64x(0xffffffffffffffffull,0ull) ) ); \
   s1 = _mm_or_si128( \
           _mm_and_si128( s0, _mm_set_epi64x(0xffffffffffffffffull,0ull) ), \
           _mm_and_si128( s1, _mm_set_epi64x(0ull,0xffffffffffffffffull) ) ); \
   s0 = t; \
} while(0)

#define mm128_rotr256_1x64(s0, s1) do { \
   __m128i t; \
   s0 = mm128_swap64( s0); \
   s1 = mm128_swap64( s1); \
   t = _mm_or_si128( \
          _mm_and_si128( s0, _mm_set_epi64x(0xffffffffffffffffull,0ull) ), \
          _mm_and_si128( s1, _mm_set_epi64x(0ull,0xffffffffffffffffull) ) ); \
   s1 = _mm_or_si128( \
          _mm_and_si128( s0, _mm_set_epi64x(0ull,0xffffffffffffffffull) ), \
          _mm_and_si128( s1, _mm_set_epi64x(0xffffffffffffffffull,0ull) ) ); \
   s0 = t; \
} while(0)


// vectored version of BYTES_SWAP32
inline __m128i  mm_byteswap_epi32( __m128i x )
{
  __m128i x1 = _mm_and_si128( x, _mm_set_epi32( 0x0000ff00, 0x0000ff00,
                                                0x0000ff00, 0x0000ff00 ) );
  __m128i x2 = _mm_and_si128( x, _mm_set_epi32( 0x00ff0000, 0x00ff0000,
                                                0x00ff0000, 0x00ff0000 ) );
  __m128i x0 = _mm_slli_epi32( x, 24 );   // x0 = x << 24
          x1 = _mm_slli_epi32( x1, 8 );   // x1 = mask(x) << 8
          x2 = _mm_srli_epi32( x2, 8 );   // x2 = mask(x) >> 8
  __m128i x3 = _mm_srli_epi32( x, 24 );   // x3 = x >> 24
  return _mm_or_si128( _mm_or_si128( x0, x1 ), _mm_or_si128( x2, x3 ) );
}

// Functions for interleaving buffers for vector processing
// change size to bits for consistency

#if defined (__AVX2__)

// interleave 4 arrays of 64 bit elements for AVX2 processing
// bit_len must be multiple of 64
inline void m256_interleave_4x64( uint64_t *dst, uint64_t *src0,
              uint64_t *src1, uint64_t *src2, uint64_t *src3, int bit_len )
{
   uint64_t *d = dst;
   for ( int i = 0; i < bit_len>>6; i++, d += 4 )
   {
      *d     = *(src0+i);
      *(d+1) = *(src1+i);     
      *(d+2) = *(src2+i);
      *(d+3) = *(src3+i);
  }
}

// Deinterleave 4 arrays into indivudual 64 bit arrays for scalar processing
// bit_len must be multiple 0f 64
inline void m256_deinterleave_4x64( uint64_t *dst0, uint64_t *dst1,
                uint64_t *dst2,uint64_t *dst3, uint64_t *src, int bit_len )
{
  uint64_t *s = src;
   for ( int i = 0; i < bit_len>>6; i++, s += 4 )
  {
     *(dst0+i) = *s;
     *(dst1+i) = *(s+1);    
     *(dst2+i) = *(s+2);   
     *(dst3+i) = *(s+3);   
  }
}

// interleave 8 arrays of 32 bit elements for AVX2 processing
// bit_len must be multiple of 32
inline void m256_interleave_8x32( uint32_t *dst, uint32_t *src0,
     uint32_t *src1, uint32_t *src2, uint32_t *src3, uint32_t *src4,
     uint32_t *src5, uint32_t *src6, uint32_t *src7, int bit_len )
{
   uint32_t *d = dst;;
   for ( int i = 0; i < bit_len>>5; i++, d += 8 )
   {
      *d     = *(src0+i);
      *(d+1) = *(src1+i);
      *(d+2) = *(src2+i);
      *(d+3) = *(src3+i);
      *(d+4) = *(src4+i);
      *(d+5) = *(src5+i);
      *(d+6) = *(src6+i);
      *(d+7) = *(src7+i);
  }
}

// Deinterleave 8 arrays into indivdual buffers for scalar processing
// bit_len must be multiple of 32
inline void m256_deinterleave_8x32( uint32_t *dst0, uint32_t *dst1,
                uint32_t *dst2,uint32_t *dst3, uint32_t *dst4, uint32_t *dst5,
                uint32_t *dst6,uint32_t *dst7,uint32_t *src, int bit_len )
{
  uint32_t *s = src;
  for ( int i = 0; i < bit_len>>5; i++, s += 8 )
  {
     *(dst0+i) = *( s     );
     *(dst1+i) = *( s + 1 );
     *(dst2+i) = *( s + 2 );
     *(dst3+i) = *( s + 3 );
     *(dst4+i) = *( s + 4 );
     *(dst5+i) = *( s + 5 ); 
     *(dst6+i) = *( s + 6 );
     *(dst7+i) = *( s + 7 );
  }
}

// convert 4x32 byte (128 bit) vectors to 4x64 (256 bit) vectors for AVX2
// bit_len must be multiple of 64
inline void m256_reinterleave_4x64( uint64_t *dst, uint32_t *src,
                                         int  bit_len )
{
   uint32_t *d = (uint32_t*)dst;
   for ( int i = 0; i < bit_len >> 5; i += 8 )
   {
      *( d + i     ) = *( src + i     );      // 0 <- 0    8 <- 8
      *( d + i + 1 ) = *( src + i + 4 );      // 1 <- 4    9 <- 12
      *( d + i + 2 ) = *( src + i + 1 );      // 2 <- 1    10 <- 9
      *( d + i + 3 ) = *( src + i + 5 );      // 3 <- 5    11 <- 13
      *( d + i + 4 ) = *( src + i + 2 );      // 4 <- 2    12 <- 10
      *( d + i + 5 ) = *( src + i + 6 );      // 5 <- 6    13 <- 14
      *( d + i + 6 ) = *( src + i + 3 );      // 6 <- 3    14 <- 11
      *( d + i + 7 ) = *( src + i + 7 );      // 7 <- 7    15 <- 15
     }
}

// convert 4x64 byte (256 bit) vectors to 4x32 (128 bit) vectors for AVX
// bit_len must be multiple of 64
inline void m128_reinterleave_4x32( uint32_t *dst, uint64_t *src,
                                         int  bit_len )
{
   uint32_t *s = (uint32_t*)src;
   for ( int i = 0; i < bit_len >> 5; i +=8 )
   {
      *( dst + i     ) = *( s + i     );
      *( dst + i + 1 ) = *( s + i + 2 );
      *( dst + i + 2 ) = *( s + i + 4 );
      *( dst + i + 3 ) = *( s + i + 6 );
      *( dst + i + 4 ) = *( s + i + 1 );
      *( dst + i + 5 ) = *( s + i + 3 );
      *( dst + i + 6 ) = *( s + i + 5 );
      *( dst + i + 7 ) = *( s + i + 7 );
   }
}

#endif

// interleave 4 arrays of 32 bit elements for AVX processing
// bit_len must be multiple of 32
inline void m128_interleave_4x32( uint32_t *dst, uint32_t *src0,
              uint32_t *src1, uint32_t *src2, uint32_t *src3, int bit_len )
{
   uint32_t *d = dst;;
   for ( int i = 0; i < bit_len >> 5; i++, d += 4 )
   {
      *d     = *(src0+i);
      *(d+1) = *(src1+i);
      *(d+2) = *(src2+i);
      *(d+3) = *(src3+i);
   }
}

// deinterleave 4 arrays into individual buffers for scalarm processing
// bit_len must be multiple of 32
inline void m128_deinterleave_4x32( uint32_t *dst0, uint32_t *dst1,
                uint32_t *dst2,uint32_t *dst3, uint32_t *src, int bit_len )
{
  uint32_t *s = src;
  for ( int i = 0; i < bit_len >> 5; i++, s += 4 )
  {
     *(dst0+i) = *s;
     *(dst1+i) = *(s+1);
     *(dst2+i) = *(s+2);
     *(dst3+i) = *(s+3);
  }
}


