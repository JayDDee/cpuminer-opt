#include <stddef.h>
#include <stdint.h>
#include "keccak-hash-4way.h"
#include "keccak-gate.h"

//#if defined(__AVX2__)

static const uint64_t RC[] = {
        0x0000000000000001, 0x0000000000008082,
        0x800000000000808A, 0x8000000080008000,
        0x000000000000808B, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009,
        0x000000000000008A, 0x0000000000000088,
        0x0000000080008009, 0x000000008000000A,
        0x000000008000808B, 0x800000000000008B,
        0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080,
        0x000000000000800A, 0x800000008000000A,
        0x8000000080008081, 0x8000000000008080,
        0x0000000080000001, 0x8000000080008008
};

// generic macros

#define a00   (kc->w[ 0])
#define a10   (kc->w[ 1])
#define a20   (kc->w[ 2])
#define a30   (kc->w[ 3])
#define a40   (kc->w[ 4])
#define a01   (kc->w[ 5])
#define a11   (kc->w[ 6])
#define a21   (kc->w[ 7])
#define a31   (kc->w[ 8])
#define a41   (kc->w[ 9])
#define a02   (kc->w[10])
#define a12   (kc->w[11])
#define a22   (kc->w[12])
#define a32   (kc->w[13])
#define a42   (kc->w[14])
#define a03   (kc->w[15])
#define a13   (kc->w[16])
#define a23   (kc->w[17])
#define a33   (kc->w[18])
#define a43   (kc->w[19])
#define a04   (kc->w[20])
#define a14   (kc->w[21])
#define a24   (kc->w[22])
#define a34   (kc->w[23])
#define a44   (kc->w[24])

#define MOV64(d, s)      (d = s)
#define XOR64_IOTA       XOR


#define LPAR   (
#define RPAR   )

#define DO(x)   x

#if defined(SIMD512)

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = _mm512_xor_si512( kc->w[j], buf[j] ); \
} while (0)

// Targetted macros, keccak-macros.h is included for each target.

#define DECL64(x)          __m512i x
#define XOR(d, a, b)       (d = _mm512_xor_si512(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = _mm512_and_si512(a,b))
#define OR64(d, a, b)      (d = _mm512_or_si512(a,b))
#define NOT64(d, s)        (d = mm512_not( s ) )
#define ROL64(d, v, n)     (d = mm512_rol_64(v, n))
#define XOROR(d, a, b, c)  (d = mm512_xoror(a, b, c))
#define XORAND(d, a, b, c) (d = mm512_xorand(a, b, c))
#define XOR3( d, a, b, c ) (d = mm512_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_512)

#define KECCAK_F_1600_512   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, _mm512_set1_epi64( RC[j + 0] ) ); \
       KF_ELT( 1,  2, _mm512_set1_epi64( RC[j + 1] ) ); \
       KF_ELT( 2,  3, _mm512_set1_epi64( RC[j + 2] ) ); \
       KF_ELT( 3,  4, _mm512_set1_epi64( RC[j + 3] ) ); \
       KF_ELT( 4,  5, _mm512_set1_epi64( RC[j + 4] ) ); \
       KF_ELT( 5,  6, _mm512_set1_epi64( RC[j + 5] ) ); \
       KF_ELT( 6,  7, _mm512_set1_epi64( RC[j + 6] ) ); \
       KF_ELT( 7,  8, _mm512_set1_epi64( RC[j + 7] ) ); \
       P8_TO_P0; \
    } \
} while (0)

static void keccak64_8way_init( keccak64_ctx_m512i *kc, unsigned out_size )
{
   __m512i zero = m512_zero;
   __m512i neg1 = m512_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64_8way_core( keccak64_ctx_m512i *kc, const void *data, size_t len,
               size_t lim )
{
    __m512i *buf;
    __m512i *vdata = (__m512i*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        memcpy_512( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }
    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        memcpy_512( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64_8way_close( keccak64_ctx_m512i *kc, void *dst,
                                 size_t byte_len, size_t lim )
{
    __m512i tmp[lim + 1] __attribute__ ((aligned (64)));
    size_t j;
    size_t m512_len = byte_len >> 3;
    const unsigned eb = hard_coded_eb;

    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        tmp[0] = _mm512_set1_epi64( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        tmp[0] = _mm512_set1_epi64( eb );
        memset_zero_512( tmp + 1, (j>>3) - 2 );
        tmp[ (j>>3) - 1] = _mm512_set1_epi64( 0x8000000000000000 );
    }
    keccak64_8way_core( kc, tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    memcpy_512( dst, kc->w, m512_len );
}

void keccak256_8x64_init( void *kc )
{
   keccak64_8way_init( kc, 256 );
}

void
keccak256_8x64_update(void *cc, const void *data, size_t len)
{
    keccak64_8way_core(cc, data, len, 136);
}

void
keccak256_8x64_close(void *cc, void *dst)
{
    keccak64_8way_close(cc, dst, 32, 136);
}

void keccak256_8x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_8x64_init( cc );
   keccak256_8x64_update( cc, data, len );
   keccak256_8x64_close( cc, dst );
}

void keccak512_8x64_init( void *kc )
{
   keccak64_8way_init( kc, 512 );
}

void
keccak512_8x64_update(void *cc, const void *data, size_t len)
{
        keccak64_8way_core(cc, data, len, 72);
}

void
keccak512_8x64_close(void *cc, void *dst)
{
        keccak64_8way_close(cc, dst, 64, 72);
}

void keccak512_8x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_8x64_init( cc );
   keccak512_8x64_update( cc, data, len );
   keccak512_8x64_close( cc, dst );
}

#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef XOROR
#undef XORAND
#undef XOR3

#endif  // AVX512

#if defined(__AVX2__)

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = _mm256_xor_si256( kc->w[j], buf[j] ); \
} while (0)

#define DECL64(x)          __m256i x
#define XOR(d, a, b)       (d = _mm256_xor_si256(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = _mm256_and_si256(a,b))
#define OR64(d, a, b)      (d = _mm256_or_si256(a,b))
#define NOT64(d, s)        (d = mm256_not( s ) )
#define ROL64(d, v, n)     (d = mm256_rol_64(v, n))
#define XOROR(d, a, b, c)  (d = mm256_xoror( a, b, c ) )
#define XORAND(d, a, b, c) (d = mm256_xorand( a, b, c ) )
#define XOR3( d, a, b, c ) (d = mm256_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_256)

#define KECCAK_F_1600_256   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, _mm256_set1_epi64x( RC[j + 0] ) ); \
       KF_ELT( 1,  2, _mm256_set1_epi64x( RC[j + 1] ) ); \
       KF_ELT( 2,  3, _mm256_set1_epi64x( RC[j + 2] ) ); \
       KF_ELT( 3,  4, _mm256_set1_epi64x( RC[j + 3] ) ); \
       KF_ELT( 4,  5, _mm256_set1_epi64x( RC[j + 4] ) ); \
       KF_ELT( 5,  6, _mm256_set1_epi64x( RC[j + 5] ) ); \
       KF_ELT( 6,  7, _mm256_set1_epi64x( RC[j + 6] ) ); \
       KF_ELT( 7,  8, _mm256_set1_epi64x( RC[j + 7] ) ); \
       P8_TO_P0; \
    } \
} while (0)


static void keccak64_init( keccak64_ctx_m256i *kc, unsigned out_size )
{
   __m256i zero = m256_zero;
   __m256i neg1 = m256_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64_core( keccak64_ctx_m256i *kc, const void *data, size_t len,
               size_t lim )
{
    __m256i *buf;
    __m256i *vdata = (__m256i*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        memcpy_256( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }

    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        memcpy_256( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64_close( keccak64_ctx_m256i *kc, void *dst, size_t byte_len,
            size_t lim )
{
    __m256i tmp[lim + 1] __attribute__ ((aligned (32)));
    size_t j;
    size_t m256_len = byte_len >> 3;
    const unsigned eb = hard_coded_eb;

    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        tmp[0] = _mm256_set1_epi64x( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        tmp[0] = _mm256_set1_epi64x( eb );
        memset_zero_256( tmp + 1, (j>>3) - 2 );
        tmp[ (j>>3) - 1] = _mm256_set1_epi64x( 0x8000000000000000 );
    }
    keccak64_core( kc, tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    memcpy_256( dst, kc->w, m256_len );
}

void keccak256_4x64_init( void *kc )
{
   keccak64_init( kc, 256 );
}

void
keccak256_4x64_update(void *cc, const void *data, size_t len)
{
    keccak64_core(cc, data, len, 136);
}

void
keccak256_4x64_close(void *cc, void *dst)
{
    keccak64_close(cc, dst, 32, 136);
}

void keccak256_4x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_4x64_init( cc );
   keccak256_4x64_update( cc, data, len );
   keccak256_4x64_close( cc, dst );
}

void keccak512_4x64_init( void *kc )
{
   keccak64_init( kc, 512 );
}

void
keccak512_4x64_update(void *cc, const void *data, size_t len)
{
   keccak64_core(cc, data, len, 72);
}

void
keccak512_4x64_close(void *cc, void *dst)
{
   keccak64_close(cc, dst, 64, 72);
}

void keccak512_4x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_4x64_init( cc );
   keccak512_4x64_update( cc, data, len );
   keccak512_4x64_close( cc, dst );
}

#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef KECCAK_F_1600_256
#undef XOROR
#undef XORAND
#undef XOR3

#endif  // AVX2

// SSE2 & NEON

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = v128_xor( kc->w[j], buf[j] ); \
} while (0)

#define DECL64(x)          v128_t x
#define XOR(d, a, b)       (d = v128_xor(a,b))
#define XOR64              XOR
#define AND64(d, a, b)     (d = v128_and(a,b))
#define OR64(d, a, b)      (d = v128_or(a,b))
#define NOT64(d, s)        (d = v128_not( s ) )
#define ROL64(d, v, n)     (d = v128_rol64(v, n))
#define XOROR(d, a, b, c)  (d = v128_xoror( a, b, c ) )
#define XORAND(d, a, b, c) (d = v128_xorand( a, b, c ) )
#define XOR3( d, a, b, c ) (d = v128_xor3( a, b, c ))

#include "keccak-macros.c"

#define KECCAK_F_1600   DO(KECCAK_F_1600_256)

#define KECCAK_F_1600_256   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, v128_64( RC[j + 0] ) ); \
       KF_ELT( 1,  2, v128_64( RC[j + 1] ) ); \
       KF_ELT( 2,  3, v128_64( RC[j + 2] ) ); \
       KF_ELT( 3,  4, v128_64( RC[j + 3] ) ); \
       KF_ELT( 4,  5, v128_64( RC[j + 4] ) ); \
       KF_ELT( 5,  6, v128_64( RC[j + 5] ) ); \
       KF_ELT( 6,  7, v128_64( RC[j + 6] ) ); \
       KF_ELT( 7,  8, v128_64( RC[j + 7] ) ); \
       P8_TO_P0; \
    } \
} while (0)

static void keccak64x2_init( keccak64_ctx_v128 *kc, unsigned out_size )
{
   v128_t zero = v128_zero;
   v128_t neg1 = v128_neg1;

   // Initialization for the "lane complement".
   kc->w[ 0] = zero;   kc->w[ 1] = neg1;
   kc->w[ 2] = neg1;   kc->w[ 3] = zero;
   kc->w[ 4] = zero;   kc->w[ 5] = zero;
   kc->w[ 6] = zero;   kc->w[ 7] = zero;
   kc->w[ 8] = neg1;   kc->w[ 9] = zero;
   kc->w[10] = zero;   kc->w[11] = zero;
   kc->w[12] = neg1;   kc->w[13] = zero;
   kc->w[14] = zero;   kc->w[15] = zero;
   kc->w[16] = zero;   kc->w[17] = neg1;
   kc->w[18] = zero;   kc->w[19] = zero;
   kc->w[20] = neg1;   kc->w[21] = zero;
   kc->w[22] = zero;   kc->w[23] = zero;
   kc->w[24] = zero;   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64x2_core( keccak64_ctx_v128 *kc, const void *data, size_t len,
               size_t lim )
{
    v128_t *buf;
    v128_t *vdata = (v128_t*)data;
    size_t ptr;

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        v128_memcpy( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }

    while ( len > 0 )
    {
        size_t clen;

        clen = (lim - ptr);
        if ( clen > len )
             clen = len;
        v128_memcpy( buf + (ptr>>3), vdata, clen>>3 );
        ptr += clen;
        vdata = vdata + (clen>>3);
        len -= clen;
        if ( ptr == lim )
        {
            INPUT_BUF( lim );
            KECCAK_F_1600;
            ptr = 0;
        }
    }
    kc->ptr = ptr;
}

static void keccak64x2_close( keccak64_ctx_v128 *kc, void *dst,
                              size_t byte_len, size_t lim )
{
    unsigned eb;
    union {
       v128_t tmp[140];
       uint64_t dummy;   /* for alignment */
    } u;
    size_t j;
    size_t v128_len = byte_len >> 3;

    eb = hard_coded_eb;
    if ( kc->ptr == (lim - 8) )
    {
        const uint64_t t = eb | 0x8000000000000000;
        u.tmp[0] = v128_64( t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        u.tmp[0] = v128_64( eb );
        v128_memset_zero( u.tmp + 1, (j>>3) - 2 );
        u.tmp[ (j>>3) - 1] = v128_64( 0x8000000000000000 );
    }
    keccak64x2_core( kc, u.tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    v128_memcpy( dst, kc->w, v128_len );
}

void keccak256_2x64_init( void *kc )
{
   keccak64x2_init( kc, 256 );
}

void
keccak256_2x64_update(void *cc, const void *data, size_t len)
{
    keccak64x2_core(cc, data, len, 136);
}

void
keccak256_2x64_close(void *cc, void *dst)
{
    keccak64x2_close(cc, dst, 32, 136);
}

void keccak256_2x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak256_2x64_init( cc );
   keccak256_2x64_update( cc, data, len );
   keccak256_2x64_close( cc, dst );
}

void keccak512_2x64_init( void *kc )
{
   keccak64x2_init( kc, 512 );
}

void
keccak512_2x64_update(void *cc, const void *data, size_t len)
{
   keccak64x2_core(cc, data, len, 72);
}

void
keccak512_2x64_close(void *cc, void *dst)
{
   keccak64x2_close(cc, dst, 64, 72);
}

void keccak512_2x64_ctx( void *cc, void *dst, const void *data, size_t len )
{
   keccak512_2x64_init( cc );
   keccak512_2x64_update( cc, data, len );
   keccak512_2x64_close( cc, dst );
}


#undef INPUT_BUF
#undef DECL64
#undef XOR64
#undef XOR
#undef AND64
#undef OR64
#undef NOT64
#undef ROL64
#undef KECCAK_F_1600
#undef XOROR
#undef XORAND
#undef XOR3
        

