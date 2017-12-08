#include <stddef.h>
#include "keccak-hash-4way.h"

#if defined(__AVX2__)

static const sph_u64 RC[] = {
        SPH_C64(0x0000000000000001), SPH_C64(0x0000000000008082),
        SPH_C64(0x800000000000808A), SPH_C64(0x8000000080008000),
        SPH_C64(0x000000000000808B), SPH_C64(0x0000000080000001),
        SPH_C64(0x8000000080008081), SPH_C64(0x8000000000008009),
        SPH_C64(0x000000000000008A), SPH_C64(0x0000000000000088),
        SPH_C64(0x0000000080008009), SPH_C64(0x000000008000000A),
        SPH_C64(0x000000008000808B), SPH_C64(0x800000000000008B),
        SPH_C64(0x8000000000008089), SPH_C64(0x8000000000008003),
        SPH_C64(0x8000000000008002), SPH_C64(0x8000000000000080),
        SPH_C64(0x000000000000800A), SPH_C64(0x800000008000000A),
        SPH_C64(0x8000000080008081), SPH_C64(0x8000000000008080),
        SPH_C64(0x0000000080000001), SPH_C64(0x8000000080008008)
};

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

#define DECL_STATE
#define READ_STATE(sc)
#define WRITE_STATE(sc)

#define INPUT_BUF(size)   do { \
    size_t j; \
    for (j = 0; j < (size>>3); j++ ) \
        kc->w[j ] = _mm256_xor_si256( kc->w[j], buf[j] ); \
} while (0)

#define DECL64(x)        __m256i x
#define MOV64(d, s)      (d = s)
#define XOR64(d, a, b)   (d = _mm256_xor_si256(a,b))
#define AND64(d, a, b)   (d = _mm256_and_si256(a,b))
#define OR64(d, a, b)    (d = _mm256_or_si256(a,b))
#define NOT64(d, s)      (d = _mm256_xor_si256(s,mm256_neg1))
#define ROL64(d, v, n)   (d = mm256_rotl_64(v, n))
#define XOR64_IOTA       XOR64

#define TH_ELT(t, c0, c1, c2, c3, c4, d0, d1, d2, d3, d4)   do { \
                DECL64(tt0); \
                DECL64(tt1); \
                DECL64(tt2); \
                DECL64(tt3); \
                XOR64(tt0, d0, d1); \
                XOR64(tt1, d2, d3); \
                XOR64(tt0, tt0, d4); \
                XOR64(tt0, tt0, tt1); \
                ROL64(tt0, tt0, 1); \
                XOR64(tt2, c0, c1); \
                XOR64(tt3, c2, c3); \
                XOR64(tt0, tt0, c4); \
                XOR64(tt2, tt2, tt3); \
                XOR64(t, tt0, tt2); \
        } while (0)

#define THETA(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
        b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
        b40, b41, b42, b43, b44) \
        do { \
                DECL64(t0); \
                DECL64(t1); \
                DECL64(t2); \
                DECL64(t3); \
                DECL64(t4); \
                TH_ELT(t0, b40, b41, b42, b43, b44, b10, b11, b12, b13, b14); \
                TH_ELT(t1, b00, b01, b02, b03, b04, b20, b21, b22, b23, b24); \
                TH_ELT(t2, b10, b11, b12, b13, b14, b30, b31, b32, b33, b34); \
                TH_ELT(t3, b20, b21, b22, b23, b24, b40, b41, b42, b43, b44); \
                TH_ELT(t4, b30, b31, b32, b33, b34, b00, b01, b02, b03, b04); \
                XOR64(b00, b00, t0); \
                XOR64(b01, b01, t0); \
                XOR64(b02, b02, t0); \
                XOR64(b03, b03, t0); \
                XOR64(b04, b04, t0); \
                XOR64(b10, b10, t1); \
                XOR64(b11, b11, t1); \
                XOR64(b12, b12, t1); \
                XOR64(b13, b13, t1); \
                XOR64(b14, b14, t1); \
                XOR64(b20, b20, t2); \
                XOR64(b21, b21, t2); \
                XOR64(b22, b22, t2); \
                XOR64(b23, b23, t2); \
                XOR64(b24, b24, t2); \
                XOR64(b30, b30, t3); \
                XOR64(b31, b31, t3); \
                XOR64(b32, b32, t3); \
                XOR64(b33, b33, t3); \
                XOR64(b34, b34, t3); \
                XOR64(b40, b40, t4); \
                XOR64(b41, b41, t4); \
                XOR64(b42, b42, t4); \
                XOR64(b43, b43, t4); \
                XOR64(b44, b44, t4); \
        } while (0)

#define RHO(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
        b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
        b40, b41, b42, b43, b44) \
        do { \
                /* ROL64(b00, b00,  0); */ \
                ROL64(b01, b01, 36); \
                ROL64(b02, b02,  3); \
                ROL64(b03, b03, 41); \
                ROL64(b04, b04, 18); \
                ROL64(b10, b10,  1); \
                ROL64(b11, b11, 44); \
                ROL64(b12, b12, 10); \
                ROL64(b13, b13, 45); \
                ROL64(b14, b14,  2); \
                ROL64(b20, b20, 62); \
                ROL64(b21, b21,  6); \
                ROL64(b22, b22, 43); \
                ROL64(b23, b23, 15); \
                ROL64(b24, b24, 61); \
                ROL64(b30, b30, 28); \
                ROL64(b31, b31, 55); \
                ROL64(b32, b32, 25); \
                ROL64(b33, b33, 21); \
                ROL64(b34, b34, 56); \
                ROL64(b40, b40, 27); \
                ROL64(b41, b41, 20); \
                ROL64(b42, b42, 39); \
                ROL64(b43, b43,  8); \
                ROL64(b44, b44, 14); \
        } while (0)

/*
 * The KHI macro integrates the "lane complement" optimization. On input,
 * some words are complemented:
 *    a00 a01 a02 a04 a13 a20 a21 a22 a30 a33 a34 a43
 * On output, the following words are complemented:
 *    a04 a10 a20 a22 a23 a31
 *
 * The (implicit) permutation and the theta expansion will bring back
 * the input mask for the next round.
 */

#define KHI_XO(d, a, b, c)   do { \
                DECL64(kt); \
                OR64(kt, b, c); \
                XOR64(d, a, kt); \
        } while (0)

#define KHI_XA(d, a, b, c)   do { \
                DECL64(kt); \
                AND64(kt, b, c); \
                XOR64(d, a, kt); \
        } while (0)

#define KHI(b00, b01, b02, b03, b04, b10, b11, b12, b13, b14, \
        b20, b21, b22, b23, b24, b30, b31, b32, b33, b34, \
        b40, b41, b42, b43, b44) \
        do { \
                DECL64(c0); \
                DECL64(c1); \
                DECL64(c2); \
                DECL64(c3); \
                DECL64(c4); \
                DECL64(bnn); \
                NOT64(bnn, b20); \
                KHI_XO(c0, b00, b10, b20); \
                KHI_XO(c1, b10, bnn, b30); \
                KHI_XA(c2, b20, b30, b40); \
                KHI_XO(c3, b30, b40, b00); \
                KHI_XA(c4, b40, b00, b10); \
                MOV64(b00, c0); \
                MOV64(b10, c1); \
                MOV64(b20, c2); \
                MOV64(b30, c3); \
                MOV64(b40, c4); \
                NOT64(bnn, b41); \
                KHI_XO(c0, b01, b11, b21); \
                KHI_XA(c1, b11, b21, b31); \
                KHI_XO(c2, b21, b31, bnn); \
                KHI_XO(c3, b31, b41, b01); \
                KHI_XA(c4, b41, b01, b11); \
                MOV64(b01, c0); \
                MOV64(b11, c1); \
                MOV64(b21, c2); \
                MOV64(b31, c3); \
                MOV64(b41, c4); \
                NOT64(bnn, b32); \
                KHI_XO(c0, b02, b12, b22); \
                KHI_XA(c1, b12, b22, b32); \
                KHI_XA(c2, b22, bnn, b42); \
                KHI_XO(c3, bnn, b42, b02); \
                KHI_XA(c4, b42, b02, b12); \
                MOV64(b02, c0); \
                MOV64(b12, c1); \
                MOV64(b22, c2); \
                MOV64(b32, c3); \
                MOV64(b42, c4); \
                NOT64(bnn, b33); \
                KHI_XA(c0, b03, b13, b23); \
                KHI_XO(c1, b13, b23, b33); \
                KHI_XO(c2, b23, bnn, b43); \
                KHI_XA(c3, bnn, b43, b03); \
                KHI_XO(c4, b43, b03, b13); \
                MOV64(b03, c0); \
                MOV64(b13, c1); \
                MOV64(b23, c2); \
                MOV64(b33, c3); \
                MOV64(b43, c4); \
                NOT64(bnn, b14); \
                KHI_XA(c0, b04, bnn, b24); \
                KHI_XO(c1, bnn, b24, b34); \
                KHI_XA(c2, b24, b34, b44); \
                KHI_XO(c3, b34, b44, b04); \
                KHI_XA(c4, b44, b04, b14); \
                MOV64(b04, c0); \
                MOV64(b14, c1); \
                MOV64(b24, c2); \
                MOV64(b34, c3); \
                MOV64(b44, c4); \
        } while (0)

#define IOTA(r)   XOR64_IOTA(a00, a00, r)

#define P0    a00, a01, a02, a03, a04, a10, a11, a12, a13, a14, a20, a21, \
              a22, a23, a24, a30, a31, a32, a33, a34, a40, a41, a42, a43, a44
#define P1    a00, a30, a10, a40, a20, a11, a41, a21, a01, a31, a22, a02, \
              a32, a12, a42, a33, a13, a43, a23, a03, a44, a24, a04, a34, a14
#define P2    a00, a33, a11, a44, a22, a41, a24, a02, a30, a13, a32, a10, \
              a43, a21, a04, a23, a01, a34, a12, a40, a14, a42, a20, a03, a31
#define P3    a00, a23, a41, a14, a32, a24, a42, a10, a33, a01, a43, a11, \
              a34, a02, a20, a12, a30, a03, a21, a44, a31, a04, a22, a40, a13
#define P4    a00, a12, a24, a31, a43, a42, a04, a11, a23, a30, a34, a41, \
              a03, a10, a22, a21, a33, a40, a02, a14, a13, a20, a32, a44, a01
#define P5    a00, a21, a42, a13, a34, a04, a20, a41, a12, a33, a03, a24, \
              a40, a11, a32, a02, a23, a44, a10, a31, a01, a22, a43, a14, a30
#define P6    a00, a02, a04, a01, a03, a20, a22, a24, a21, a23, a40, a42, \
              a44, a41, a43, a10, a12, a14, a11, a13, a30, a32, a34, a31, a33
#define P7    a00, a10, a20, a30, a40, a22, a32, a42, a02, a12, a44, a04, \
              a14, a24, a34, a11, a21, a31, a41, a01, a33, a43, a03, a13, a23
#define P8    a00, a11, a22, a33, a44, a32, a43, a04, a10, a21, a14, a20, \
              a31, a42, a03, a41, a02, a13, a24, a30, a23, a34, a40, a01, a12
#define P9    a00, a41, a32, a23, a14, a43, a34, a20, a11, a02, a31, a22, \
              a13, a04, a40, a24, a10, a01, a42, a33, a12, a03, a44, a30, a21
#define P10   a00, a24, a43, a12, a31, a34, a03, a22, a41, a10, a13, a32, \
              a01, a20, a44, a42, a11, a30, a04, a23, a21, a40, a14, a33, a02
#define P11   a00, a42, a34, a21, a13, a03, a40, a32, a24, a11, a01, a43, \
              a30, a22, a14, a04, a41, a33, a20, a12, a02, a44, a31, a23, a10
#define P12   a00, a04, a03, a02, a01, a40, a44, a43, a42, a41, a30, a34, \
              a33, a32, a31, a20, a24, a23, a22, a21, a10, a14, a13, a12, a11
#define P13   a00, a20, a40, a10, a30, a44, a14, a34, a04, a24, a33, a03, \
              a23, a43, a13, a22, a42, a12, a32, a02, a11, a31, a01, a21, a41
#define P14   a00, a22, a44, a11, a33, a14, a31, a03, a20, a42, a23, a40, \
              a12, a34, a01, a32, a04, a21, a43, a10, a41, a13, a30, a02, a24
#define P15   a00, a32, a14, a41, a23, a31, a13, a40, a22, a04, a12, a44, \
              a21, a03, a30, a43, a20, a02, a34, a11, a24, a01, a33, a10, a42
#define P16   a00, a43, a31, a24, a12, a13, a01, a44, a32, a20, a21, a14, \
              a02, a40, a33, a34, a22, a10, a03, a41, a42, a30, a23, a11, a04
#define P17   a00, a34, a13, a42, a21, a01, a30, a14, a43, a22, a02, a31, \
              a10, a44, a23, a03, a32, a11, a40, a24, a04, a33, a12, a41, a20
#define P18   a00, a03, a01, a04, a02, a30, a33, a31, a34, a32, a10, a13, \
              a11, a14, a12, a40, a43, a41, a44, a42, a20, a23, a21, a24, a22
#define P19   a00, a40, a30, a20, a10, a33, a23, a13, a03, a43, a11, a01, \
              a41, a31, a21, a44, a34, a24, a14, a04, a22, a12, a02, a42, a32
#define P20   a00, a44, a33, a22, a11, a23, a12, a01, a40, a34, a41, a30, \
              a24, a13, a02, a14, a03, a42, a31, a20, a32, a21, a10, a04, a43
#define P21   a00, a14, a23, a32, a41, a12, a21, a30, a44, a03, a24, a33, \
              a42, a01, a10, a31, a40, a04, a13, a22, a43, a02, a11, a20, a34
#define P22   a00, a31, a12, a43, a24, a21, a02, a33, a14, a40, a42, a23, \
              a04, a30, a11, a13, a44, a20, a01, a32, a34, a10, a41, a22, a03
#define P23   a00, a13, a21, a34, a42, a02, a10, a23, a31, a44, a04, a12, \
              a20, a33, a41, a01, a14, a22, a30, a43, a03, a11, a24, a32, a40

#define P8_TO_P0   do { \
                DECL64(t); \
                MOV64(t, a01); \
                MOV64(a01, a11); \
                MOV64(a11, a43); \
                MOV64(a43, t); \
                MOV64(t, a02); \
                MOV64(a02, a22); \
                MOV64(a22, a31); \
                MOV64(a31, t); \
                MOV64(t, a03); \
                MOV64(a03, a33); \
                MOV64(a33, a24); \
                MOV64(a24, t); \
                MOV64(t, a04); \
                MOV64(a04, a44); \
                MOV64(a44, a12); \
                MOV64(a12, t); \
                MOV64(t, a10); \
                MOV64(a10, a32); \
                MOV64(a32, a13); \
                MOV64(a13, t); \
                MOV64(t, a14); \
                MOV64(a14, a21); \
                MOV64(a21, a20); \
                MOV64(a20, t); \
                MOV64(t, a23); \
                MOV64(a23, a42); \
                MOV64(a42, a40); \
                MOV64(a40, t); \
                MOV64(t, a30); \
                MOV64(a30, a41); \
                MOV64(a41, a34); \
                MOV64(a34, t); \
        } while (0)

#define LPAR   (
#define RPAR   )

#define KF_ELT(r, s, k)   do { \
                THETA LPAR P ## r RPAR; \
                RHO LPAR P ## r RPAR; \
                KHI LPAR P ## s RPAR; \
                IOTA(k); \
        } while (0)

#define DO(x)   x

#define KECCAK_F_1600   DO(KECCAK_F_1600_)

#define KECCAK_F_1600_   do { \
    int j; \
    for (j = 0; j < 24; j += 8) \
    { \
       KF_ELT( 0,  1, (_mm256_set_epi64x( RC[j + 0], RC[j + 0], \
                                       RC[j + 0], RC[j + 0])) ); \
       KF_ELT( 1,  2, (_mm256_set_epi64x( RC[j + 1], RC[j + 1], \
                                       RC[j + 1], RC[j + 1])) ); \
       KF_ELT( 2,  3, (_mm256_set_epi64x( RC[j + 2], RC[j + 2], \
                                       RC[j + 2], RC[j + 2])) ); \
       KF_ELT( 3,  4, (_mm256_set_epi64x( RC[j + 3], RC[j + 3], \
                                       RC[j + 3], RC[j + 3])) ); \
       KF_ELT( 4,  5, (_mm256_set_epi64x( RC[j + 4], RC[j + 4], \
                                       RC[j + 4], RC[j + 4])) ); \
       KF_ELT( 5,  6, (_mm256_set_epi64x( RC[j + 5], RC[j + 5], \
                                       RC[j + 5], RC[j + 5])) ); \
       KF_ELT( 6,  7, (_mm256_set_epi64x( RC[j + 6], RC[j + 6], \
                                       RC[j + 6], RC[j + 6])) ); \
       KF_ELT( 7,  8, (_mm256_set_epi64x( RC[j + 7], RC[j + 7], \
                                       RC[j + 7], RC[j + 7])) ); \
       P8_TO_P0; \
    } \
} while (0)


static void keccak64_init( keccak64_ctx_m256i *kc, unsigned out_size )
{
   int i;
   for (i = 0; i < 25; i ++)
          kc->w[i] = _mm256_setzero_si256();

   // Initialization for the "lane complement".
   kc->w[ 1] = mm256_neg1;
   kc->w[ 2] = mm256_neg1;
   kc->w[ 8] = mm256_neg1;
   kc->w[12] = mm256_neg1;
   kc->w[17] = mm256_neg1;
   kc->w[20] = mm256_neg1;
   kc->ptr = 0;
   kc->lim = 200 - (out_size >> 2);
}

static void
keccak64_core( keccak64_ctx_m256i *kc, const void *data, size_t len,
               size_t lim )
{
    __m256i *buf;
    __m256i *vdata = (__m256i*)data;
    size_t ptr;
    DECL_STATE

    buf = kc->buf;
    ptr = kc->ptr;

    if ( len < (lim - ptr) )
    {
        memcpy_256( buf + (ptr>>3), vdata, len>>3 );
        kc->ptr = ptr + len;
        return;
    }

    READ_STATE( kc );
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
    WRITE_STATE( kc );
    kc->ptr = ptr;
}

static void keccak64_close( keccak64_ctx_m256i *kc, void *dst, size_t byte_len,
            size_t lim )
{
    unsigned eb;
    union {
       __m256i tmp[lim + 1];
       sph_u64 dummy;   /* for alignment */
    } u;
    size_t j;
    size_t m256_len = byte_len >> 3;

    eb = 0x100  >> 8;
    if ( kc->ptr == (lim - 8) )
    {
        uint64_t t = eb | 0x8000000000000000;
        u.tmp[0] = _mm256_set_epi64x( t, t, t, t );
        j = 8;
    }
    else
    {
        j = lim - kc->ptr;
        u.tmp[0] = _mm256_set_epi64x( eb, eb, eb, eb );
        memset_zero_256( u.tmp + 1, (j>>3) - 2 );
        u.tmp[ (j>>3) - 1] = _mm256_set_epi64x( 0x8000000000000000,
                0x8000000000000000, 0x8000000000000000, 0x8000000000000000);
    }
    keccak64_core( kc, u.tmp, j, lim );
    /* Finalize the "lane complement" */
    NOT64( kc->w[ 1], kc->w[ 1] );
    NOT64( kc->w[ 2], kc->w[ 2] );
    NOT64( kc->w[ 8], kc->w[ 8] );
    NOT64( kc->w[12], kc->w[12] );
    NOT64( kc->w[17], kc->w[17] );
    NOT64( kc->w[20], kc->w[20] );
    for ( j = 0; j < m256_len; j++ )
         u.tmp[j] =  kc->w[j]; 
    memcpy_256( dst, u.tmp, m256_len );
}

void keccak256_4way_init( void *kc )
{
   keccak64_init( kc, 256 );
}

void
keccak256_4way(void *cc, const void *data, size_t len)
{
    keccak64_core(cc, data, len, 136);
}

void
keccak256_4way_close(void *cc, void *dst)
{
    keccak64_close(cc, dst, 32, 136);
}

void keccak512_4way_init( void *kc )
{
   keccak64_init( kc, 512 );
}

void
keccak512_4way(void *cc, const void *data, size_t len)
{
        keccak64_core(cc, data, len, 72);
}

void
keccak512_4way_close(void *cc, void *dst)
{
        keccak64_close(cc, dst, 64, 72);
}

#endif
