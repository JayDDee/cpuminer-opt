/* $Id: md_helper.c 216 2010-06-08 09:46:57Z tp $ */
/*
 * This file contains some functions which implement the external data
 * handling and padding for Merkle-Damgard hash functions which follow
 * the conventions set out by MD4 (little-endian) or SHA-1 (big-endian).
 *
 * API: this file is meant to be included, not compiled as a stand-alone
 * file. Some macros must be defined:
 *   RFUN   name for the round function
 *   HASH   "short name" for the hash function
 *   BE32   defined for big-endian, 32-bit based (e.g. SHA-1)
 *   LE32   defined for little-endian, 32-bit based (e.g. MD5)
 *   BE64   defined for big-endian, 64-bit based (e.g. SHA-512)
 *   LE64   defined for little-endian, 64-bit based (no example yet)
 *   PW01   if defined, append 0x01 instead of 0x80 (for Tiger)
 *   BLEN   if defined, length of a message block (in bytes)
 *   PLW1   if defined, length is defined on one 64-bit word only (for Tiger)
 *   PLW4   if defined, length is defined on four 64-bit words (for WHIRLPOOL)
 *   SVAL   if defined, reference to the context state information
 *
 * BLEN is used when a message block is not 16 (32-bit or 64-bit) words:
 * this is used for instance for Tiger, which works on 64-bit words but
 * uses 512-bit message blocks (eight 64-bit words). PLW1 and PLW4 are
 * ignored if 32-bit words are used; if 64-bit words are used and PLW1 is
 * set, then only one word (64 bits) will be used to encode the input
 * message length (in bits), otherwise two words will be used (as in
 * SHA-384 and SHA-512). If 64-bit words are used and PLW4 is defined (but
 * not PLW1), four 64-bit words will be used to encode the message length
 * (in bits). Note that regardless of those settings, only 64-bit message
 * lengths are supported (in bits): messages longer than 2 Exabytes will be
 * improperly hashed (this is unlikely to happen soon: 2 Exabytes is about
 * 2 millions Terabytes, which is huge).
 *
 * If CLOSE_ONLY is defined, then this file defines only the sph_XXX_close()
 * function. This is used for Tiger2, which is identical to Tiger except
 * when it comes to the padding (Tiger2 uses the standard 0x80 byte instead
 * of the 0x01 from original Tiger).
 *
 * The RFUN function is invoked with two arguments, the first pointing to
 * aligned data (as a "const void *"), the second being state information
 * from the context structure. By default, this state information is the
 * "val" field from the context, and this field is assumed to be an array
 * of words ("sph_u32" or "sph_u64", depending on BE32/LE32/BE64/LE64).
 * from the context structure. The "val" field can have any type, except
 * for the output encoding which assumes that it is an array of "sph_u32"
 * values. By defining NO_OUTPUT, this last step is deactivated; the
 * includer code is then responsible for writing out the hash result. When
 * NO_OUTPUT is defined, the third parameter to the "close()" function is
 * ignored.
 *
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
 *
 * @author   Thomas Pornin <thomas.pornin@cryptolog.com>
 */

#ifdef _MSC_VER
#pragma warning (disable: 4146)
#endif

#undef SPH_XCAT
#define SPH_XCAT(a, b)     SPH_XCAT_(a, b)
#undef SPH_XCAT_
#define SPH_XCAT_(a, b)    a ## b

#undef SPH_BLEN
#undef SPH_WLEN
#if defined BE64 || defined LE64
#define SPH_BLEN    128U
#define SPH_WLEN      8U
#else
#define SPH_BLEN     64U
#define SPH_WLEN      4U
#endif

#ifdef BLEN
#undef SPH_BLEN
#define SPH_BLEN    BLEN
#endif

#undef SPH_MAXPAD
#if defined PLW1
#define SPH_MAXPAD   (SPH_BLEN - SPH_WLEN)
#elif defined PLW4
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 2))
#else
#define SPH_MAXPAD   (SPH_BLEN - (SPH_WLEN << 1))
#endif

#undef SPH_VAL
#undef SPH_NO_OUTPUT
#ifdef SVAL
#define SPH_VAL         SVAL
#define SPH_NO_OUTPUT   1
#else
#define SPH_VAL   sc->val
#endif

#ifndef CLOSE_ONLY

#ifdef SPH_UPTR
static void
SPH_XCAT(HASH, _short)( void *cc, const void *data, size_t len )
#else
void
HASH ( void *cc, const void *data, size_t len )
#endif
{
   SPH_XCAT( HASH, _context ) *sc;
   __m256i *vdata = (__m256i*)data;
   size_t ptr;

   sc = cc;
   ptr = (unsigned)sc->count & (SPH_BLEN - 1U);
   while ( len > 0 )
   {
      size_t clen;
      clen = SPH_BLEN - ptr;
      if ( clen > len )
         clen = len;
      memcpy_256( sc->buf + (ptr>>3), vdata, clen>>3 );
      vdata = vdata + (clen>>3);
      ptr += clen;
      len -= clen;
      if ( ptr == SPH_BLEN )
      {
         RFUN( sc->buf, SPH_VAL );
         ptr = 0;
      }
         sc->count += clen;
   }
}

#ifdef SPH_UPTR
void
HASH (void *cc, const void *data, size_t len)
{
   SPH_XCAT(HASH, _context) *sc;
   __m256i *vdata = (__m256i*)data;
   unsigned ptr;

   if ( len < (2 * SPH_BLEN) )
   {
      SPH_XCAT(HASH, _short)(cc, data, len);
      return;
   }
   sc = cc;
   ptr = (unsigned)sc->count & (SPH_BLEN - 1U);
   if ( ptr > 0 )
   {
      unsigned t;
      t = SPH_BLEN - ptr;
      SPH_XCAT( HASH, _short )( cc, data, t );
      vdata = vdata + (t>>3);
      len -= t;
   }
   SPH_XCAT( HASH, _short )( cc, data, len );
}
#endif

#endif

/*
 * Perform padding and produce result. The context is NOT reinitialized
 * by this function.
 */
static void
SPH_XCAT( HASH, _addbits_and_close )(void *cc, 	unsigned ub, unsigned n,
          void *dst, unsigned rnum )
{
    SPH_XCAT(HASH, _context) *sc;
    unsigned ptr, u;
    sc = cc;
    ptr = (unsigned)sc->count & (SPH_BLEN - 1U);

//uint64_t *b= (uint64_t*)sc->buf;
//uint64_t *s= (uint64_t*)sc->state;
//printf("Vptr 1= %u\n", ptr);
//printf("VBuf %016llx %016llx %016llx %016llx\n", b[0], b[4], b[8], b[12] );
//printf("VBuf %016llx %016llx %016llx %016llx\n", b[16], b[20], b[24], b[28] );

#ifdef PW01
    sc->buf[ptr>>3] = _mm256_set1_epi64x( 0x100 >> 8 );
//    sc->buf[ptr++] = 0x100 >> 8;
#else
// need to overwrite exactly one byte
//    sc->buf[ptr>>3] = _mm256_set_epi64x( 0, 0, 0, 0x80 );
    sc->buf[ptr>>3] = _mm256_set1_epi64x( 0x80 );
//    ptr++;
#endif
    ptr += 8;

//printf("Vptr 2= %u\n", ptr);
//printf("VBuf %016llx %016llx %016llx %016llx\n", b[0], b[4], b[8], b[12] );
//printf("VBuf %016llx %016llx %016llx %016llx\n", b[16], b[20], b[24], b[28] );

    if ( ptr > SPH_MAXPAD )
    {
         memset_zero_256( sc->buf + (ptr>>3), (SPH_BLEN - ptr) >> 3 );
         RFUN( sc->buf, SPH_VAL );
         memset_zero_256( sc->buf, SPH_MAXPAD >> 3 );
    }
    else
    {
         memset_zero_256( sc->buf + (ptr>>3), (SPH_MAXPAD - ptr) >> 3 );
    }
#if defined BE64
#if defined PLW1
    sc->buf[ SPH_MAXPAD>>3 ] =
                 mm256_bswap_64( _mm256_set1_epi64x( sc->count << 3 ) );
#elif defined PLW4
    memset_zero_256( sc->buf + (SPH_MAXPAD>>3), ( 2 * SPH_WLEN ) >> 3 );
    sc->buf[ (SPH_MAXPAD + 2 * SPH_WLEN ) >> 3 ] =
                mm256_bswap_64( _mm256_set1_epi64x( sc->count >> 61 ) );
    sc->buf[ (SPH_MAXPAD + 3 * SPH_WLEN ) >> 3 ] =
                mm256_bswap_64( _mm256_set1_epi64x( sc->count << 3 ) );
#else
    sc->buf[ ( SPH_MAXPAD + 2 * SPH_WLEN ) >> 3 ] =
               mm256_bswap_64( _mm256_set1_epi64x( sc->count >> 61 ) );
    sc->buf[ ( SPH_MAXPAD + 3 * SPH_WLEN ) >> 3 ] =
               mm256_bswap_64( _mm256_set1_epi64x( sc->count << 3 ) );
#endif  // PLW
#else  // LE64
#if defined PLW1
    sc->buf[ SPH_MAXPAD >> 3 ] = _mm256_set1_epi64x( sc->count << 3 );
#elif defined PLW4
    sc->buf[ SPH_MAXPAD >> 3 ] = _mm256_set1_epi64x( sc->count << 3 );
    sc->buf[ ( SPH_MAXPAD + SPH_WLEN ) >> 3 ] =
                       _mm256_set1_epi64x( c->count >> 61 );
    memset_zero_256( sc->buf + ( ( SPH_MAXPAD + 2 * SPH_WLEN ) >> 3 ),
                       2 * SPH_WLEN );
#else
    sc->buf[ SPH_MAXPAD >> 3 ] = _mm256_set1_epi64x( sc->count << 3 );
    sc->buf[ ( SPH_MAXPAD + SPH_WLEN ) >> 3 ] =
                          _mm256_set1_epi64x( sc->count >> 61 );
#endif // PLW

#endif // LE64

//printf("Vptr 3= %u\n", ptr);
//printf("VBuf   %016llx %016llx %016llx %016llx\n", b[0], b[4], b[8], b[12] );
//printf("VBuf   %016llx %016llx %016llx %016llx\n", b[16], b[20], b[24], b[28] );
    RFUN( sc->buf, SPH_VAL );

//printf("Vptr after= %u\n", ptr);
//printf("VState %016llx %016llx %016llx %016llx\n", s[0], s[4], s[8], s[12] );
//printf("VState %016llx %016llx %016llx %016llx\n", s[16], s[20], s[24], s[28] );

#ifdef SPH_NO_OUTPUT
    (void)dst;
    (void)rnum;
    (void)u;
#else
    for ( u = 0; u < rnum; u ++ )
    {
#if defined BE64
       ((__m256i*)dst)[u] = mm256_bswap_64( sc->val[u] );
#else  // LE64
       ((__m256i*)dst)[u] = sc->val[u];
#endif
    }
#endif
}

static void
SPH_XCAT( HASH, _mdclose )( void *cc, void *dst, unsigned rnum )
{
   SPH_XCAT( HASH, _addbits_and_close )( cc, 0, 0, dst, rnum );
}
