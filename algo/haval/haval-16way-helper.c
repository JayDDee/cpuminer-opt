/* $Id: haval_helper.c 218 2010-06-08 17:06:34Z tp $ */
/*
 * Helper code, included (three times !) by HAVAL implementation.
 *
 * TODO: try to merge this with md_helper.c.
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

#undef SPH_XCAT
#define SPH_XCAT(a, b)    SPH_XCAT_(a, b)
#undef SPH_XCAT_
#define SPH_XCAT_(a, b)   a ## b

static void
SPH_XCAT(SPH_XCAT(haval, PASSES), _16way_update)
( haval_16way_context *sc, const void *data, size_t len )
{
   __m512i *vdata = (__m512i*)data;
   unsigned current;

   current = (unsigned)sc->count_low & 127U;
   while ( len > 0 )
   {
      unsigned clen;
      uint32_t clow, clow2;

      clen = 128U - current;
      if ( clen > len )
         clen = len;
      memcpy_512( sc->buf + (current>>2), vdata, clen>>2 );
      vdata += clen>>2;
      current += clen;
      len -= clen;
      if ( current == 128U )
      {
         DSTATE_16W;
         IN_PREPARE_16W(sc->buf);
         RSTATE_16W;
         SPH_XCAT(CORE_16W, PASSES)(INW_16W);
         WSTATE_16W;
         current = 0;
      }
      clow = sc->count_low;
      clow2 = clow + clen;
      sc->count_low = clow2;
      if ( clow2 < clow )
         sc->count_high ++;
   }
}

static void
SPH_XCAT(SPH_XCAT(haval, PASSES), _16way_close)( haval_16way_context *sc,
                                                void *dst)
{
   unsigned current;
   DSTATE_16W;

   current = (unsigned)sc->count_low & 127UL;

   sc->buf[ current>>2 ] = v512_32( 1 );
   current += 4;   
   RSTATE_16W;
   if ( current > 116UL )
   {
      memset_zero_512( sc->buf + ( current>>2 ), (128UL-current) >> 2 );
      do
      {
         IN_PREPARE_16W(sc->buf);
         SPH_XCAT(CORE_16W, PASSES)(INW_16W);
      } while (0);
      current = 0;
   }

   uint32_t t1, t2;
   memset_zero_512( sc->buf + ( current>>2 ), (116UL-current) >> 2 );
   t1 = 0x01 | (PASSES << 3);
   t2 = sc->olen << 3;
   sc->buf[ 116>>2 ] = v512_32( ( t1 << 16 ) | ( t2 << 24 ) );
   sc->buf[ 120>>2 ] = v512_32( sc->count_low << 3 );
   sc->buf[ 124>>2 ] = v512_32( (sc->count_high << 3)
                                     | (sc->count_low >> 29) );
   do
   {
      IN_PREPARE_16W(sc->buf);
      SPH_XCAT(CORE_16W, PASSES)(INW_16W);
   } while (0);
   WSTATE_16W;
   haval_16way_out( sc, dst );
}
